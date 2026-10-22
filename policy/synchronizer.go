package policy

import (
	"context"
	"errors"
	"sync"
	"time"

	authorization "github.com/faustbrian/go-authorization/v4"
)

// DefaultSyncInterval is the default 30-second repository polling cadence.
const DefaultSyncInterval = 30 * time.Second

// DefaultMaxStaleness is the default two-minute entry-time freshness allowance.
const DefaultMaxStaleness = 2 * time.Minute

var (
	// ErrNilRepository identifies policy synchronizer repository is nil. Compare with errors.Is, not error text.
	ErrNilRepository = errors.New("policy synchronizer repository is nil")
	// ErrNilCompiler identifies policy synchronizer compiler is nil. Compare with errors.Is, not error text.
	ErrNilCompiler = errors.New("policy synchronizer compiler is nil")
	// ErrNilEngine identifies policy synchronizer engine is nil. Compare with errors.Is, not error text.
	ErrNilEngine = errors.New("policy synchronizer engine is nil")
	// ErrInvalidSyncInterval identifies policy synchronizer interval is invalid. Compare with errors.Is, not error text.
	ErrInvalidSyncInterval = errors.New("policy synchronizer interval is invalid")
	// ErrInvalidMaxStaleness identifies policy synchronizer maximum staleness is invalid. Compare with errors.Is, not error text.
	ErrInvalidMaxStaleness = errors.New("policy synchronizer maximum staleness is invalid")
	// ErrStaleManifest identifies policy repository manifest is stale. Compare with errors.Is, not error text.
	ErrStaleManifest = errors.New("policy repository manifest is stale")
	// ErrPolicyStale identifies authorization policy verification is stale. Compare with errors.Is, not error text.
	ErrPolicyStale = errors.New("authorization policy verification is stale")
)

// SynchronizerOption configures one construction synchronously;
// nil/custom options are trusted and may panic.
type SynchronizerOption func(*Synchronizer)

// WithSyncInterval sets a positive polling interval validated at construction.
func WithSyncInterval(interval time.Duration) SynchronizerOption {
	return func(synchronizer *Synchronizer) {
		synchronizer.interval = interval
	}
}

// WithMaxStaleness sets a positive admission age validated at construction.
func WithMaxStaleness(maxStaleness time.Duration) SynchronizerOption {
	return func(synchronizer *Synchronizer) {
		synchronizer.maxStaleness = maxStaleness
	}
}

// WithSynchronizerClock borrows a prompt concurrency-safe clock; nil
// is ignored. It may be called under the verification lock and must not reenter.
func WithSynchronizerClock(clock func() time.Time) SynchronizerOption {
	return func(synchronizer *Synchronizer) {
		if clock != nil {
			synchronizer.clock = clock
		}
	}
}

// Synchronizer keeps an engine converged with its authoritative repository.
// Direct repository polling is the correctness path; external invalidation
// transports may call Observe to reduce propagation latency. Reload serializes
// under reloadMu across repository I/O and compiler callbacks; waiting for that
// mutex is not context-cancelable. Clocks run under verifiedMu on successful reload
// and must not reenter verification methods. No collaborators are closed here.
// Freshness admission samples before Engine.Decide, not throughout a long decision.
type Synchronizer struct {
	repository   Repository
	compiler     *Compiler
	engine       *authorization.Engine
	interval     time.Duration
	maxStaleness time.Duration
	clock        func() time.Time
	reloadMu     sync.Mutex
	verifiedMu   sync.RWMutex
	verifiedAt   time.Time
}

// NewSynchronizer borrows repository/compiler/engine and creates no worker.
// Literal nil collaborators and non-positive interval/age fail; typed-nil
// repositories/custom callbacks are not sandboxed. Caller starts/supervises Run.
func NewSynchronizer(
	repository Repository,
	compiler *Compiler,
	engine *authorization.Engine,
	options ...SynchronizerOption,
) (*Synchronizer, error) {
	if repository == nil {
		return nil, ErrNilRepository
	}
	if compiler == nil {
		return nil, ErrNilCompiler
	}
	if engine == nil {
		return nil, ErrNilEngine
	}
	synchronizer := &Synchronizer{
		repository:   repository,
		compiler:     compiler,
		engine:       engine,
		interval:     DefaultSyncInterval,
		maxStaleness: DefaultMaxStaleness,
		clock:        time.Now,
	}
	for _, option := range options {
		option(synchronizer)
	}
	if synchronizer.interval <= 0 {
		return nil, ErrInvalidSyncInterval
	}
	if synchronizer.maxStaleness <= 0 {
		return nil, ErrInvalidMaxStaleness
	}
	return synchronizer, nil
}

// Reload activates a newer repository manifest. Equal revisions are a no-op;
// older repository state fails rather than rolling the engine back. Same-revision
// envelope validation marks freshness without recompiling or comparing content;
// repository revisions must identify immutable semantics. Compilation/publication
// can complete after cancellation inside a successful noncooperative callback.
// Failed reloads leave the last active engine/freshness time, not a new empty view.
func (synchronizer *Synchronizer) Reload(ctx context.Context) (bool, error) {
	// Serialize source reads through activation; independent Engine writers can
	// still win the later expected-revision check and cause a local conflict.
	synchronizer.reloadMu.Lock()
	defer synchronizer.reloadMu.Unlock()
	switch err := ctx.Err(); err {
	case nil:
	default:
		return false, err
	}
	manifest, err := synchronizer.repository.Load(ctx)
	switch err {
	case nil:
	default:
		return false, err
	}
	switch validationErr := manifest.Validate(); validationErr {
	case nil:
	default:
		return false, validationErr
	}
	current := synchronizer.engine.Revision()
	if manifest.Revision < current {
		return false, ErrStaleManifest
	}
	if manifest.Revision == current {
		synchronizer.markVerified()
		return false, nil
	}
	snapshot, err := synchronizer.compiler.Compile(manifest)
	if err != nil {
		return false, err
	}
	if err := synchronizer.engine.ReplaceSnapshot(snapshot, current); err != nil {
		return false, err
	}
	synchronizer.markVerified()
	return true, nil
}

// Decide enforces the maximum age of the last successful repository
// verification before delegating to Engine. Zero verification or a
// backward clock fails closed; exact MaxStaleness remains admitted. Age is checked
// once at entry, not rechecked after an evaluator blocks. Clock panics are not
// contained; ctx cancellation may be reported as stale first.
func (synchronizer *Synchronizer) Decide(
	ctx context.Context,
	request authorization.Request,
) (authorization.Decision, error) {
	verifiedAt, verified := synchronizer.LastVerified()
	now := synchronizer.clock()
	if !verified || now.Before(verifiedAt) || now.Sub(verifiedAt) > synchronizer.maxStaleness {
		return authorization.Decision{
			Outcome:  authorization.Deny,
			Reason:   authorization.ReasonPolicyStale,
			Revision: synchronizer.engine.Revision(),
		}, ErrPolicyStale
	}
	return synchronizer.engine.Decide(ctx, request)
}

// LastVerified reports the time of the latest successful authoritative
// repository verification, including a same-revision verification.
func (synchronizer *Synchronizer) LastVerified() (time.Time, bool) {
	synchronizer.verifiedMu.RLock()
	defer synchronizer.verifiedMu.RUnlock()
	return synchronizer.verifiedAt, !synchronizer.verifiedAt.IsZero()
}

func (synchronizer *Synchronizer) markVerified() {
	synchronizer.verifiedMu.Lock()
	defer synchronizer.verifiedMu.Unlock()
	synchronizer.verifiedAt = synchronizer.clock()
}

// Observe handles an untrusted invalidation revision by reloading the source
// of truth. It rejects hints ahead of the repository state. Hints at/below the
// active revision return immediately without refreshing verification or checking ctx.
// A hint is never authoritative content or proof of publisher identity.
func (synchronizer *Synchronizer) Observe(
	ctx context.Context,
	revision authorization.Revision,
) error {
	if revision <= synchronizer.engine.Revision() {
		return nil
	}
	if _, err := synchronizer.Reload(ctx); err != nil {
		return err
	}
	if synchronizer.engine.Revision() < revision {
		return ErrStaleManifest
	}
	return nil
}

// Run performs an immediate repository check and then polls until cancellation
// or the first reload error. It owns/stops the ticker within the call and creates
// no detached worker. Applications supervise restart/backoff; no retries are added.
// Shutdown waits on cooperative repository/compiler work and mutex acquisition.
func (synchronizer *Synchronizer) Run(ctx context.Context) error {
	_, err := synchronizer.Reload(ctx)
	switch err {
	case nil:
	default:
		return err
	}
	ticker := time.NewTicker(synchronizer.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			_, reloadErr := synchronizer.Reload(ctx)
			switch reloadErr {
			case nil:
			default:
				return reloadErr
			}
		}
	}
}
