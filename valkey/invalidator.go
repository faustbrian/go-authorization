// Package valkey distributes monotonic policy revision invalidations through
// Valkey as advisory hints, not authorization or policy content. New borrows a
// native Client; Watch owns a Receive goroutine/ticker only until the call joins
// on cancellation. The client must cooperate; shutdown can otherwise block.
// Publish uses Lua numeric comparison, not an exact full-uint64 ordering primitive.
// Backend persistence/replication, credentials, retries and client close are
// deployment-owned; repository polling remains the authoritative correctness path.
package valkey

import (
	"cmp"
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	authorization "github.com/faustbrian/go-authorization/v3"
	native "github.com/valkey-io/valkey-go"
)

const (
	// DefaultPrefix is the default Valkey key/channel namespace; applications own isolation.
	DefaultPrefix = "authorization"
	// DefaultPollInterval is the default 30-second advisory-key polling cadence.
	DefaultPollInterval = 30 * time.Second
)

var (
	// ErrNilClient identifies authorization valkey client is nil. Compare with errors.Is, not error text.
	ErrNilClient = errors.New("authorization valkey client is nil")
	// ErrInvalidPrefix identifies authorization valkey prefix is invalid. Compare with errors.Is, not error text.
	ErrInvalidPrefix = errors.New("authorization valkey prefix is invalid")
	// ErrInvalidPollInterval identifies authorization valkey poll interval is invalid. Compare with errors.Is, not error text.
	ErrInvalidPollInterval = errors.New("authorization valkey poll interval is invalid")
	// ErrInvalidRevision identifies authorization valkey revision is invalid. Compare with errors.Is, not error text.
	ErrInvalidRevision = errors.New("authorization valkey revision is invalid")
	// ErrInvalidResponse identifies authorization valkey response is invalid. Compare with errors.Is, not error text.
	ErrInvalidResponse = errors.New("authorization valkey response is invalid")
	// ErrNilHandler identifies authorization valkey handler is nil. Compare with errors.Is, not error text.
	ErrNilHandler = errors.New("authorization valkey handler is nil")
)

const publishScript = `local current = redis.call('GET', KEYS[1])
local next = tonumber(ARGV[2])
if current and tonumber(current) >= next then
    return 0
end
redis.call('SET', KEYS[1], ARGV[2])
redis.call('PUBLISH', ARGV[1], ARGV[2])
return 1`

// Options selects caller-owned key/channel namespace and polling cadence.
type Options struct {
	// Prefix selects Valkey key/channel names; empty chooses DefaultPrefix.
	Prefix string
	// PollInterval chooses periodic advisory-key reads; zero selects 30 seconds, negative is invalid.
	PollInterval time.Duration
}

// Invalidator borrows a native client with no Close ownership; zero is unusable.
// Concurrent use depends on client/callback safety, not policy authentication.
type Invalidator struct {
	client       native.Client
	key          string
	channel      string
	pollInterval time.Duration
}

// New rejects literal nil clients and blank/negative settings, with
// default prefix/interval for zero fields. Typed-nil clients and callbacks are
// not panic-contained; caller namespace strings are not authenticated scope.
func New(client native.Client, options Options) (*Invalidator, error) {
	if client == nil {
		return nil, ErrNilClient
	}
	if options.Prefix == "" {
		options.Prefix = DefaultPrefix
	}
	if strings.TrimSpace(options.Prefix) == "" {
		return nil, ErrInvalidPrefix
	}
	switch cmp.Compare(options.PollInterval, time.Duration(0)) {
	case 0:
		options.PollInterval = DefaultPollInterval
	case -1:
		return nil, ErrInvalidPollInterval
	}
	return &Invalidator{
		client:       client,
		key:          options.Prefix + ":revision",
		channel:      options.Prefix + ":invalidate",
		pollInterval: options.PollInterval,
	}, nil
}

// Publish atomically sets the key and emits a wakeup within one Lua operation.
// It rejects zero and otherwise delegates ordering to Lua tonumber, which is not
// an exact full-uint64 comparator; applications must stay within the backend's
// exact numeric domain. False means the script considered existing state >= next.
// Backend persistence/replication is not guaranteed, and an error can require
// reconciling unknown execution state. No authoritative policy data is published.
func (invalidator *Invalidator) Publish(
	ctx context.Context,
	revision authorization.Revision,
) (bool, error) {
	if revision == 0 {
		return false, ErrInvalidRevision
	}
	encoded := strconv.FormatUint(uint64(revision), 10)
	result, err := invalidator.client.Do(
		ctx,
		invalidator.client.B().Eval().Script(publishScript).Numkeys(1).
			Key(invalidator.key).Arg(invalidator.channel, encoded).Build(),
	).ToInt64()
	if err != nil {
		return false, err
	}
	if result != 0 && result != 1 {
		return false, ErrInvalidResponse
	}
	return result == 1, nil
}

// Revision reads the current advisory key as exact nonzero uint64 decimal text.
// Missing keys return zero; deletion/eviction/restoration can remove/reset state,
// so zero is not proof that a policy was never published. Client response allocation,
// credentials, persistence and untrusted mutation remain external trust boundaries.
func (invalidator *Invalidator) Revision(
	ctx context.Context,
) (authorization.Revision, error) {
	encoded, err := invalidator.client.Do(
		ctx,
		invalidator.client.B().Get().Key(invalidator.key).Build(),
	).ToString()
	if native.IsValkeyNil(err) {
		return 0, nil
	}
	switch err {
	case nil:
	default:
		return 0, err
	}
	parsed, err := strconv.ParseUint(encoded, 10, 64)
	if err != nil || parsed == 0 {
		return 0, ErrInvalidRevision
	}
	return authorization.Revision(parsed), nil
}

// Watch observes newer revisions. Pub/sub only wakes the watcher; every
// notification triggers a key read and periodic polling continues after Receive
// exits (its error is not returned). The handler runs serially and advances the
// local after revision only on success; polling/key/handler errors stop the call.
// Cancellation joins Receive, requiring cooperative client I/O. Handler panics are
// not contained and its work is not preempted; repository verification belongs to
// the handler. The key is advisory and backend durability must be configured.
func (invalidator *Invalidator) Watch(
	ctx context.Context,
	after authorization.Revision,
	handler func(authorization.Revision) error,
) error {
	if handler == nil {
		return ErrNilHandler
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	watchCtx, cancel := context.WithCancel(ctx)
	wakeup := make(chan struct{}, 1)
	receiveDone := make(chan error, 1)
	subscriptionDone := make(chan struct{})
	go func() {
		defer close(subscriptionDone)
		receiveDone <- invalidator.client.Receive(
			watchCtx,
			invalidator.client.B().Subscribe().Channel(invalidator.channel).Build(),
			func(native.PubSubMessage) {
				select {
				case wakeup <- struct{}{}:
				default:
				}
			},
		)
	}()
	defer func() {
		cancel()
		<-subscriptionDone
	}()

	ticker := time.NewTicker(invalidator.pollInterval)
	defer ticker.Stop()
	observe := func() error {
		revision, err := invalidator.Revision(watchCtx)
		switch err {
		case nil:
		default:
			return err
		}
		switch cmp.Compare(revision, after) {
		case 1:
			if err := handler(revision); err != nil {
				return err
			}
			after = revision
		}
		return nil
	}
	switch err := observe(); err {
	case nil:
	default:
		return err
	}

	for {
		select {
		case <-watchCtx.Done():
			return watchCtx.Err()
		case <-ticker.C:
			if err := observe(); err != nil {
				return err
			}
		case <-wakeup:
			if err := observe(); err != nil {
				return err
			}
		case <-receiveDone:
			receiveDone = nil
		}
	}
}
