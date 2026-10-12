// Package authcache provides the legacy authorization cache adapter.
//
// Deprecated: use github.com/faustbrian/go-authorization/v3/adapters/cache. This
// package remains supported for the longer of 180 days after successor public
// availability and two subsequently published stable root-module minor
// releases.
package authcache

import (
	authorization "github.com/faustbrian/go-authorization/v3"
	adapter "github.com/faustbrian/go-authorization/v3/adapters/cache"
	"github.com/faustbrian/go-authorization/v3/policy"
	cache "github.com/faustbrian/go-cache/v2"
)

var (
	// ErrManifestTooLarge preserves the direct adapter error identity for errors.Is.
	ErrManifestTooLarge = adapter.ErrManifestTooLarge
	// ErrInvalidRevision preserves the direct adapter error identity for errors.Is.
	ErrInvalidRevision = adapter.ErrInvalidRevision
	// ErrNilRepository preserves the direct adapter error identity for errors.Is.
	ErrNilRepository = adapter.ErrNilRepository
)

// ManifestCodec retains the released named codec and delegates size/profile policy.
type ManifestCodec struct {
	// MaxEncodedSize caps admitted encoding; non-positive values select 1 MiB.
	MaxEncodedSize int
}

// Encode delegates validated serialization with post-allocation size rejection.
func (codec ManifestCodec) Encode(manifest policy.Manifest) ([]byte, error) {
	return adapter.ManifestCodec{MaxEncodedSize: codec.MaxEncodedSize}.Encode(manifest)
}

// Decode delegates byte admission and application-profile validation.
func (codec ManifestCodec) Decode(encoded []byte) (policy.Manifest, error) {
	return adapter.ManifestCodec{MaxEncodedSize: codec.MaxEncodedSize}.Decode(encoded)
}

// RevisionKeyEncoder retains the released nonzero decimal revision-key contract.
type RevisionKeyEncoder struct{}

// EncodeKey delegates exact nonzero decimal key encoding.
func (RevisionKeyEncoder) EncodeKey(revision authorization.Revision) ([]byte, error) {
	return (adapter.RevisionKeyEncoder{}).EncodeKey(revision)
}

// Config retains released composition fields; collaborators stay caller-owned.
type Config struct {
	// Namespace separates application policy cache keys; callers own scope/uniqueness.
	Namespace string
	// Backend is borrowed; callers own its capacity, transport and shutdown policy.
	Backend cache.Backend
	// TTL is delegated cache expiration policy, not repository verification freshness.
	TTL cache.TTLPolicy
	// Clock is borrowed time policy and must be prompt/concurrency-safe; no lifecycle is owned.
	Clock cache.Clock
	// Observer is delegated borrowed cache observation; no ownership transfer occurs.
	Observer cache.Observer
	// MaxValue caps encoded cache bytes; zero selects 1 MiB.
	MaxValue int
	// MaxBatch is delegated to the cache multi-key admission policy.
	MaxBatch int
	// MaxKeySize is delegated key admission; zero selects 256.
	MaxKeySize int
}

// New delegates to adapters/cache and retains its advisory, borrowed lifecycle.
func New(config Config) (*cache.Cache[authorization.Revision, policy.Manifest], error) {
	return adapter.New(adapter.Config{
		Namespace: config.Namespace, Backend: config.Backend, TTL: config.TTL,
		Clock: config.Clock, Observer: config.Observer, MaxValue: config.MaxValue,
		MaxBatch: config.MaxBatch, MaxKeySize: config.MaxKeySize,
	})
}

// RepositoryLoader delegates fresh exact-revision reads, not cache-hit
// verification; direct calls retain raw repository error/callback semantics.
func RepositoryLoader(
	repository policy.Repository,
) (cache.Loader[authorization.Revision, policy.Manifest], error) {
	return adapter.RepositoryLoader(repository)
}
