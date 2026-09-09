// Package authorizationcache provides explicit advisory cache adapters for
// portable policy manifests. Cached manifests never replace repository
// verification.
package authorizationcache

import (
	"context"
	"errors"
	"strconv"

	authorization "github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-authorization/policy"
	cache "github.com/faustbrian/go-cache"
)

const (
	defaultMaxEncodedSize = 1 << 20
	defaultMaxKeySize     = 256
)

var (
	// ErrManifestTooLarge reports that an encoded manifest exceeds the configured bound.
	ErrManifestTooLarge = errors.New("authorization cached manifest is too large")
	// ErrInvalidRevision reports that a zero revision cannot be used as a cache key.
	ErrInvalidRevision = errors.New("authorization cached revision is invalid")
	// ErrNilRepository reports that RepositoryLoader received no policy repository.
	ErrNilRepository = errors.New("authorization cached repository is nil")
)

// ManifestCodec encodes and decodes policy manifests with a bounded encoded size.
type ManifestCodec struct {
	// MaxEncodedSize is the byte limit; non-positive values use the package default.
	MaxEncodedSize int
}

// Encode serializes manifest and rejects results larger than MaxEncodedSize.
func (codec ManifestCodec) Encode(manifest policy.Manifest) ([]byte, error) {
	encoded, err := policy.Encode(manifest)
	if err != nil {
		return nil, err
	}
	if len(encoded) > codec.limit() {
		return nil, ErrManifestTooLarge
	}
	return encoded, nil
}

// Decode parses encoded after enforcing MaxEncodedSize.
func (codec ManifestCodec) Decode(encoded []byte) (policy.Manifest, error) {
	if len(encoded) > codec.limit() {
		return policy.Manifest{}, ErrManifestTooLarge
	}
	return policy.Decode(encoded)
}

func (codec ManifestCodec) limit() int {
	if codec.MaxEncodedSize <= 0 {
		return defaultMaxEncodedSize
	}
	return codec.MaxEncodedSize
}

// RevisionKeyEncoder encodes non-zero policy revisions as stable decimal cache keys.
type RevisionKeyEncoder struct{}

// EncodeKey returns revision's decimal representation or ErrInvalidRevision for zero.
func (RevisionKeyEncoder) EncodeKey(revision authorization.Revision) ([]byte, error) {
	if revision == 0 {
		return nil, ErrInvalidRevision
	}
	return []byte(strconv.FormatUint(uint64(revision), 10)), nil
}

// Config configures an advisory manifest cache and its resource bounds.
type Config struct {
	// Namespace isolates keys owned by this application.
	Namespace string
	// Backend stores encoded cache entries and retains ownership of its resources.
	Backend cache.Backend
	// TTL controls entry expiration.
	TTL cache.TTLPolicy
	// Clock supplies cache time behavior.
	Clock cache.Clock
	// Observer receives bounded cache operation observations.
	Observer cache.Observer
	// MaxValue bounds an encoded manifest; zero uses the package default.
	MaxValue int
	// MaxBatch bounds multi-key cache operations.
	MaxBatch int
	// MaxKeySize bounds encoded cache keys; zero uses the package default.
	MaxKeySize int
}

// New constructs an advisory manifest cache from config.
func New(config Config) (*cache.Cache[authorization.Revision, policy.Manifest], error) {
	if config.MaxValue == 0 {
		config.MaxValue = defaultMaxEncodedSize
	}
	if config.MaxKeySize == 0 {
		config.MaxKeySize = defaultMaxKeySize
	}
	keys, err := cache.NewKeySpace(
		config.Namespace,
		"authorization-policy",
		1,
		RevisionKeyEncoder{},
		config.MaxKeySize,
	)
	if err != nil {
		return nil, err
	}
	return cache.New(cache.Config[authorization.Revision, policy.Manifest]{
		Backend: config.Backend, Keys: keys, Codec: ManifestCodec{MaxEncodedSize: config.MaxValue},
		TTL: config.TTL, Clock: config.Clock, MaxValue: config.MaxValue,
		MaxBatch: config.MaxBatch, Observer: config.Observer,
	})
}

// RepositoryLoader returns a loader that reports a hit only for the repository's exact current revision.
func RepositoryLoader(
	repository policy.Repository,
) (cache.Loader[authorization.Revision, policy.Manifest], error) {
	if repository == nil {
		return nil, ErrNilRepository
	}
	return func(
		ctx context.Context,
		revision authorization.Revision,
	) (cache.LoadResult[policy.Manifest], error) {
		manifest, err := repository.Load(ctx)
		if err != nil {
			return cache.LoadResult[policy.Manifest]{}, err
		}
		if manifest.Revision != revision {
			return cache.LoadResult[policy.Manifest]{}, nil
		}
		return cache.LoadResult[policy.Manifest]{Value: manifest, Found: true}, nil
	}, nil
}
