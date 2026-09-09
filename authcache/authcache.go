// Package authcache provides the legacy authorization cache adapter.
//
// Deprecated: use github.com/faustbrian/go-authorization/adapters/cache. This
// package remains supported for the longer of 180 days after successor public
// availability and two subsequently published stable root-module minor
// releases.
package authcache

import (
	authorization "github.com/faustbrian/go-authorization"
	adapter "github.com/faustbrian/go-authorization/adapters/cache"
	"github.com/faustbrian/go-authorization/policy"
	cache "github.com/faustbrian/go-cache"
)

var (
	ErrManifestTooLarge = adapter.ErrManifestTooLarge
	ErrInvalidRevision  = adapter.ErrInvalidRevision
	ErrNilRepository    = adapter.ErrNilRepository
)

type ManifestCodec struct {
	MaxEncodedSize int
}

func (codec ManifestCodec) Encode(manifest policy.Manifest) ([]byte, error) {
	return adapter.ManifestCodec{MaxEncodedSize: codec.MaxEncodedSize}.Encode(manifest)
}

func (codec ManifestCodec) Decode(encoded []byte) (policy.Manifest, error) {
	return adapter.ManifestCodec{MaxEncodedSize: codec.MaxEncodedSize}.Decode(encoded)
}

type RevisionKeyEncoder struct{}

func (RevisionKeyEncoder) EncodeKey(revision authorization.Revision) ([]byte, error) {
	return (adapter.RevisionKeyEncoder{}).EncodeKey(revision)
}

type Config struct {
	Namespace  string
	Backend    cache.Backend
	TTL        cache.TTLPolicy
	Clock      cache.Clock
	Observer   cache.Observer
	MaxValue   int
	MaxBatch   int
	MaxKeySize int
}

func New(config Config) (*cache.Cache[authorization.Revision, policy.Manifest], error) {
	return adapter.New(adapter.Config{
		Namespace: config.Namespace, Backend: config.Backend, TTL: config.TTL,
		Clock: config.Clock, Observer: config.Observer, MaxValue: config.MaxValue,
		MaxBatch: config.MaxBatch, MaxKeySize: config.MaxKeySize,
	})
}

func RepositoryLoader(
	repository policy.Repository,
) (cache.Loader[authorization.Revision, policy.Manifest], error) {
	return adapter.RepositoryLoader(repository)
}
