package api

import "github.com/dgraph-io/ristretto/v2"

func newDefaultCache[T any]() (*ristretto.Cache[string, T], error) {
	return ristretto.NewCache(&ristretto.Config[string, T]{
		NumCounters: 1e6,
		MaxCost:     1e4,
		BufferItems: 64,
	})
}
