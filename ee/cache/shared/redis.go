// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"context"
	"crypto/tls"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisOptions configure the Redis backend.
type RedisOptions struct {
	// Addr is host:port. Required.
	Addr string
	// Username and Password authenticate to the server. A shared cache holds
	// masked answers rather than raw values, but it is still part of the
	// deployment and an unauthenticated one on a shared network is a way to
	// read what every tenant has asked.
	Username string
	Password string
	// DB selects a logical database.
	DB int
	// TLS enables an encrypted connection. Off only for a Redis reachable
	// exclusively over a private network the operator controls.
	TLS bool
	// PoolSize bounds connections. Zero uses the client default.
	PoolSize int
}

// RedisBackend stores entries in Redis.
type RedisBackend struct{ c *redis.Client }

var _ Backend = (*RedisBackend)(nil)

// NewRedis connects to Redis. It does not dial: the client connects lazily, so
// a Redis that is briefly down delays a cache lookup rather than preventing the
// gateway from starting.
func NewRedis(o RedisOptions) (*RedisBackend, error) {
	if o.Addr == "" {
		return nil, errors.New("shared: redis address is required")
	}
	opt := &redis.Options{
		Addr:     o.Addr,
		Username: o.Username,
		Password: o.Password,
		DB:       o.DB,
		PoolSize: o.PoolSize,
	}
	if o.TLS {
		opt.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &RedisBackend{c: redis.NewClient(opt)}, nil
}

// Get returns the value at key. A missing key is (nil, false, nil); anything
// else that went wrong is an error, because the tier above counts the two
// differently and an outage reported as a miss is invisible.
func (r *RedisBackend) Get(ctx context.Context, key string) ([]byte, bool, error) {
	val, err := r.c.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return val, true, nil
}

// Set stores val under key for ttl.
func (r *RedisBackend) Set(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	return r.c.Set(ctx, key, val, ttl).Err()
}

// Close releases the connection pool.
func (r *RedisBackend) Close() error { return r.c.Close() }

// Ping verifies the server is reachable, for a readiness check or a startup
// log line. It is deliberately not called by NewRedis: a cache tier that
// prevents startup when it is unavailable would make the gateway less
// available than it was without one.
func (r *RedisBackend) Ping(ctx context.Context) error { return r.c.Ping(ctx).Err() }
