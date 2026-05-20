package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// kiroCacheRedisKeyPrefix uses a hash tag so all keys for a given credKey land on
	// the same cluster slot, enabling atomic multi-key operations if needed in future.
	kiroCacheRedisKeyPrefix = "kiro:cachetrack:{%016x}"
	// kiroCacheRedisKeyTTLBuffer is added on top of the max entry expiry when setting
	// the Redis key TTL, so the key outlives all its entries.
	kiroCacheRedisKeyTTLBuffer = 5 * time.Minute
)

// redisCacheEntry is the JSON-serialisable form stored as a Redis hash field value.
type redisCacheEntry struct {
	Tokens      int   `json:"tokens"`
	TTLMs       int64 `json:"ttl_ms"`
	ExpiresAtMs int64 `json:"expires_at_ms"`
}

// redisKiroCacheTracker implements KiroCacheTracker using a Redis hash per account.
// Key format: kiro:cachetrack:{<credKey hex>}
// Field:      hex(prefixFingerprint[32]byte)
// Value:      JSON redisCacheEntry
//
// Concurrency: HGETALL → Go compute → Pipeline HSET+EXPIREAT.
// A small race window exists between read and write, but the worst case is a
// duplicate cache-creation event — far better than the in-memory multi-pod problem.
type redisKiroCacheTracker struct {
	client *redis.Client
}

// NewRedisKiroCacheTracker returns a KiroCacheTracker backed by Redis.
func NewRedisKiroCacheTracker(client *redis.Client) KiroCacheTracker {
	return &redisKiroCacheTracker{client: client}
}

func (r *redisKiroCacheTracker) ComputeAndUpdate(credKey uint64, profile *kiroCacheProfile) *kiroCacheEmulationUsage {
	out := &kiroCacheEmulationUsage{}
	if r == nil || profile == nil || credKey == 0 {
		return out
	}
	lastBreakpoint := profile.lastCacheableBreakpoint()
	if lastBreakpoint == nil {
		return out
	}
	lastBreakpointTokens := min(lastBreakpoint.cumulativeTokens, profile.totalInputTokens)

	ctx := context.Background()
	key := fmt.Sprintf(kiroCacheRedisKeyPrefix, credKey)
	now := time.Now()

	// 1. Read all existing entries for this account.
	raw, err := r.client.HGetAll(ctx, key).Result()
	if err != nil {
		log.Printf("kiro redis tracker: HGETALL %s: %v", key, err)
		// Fall through with empty map — treat as cold cache.
		raw = map[string]string{}
	}

	entries := parseRedisCacheEntries(raw)

	// 2. Compute: find longest matching cached prefix (same logic as in-memory impl).
	matchedTokens := 0
	breakpoints := profile.cacheableBreakpoints()
	for i, seen := len(breakpoints)-1, 0; i >= 0 && seen < kiroCachePrefixLookbackLimit; i, seen = i-1, seen+1 {
		bp := breakpoints[i]
		candidate := profile.blocks[bp.blockIndex]
		fpHex := hex.EncodeToString(candidate.prefixFingerprint[:])
		entry, ok := entries[fpHex]
		if !ok {
			continue
		}
		expiresAt := time.UnixMilli(entry.ExpiresAtMs)
		if !expiresAt.After(now) {
			continue
		}
		// Refresh TTL on hit.
		entry.ExpiresAtMs = now.Add(time.Duration(entry.TTLMs) * time.Millisecond).UnixMilli()
		entries[fpHex] = entry
		matchedTokens = min(bp.cumulativeTokens, profile.totalInputTokens)
		break
	}

	// 3. Update: write all cacheable breakpoints.
	maxExpiresAt := now
	for _, bp := range profile.cacheableBreakpoints() {
		block := profile.blocks[bp.blockIndex]
		fpHex := hex.EncodeToString(block.prefixFingerprint[:])
		expiresAt := now.Add(bp.ttl)
		ttlMs := bp.ttl.Milliseconds()

		if existing, ok := entries[fpHex]; ok {
			if block.cumulativeTokens > existing.Tokens {
				existing.Tokens = block.cumulativeTokens
			}
			if ttlMs > existing.TTLMs {
				existing.TTLMs = ttlMs
			}
			if expiresAt.UnixMilli() > existing.ExpiresAtMs {
				existing.ExpiresAtMs = expiresAt.UnixMilli()
			}
			entries[fpHex] = existing
		} else {
			entries[fpHex] = redisCacheEntry{
				Tokens:      block.cumulativeTokens,
				TTLMs:       ttlMs,
				ExpiresAtMs: expiresAt.UnixMilli(),
			}
		}
		if expiresAt.After(maxExpiresAt) {
			maxExpiresAt = expiresAt
		}
	}

	// 4. Persist: pipeline HSET for updated fields + EXPIREAT on the key.
	if err := r.persistEntries(ctx, key, entries, maxExpiresAt); err != nil {
		log.Printf("kiro redis tracker: persist %s: %v", key, err)
	}

	newTokens := max(lastBreakpointTokens-matchedTokens, 0)
	out.CacheReadInputTokens = max(matchedTokens, 0)
	out.CacheCreationInputTokens = newTokens
	out.CacheCreation5mInputTokens, out.CacheCreation1hInputTokens = profile.ttlBreakdown(matchedTokens)
	return out
}

func (r *redisKiroCacheTracker) persistEntries(ctx context.Context, key string, entries map[string]redisCacheEntry, maxExpiresAt time.Time) error {
	if len(entries) == 0 {
		return nil
	}
	// Build flat field/value slice for HSET.
	fields := make([]any, 0, len(entries)*2)
	for fpHex, entry := range entries {
		b, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		fields = append(fields, fpHex, string(b))
	}
	if len(fields) == 0 {
		return nil
	}
	keyTTL := time.Until(maxExpiresAt) + kiroCacheRedisKeyTTLBuffer
	if keyTTL <= 0 {
		keyTTL = kiroCacheRedisKeyTTLBuffer
	}
	pipe := r.client.Pipeline()
	pipe.HSet(ctx, key, fields...)
	pipe.Expire(ctx, key, keyTTL)
	_, err := pipe.Exec(ctx)
	return err
}

func parseRedisCacheEntries(raw map[string]string) map[string]redisCacheEntry {
	out := make(map[string]redisCacheEntry, len(raw))
	for fpHex, val := range raw {
		var entry redisCacheEntry
		if err := json.Unmarshal([]byte(val), &entry); err != nil {
			continue
		}
		out[fpHex] = entry
	}
	return out
}
