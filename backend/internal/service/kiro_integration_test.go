package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/kirocooldown"
	"github.com/stretchr/testify/require"
)

// MockKiroCooldownStore is an in-memory implementation of KiroCooldownStore for testing.
type MockKiroCooldownStore struct {
	mu               sync.Mutex
	states           map[string]*kirocooldown.State
	mark429Count     map[string]int
	markSuccessCount map[string]int
}

func NewMockKiroCooldownStore() *MockKiroCooldownStore {
	return &MockKiroCooldownStore{
		states:           make(map[string]*kirocooldown.State),
		mark429Count:     make(map[string]int),
		markSuccessCount: make(map[string]int),
	}
}

func (m *MockKiroCooldownStore) ReserveRequest(_ context.Context, tokenKey string) (time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.states[tokenKey]
	if ok && state != nil && state.Active && state.CooldownUntil.After(time.Now()) {
		return 0, kirocooldown.NewError(time.Until(state.CooldownUntil), state.Reason)
	}
	return 0, nil
}

func (m *MockKiroCooldownStore) MarkSuccess(_ context.Context, tokenKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.states, tokenKey)
	m.markSuccessCount[tokenKey]++
	return nil
}

func (m *MockKiroCooldownStore) Mark429(_ context.Context, tokenKey string) (time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mark429Count[tokenKey]++
	cooldown := 60 * time.Second
	m.states[tokenKey] = &kirocooldown.State{
		Active:        true,
		Reason:        kirocooldown.CooldownReason429,
		CooldownUntil: time.Now().Add(cooldown),
		Remaining:     cooldown,
	}
	return cooldown, nil
}

func (m *MockKiroCooldownStore) MarkSuspended(_ context.Context, tokenKey string) (time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cooldown := kirocooldown.LongCooldown
	m.states[tokenKey] = &kirocooldown.State{
		Active:        true,
		Reason:        kirocooldown.CooldownReasonSuspended,
		CooldownUntil: time.Now().Add(cooldown),
		Remaining:     cooldown,
	}
	return cooldown, nil
}

func (m *MockKiroCooldownStore) GetState(_ context.Context, tokenKey string) (*kirocooldown.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.states[tokenKey]
	if !ok {
		return nil, nil
	}
	// Return nil if cooldown has expired.
	if state != nil && state.Active && !state.CooldownUntil.After(time.Now()) {
		return nil, nil
	}
	return state, nil
}

func (m *MockKiroCooldownStore) GetStateBatch(_ context.Context, tokenKeys []string) (map[string]*kirocooldown.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make(map[string]*kirocooldown.State, len(tokenKeys))
	now := time.Now()
	for _, k := range tokenKeys {
		state, ok := m.states[k]
		if !ok {
			continue
		}
		if state != nil && state.Active && state.CooldownUntil.After(now) {
			result[k] = state
		}
	}
	return result, nil
}

func (m *MockKiroCooldownStore) ClearEarliestTransientCooldown(_ context.Context, tokenKeys []string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()

	// Find the transient (429) cooldown with the earliest expiry.
	var bestKey string
	var bestUntil time.Time
	for _, k := range tokenKeys {
		state, ok := m.states[k]
		if !ok || state == nil || !state.Active {
			continue
		}
		if state.Reason != kirocooldown.CooldownReason429 {
			continue
		}
		if !state.CooldownUntil.After(now) {
			continue
		}
		if bestKey == "" || state.CooldownUntil.Before(bestUntil) {
			bestKey = k
			bestUntil = state.CooldownUntil
		}
	}
	if bestKey == "" {
		return false, nil
	}
	delete(m.states, bestKey)
	return true, nil
}

// SetCooldown directly sets a cooldown state for a token key (test helper).
func (m *MockKiroCooldownStore) SetCooldown(tokenKey string, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[tokenKey] = &kirocooldown.State{
		Active:        true,
		Reason:        kirocooldown.CooldownReason429,
		CooldownUntil: time.Now().Add(d),
		Remaining:     d,
	}
}

// IsInCooldown reports whether the token key currently has an active cooldown.
func (m *MockKiroCooldownStore) IsInCooldown(tokenKey string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.states[tokenKey]
	if !ok || state == nil {
		return false
	}
	return state.Active && state.CooldownUntil.After(time.Now())
}

// newKiroOAuthAccount creates a minimal Kiro OAuth account for testing.
func newKiroOAuthAccount(id int64, creds map[string]any) *Account {
	return &Account{
		ID:          id,
		Platform:    PlatformKiro,
		Type:        AccountTypeOAuth,
		Status:      StatusActive,
		Schedulable: true,
		Credentials: creds,
	}
}

// TestKiroAccount429CooldownAndRecovery verifies that after a 429 is marked on
// account A, it becomes unschedulable while account B remains schedulable, and
// that clearing A's cooldown restores its schedulability.
func TestKiroAccount429CooldownAndRecovery(t *testing.T) {
	store := NewMockKiroCooldownStore()
	svc := &GatewayService{kiroCooldownStore: store}
	ctx := context.Background()

	accountA := newKiroOAuthAccount(1, map[string]any{
		"client_id_hash": "hash-account-a",
		"refresh_token":  "refresh-a",
	})
	accountB := newKiroOAuthAccount(2, map[string]any{
		"client_id_hash": "hash-account-b",
		"refresh_token":  "refresh-b",
	})

	// Both accounts start schedulable.
	require.True(t, svc.isKiroRuntimeSchedulable(ctx, accountA), "account A should be schedulable initially")
	require.True(t, svc.isKiroRuntimeSchedulable(ctx, accountB), "account B should be schedulable initially")

	// Mark account A with a 429.
	keyA := buildKiroAccountKey(accountA)
	_, err := store.Mark429(ctx, keyA)
	require.NoError(t, err)

	// Account A is now in cooldown.
	require.True(t, store.IsInCooldown(keyA), "account A should be in cooldown after 429")
	require.False(t, svc.isKiroRuntimeSchedulable(ctx, accountA), "account A should not be schedulable during cooldown")

	// Account B is unaffected.
	require.True(t, svc.isKiroRuntimeSchedulable(ctx, accountB), "account B should still be schedulable")

	// Clear account A's cooldown.
	err = store.MarkSuccess(ctx, keyA)
	require.NoError(t, err)

	// Account A is schedulable again.
	require.False(t, store.IsInCooldown(keyA), "account A cooldown should be cleared")
	require.True(t, svc.isKiroRuntimeSchedulable(ctx, accountA), "account A should be schedulable after recovery")
}

// TestKiroCooldownPoolRecovery verifies that when all accounts are in 429
// cooldown, ClearEarliestTransientCooldown clears exactly one (the earliest).
func TestKiroCooldownPoolRecovery(t *testing.T) {
	store := NewMockKiroCooldownStore()
	ctx := context.Background()

	accounts := []Account{
		*newKiroOAuthAccount(10, map[string]any{"client_id_hash": "hash-c1", "refresh_token": "r1"}),
		*newKiroOAuthAccount(11, map[string]any{"client_id_hash": "hash-c2", "refresh_token": "r2"}),
		*newKiroOAuthAccount(12, map[string]any{"client_id_hash": "hash-c3", "refresh_token": "r3"}),
	}

	// Set all three accounts into 429 cooldown with staggered expiry times so
	// the "earliest" is deterministic.
	key0 := buildKiroAccountKey(&accounts[0])
	key1 := buildKiroAccountKey(&accounts[1])
	key2 := buildKiroAccountKey(&accounts[2])

	store.SetCooldown(key0, 30*time.Second) // earliest
	store.SetCooldown(key1, 60*time.Second)
	store.SetCooldown(key2, 90*time.Second)

	require.True(t, store.IsInCooldown(key0))
	require.True(t, store.IsInCooldown(key1))
	require.True(t, store.IsInCooldown(key2))

	// ClearEarliestTransientCooldown should clear exactly one.
	cleared, err := store.ClearEarliestTransientCooldown(ctx, []string{key0, key1, key2})
	require.NoError(t, err)
	require.True(t, cleared, "should have cleared one cooldown")

	// The earliest (key0) should be cleared; the others remain.
	require.False(t, store.IsInCooldown(key0), "earliest cooldown should be cleared")
	require.True(t, store.IsInCooldown(key1), "second cooldown should remain")
	require.True(t, store.IsInCooldown(key2), "third cooldown should remain")

	// tryRecoverKiroCooldownPool exercises the same path through GatewayService.
	// Reset state and verify the service-level wrapper also clears exactly one.
	store2 := NewMockKiroCooldownStore()
	svc2 := &GatewayService{kiroCooldownStore: store2}

	accounts2 := []Account{
		*newKiroOAuthAccount(20, map[string]any{"client_id_hash": "hash-d1", "refresh_token": "s1"}),
		*newKiroOAuthAccount(21, map[string]any{"client_id_hash": "hash-d2", "refresh_token": "s2"}),
		*newKiroOAuthAccount(22, map[string]any{"client_id_hash": "hash-d3", "refresh_token": "s3"}),
	}
	k0 := buildKiroAccountKey(&accounts2[0])
	k1 := buildKiroAccountKey(&accounts2[1])
	k2 := buildKiroAccountKey(&accounts2[2])

	store2.SetCooldown(k0, 30*time.Second)
	store2.SetCooldown(k1, 60*time.Second)
	store2.SetCooldown(k2, 90*time.Second)

	recovered := svc2.tryRecoverKiroCooldownPool(ctx, accounts2, "", nil, false)
	require.True(t, recovered, "tryRecoverKiroCooldownPool should report recovery")

	clearedCount := 0
	for _, k := range []string{k0, k1, k2} {
		if !store2.IsInCooldown(k) {
			clearedCount++
		}
	}
	require.Equal(t, 1, clearedCount, "exactly one cooldown should be cleared")
}

// TestKiroTokenCacheKeyIncludesProfileArn verifies that KiroTokenCacheKey
// produces distinct keys for the same client_id_hash with different profile_arns,
// and that the absence of profile_arn preserves the legacy key format.
func TestKiroTokenCacheKeyIncludesProfileArn(t *testing.T) {
	const clientIDHash = "abc123hash"

	accountWithArn1 := &Account{
		ID:       100,
		Platform: PlatformKiro,
		Type:     AccountTypeOAuth,
		Credentials: map[string]any{
			"client_id_hash": clientIDHash,
			"profile_arn":    "arn:aws:codewhisperer:us-east-1:111111111111:profile/PROFILE_A",
		},
	}
	accountWithArn2 := &Account{
		ID:       101,
		Platform: PlatformKiro,
		Type:     AccountTypeOAuth,
		Credentials: map[string]any{
			"client_id_hash": clientIDHash,
			"profile_arn":    "arn:aws:codewhisperer:us-east-1:222222222222:profile/PROFILE_B",
		},
	}
	accountNoArn := &Account{
		ID:       102,
		Platform: PlatformKiro,
		Type:     AccountTypeOAuth,
		Credentials: map[string]any{
			"client_id_hash": clientIDHash,
		},
	}

	keyArn1 := KiroTokenCacheKey(accountWithArn1)
	keyArn2 := KiroTokenCacheKey(accountWithArn2)
	keyNoArn := KiroTokenCacheKey(accountNoArn)

	// Different profile_arns must produce different keys.
	require.NotEqual(t, keyArn1, keyArn2, "different profile_arns should produce different cache keys")

	// Keys with profile_arn must differ from the key without profile_arn.
	require.NotEqual(t, keyArn1, keyNoArn, "key with profile_arn should differ from key without")
	require.NotEqual(t, keyArn2, keyNoArn, "key with profile_arn should differ from key without")

	// The no-arn key must use the legacy format (no colon-separated suffix beyond the hash).
	require.Equal(t, "kiro:"+clientIDHash, keyNoArn, "no-arn key should match legacy format")

	// Keys with profile_arn must start with the same prefix as the no-arn key.
	require.Contains(t, keyArn1, "kiro:"+clientIDHash+":")
	require.Contains(t, keyArn2, "kiro:"+clientIDHash+":")
}
