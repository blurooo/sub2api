package service

import (
	"context"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/kirocooldown"
)

// KiroPoolStatus summarises the health of Kiro OAuth accounts in a group.
type KiroPoolStatus struct {
	Total          int `json:"total"`
	Available      int `json:"available"`
	Cooldown       int `json:"cooldown"`
	QuotaExhausted int `json:"quota_exhausted"`
	Suspended      int `json:"suspended"`
}

// GetKiroPoolStatus returns a snapshot of Kiro OAuth account states for the
// given group (or all groups when groupID is nil).
func (s *GatewayService) GetKiroPoolStatus(ctx context.Context, groupID *int64) (*KiroPoolStatus, error) {
	var (
		accounts []Account
		err      error
	)
	if groupID != nil {
		accounts, err = s.accountRepo.ListSchedulableByGroupIDAndPlatform(ctx, *groupID, PlatformKiro)
	} else {
		accounts, err = s.accountRepo.ListSchedulableByPlatform(ctx, PlatformKiro)
	}
	if err != nil {
		return nil, err
	}

	// Filter to OAuth accounts only — API-key accounts don't use the cooldown store.
	kiroAccounts := make([]Account, 0, len(accounts))
	for i := range accounts {
		if accounts[i].Type == AccountTypeOAuth {
			kiroAccounts = append(kiroAccounts, accounts[i])
		}
	}

	status := &KiroPoolStatus{Total: len(kiroAccounts)}
	if len(kiroAccounts) == 0 {
		return status, nil
	}

	cooldownStates := s.batchGetKiroCooldownStates(ctx, kiroAccounts)
	now := time.Now()

	for i := range kiroAccounts {
		acc := &kiroAccounts[i]
		key := buildKiroAccountKey(acc)

		var state *kirocooldown.State
		if cooldownStates != nil {
			state = cooldownStates[key]
		}

		switch {
		case state != nil && state.Active && state.Reason == kirocooldown.CooldownReasonSuspended:
			status.Suspended++
		case state != nil && state.Active:
			// Any other active cooldown (e.g. rate_limit_exceeded)
			status.Cooldown++
		case acc.RateLimitResetAt != nil && now.Before(*acc.RateLimitResetAt):
			status.QuotaExhausted++
		default:
			status.Available++
		}
	}

	return status, nil
}
