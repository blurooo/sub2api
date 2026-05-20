package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

const (
	kiroTokenRefreshSkew = 5 * time.Minute // trigger refresh 5 min before expiry
	kiroTokenCacheSkew   = 3 * time.Minute // cache TTL cutoff 3 min before expiry (expires after refresh triggers)
)

type KiroTokenCache = GeminiTokenCache

type kiroAccountTokenRefresher interface {
	RefreshAccountToken(ctx context.Context, account *Account) (*KiroTokenInfo, error)
	BuildAccountCredentials(tokenInfo *KiroTokenInfo) map[string]any
}

type KiroTokenProvider struct {
	accountRepo      AccountRepository
	tokenCache       KiroTokenCache
	kiroOAuthService kiroAccountTokenRefresher
	refreshAPI       *OAuthRefreshAPI
	executor         OAuthRefreshExecutor
	refreshPolicy    ProviderRefreshPolicy
}

func NewKiroTokenProvider(
	accountRepo AccountRepository,
	tokenCache KiroTokenCache,
	kiroOAuthService *KiroOAuthService,
) *KiroTokenProvider {
	return &KiroTokenProvider{
		accountRepo:      accountRepo,
		tokenCache:       tokenCache,
		kiroOAuthService: kiroOAuthService,
		refreshPolicy:    GeminiProviderRefreshPolicy(),
	}
}

func (p *KiroTokenProvider) SetRefreshAPI(api *OAuthRefreshAPI, executor OAuthRefreshExecutor) {
	p.refreshAPI = api
	p.executor = executor
}

func (p *KiroTokenProvider) SetRefreshPolicy(policy ProviderRefreshPolicy) {
	p.refreshPolicy = policy
}

func (p *KiroTokenProvider) GetAccessToken(ctx context.Context, account *Account) (string, error) {
	if account == nil {
		return "", errors.New("account is nil")
	}
	if account.Platform != PlatformKiro || account.Type != AccountTypeOAuth {
		return "", errors.New("not a kiro oauth account")
	}

	cacheKey := KiroTokenCacheKey(account)
	if p.tokenCache != nil {
		if token, err := p.tokenCache.GetAccessToken(ctx, cacheKey); err == nil && strings.TrimSpace(token) != "" {
			return token, nil
		}
	}

	expiresAt := account.GetCredentialAsTime("expires_at")
	needsRefresh := expiresAt == nil || time.Until(*expiresAt) <= kiroTokenRefreshSkew

	if needsRefresh && p.refreshAPI != nil && p.executor != nil {
		result, err := p.refreshAPI.RefreshIfNeeded(ctx, account, p.executor, kiroTokenRefreshSkew)
		if err != nil {
			if p.refreshPolicy.OnRefreshError == ProviderRefreshErrorReturn {
				return "", err
			}
		} else if result.LockHeld {
			if p.refreshPolicy.OnLockHeld == ProviderLockHeldWaitForCache && p.tokenCache != nil {
				if token, cacheErr := p.tokenCache.GetAccessToken(ctx, cacheKey); cacheErr == nil && strings.TrimSpace(token) != "" {
					return token, nil
				}
				// Cache miss while another goroutine holds the refresh lock.
				// Wait briefly and retry once — the lock holder should populate the cache shortly.
				time.Sleep(500 * time.Millisecond)
				if token, cacheErr := p.tokenCache.GetAccessToken(ctx, cacheKey); cacheErr == nil && strings.TrimSpace(token) != "" {
					return token, nil
				}
			}
		} else {
			account = result.Account
			expiresAt = account.GetCredentialAsTime("expires_at")
		}
	}
	// When needsRefresh is true but refreshAPI is nil there is no refresh action to take,
	// so acquiring a Redis lock here would be meaningless — skip it entirely.

	accessToken := account.GetCredential("access_token")
	if strings.TrimSpace(accessToken) == "" {
		return "", errors.New("access_token not found in credentials")
	}

	if p.tokenCache != nil {
		latestAccount, isStale := CheckTokenVersion(ctx, account, p.accountRepo)
		if isStale && latestAccount != nil {
			accessToken = latestAccount.GetCredential("access_token")
			if strings.TrimSpace(accessToken) == "" {
				return "", errors.New("access_token not found after version check")
			}
		} else {
			ttl := 30 * time.Minute
			if expiresAt != nil {
				until := time.Until(*expiresAt)
				switch {
				case until > kiroTokenCacheSkew:
					ttl = until - kiroTokenCacheSkew
				case until > 0:
					ttl = until
				default:
					ttl = time.Minute
				}
			}
			_ = p.tokenCache.SetAccessToken(ctx, cacheKey, accessToken, ttl)
		}
	}

	return accessToken, nil
}

// KiroTokenCacheKey returns the Redis/memory cache key for a short-lived access token.
//
// Key design notes vs. the other two key functions in this package:
//
//   - kiroCacheCredentialKey (kiro_cache_emulation.go): identifies a full credential
//     bundle (refresh_token, api_key, etc.) used for cache-based OIDC emulation. It
//     intentionally includes every credential field so that any credential change
//     produces a distinct slot.
//
//   - buildKiroAccountKey (kiro_http_helpers.go): identifies the runtime fingerprint
//     (User-Agent, OS version, etc.) tied to an IDC client. It also includes
//     profile_arn so that different AWS permission sets get independent fingerprints.
//
//   - KiroTokenCacheKey (this function): caches the bearer access token that is
//     scoped to a specific (IDC client, AWS profile) pair. A single IDC client_id can
//     be bound to multiple profile_arns (different AWS accounts / permission sets),
//     each producing a distinct STS token. Without profile_arn in the key, tokens
//     from different profiles collide and cause authentication errors.
//
// When profile_arn is absent the key is identical to the previous format, so existing
// cache entries expire naturally without any forced invalidation.
func KiroTokenCacheKey(account *Account) string {
	if account == nil {
		return "kiro:account:0"
	}
	profileSuffix := kiroProfileArnSuffix(account.GetCredential("profile_arn"))
	if clientIDHash := strings.TrimSpace(account.GetCredential("client_id_hash")); clientIDHash != "" {
		return "kiro:" + clientIDHash + profileSuffix
	}
	if clientID := strings.TrimSpace(account.GetCredential("client_id")); clientID != "" {
		return "kiro:client:" + clientID + profileSuffix
	}
	return "kiro:account:" + strconv.FormatInt(account.ID, 10)
}

// kiroProfileArnSuffix returns ":<sha8(profileArn)>" when profileArn is non-empty,
// or "" otherwise (preserving backward-compatible key format).
func kiroProfileArnSuffix(profileArn string) string {
	if profileArn = strings.TrimSpace(profileArn); profileArn == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(profileArn))
	return ":" + hex.EncodeToString(sum[:8])
}

func (p *KiroTokenProvider) ForceRefreshAccessToken(ctx context.Context, account *Account) (string, error) {
	if account == nil {
		return "", errors.New("account is nil")
	}
	if account.Platform != PlatformKiro || account.Type != AccountTypeOAuth {
		return "", errors.New("not a kiro oauth account")
	}
	if p.kiroOAuthService == nil {
		return "", errors.New("kiro oauth service is nil")
	}

	cacheKey := KiroTokenCacheKey(account)
	lockHeld := false
	if p.tokenCache != nil {
		locked, lockErr := p.tokenCache.AcquireRefreshLock(ctx, cacheKey, 30*time.Second)
		if lockErr == nil && locked {
			lockHeld = true
			defer func() { _ = p.tokenCache.ReleaseRefreshLock(ctx, cacheKey) }()
		}
	}

	if p.accountRepo != nil {
		if latestAccount, err := p.accountRepo.GetByID(ctx, account.ID); err == nil && latestAccount != nil {
			account = latestAccount
		}
	}

	tokenInfo, err := p.kiroOAuthService.RefreshAccountToken(ctx, account)
	if err != nil {
		if !lockHeld {
			if latestAccount, stale := CheckTokenVersion(ctx, account, p.accountRepo); stale && latestAccount != nil {
				account = latestAccount
				if accessToken := strings.TrimSpace(account.GetCredential("access_token")); accessToken != "" {
					_ = p.cacheAccessToken(ctx, account, accessToken)
					return accessToken, nil
				}
			}
		}
		if isNonRetryableRefreshError(err) && p.accountRepo != nil {
			errorMsg := "Token refresh failed (non-retryable): " + err.Error()
			_ = p.accountRepo.SetError(ctx, account.ID, errorMsg)
		}
		return "", err
	}

	newCredentials := MergeCredentials(account.Credentials, p.kiroOAuthService.BuildAccountCredentials(tokenInfo))
	newCredentials["_token_version"] = time.Now().UnixMilli()
	if err := persistAccountCredentials(ctx, p.accountRepo, account, newCredentials); err != nil {
		return "", err
	}

	// Prefer tokenInfo.AccessToken (the freshly-issued value) over the in-memory
	// account credential, because persistAccountCredentials writes to the repo but
	// does not guarantee a write-back to the account struct in memory.
	accessToken := strings.TrimSpace(tokenInfo.AccessToken)
	if accessToken == "" {
		accessToken = strings.TrimSpace(account.GetCredential("access_token"))
	}
	if accessToken == "" {
		return "", errors.New("access_token not found after kiro refresh")
	}
	if err := p.cacheAccessToken(ctx, account, accessToken); err != nil {
		return "", err
	}
	return accessToken, nil
}

func (p *KiroTokenProvider) cacheAccessToken(ctx context.Context, account *Account, accessToken string) error {
	if p.tokenCache == nil || account == nil || strings.TrimSpace(accessToken) == "" {
		return nil
	}
	ttl := 30 * time.Minute
	if expiresAt := account.GetCredentialAsTime("expires_at"); expiresAt != nil {
		until := time.Until(*expiresAt)
		switch {
		case until > kiroTokenCacheSkew:
			ttl = until - kiroTokenCacheSkew
		case until > 0:
			ttl = until
		default:
			ttl = time.Minute
		}
	}
	return p.tokenCache.SetAccessToken(ctx, KiroTokenCacheKey(account), accessToken, ttl)
}
