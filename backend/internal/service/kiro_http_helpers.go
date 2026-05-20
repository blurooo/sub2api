package service

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"runtime"
	"strings"

	kiropkg "github.com/Wei-Shaw/sub2api/internal/pkg/kiro"
	"github.com/google/uuid"
)

const (
	// 来源：官方 Kiro 客户端硬编码值，需跟随官方客户端更新
	kiroSocialProfileARN    = "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK"
	kiroBuilderIDProfileARN = "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX"
)

func buildKiroAccountKey(account *Account) string {
	if account == nil {
		return ""
	}
	return kiropkg.BuildAccountKey(
		account.GetCredential("client_id"),
		account.GetCredential("client_id_hash"),
		account.GetCredential("refresh_token"),
		account.GetCredential("profile_arn"),
		account.ID,
	)
}

// truncateKiroAccountKey returns the first 8 characters of a Kiro account key
// for use as a lightweight, partially-anonymised diagnostic identifier.
func truncateKiroAccountKey(key string) string {
	if len(key) > 8 {
		return key[:8]
	}
	return key
}

func buildKiroMachineID(account *Account) string {
	if account == nil {
		return kiropkg.BuildMachineID("", "", "account:nil")
	}
	for _, key := range []string{"machine_id", "machineId"} {
		if machineID, ok := kiropkg.NormalizeMachineID(account.GetCredential(key)); ok {
			return machineID
		}
	}
	fallbackKey := buildKiroMachineIDFallbackKey(account)
	if account.Type == AccountTypeAPIKey {
		return kiropkg.BuildMachineID("", firstKiroCredential(account, "kiro_api_key", "kiroApiKey", "api_key"), fallbackKey)
	}
	return kiropkg.BuildMachineID(account.GetCredential("refresh_token"), "", fallbackKey)
}

func firstKiroCredential(account *Account, keys ...string) string {
	if account == nil {
		return ""
	}
	for _, key := range keys {
		if value := strings.TrimSpace(account.GetCredential(key)); value != "" {
			return value
		}
	}
	return ""
}

func buildKiroMachineIDFallbackKey(account *Account) string {
	if account == nil {
		return "account:nil"
	}
	if account.ID > 0 {
		return fmt.Sprintf("account:%d", account.ID)
	}
	for _, key := range []string{"client_id", "profile_arn"} {
		if value := strings.TrimSpace(account.GetCredential(key)); value != "" {
			return key + ":" + value
		}
	}
	if name := strings.TrimSpace(account.Name); name != "" {
		return "name:" + name
	}
	return "account:unknown"
}

func buildKiroRequestID(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	if requestID := strings.TrimSpace(resp.Header.Get("x-request-id")); requestID != "" {
		return requestID
	}
	if requestID := strings.TrimSpace(resp.Header.Get("x-amzn-requestid")); requestID != "" {
		return requestID
	}
	return strings.TrimSpace(resp.Header.Get("x-amz-request-id"))
}

func isKiroSuspendedBody(respBody []byte) bool {
	body := string(respBody)
	return strings.Contains(body, "SUSPENDED") || strings.Contains(body, "TEMPORARILY_SUSPENDED")
}

func isKiroTokenErrorBody(respBody []byte) bool {
	lower := strings.ToLower(string(respBody))
	return strings.Contains(lower, "token") ||
		strings.Contains(lower, "expired") ||
		strings.Contains(lower, "invalid") ||
		strings.Contains(lower, "unauthorized")
}

func kiroProxyURL(account *Account) string {
	if account != nil && account.ProxyID != nil && account.Proxy != nil {
		return account.Proxy.URL()
	}
	return ""
}

func kiroAPIRegion(account *Account) string {
	if account == nil {
		return kiroDefaultRegion
	}
	region := strings.TrimSpace(account.GetCredential("api_region"))
	if region == "" {
		region = kiroDefaultRegion
	}
	return region
}

func applyKiroConditionalHeaders(req *http.Request, account *Account) {
	if req == nil || account == nil {
		return
	}
	if strings.EqualFold(strings.TrimSpace(account.GetCredential("auth_method")), "external_idp") {
		req.Header.Set("TokenType", "EXTERNAL_IDP")
	}
	if strings.EqualFold(strings.TrimSpace(account.GetCredential("provider")), "Internal") {
		req.Header.Set("redirect-for-internal", "true")
	}
}

func resolveKiroPayloadProfileArn(account *Account) string {
	if account == nil {
		return ""
	}
	if arn := strings.TrimSpace(account.GetCredential("profile_arn")); arn != "" {
		return arn
	}
	provider := strings.TrimSpace(account.GetCredential("provider"))
	if strings.EqualFold(provider, "Github") || strings.EqualFold(provider, "Google") {
		return kiroSocialProfileARN
	}
	return kiroBuilderIDProfileARN
}

func idcRustOS() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "darwin":
		return "macos"
	default:
		return "linux"
	}
}

func newKiroJSONRequest(ctx context.Context, endpointURL string, payload []byte, token, accountKey, machineID, amzTarget string, account *Account) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Authorization", "Bearer "+token)

	isIDC := account != nil && strings.EqualFold(strings.TrimSpace(account.GetCredential("auth_method")), "external_idp")
	if isIDC {
		os := idcRustOS()
		req.Header.Set("User-Agent", fmt.Sprintf("aws-sdk-rust/1.3.9 os/%s lang/rust/1.87.0", os))
		req.Header.Set("X-Amz-User-Agent", fmt.Sprintf("aws-sdk-rust/1.3.9 ua/2.1 api/ssooidc/1.88.0 os/%s lang/rust/1.87.0 m/E app/AmazonQ-For-CLI", os))
		req.Header.Set("x-amzn-kiro-agent-mode", "vibe")
	} else {
		req.Header.Set("User-Agent", kiropkg.BuildRuntimeUserAgent(accountKey, machineID))
		req.Header.Set("X-Amz-User-Agent", kiropkg.BuildRuntimeAmzUserAgent(accountKey, machineID))
		req.Header.Set("x-amzn-kiro-agent-mode", "spec")
	}

	req.Header.Set("Amz-Sdk-Request", "attempt=1; max=3")
	req.Header.Set("Amz-Sdk-Invocation-Id", uuid.NewString())
	if amzTarget != "" {
		req.Header.Set("X-Amz-Target", amzTarget)
	}
	if account != nil {
		profileArn := strings.TrimSpace(account.GetCredential("profile_arn"))
		if profileArn != "" {
			_ = profileArn
		}
	}
	applyKiroConditionalHeaders(req, account)
	return req, nil
}
