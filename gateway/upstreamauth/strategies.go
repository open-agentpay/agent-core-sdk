package upstreamauth

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

func init() {
	Register(&NoneAuthenticator{})
	Register(&APIKeyAuthenticator{})
	Register(&BearerAuthenticator{})
	Register(&BasicAuthenticator{})
	Register(&OAuth2Authenticator{})
	Register(&HMACAuthenticator{})
	Register(&CustomTemplateAuthenticator{})
}

// ----------------------------------------------------------------------------
// 1. None Authenticator
// ----------------------------------------------------------------------------

type NoneAuthenticator struct{}

func (a *NoneAuthenticator) Type() string { return "none" }

func (a *NoneAuthenticator) Schema() AuthTypeSchema {
	return AuthTypeSchema{
		Type:        "none",
		Label:       "无鉴权 (None)",
		Description: "网关透传请求，不向上游注入任何认证凭证",
		Fields:      []FieldSchema{},
	}
}

func (a *NoneAuthenticator) Validate(params map[string]any, secrets map[string]string) error {
	return nil
}

func (a *NoneAuthenticator) Apply(ctx context.Context, req *http.Request, params map[string]any, secrets map[string]string) error {
	return nil
}

// ----------------------------------------------------------------------------
// 2. API Key Authenticator
// ----------------------------------------------------------------------------

type APIKeyAuthenticator struct{}

func (a *APIKeyAuthenticator) Type() string { return "api_key" }

func (a *APIKeyAuthenticator) Schema() AuthTypeSchema {
	return AuthTypeSchema{
		Type:        "api_key",
		Label:       "API Key 鉴权",
		Description: "通过 HTTP Header、Query URL 参数或 Cookie 向目标上游传递密钥凭证",
		Fields: []FieldSchema{
			{
				Key:          "in",
				Label:        "传递位置",
				Kind:         KindSelect,
				Options:      []string{"header", "query", "cookie"},
				Required:     true,
				DefaultValue: "header",
				Secret:       false,
				Description:  "指定 API Key 注入的位置",
			},
			{
				Key:          "name",
				Label:        "参数名称",
				Kind:         KindText,
				Required:     true,
				DefaultValue: "X-API-Key",
				Secret:       false,
				Description:  "请求头名、查询参数名或 Cookie 名，例如 X-API-Key 或 api_key",
			},
			{
				Key:          "prefix",
				Label:        "参数值前缀",
				Kind:         KindText,
				Required:     false,
				DefaultValue: "",
				Secret:       false,
				Description:  "选填，例如 'Bearer ' 或 'Token '，为空则直接传递原始密钥",
			},
			{
				Key:         "value",
				Label:       "API Key 密钥值",
				Kind:        KindPassword,
				Required:    true,
				Secret:      true,
				Description: "上游服务颁发的密钥值（密文存储，永不回显）",
			},
		},
	}
}

func (a *APIKeyAuthenticator) Validate(params map[string]any, secrets map[string]string) error {
	name, _ := params["name"].(string)
	if strings.TrimSpace(name) == "" {
		return errors.New("api_key name is required")
	}
	inPos, _ := params["in"].(string)
	if inPos != "header" && inPos != "query" && inPos != "cookie" {
		return errors.New("api_key 'in' must be one of: header, query, cookie")
	}
	return nil
}

func (a *APIKeyAuthenticator) Apply(ctx context.Context, req *http.Request, params map[string]any, secrets map[string]string) error {
	inPos, _ := params["in"].(string)
	name, _ := params["name"].(string)
	prefix, _ := params["prefix"].(string)
	val := secrets["value"]

	if name == "" || val == "" {
		return nil
	}
	combinedVal := prefix + val

	switch inPos {
	case "query":
		q := req.URL.Query()
		q.Set(name, combinedVal)
		req.URL.RawQuery = q.Encode()
	case "cookie":
		req.AddCookie(&http.Cookie{Name: name, Value: combinedVal})
	default: // "header"
		req.Header.Set(name, combinedVal)
	}
	return nil
}

// ----------------------------------------------------------------------------
// 3. Bearer Authenticator
// ----------------------------------------------------------------------------

type BearerAuthenticator struct{}

func (a *BearerAuthenticator) Type() string { return "bearer" }

func (a *BearerAuthenticator) Schema() AuthTypeSchema {
	return AuthTypeSchema{
		Type:        "bearer",
		Label:       "Bearer Token",
		Description: "在 HTTP 请求头中注入 Authorization: Bearer <token>",
		Fields: []FieldSchema{
			{
				Key:         "token",
				Label:       "Bearer Token",
				Kind:        KindPassword,
				Required:    true,
				Secret:      true,
				Description: "长期有效的 API 访问令牌或 JWT Token",
			},
		},
	}
}

func (a *BearerAuthenticator) Validate(params map[string]any, secrets map[string]string) error {
	return nil
}

func (a *BearerAuthenticator) Apply(ctx context.Context, req *http.Request, params map[string]any, secrets map[string]string) error {
	token := secrets["token"]
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return nil
}

// ----------------------------------------------------------------------------
// 4. Basic Authenticator
// ----------------------------------------------------------------------------

type BasicAuthenticator struct{}

func (a *BasicAuthenticator) Type() string { return "basic" }

func (a *BasicAuthenticator) Schema() AuthTypeSchema {
	return AuthTypeSchema{
		Type:        "basic",
		Label:       "HTTP Basic 认证",
		Description: "在 HTTP 请求头中注入标准 Base64 编码的用户名与密码",
		Fields: []FieldSchema{
			{
				Key:         "username",
				Label:       "用户名",
				Kind:        KindText,
				Required:    true,
				Secret:      true,
				Description: "上游服务分配的用户名",
			},
			{
				Key:         "password",
				Label:       "密码",
				Kind:        KindPassword,
				Required:    true,
				Secret:      true,
				Description: "上游服务分配的密码",
			},
		},
	}
}

func (a *BasicAuthenticator) Validate(params map[string]any, secrets map[string]string) error {
	return nil
}

func (a *BasicAuthenticator) Apply(ctx context.Context, req *http.Request, params map[string]any, secrets map[string]string) error {
	user := secrets["username"]
	pass := secrets["password"]
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	return nil
}

// ----------------------------------------------------------------------------
// 5. OAuth2 Client Credentials Authenticator
// ----------------------------------------------------------------------------

type cachedToken struct {
	accessToken string
	expiresAt   time.Time
}

type OAuth2Authenticator struct {
	mu         sync.Mutex
	tokenCache map[string]*cachedToken
	client     *http.Client
}

func (a *OAuth2Authenticator) Type() string { return "oauth2_client_credentials" }

func (a *OAuth2Authenticator) Schema() AuthTypeSchema {
	return AuthTypeSchema{
		Type:        "oauth2_client_credentials",
		Label:       "OAuth 2.0 客户端凭证",
		Description: "自动向上游 Token URL 请求 Access Token，支持内存缓存与过期自动刷新",
		Fields: []FieldSchema{
			{
				Key:          "token_url",
				Label:        "Token 端点 URL",
				Kind:         KindText,
				Required:     true,
				Secret:       false,
				Description:  "获取 Access Token 的上游 OAuth2 端点完整 URL",
				DefaultValue: "https://auth.example.com/oauth/token",
			},
			{
				Key:         "scope",
				Label:       "权限范围 (Scope)",
				Kind:        KindText,
				Required:    false,
				Secret:      false,
				Description: "选填，多个 scope 以空格分隔",
			},
			{
				Key:          "auth_style",
				Label:        "凭证传递方式",
				Kind:         KindSelect,
				Options:      []string{"header", "params"},
				Required:     true,
				DefaultValue: "header",
				Secret:       false,
				Description:  "header: Basic Auth 传递; params: 在请求体参数中传递",
			},
			{
				Key:         "client_id",
				Label:       "Client ID",
				Kind:        KindText,
				Required:    true,
				Secret:      true,
				Description: "客户端标识",
			},
			{
				Key:         "client_secret",
				Label:       "Client Secret",
				Kind:        KindPassword,
				Required:    true,
				Secret:      true,
				Description: "客户端机密密钥",
			},
		},
	}
}

func (a *OAuth2Authenticator) Validate(params map[string]any, secrets map[string]string) error {
	tokenURL, _ := params["token_url"].(string)
	if !strings.HasPrefix(tokenURL, "http://") && !strings.HasPrefix(tokenURL, "https://") {
		return errors.New("oauth2 token_url must be an absolute HTTP/HTTPS URL")
	}
	return nil
}

func (a *OAuth2Authenticator) SetTransport(rt http.RoundTripper) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client == nil {
		a.client = &http.Client{Timeout: 10 * time.Second}
	}
	a.client.Transport = rt
}

func (a *OAuth2Authenticator) Apply(ctx context.Context, req *http.Request, params map[string]any, secrets map[string]string) error {
	tokenURL, _ := params["token_url"].(string)
	scope, _ := params["scope"].(string)
	authStyle, _ := params["auth_style"].(string)
	clientID := secrets["client_id"]
	clientSecret := secrets["client_secret"]

	if tokenURL == "" || clientID == "" || clientSecret == "" {
		return nil
	}

	cacheKey := fmt.Sprintf("%s|%s|%s", tokenURL, clientID, scope)

	a.mu.Lock()
	if a.tokenCache == nil {
		a.tokenCache = make(map[string]*cachedToken)
	}
	if a.client == nil {
		a.client = &http.Client{Timeout: 10 * time.Second}
	}
	entry, exists := a.tokenCache[cacheKey]
	// Re-use cached token if still valid for > 30 seconds
	if exists && time.Until(entry.expiresAt) > 30*time.Second {
		token := entry.accessToken
		a.mu.Unlock()
		req.Header.Set("Authorization", "Bearer "+token)
		return nil
	}
	a.mu.Unlock()

	// Fetch new token
	token, expiresIn, err := a.fetchToken(ctx, tokenURL, clientID, clientSecret, scope, authStyle)
	if err != nil {
		return fmt.Errorf("oauth2 token fetch failed: %w", err)
	}

	a.mu.Lock()
	a.tokenCache[cacheKey] = &cachedToken{
		accessToken: token,
		expiresAt:   time.Now().Add(time.Duration(expiresIn) * time.Second),
	}
	a.mu.Unlock()

	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func (a *OAuth2Authenticator) fetchToken(ctx context.Context, tokenURL, clientID, clientSecret, scope, authStyle string) (string, int64, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	if scope != "" {
		data.Set("scope", scope)
	}

	if authStyle == "params" {
		data.Set("client_id", clientID)
		data.Set("client_secret", clientSecret)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", 0, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authStyle != "params" {
		httpReq.SetBasicAuth(clientID, clientSecret)
	}

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return "", 0, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var parsed struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
		return "", 0, fmt.Errorf("decode token response: %w", err)
	}
	if parsed.AccessToken == "" {
		return "", 0, errors.New("empty access_token received from upstream")
	}
	if parsed.ExpiresIn <= 0 {
		parsed.ExpiresIn = 3600 // default 1 hour if not specified
	}

	return parsed.AccessToken, parsed.ExpiresIn, nil
}

// ----------------------------------------------------------------------------
// 6. HMAC / Custom Signature Authenticator
// ----------------------------------------------------------------------------

type HMACAuthenticator struct{}

func (a *HMACAuthenticator) Type() string { return "hmac_sign" }

func (a *HMACAuthenticator) Schema() AuthTypeSchema {
	return AuthTypeSchema{
		Type:        "hmac_sign",
		Label:       "HMAC 自定义签名",
		Description: "支持金融开放平台与国内 API 常见的 appkey + timestamp + sign 模式",
		Fields: []FieldSchema{
			{
				Key:          "algorithm",
				Label:        "签名算法",
				Kind:         KindSelect,
				Options:      []string{"hmac_sha256", "md5", "sha256"},
				Required:     true,
				DefaultValue: "hmac_sha256",
				Secret:       false,
				Description:  "HMAC-SHA256、MD5 或 SHA256 签名算法",
			},
			{
				Key:          "sign_header",
				Label:        "签名请求头",
				Kind:         KindText,
				Required:     true,
				DefaultValue: "X-Signature",
				Secret:       false,
				Description:  "放置计算签名的请求头，例如 X-Signature 或 sign",
			},
			{
				Key:          "timestamp_header",
				Label:        "时间戳请求头",
				Kind:         KindText,
				Required:     true,
				DefaultValue: "X-Timestamp",
				Secret:       false,
				Description:  "放置当前秒级时间戳的请求头，例如 X-Timestamp 或 timestamp",
			},
			{
				Key:          "app_key_header",
				Label:        "AppKey 请求头",
				Kind:         KindText,
				Required:     false,
				DefaultValue: "X-App-Key",
				Secret:       false,
				Description:  "选填，放置 AppKey 的请求头",
			},
			{
				Key:         "app_key",
				Label:       "App Key",
				Kind:        KindText,
				Required:    false,
				Secret:      false,
				Description: "选填，应用公钥/标识",
			},
			{
				Key:         "secret",
				Label:       "签名密钥 (Secret)",
				Kind:        KindPassword,
				Required:    true,
				Secret:      true,
				Description: "用于计算签名的私钥/密钥",
			},
		},
	}
}

func (a *HMACAuthenticator) Validate(params map[string]any, secrets map[string]string) error {
	algo, _ := params["algorithm"].(string)
	if algo != "hmac_sha256" && algo != "md5" && algo != "sha256" {
		return errors.New("unsupported hmac algorithm, must be hmac_sha256, md5, or sha256")
	}
	signHdr, _ := params["sign_header"].(string)
	if strings.TrimSpace(signHdr) == "" {
		return errors.New("sign_header is required")
	}
	return nil
}

func (a *HMACAuthenticator) Apply(ctx context.Context, req *http.Request, params map[string]any, secrets map[string]string) error {
	algo, _ := params["algorithm"].(string)
	signHdr, _ := params["sign_header"].(string)
	tsHdr, _ := params["timestamp_header"].(string)
	appKeyHdr, _ := params["app_key_header"].(string)
	appKey, _ := params["app_key"].(string)
	secret := secrets["secret"]

	if signHdr == "" || secret == "" {
		return nil
	}

	ts := fmt.Sprintf("%d", time.Now().Unix())
	if tsHdr != "" {
		req.Header.Set(tsHdr, ts)
	}
	if appKeyHdr != "" && appKey != "" {
		req.Header.Set(appKeyHdr, appKey)
	}

	// Canonical payload to sign: method + "\n" + path + "\n" + timestamp + "\n" + secret
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s", req.Method, req.URL.Path, ts, secret)

	var signature string
	switch algo {
	case "md5":
		h := md5.Sum([]byte(stringToSign))
		signature = hex.EncodeToString(h[:])
	case "sha256":
		h := sha256.Sum256([]byte(stringToSign))
		signature = hex.EncodeToString(h[:])
	default: // "hmac_sha256"
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(fmt.Sprintf("%s\n%s\n%s", req.Method, req.URL.Path, ts)))
		signature = hex.EncodeToString(mac.Sum(nil))
	}

	req.Header.Set(signHdr, signature)
	return nil
}

// ----------------------------------------------------------------------------
// 7. Custom Template Authenticator
// ----------------------------------------------------------------------------

type CustomTemplateAuthenticator struct{}

func (a *CustomTemplateAuthenticator) Type() string { return "custom_template" }

func (a *CustomTemplateAuthenticator) Schema() AuthTypeSchema {
	return AuthTypeSchema{
		Type:        "custom_template",
		Label:       "模板化自定义请求头",
		Description: "通过模板变量与命名密钥灵活组合请求头，安全可控，杜绝不受信脚本",
		Fields: []FieldSchema{
			{
				Key:          "headers_template",
				Label:        "请求头模板 (JSON Key-Value)",
				Kind:         KindTextarea,
				Required:     true,
				Secret:       false,
				DefaultValue: "{\n  \"X-Custom-Auth\": \"Bearer {{secret.custom_token}}\",\n  \"X-Request-Timestamp\": \"{{timestamp}}\"\n}",
				Description:  "支持变量: {{secret.<name>}}, {{timestamp}}, {{method}}, {{path}}",
			},
			{
				Key:         "custom_secrets",
				Label:       "命名密钥字典 (JSON Key-Value)",
				Kind:        KindTextarea,
				Required:    false,
				Secret:      true,
				Description: "命名密钥 JSON，例如: {\"custom_token\": \"secret_xyz123\"}",
			},
		},
	}
}

func (a *CustomTemplateAuthenticator) Validate(params map[string]any, secrets map[string]string) error {
	tmplStr, _ := params["headers_template"].(string)
	if strings.TrimSpace(tmplStr) == "" {
		return errors.New("headers_template is required")
	}
	var headers map[string]string
	if err := json.Unmarshal([]byte(tmplStr), &headers); err != nil {
		return fmt.Errorf("headers_template must be valid JSON key-value map: %w", err)
	}
	return nil
}

func (a *CustomTemplateAuthenticator) Apply(ctx context.Context, req *http.Request, params map[string]any, secrets map[string]string) error {
	tmplStr, _ := params["headers_template"].(string)
	if tmplStr == "" {
		return nil
	}

	var headers map[string]string
	if err := json.Unmarshal([]byte(tmplStr), &headers); err != nil {
		return nil
	}

	ts := fmt.Sprintf("%d", time.Now().Unix())

	// Merge any named custom_secrets if provided
	namedSecrets := make(map[string]string)
	if raw, ok := secrets["custom_secrets"]; ok && raw != "" {
		_ = json.Unmarshal([]byte(raw), &namedSecrets)
	}
	for k, v := range secrets {
		if k != "custom_secrets" {
			namedSecrets[k] = v
		}
	}

	for hdrKey, hdrValTmpl := range headers {
		rendered := hdrValTmpl
		rendered = strings.ReplaceAll(rendered, "{{timestamp}}", ts)
		rendered = strings.ReplaceAll(rendered, "{{method}}", req.Method)
		rendered = strings.ReplaceAll(rendered, "{{path}}", req.URL.Path)

		for sKey, sVal := range namedSecrets {
			placeholder := fmt.Sprintf("{{secret.%s}}", sKey)
			rendered = strings.ReplaceAll(rendered, placeholder, sVal)
		}

		req.Header.Set(hdrKey, rendered)
	}
	return nil
}

// ----------------------------------------------------------------------------
// MaskSecrets for safe logging/auditing
// ----------------------------------------------------------------------------

func MaskHeader(headerName string, headerValue string) string {
	lower := strings.ToLower(headerName)
	if strings.Contains(lower, "auth") || strings.Contains(lower, "key") ||
		strings.Contains(lower, "token") || strings.Contains(lower, "secret") ||
		strings.Contains(lower, "sign") {
		if len(headerValue) <= 8 {
			return "●●●●●●"
		}
		return headerValue[:4] + "●●●●●●" + headerValue[len(headerValue)-2:]
	}
	return headerValue
}
