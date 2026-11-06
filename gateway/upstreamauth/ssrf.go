package upstreamauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ErrSSRFBlocked is returned when an upstream URL targets a prohibited internal, loopback, or metadata address.
var ErrSSRFBlocked = errors.New("SSRF protection: upstream URL targets a restricted internal, loopback, link-local, or metadata address")

var cgnatCIDR = mustParseCIDR("100.64.0.0/10")

func mustParseCIDR(s string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipNet
}

// IsPrivateUpstreamAllowed checks whether private/loopback upstream targets are explicitly enabled for local testing.
func IsPrivateUpstreamAllowed() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("AGENTPAY_ALLOW_PRIVATE_UPSTREAM")))
	return v == "true" || v == "1"
}

// IsBlockedIP returns true if ip is loopback, private, link-local (including 169.254.169.254),
// multicast, unspecified, or CGNAT.
// # SECURITY-REVIEW
func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		if cgnatCIDR.Contains(ip4) {
			return true
		}
		// Broadcast 255.255.255.255
		if ip4[0] == 255 && ip4[1] == 255 && ip4[2] == 255 && ip4[3] == 255 {
			return true
		}
	}
	return false
}

// ValidateUpstreamURL validates the scheme, host, and literal IP/hostname against SSRF rules.
// # SECURITY-REVIEW
func ValidateUpstreamURL(rawURL string) error {
	clean := strings.TrimSpace(rawURL)
	if clean == "" {
		return errors.New("upstream_url is required")
	}
	u, err := url.Parse(clean)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("invalid upstream_url: must include scheme (http/https) and host")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("invalid upstream_url scheme %q: must be http or https", u.Scheme)
	}

	if IsPrivateUpstreamAllowed() {
		return nil
	}

	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return errors.New("invalid upstream_url: empty hostname")
	}

	if host == "localhost" ||
		strings.HasSuffix(host, ".localhost") ||
		host == "metadata.google.internal" ||
		host == "metadata" ||
		host == "instance-data" {
		return fmt.Errorf("%w: host %q is prohibited", ErrSSRFBlocked, host)
	}

	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedIP(ip) {
			return fmt.Errorf("%w: IP %s is prohibited", ErrSSRFBlocked, ip.String())
		}
	}

	// Optional domain allowlist enforcement via AGENTPAY_UPSTREAM_DOMAIN_ALLOWLIST
	if allowlistRaw := strings.TrimSpace(os.Getenv("AGENTPAY_UPSTREAM_DOMAIN_ALLOWLIST")); allowlistRaw != "" {
		allowed := false
		for _, item := range strings.Split(allowlistRaw, ",") {
			domain := strings.ToLower(strings.TrimSpace(item))
			if domain == "" {
				continue
			}
			if host == domain || strings.HasSuffix(host, "."+domain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%w: host %q is not in AGENTPAY_UPSTREAM_DOMAIN_ALLOWLIST", ErrSSRFBlocked, host)
		}
	}

	return nil
}

// ValidateUpstreamURLWithDNS validates the URL and resolves its DNS records to block DNS-based SSRF.
// # SECURITY-REVIEW
func ValidateUpstreamURLWithDNS(ctx context.Context, rawURL string) error {
	if err := ValidateUpstreamURL(rawURL); err != nil {
		return err
	}
	if IsPrivateUpstreamAllowed() {
		return nil
	}

	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return err
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedIP(ip) {
			return fmt.Errorf("%w: IP %s is prohibited", ErrSSRFBlocked, ip.String())
		}
		return nil
	}

	resolveCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(resolveCtx, host)
	if err != nil {
		return fmt.Errorf("failed to resolve upstream host %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("upstream host %q resolved to no IP addresses", host)
	}
	for _, addr := range addrs {
		if IsBlockedIP(addr.IP) {
			return fmt.Errorf("%w: host %q resolved to prohibited IP %s", ErrSSRFBlocked, host, addr.IP.String())
		}
	}
	return nil
}

// SafeDialContext dials the target address only after verifying the resolved IP is not internal/loopback/link-local.
// Prevents DNS rebinding attacks.
// # SECURITY-REVIEW
func SafeDialContext(dialer *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if dialer == nil {
		dialer = &net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if IsPrivateUpstreamAllowed() {
			return dialer.DialContext(ctx, network, addr)
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		lowerHost := strings.ToLower(strings.TrimSpace(host))
		if lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".localhost") || lowerHost == "metadata.google.internal" {
			return nil, fmt.Errorf("%w: host %q is prohibited", ErrSSRFBlocked, host)
		}
		if ip := net.ParseIP(host); ip != nil {
			if IsBlockedIP(ip) {
				return nil, fmt.Errorf("%w: IP %s is prohibited", ErrSSRFBlocked, ip.String())
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}

		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("no IP addresses found for host %q", host)
		}
		for _, a := range addrs {
			if IsBlockedIP(a.IP) {
				return nil, fmt.Errorf("%w: host %q resolved to prohibited IP %s", ErrSSRFBlocked, host, a.IP.String())
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(addrs[0].IP.String(), port))
	}
}

// NewSafeHTTPClient constructs an *http.Client with SSRF dial-time protection and redirect re-validation.
// # SECURITY-REVIEW
func NewSafeHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           SafeDialContext(nil),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          50,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("stopped after 3 redirects")
			}
			if err := ValidateUpstreamURLWithDNS(req.Context(), req.URL.String()); err != nil {
				return err
			}
			// Strip sensitive credentials if redirected across hosts
			if len(via) > 0 && !strings.EqualFold(via[0].URL.Host, req.URL.Host) {
				req.Header.Del("Authorization")
				req.Header.Del("Cookie")
				req.Header.Del("X-API-Key")
			}
			return nil
		},
	}
}
