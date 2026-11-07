package x402

import (
	"fmt"
	"strings"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
)

// SettlementDefaults defines default settlement parameters across routes.
type SettlementDefaults struct {
	DefaultNetwork       string
	DefaultAsset         string
	DefaultAssetSymbol   string
	DefaultAssetDecimals int
	DefaultPayTo         string
}

// onchainParams is the resolved challenge and settlement parameter view of a route.
type onchainParams struct {
	Network  string
	Asset    string
	Contract string
	Symbol   string
	Decimals int
	Price    int64
	Payee    string
}

// resolveOnchainAsset resolves an on-chain asset address and symbol using the processor's resolver or defaults.
func (p *PaymentProcessor) resolveOnchainAsset(network, assetOrSymbol string, d SettlementDefaults) (contractAddress string, symbol string) {
	cleanNet := strings.ToLower(strings.TrimSpace(network))
	if cleanNet == "" {
		cleanNet = strings.ToLower(strings.TrimSpace(d.DefaultNetwork))
	}
	cleanAsset := strings.TrimSpace(assetOrSymbol)

	// 1. If custom AssetResolver is injected by the host application (e.g. AgentPay), delegate to it first
	if p.assetResolver != nil {
		if addr, sym := p.assetResolver.ResolveAsset(cleanNet, cleanAsset); addr != "" {
			return addr, sym
		}
	}

	// 2. If assetOrSymbol is already a hexadecimal contract address (e.g. 0x...)
	if strings.HasPrefix(strings.ToLower(cleanAsset), "0x") {
		sym := "USDC"
		if d.DefaultAssetSymbol != "" {
			sym = d.DefaultAssetSymbol
		}
		return cleanAsset, sym
	}

	// 3. Fallback using configured SettlementDefaults (chain-agnostic configuration from config/yaml)
	sym := cleanAsset
	if sym == "" {
		sym = d.DefaultAssetSymbol
	}
	if sym == "" {
		sym = "USDC"
	}

	// If the configured default asset is a contract address and matches the symbol or is set as default
	if d.DefaultAsset != "" && strings.HasPrefix(strings.ToLower(d.DefaultAsset), "0x") {
		if cleanAsset == "" || strings.EqualFold(cleanAsset, d.DefaultAssetSymbol) || strings.EqualFold(cleanAsset, "USDC") {
			return strings.ToLower(d.DefaultAsset), sym
		}
	}

	return cleanAsset, sym
}

// resolveOnchain merges route config with settlement defaults.
func (p *PaymentProcessor) resolveOnchain(route *rcu.RouteConfig) onchainParams {
	d := p.settlementDefaults

	network := d.DefaultNetwork
	if network == "" {
		network = "agentpay:internal-ledger"
	}
	if route.Network != "" {
		network = route.Network
	}

	price := route.PriceBaseUnits
	if route.OnchainPriceBaseUnits != nil && *route.OnchainPriceBaseUnits > 0 {
		price = *route.OnchainPriceBaseUnits
	}

	rawAsset := route.Asset
	if route.OnchainAsset != "" {
		rawAsset = route.OnchainAsset
	}
	if rawAsset == "" && d.DefaultAssetSymbol != "" {
		rawAsset = d.DefaultAssetSymbol
	}
	if rawAsset == "" {
		rawAsset = "USDC"
	}

	contract, symbol := p.resolveOnchainAsset(network, rawAsset, d)

	payee := route.PayeeAddress
	if payee == "" {
		payee = d.DefaultPayTo
	}
	if payee == "" {
		payee = "agentpay:route:default"
	}

	decimals := d.DefaultAssetDecimals
	if decimals <= 0 {
		decimals = 6
	}

	return onchainParams{
		Network:  network,
		Asset:    rawAsset,
		Contract: contract,
		Symbol:   symbol,
		Decimals: decimals,
		Price:    price,
		Payee:    payee,
	}
}

// verifyChallenge rebuilds the challenge the verifier checks the buyer's authorization against.
func (o onchainParams) verifyChallenge(auth *PaymentAuthorization) *PaymentChallenge {
	return &PaymentChallenge{
		Version:     auth.Version,
		ChallengeID: auth.ChallengeID,
		Network:     o.Network,
		Asset:       o.Contract,
		AssetSymbol: o.Symbol,
		Decimals:    o.Decimals,
		Amount:      fmt.Sprintf("%d", o.Price),
		Payee:       o.Payee,
		Scheme:      TransferAuthorizationScheme,
		ValidAfter:  auth.ValidAfter,
		ValidBefore: auth.ValidBefore,
	}
}

// newChallenge issues a fresh 402 challenge.
func (o onchainParams) newChallenge(resourcePath string, ttl time.Duration) *PaymentChallenge {
	ch := NewChallenge(o.Network, o.Contract, o.Symbol, o.Decimals,
		fmt.Sprintf("%d", o.Price), o.Payee, "", resourcePath, ttl)
	ch.Scheme = TransferAuthorizationScheme
	return ch
}
