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

	asset := route.Asset
	if route.OnchainAsset != "" {
		asset = route.OnchainAsset
	}
	if asset == "" && d.DefaultAssetSymbol != "" {
		asset = d.DefaultAssetSymbol
	}
	if asset == "" {
		asset = "CNY"
	}

	contract := asset
	symbol := asset
	if strings.HasPrefix(strings.ToLower(asset), "0x") {
		symbol = "CNY"
	}
	if d.DefaultAssetSymbol != "" && (asset == "" || strings.HasPrefix(strings.ToLower(asset), "0x")) {
		symbol = d.DefaultAssetSymbol
	}

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
		Network: network, Asset: asset, Contract: contract, Symbol: symbol,
		Decimals: decimals, Price: price, Payee: payee,
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
		ValidAfter:  auth.ValidAfter,
		ValidBefore: auth.ValidBefore,
	}
}

// newChallenge issues a fresh 402 challenge.
func (o onchainParams) newChallenge(resourcePath string, ttl time.Duration) *PaymentChallenge {
	return NewChallenge(o.Network, o.Contract, o.Symbol, o.Decimals,
		fmt.Sprintf("%d", o.Price), o.Payee, "", resourcePath, ttl)
}
