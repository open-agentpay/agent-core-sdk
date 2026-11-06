package x402

import (
	"fmt"
	"time"

	"github.com/agent-core-sdk/gateway/rcu"
)

// onchainParams is the resolved on-chain settlement view of a route.
type onchainParams struct {
	Network  string
	Asset    string // configured asset name/symbol (input to resolution)
	Contract string // resolved token contract address
	Symbol   string // resolved display symbol
	Decimals int
	Price    int64
	Payee    string
}

// resolveOnchain is the single place that merges route config with settlement defaults.
func (p *PaymentProcessor) resolveOnchain(route *rcu.RouteConfig) onchainParams {
	d := p.settlementDefaults

	network := d.DefaultNetwork
	if network == "" {
		network = DefaultOnchainNetwork
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
	contract, symbol := ResolveOnchainAssetWithDefaults(network, asset, d)

	payee := route.PayeeAddress
	if payee == "" {
		payee = d.DefaultPayTo
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
func (o onchainParams) verifyChallenge(auth *PaymentAuthorization, facilitatorURL string) *PaymentChallenge {
	return &PaymentChallenge{
		Version:        auth.Version,
		ChallengeID:    auth.ChallengeID,
		Network:        o.Network,
		Asset:          o.Contract,
		AssetSymbol:    o.Symbol,
		Decimals:       o.Decimals,
		Amount:         fmt.Sprintf("%d", o.Price),
		Payee:          o.Payee,
		ValidAfter:     auth.ValidAfter,
		ValidBefore:    auth.ValidBefore,
		FacilitatorURL: facilitatorURL,
	}
}

// newChallenge issues a fresh 402 challenge.
func (o onchainParams) newChallenge(facilitatorURL, resourcePath string, ttl time.Duration) *PaymentChallenge {
	return NewChallenge(o.Network, o.Contract, o.Symbol, o.Decimals,
		fmt.Sprintf("%d", o.Price), o.Payee, facilitatorURL, resourcePath, ttl)
}
