package x402

// AssetResolver resolves an abstract asset (e.g. "USDC") on a given network (e.g. "eip155:421614")
// into a concrete contract address (e.g. EVM 0x token contract) and a display symbol.
// This interface allows host applications (like AgentPay) to inject chain-specific
// token contract registries without hardcoding any blockchain details into agent-core-sdk.
type AssetResolver interface {
	ResolveAsset(network, assetOrSymbol string) (contractAddress string, symbol string)
}

// AssetResolverFunc allows using an ordinary function as an AssetResolver.
type AssetResolverFunc func(network, assetOrSymbol string) (contractAddress string, symbol string)

// ResolveAsset calls f(network, assetOrSymbol).
func (f AssetResolverFunc) ResolveAsset(network, assetOrSymbol string) (string, string) {
	return f(network, assetOrSymbol)
}
