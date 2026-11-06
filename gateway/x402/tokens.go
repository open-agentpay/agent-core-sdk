package x402

import (
	"strings"
)

// DefaultOnchainNetwork is the default CAIP-2 network if none is specified in route.
const DefaultOnchainNetwork = "eip155:84532"

// KnownUSDCContracts maps CAIP-2 network identifiers to their official USDC ERC-20 contract addresses.
// Aligned with Circle official deployments and AgentPay multi-chain specs.
var KnownUSDCContracts = map[string]string{
	"eip155:84532":    "0x036CbD53842c5426634e7929541eC2318f3dCF7e", // Base Sepolia Testnet
	"eip155:8453":     "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // Base Mainnet
	"eip155:421614":   "0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d", // Arbitrum Sepolia Testnet
	"eip155:42161":    "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", // Arbitrum One Mainnet
	"eip155:10":       "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", // Optimism Mainnet
	"eip155:11155420": "0x5fd84259d66Cd46123540766Be93DFE6D43130D7", // Optimism Sepolia
	"eip155:137":      "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", // Polygon PoS Mainnet
	"eip155:1":        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", // Ethereum Mainnet
	"eip155:11155111": "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238", // Ethereum Sepolia
}

// SettlementDefaults defines default blockchain settlement parameters across routes.
type SettlementDefaults struct {
	DefaultNetwork       string
	DefaultAsset         string
	DefaultAssetSymbol   string
	DefaultAssetDecimals int
	DefaultPayTo         string
}

// ResolveOnchainAsset resolves the on-chain contract address (EVM 0x format) and token symbol (e.g. "USDC").
// 1. If assetOrSymbol is already a valid EVM contract address (starts with "0x"), it is preserved.
// 2. If assetOrSymbol is empty or a symbol string (such as "USDC" or "USD"), it resolves to the official
//    USDC contract address corresponding to the target network.
func ResolveOnchainAsset(network, assetOrSymbol string) (contractAddress string, symbol string) {
	return ResolveOnchainAssetWithDefaults(network, assetOrSymbol, SettlementDefaults{
		DefaultNetwork: DefaultOnchainNetwork,
	})
}

// ResolveOnchainAssetWithDefaults resolves on-chain contract address and token symbol with configurable settlement defaults.
func ResolveOnchainAssetWithDefaults(network, assetOrSymbol string, defaults SettlementDefaults) (contractAddress string, symbol string) {
	cleanNet := strings.ToLower(strings.TrimSpace(network))
	if cleanNet == "" {
		cleanNet = strings.ToLower(strings.TrimSpace(defaults.DefaultNetwork))
	}
	if cleanNet == "" {
		cleanNet = DefaultOnchainNetwork
	}
	cleanAsset := strings.TrimSpace(assetOrSymbol)

	// If assetOrSymbol is already an EVM 0x address
	if strings.HasPrefix(strings.ToLower(cleanAsset), "0x") {
		sym := "USDC"
		if defaults.DefaultAssetSymbol != "" {
			sym = defaults.DefaultAssetSymbol
		}
		return cleanAsset, sym
	}

	sym := "USDC"
	if defaults.DefaultAssetSymbol != "" {
		sym = defaults.DefaultAssetSymbol
	}
	if cleanAsset != "" && !strings.EqualFold(cleanAsset, "USD") {
		sym = cleanAsset
	}

	if contract, ok := KnownUSDCContracts[cleanNet]; ok {
		return contract, sym
	}

	// If a custom default asset address was configured and matches default network or fallback
	if defaults.DefaultAsset != "" && strings.HasPrefix(strings.ToLower(defaults.DefaultAsset), "0x") {
		return defaults.DefaultAsset, sym
	}

	// Fallback to default network contract if network not found
	if fallbackContract, ok := KnownUSDCContracts[DefaultOnchainNetwork]; ok {
		return fallbackContract, sym
	}

	return cleanAsset, sym
}
