package rcu

import (
	"sync"
	"testing"
)

func TestRCUManagerUpdateAndMatch(t *testing.T) {
	v1Routes := []RouteConfig{
		{
			RouteID:        "rou_market",
			PathPattern:    "/v1/market-data",
			UpstreamURL:    "https://api.example.com/market",
			PriceBaseUnits: 1000,
			Asset:          "USDC",
			Status:         "active",
		},
		{
			RouteID:        "rou_ai_wildcard",
			PathPattern:    "/v1/ai/*",
			UpstreamURL:    "https://api.example.com/ai",
			PriceBaseUnits: 5000,
			Asset:          "USDC",
			Status:         "active",
		},
	}

	snapV1 := &ConfigSnapshot{
		SchemaVersion: "2.0.0",
		TenantID:      "ten_default",
		VersionID:     "ver_v1",
		VersionNumber: 1,
		Routes:        v1Routes,
	}

	mgr, err := NewManager(snapV1)
	if err != nil {
		t.Fatalf("failed to init manager: %v", err)
	}

	// 1. Exact match
	route, ok := mgr.MatchRoute("/v1/market-data")
	if !ok || route.RouteID != "rou_market" {
		t.Errorf("expected match for /v1/market-data, got ok=%v", ok)
	}

	// 2. Wildcard prefix match
	routeAI, ok := mgr.MatchRoute("/v1/ai/generate")
	if !ok || routeAI.RouteID != "rou_ai_wildcard" {
		t.Errorf("expected match for /v1/ai/generate, got ok=%v", ok)
	}

	// 3. Unmatched route
	_, ok = mgr.MatchRoute("/v1/unknown")
	if ok {
		t.Errorf("expected false for /v1/unknown")
	}

	// 4. Hot atomic reload to V2 (concurrency safety)
	v2Routes := []RouteConfig{
		{
			RouteID:        "rou_market",
			PathPattern:    "/v1/market-data",
			UpstreamURL:    "https://api.example.com/market-v2",
			PriceBaseUnits: 2000, // price changed
			Asset:          "USDC",
			Status:         "active",
		},
	}
	snapV2 := &ConfigSnapshot{
		SchemaVersion: "2.0.0",
		TenantID:      "ten_default",
		VersionID:     "ver_v2",
		VersionNumber: 2,
		Routes:        v2Routes,
	}

	var wg sync.WaitGroup
	// Simulate 100 concurrent readers during swap
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, matched := mgr.MatchRoute("/v1/market-data")
			if matched && r == nil {
				t.Errorf("unexpected nil route")
			}
		}()
	}

	if err := mgr.Update(snapV2); err != nil {
		t.Fatalf("failed to update to V2: %v", err)
	}
	wg.Wait()

	// Verify updated state
	updatedRoute, ok := mgr.MatchRoute("/v1/market-data")
	if !ok || updatedRoute.PriceBaseUnits != 2000 {
		t.Errorf("expected updated price 2000 in V2, got %v", updatedRoute)
	}

	// AI route no longer exists in V2
	_, ok = mgr.MatchRoute("/v1/ai/generate")
	if ok {
		t.Errorf("expected /v1/ai/generate to be gone in V2")
	}
}

func TestRCUMultiTenantRouteIsolation(t *testing.T) {
	snap := &ConfigSnapshot{
		SchemaVersion: "2.0.0",
		TenantID:      "ten_alpha",
		VersionID:     "ver_multi_tenant",
		VersionNumber: 1,
		Routes: []RouteConfig{
			{
				RouteID:               "rou_alpha_1",
				TenantID:              "ten_alpha",
				ProjectID:             "prj_alpha",
				PathPattern:           "/api/v1/alpha/resource",
				UpstreamURL:           "https://alpha.internal/res",
				PriceBaseUnits:        1000,
				AllowedPaymentMethods: "wallet",
				Status:                "active",
			},
		},
	}

	mgr, err := NewManager(snap)
	if err != nil {
		t.Fatalf("failed to init manager: %v", err)
	}

	// 1. Tenant Alpha matching their own route succeeds
	route, _, _, ok := mgr.MatchRouteForTenant("ten_alpha", "/api/v1/alpha/resource")
	if !ok || route == nil || route.RouteID != "rou_alpha_1" {
		t.Fatalf("expected route match for tenant ten_alpha, got ok=%v, route=%v", ok, route)
	}

	// 2. Tenant Beta attempting to match Tenant Alpha's route is strictly rejected
	_, _, _, ok = mgr.MatchRouteForTenant("ten_beta", "/api/v1/alpha/resource")
	if ok {
		t.Fatalf("cross-tenant violation: tenant ten_beta matched ten_alpha's route!")
	}
}

func TestRCUPathTemplateMatchingAndExtraction(t *testing.T) {
	snap := &ConfigSnapshot{
		SchemaVersion: "2.0.0",
		TenantID:      "ten_default",
		VersionID:     "ver_templates",
		VersionNumber: 1,
		Routes: []RouteConfig{
			{
				RouteID:        "rou_llama_prices",
				PathPattern:    "/v1/prices/current/{coins}",
				UpstreamURL:    "https://coins.llama.fi/prices/current/{coins}",
				PriceBaseUnits: 1000,
				Asset:          "USDC",
				Status:         "active",
			},
			{
				RouteID:        "rou_coin_chart",
				PathPattern:    "/v1/coins/{id}/chart",
				UpstreamURL:    "https://coins.llama.fi/chart/{id}",
				PriceBaseUnits: 2000,
				Asset:          "USDC",
				Status:         "active",
			},
		},
	}

	mgr, err := NewManager(snap)
	if err != nil {
		t.Fatalf("failed to init manager: %v", err)
	}

	// 1. Match trailing {coins} template path
	route, ok := mgr.MatchRoute("/v1/prices/current/coingecko:ethereum,coingecko:bitcoin")
	if !ok || route.RouteID != "rou_llama_prices" {
		t.Fatalf("expected match for /v1/prices/current/coingecko:ethereum,coingecko:bitcoin, got ok=%v", ok)
	}
	params, ok := ExtractPathParams(route.PathPattern, "/v1/prices/current/coingecko:ethereum,coingecko:bitcoin")
	if !ok || params["coins"] != "coingecko:ethereum,coingecko:bitcoin" {
		t.Fatalf("expected coins param extracted, got: %+v", params)
	}

	// 2. Match base path when trailing {coins} is passed via query/body
	routeBase, ok := mgr.MatchRoute("/v1/prices/current")
	if !ok || routeBase.RouteID != "rou_llama_prices" {
		t.Fatalf("expected base path /v1/prices/current to match trailing template route, got ok=%v", ok)
	}

	// 3. Match middle segment {id} template path
	routeChart, ok := mgr.MatchRoute("/v1/coins/ethereum:0x000/chart")
	if !ok || routeChart.RouteID != "rou_coin_chart" {
		t.Fatalf("expected match for /v1/coins/ethereum:0x000/chart, got ok=%v", ok)
	}
	chartParams, ok := ExtractPathParams(routeChart.PathPattern, "/v1/coins/ethereum:0x000/chart")
	if !ok || chartParams["id"] != "ethereum:0x000" {
		t.Fatalf("expected id param extracted, got: %+v", chartParams)
	}
}


