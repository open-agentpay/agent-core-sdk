package rcu

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type TestVectorSuite struct {
	Version   string `json:"version"`
	Suite     string `json:"suite"`
	TestCases []struct {
		ID          string                 `json:"id"`
		Category    string                 `json:"category"`
		Description string                 `json:"description"`
		Input       map[string]interface{} `json:"input"`
		Expected    map[string]interface{} `json:"expected"`
	} `json:"testCases"`
}

func loadTestVectors(t *testing.T) *TestVectorSuite {
	// Look up test vector file relative to repo root
	vectorPath := filepath.Join("..", "..", "specs", "test-vectors", "config-publishing.json")
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("failed to read test vectors at %s: %v", vectorPath, err)
	}

	var suite TestVectorSuite
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatalf("failed to parse test vectors: %v", err)
	}
	return &suite
}

func TestConfigPublishingConformanceVectors(t *testing.T) {
	suite := loadTestVectors(t)

	for _, tc := range suite.TestCases {
		tc := tc
		t.Run(tc.ID, func(t *testing.T) {
			switch tc.ID {
			case "TC_CFG_01_VALID_SNAPSHOT_PUBLISHING":
				routesRaw, _ := json.Marshal(tc.Input["routes"])
				var routes []RouteConfig
				_ = json.Unmarshal(routesRaw, &routes)

				policiesRaw, _ := json.Marshal(tc.Input["policies"])
				var policies []PolicyConfig
				_ = json.Unmarshal(policiesRaw, &policies)

				valid, reason := ValidateStaticRules(routes, policies)
				if !valid {
					t.Fatalf("expected valid snapshot, got invalid: %s", reason)
				}

				hash := ComputeCanonicalSnapshotHash(routes, policies)
				prefix := tc.Expected["hash_prefix"].(string)
				if len(hash) != 7+64 || hash[:len(prefix)] != prefix {
					t.Fatalf("hash %s does not match expected prefix %s", hash, prefix)
				}

			case "TC_CFG_02_VALIDATION_REJECT_INVALID_UPSTREAM":
				routesRaw, _ := json.Marshal(tc.Input["routes"])
				var routes []RouteConfig
				_ = json.Unmarshal(routesRaw, &routes)

				valid, reason := ValidateStaticRules(routes, nil)
				if valid {
					t.Fatalf("expected validation failure for invalid upstream, got valid")
				}
				expectedErr := tc.Expected["error_code"].(string)
				if reason != expectedErr {
					t.Fatalf("expected error %s, got %s", expectedErr, reason)
				}

			case "TC_CFG_03_VALIDATION_REJECT_MAX_EXCEEDS_BUDGET":
				policiesRaw, _ := json.Marshal(tc.Input["policies"])
				var policies []PolicyConfig
				_ = json.Unmarshal(policiesRaw, &policies)

				valid, reason := ValidateStaticRules(nil, policies)
				if valid {
					t.Fatalf("expected validation failure for max exceeds budget, got valid")
				}
				expectedErr := tc.Expected["error_code"].(string)
				if reason != expectedErr {
					t.Fatalf("expected error %s, got %s", expectedErr, reason)
				}

			case "TC_CFG_04_ROLLBACK_INTEGRITY":
				v1Hash := tc.Input["v1_hash"].(string)
				newVersionNum := int64(tc.Expected["new_version_number"].(float64))
				activeHash := tc.Expected["active_hash"].(string)

				if activeHash != v1Hash {
					t.Fatalf("rollback hash mismatch: %s != %s", activeHash, v1Hash)
				}
				if newVersionNum != 3 {
					t.Fatalf("expected incremented version 3, got %d", newVersionNum)
				}

			case "TC_CFG_05_GATEWAY_CACHE_DEGRADATION":
				routesCount := int(tc.Input["in_memory_routes_count"].(float64))
				snap := &ConfigSnapshot{
					VersionID:     tc.Input["in_memory_snapshot_version"].(string),
					VersionNumber: 1,
					Routes: []RouteConfig{
						{
							RouteID:        "rou_degraded",
							PathPattern:    "/v1/api",
							UpstreamURL:    "https://upstream.internal/api",
							PriceBaseUnits: 1000,
							Asset:          "CNY",
							Status:         "active",
						},
					},
				}
				mgr, err := NewManager(snap)
				if err != nil {
					t.Fatalf("failed to init manager: %v", err)
				}

				// Even with control plane down, MatchRoute continues to work!
				route, ok := mgr.MatchRoute("/v1/api")
				if !ok || route == nil || len(mgr.Current().Routes) != routesCount {
					t.Fatalf("gateway failed to serve from local memory cache: %v", ok)
				}
			}
		})
	}
}

func TestSnapshotPolicyMatchingAndTraceability(t *testing.T) {
	routeID := "rou_chat"
	snap := &ConfigSnapshot{
		SchemaVersion: "2.0.0",
		TenantID:      "ten_trace_001",
		VersionID:     "ver_prod_snapshot_v5",
		VersionNumber: 5,
		SnapshotHash:  "sha256:11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
		Routes: []RouteConfig{
			{
				RouteID:               routeID,
				ProjectID:             "prj_main",
				PathPattern:           "/v1/chat/completions",
				UpstreamURL:           "https://api.openai.com/v1/chat",
				PriceBaseUnits:        20000,
				Asset:                 "CNY",
				AllowedPaymentMethods: "both",
				Status:                "active",
			},
		},
		Policies: []PolicyConfig{
			{
				PolicyID:            "pol_chat_limit",
				ProjectID:           "prj_main",
				RouteID:             &routeID,
				MaxAmountPerRequest: 50000,
				Rolling24hBudgetCap: 1000000,
				IsActive:            true,
			},
		},
	}

	mgr, err := NewManager(snap)
	if err != nil {
		t.Fatalf("failed to init manager: %v", err)
	}

	// Verify route and policy match
	route, policy, activeSnap, ok := mgr.MatchRouteWithPolicy("/v1/chat/completions")
	if !ok {
		t.Fatalf("expected route match")
	}
	if route.RouteID != "rou_chat" {
		t.Fatalf("expected route rou_chat, got %s", route.RouteID)
	}
	if policy == nil || policy.PolicyID != "pol_chat_limit" {
		t.Fatalf("expected policy pol_chat_limit, got %v", policy)
	}
	if activeSnap.VersionID != "ver_prod_snapshot_v5" {
		t.Fatalf("expected version ver_prod_snapshot_v5, got %s", activeSnap.VersionID)
	}

	// Verify version traceability helper
	vID, vNum, vHash := mgr.CurrentVersion()
	if vID != "ver_prod_snapshot_v5" || vNum != 5 || vHash != snap.SnapshotHash {
		t.Fatalf("version metadata mismatch: id=%s num=%d hash=%s", vID, vNum, vHash)
	}
}
