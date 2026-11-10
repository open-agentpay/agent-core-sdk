package i18n

import (
	"testing"
)

func TestI18nLookupAndFormatting(t *testing.T) {
	// 1. Direct ZH lookup
	zhMsg := ZH("ERR_WALLET_INSUFFICIENT_BALANCE")
	if zhMsg != "钱包可用余额不足以支付本次请求，请前往控制台充值。" {
		t.Errorf("unexpected ZH message: %s", zhMsg)
	}

	// 2. Direct EN lookup
	enMsg := EN("ERR_WALLET_INSUFFICIENT_BALANCE")
	if enMsg != "Wallet available balance is insufficient to cover this request." {
		t.Errorf("unexpected EN message: %s", enMsg)
	}

	// 3. Fallback to default (ZH)
	tMsg := T("ERR_WALLET_INSUFFICIENT_BALANCE")
	if tMsg != zhMsg {
		t.Errorf("expected T() to return ZH by default, got %s", tMsg)
	}

	// 4. Formatted message
	formattedZH := FormatZH("MCP_ERR_ROUTE_NOT_FOUND", "weather_tool")
	expected := "【AgentFinOps 路由错误】未找到对应工具或路由: weather_tool"
	if formattedZH != expected {
		t.Errorf("expected formatted %q, got %q", expected, formattedZH)
	}

	// 5. Unknown key fallback
	unknown := T("ERR_NON_EXISTENT")
	if unknown != "" {
		t.Errorf("expected empty string for non-existent key, got %s", unknown)
	}
}
