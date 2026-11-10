package wallet

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// dummyProvider implements PaymentProvider for contract testing.
type dummyProvider struct{}

func (d *dummyProvider) Name() string { return "dummy" }

func (d *dummyProvider) CreatePrepayOrder(ctx context.Context, req *PrepayOrderRequest) (*PrepayOrderResult, error) {
	return &PrepayOrderResult{
		OutTradeNo: req.OutTradeNo,
		CodeURL:    "weixin://wxpay/bizpayurl?pr=dummy123",
		ExpiresAt:  time.Now().Add(15 * time.Minute),
	}, nil
}

func (d *dummyProvider) ParseAndVerifyWebhook(ctx context.Context, header http.Header, body []byte) (*WebhookPaymentResult, error) {
	return &WebhookPaymentResult{
		OutTradeNo:      "top_test_123",
		TransactionID:   "wx_tx_999",
		PaidAmountCents: 1000,
		PaidAt:          time.Now(),
	}, nil
}

func (d *dummyProvider) QueryOrder(ctx context.Context, outTradeNo string) (*PrepayOrderResult, error) {
	return &PrepayOrderResult{
		OutTradeNo: outTradeNo,
		CodeURL:    "weixin://wxpay/bizpayurl?pr=dummy123",
	}, nil
}

func TestPaymentProviderContract(t *testing.T) {
	var provider PaymentProvider = &dummyProvider{}
	if provider.Name() != "dummy" {
		t.Errorf("expected dummy provider name, got %s", provider.Name())
	}

	ctx := context.Background()
	res, err := provider.CreatePrepayOrder(ctx, &PrepayOrderRequest{
		TenantID:    "ten_test",
		WalletID:    "wlt_test",
		AmountCents: 5000,
		Currency:    "CNY",
		OutTradeNo:  "top_001",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.OutTradeNo != "top_001" || res.CodeURL == "" {
		t.Errorf("invalid prepay result: %+v", res)
	}

	whRes, err := provider.ParseAndVerifyWebhook(ctx, http.Header{}, []byte("{}"))
	if err != nil {
		t.Fatalf("unexpected webhook error: %v", err)
	}
	if whRes.PaidAmountCents != 1000 || whRes.TransactionID != "wx_tx_999" {
		t.Errorf("invalid webhook result: %+v", whRes)
	}
}
