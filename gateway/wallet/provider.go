package wallet

import (
	"context"
	"net/http"
	"time"
)

// PrepayOrderRequest contains parameters to initiate a prepayment order.
// AmountCents is in minor units (integer cents for CNY, 100 cents = 1.00 CNY).
type PrepayOrderRequest struct {
	TenantID    string `json:"tenant_id"`
	WalletID    string `json:"wallet_id"`
	AmountCents int64  `json:"amount_cents"`
	Currency    string `json:"currency"`
	Description string `json:"description"`
	ClientIP    string `json:"client_ip,omitempty"`
	OutTradeNo  string `json:"out_trade_no"`
}

// PrepayOrderResult contains the result from payment provider prepay initiation.
type PrepayOrderResult struct {
	OutTradeNo string    `json:"out_trade_no"`
	CodeURL    string    `json:"code_url"` // QR code payload or payment url
	ExpiresAt  time.Time `json:"expires_at"`
}

// WebhookPaymentResult contains verified payment event details from provider.
type WebhookPaymentResult struct {
	OutTradeNo      string    `json:"out_trade_no"`
	TransactionID   string    `json:"transaction_id"`
	PaidAmountCents int64     `json:"paid_amount_cents"`
	PayerID         string    `json:"payer_id,omitempty"`
	PaidAt          time.Time `json:"paid_at"`
	RawPayload      []byte    `json:"raw_payload,omitempty"`
}

// PaymentProvider is the SPI interface for pluggable payment gateways.
// Core layer defines only this abstraction, without domestic or vendor-specific dependencies.
type PaymentProvider interface {
	Name() string
	CreatePrepayOrder(ctx context.Context, req *PrepayOrderRequest) (*PrepayOrderResult, error)
	ParseAndVerifyWebhook(ctx context.Context, header http.Header, body []byte) (*WebhookPaymentResult, error)
	QueryOrder(ctx context.Context, outTradeNo string) (*PrepayOrderResult, error)
}
