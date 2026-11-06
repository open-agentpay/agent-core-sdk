package x402

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
)

var walletAuthorizationNonce atomic.Uint64

// serveAuthorizedWalletRequest follows the SDK flow used by wallet clients:
// obtain a server-priced challenge, then retry with its request-bound authorization.
func serveAuthorizedWalletRequest(t *testing.T, processor *PaymentProcessor, recorder *httptest.ResponseRecorder, req *http.Request, route *rcu.RouteConfig, requestID string) {
	t.Helper()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	challengeRecorder := httptest.NewRecorder()
	processor.HandleRequest(challengeRecorder, req, route, requestID)
	if challengeRecorder.Code != http.StatusPaymentRequired || challengeRecorder.Header().Get(HeaderPaymentRequired) == "" {
		*recorder = *challengeRecorder
		return
	}
	var envelope struct {
		Error struct {
			Details struct {
				Challenge PaymentChallenge `json:"challenge"`
			} `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(challengeRecorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode wallet challenge: %v", err)
	}
	challenge := envelope.Error.Details.Challenge
	binding := ComputeRequestBinding(req.Method, req.URL, body)
	authorization, err := json.Marshal(WalletAuthorization{
		Version: challenge.Version, ChallengeID: challenge.ChallengeID, Scheme: challenge.Scheme,
		Nonce:      fmt.Sprintf("0x%064x", walletAuthorizationNonce.Add(1)),
		ValidAfter: challenge.ValidAfter, ValidBefore: challenge.ValidBefore,
		Amount: challenge.Amount, ResourceURI: challenge.ResourceURI, RequestBinding: binding,
	})
	if err != nil {
		t.Fatalf("encode wallet authorization: %v", err)
	}
	retry := req.Clone(req.Context())
	retry.Body = io.NopCloser(bytes.NewReader(body))
	retry.Header = req.Header.Clone()
	retry.Header.Set(HeaderPaymentSignature, string(authorization))
	processor.HandleRequest(recorder, retry, route, requestID)
}
