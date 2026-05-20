package main

import (
	"net/http"
	"testing"
)

func TestHashTextDeterministic(t *testing.T) {
	a := hashText("hello")
	b := hashText("hello")
	if a == "" || b == "" {
		t.Fatal("expected non-empty hash")
	}
	if a != b {
		t.Fatalf("expected deterministic hash, got %q and %q", a, b)
	}
}

func TestNormalizeDashboardURL(t *testing.T) {
	got := normalizeDashboardURL("https://intertrace.ai/")
	want := "https://intertrace.ai"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestEnsureGatewayEventPath(t *testing.T) {
	got := ensureGatewayEventPath("https://intertrace.ai")
	want := "https://intertrace.ai/api/gateway/event"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestBuildGatewayEventPayload(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set(intertraceOrgHeader, "header-org")
	req.Header.Set(intertraceAssetHeader, "header-asset")

	payload := buildGatewayEventPayload(req, TelemetryEvent{
		RequestID:       "req-1",
		OrgID:           "",
		Provider:        "openai",
		Model:           "gpt-4o-mini",
		Decision:        "allow",
		RiskLevel:       "safe",
		Block:           false,
		LatencyMS:       42,
		GatewayRoute:    "/v1/chat/completions",
		PromptContent:   "user email sam@example.com",
		ResponseContent: "done",
		Detections: UnifiedDetections{
			Nemo:     ServiceDetection{Status: "success"},
			Presidio: ServiceDetection{Status: "success", Categories: []string{"email_address"}},
		},
	})

	if payload.OrgID != "header-org" {
		t.Fatalf("expected org from header fallback, got %q", payload.OrgID)
	}
	if payload.InboundVerdict != "PASS" {
		t.Fatalf("expected inbound PASS, got %q", payload.InboundVerdict)
	}
	if payload.OutboundVerdict != "PASS" {
		t.Fatalf("expected outbound PASS, got %q", payload.OutboundVerdict)
	}
	if payload.LatencyGatewayMS != 42 {
		t.Fatalf("expected latency 42, got %d", payload.LatencyGatewayMS)
	}
	if payload.PromptContent == "user email sam@example.com" {
		t.Fatalf("expected prompt to be redacted, got %q", payload.PromptContent)
	}
	if len(payload.PIIDetected) == 0 {
		t.Fatal("expected pii_detected to be populated from presidio categories")
	}
	if payload.GatewayRoute != "/v1/chat/completions" {
		t.Fatalf("expected route to be preserved, got %q", payload.GatewayRoute)
	}
}

func TestApplyAuthHeadersSharedSecret(t *testing.T) {
	ingestor := &intertraceEventIngestor{
		cfg: GatewayConfig{
			TelemetryAuth: "shared-secret",
		},
	}
	headers := http.Header{}
	if err := ingestor.applyAuthHeaders(headers, "org-1", []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("applyAuthHeaders returned error: %v", err)
	}
	if headers.Get("X-Intertrace-Internal") == "" || headers.Get("X-Intertrace-Signature") == "" {
		t.Fatalf("expected shared-secret auth headers to be set, got %+v", headers)
	}
}

func TestApplyAuthHeadersOrgKeyPreferred(t *testing.T) {
	ingestor := &intertraceEventIngestor{
		cfg: GatewayConfig{
			TelemetryAuth: "shared-secret",
			OrgKeyID:      "key-default",
			OrgSecret:     "org-secret-default",
			OrgKeyIDMap: map[string]string{
				"org-2": "key-org-2",
			},
			OrgSecretMap: map[string]string{
				"org-2": "secret-org-2",
			},
		},
	}
	headers := http.Header{}
	if err := ingestor.applyAuthHeaders(headers, "org-2", []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("applyAuthHeaders returned error: %v", err)
	}
	if headers.Get("X-Intertrace-Key-Id") != "key-org-2" {
		t.Fatalf("expected org key id header, got %q", headers.Get("X-Intertrace-Key-Id"))
	}
	if headers.Get("X-Intertrace-Nonce") == "" || headers.Get("X-Intertrace-Signature") == "" {
		t.Fatalf("expected org-key signature headers to be set, got %+v", headers)
	}
	if headers.Get("X-Intertrace-Internal") != "" {
		t.Fatalf("expected shared-secret header not set when org-key auth is available")
	}
}
