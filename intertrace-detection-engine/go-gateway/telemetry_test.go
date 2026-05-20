package main

import (
	"testing"
	"time"
)

func TestTelemetryAuthHeaderPrefersStaticToken(t *testing.T) {
	g := &Gateway{
		cfg: GatewayConfig{
			TelemetryAuth: "token-123",
			ForwardAuth:   true,
		},
	}
	got := g.telemetryAuthHeader("Bearer forwarded")
	if got != "Bearer token-123" {
		t.Fatalf("expected static bearer token, got %q", got)
	}
}

func TestTelemetryAuthHeaderForwardsWhenEnabled(t *testing.T) {
	g := &Gateway{
		cfg: GatewayConfig{
			ForwardAuth: true,
		},
	}
	got := g.telemetryAuthHeader("Bearer forwarded")
	if got != "Bearer forwarded" {
		t.Fatalf("expected forwarded auth header, got %q", got)
	}
}

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

func TestNormalizeTelemetryURL(t *testing.T) {
	got := normalizeTelemetryURL("https://intertrace.ai")
	want := "https://intertrace.ai/api/v1/telemetry/traces"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestBuildTelemetryTracePayload(t *testing.T) {
	now := time.Date(2026, 5, 20, 5, 50, 0, 0, time.UTC)
	payload := buildTelemetryTracePayload(telemetryEnvelope{
		RequestID: "req-1",
		Gateway:   "go-gateway",
		Event: TelemetryEvent{
			EventType:      "detect",
			RequestID:      "req-1",
			AssetID:        "580f7f32-3954-432e-8d14-1a07bf690c79",
			HTTPStatusCode: 200,
			LatencyMS:      40,
			Decision:       "allow",
			RiskLevel:      "safe",
			Block:          false,
			Detections: UnifiedDetections{
				Nemo: ServiceDetection{Status: "success", RiskLevel: "safe", Confidence: 0.98, LatencyMS: 30},
				Presidio: ServiceDetection{
					Status: "success", RiskLevel: "safe", Confidence: 0.98, LatencyMS: 35,
				},
			},
		},
	}, now)

	if payload.Trace.Name != "gateway.detect" {
		t.Fatalf("unexpected trace name: %q", payload.Trace.Name)
	}
	if payload.Trace.AssetID != "580f7f32-3954-432e-8d14-1a07bf690c79" {
		t.Fatalf("unexpected trace asset id: %q", payload.Trace.AssetID)
	}
	if len(payload.Spans) != 3 {
		t.Fatalf("expected 3 spans (gateway + detectors), got %d", len(payload.Spans))
	}
	if payload.Spans[0].Kind != "chain" {
		t.Fatalf("expected first span kind chain, got %q", payload.Spans[0].Kind)
	}
}
