package main

import "testing"

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
