package main

import "testing"

func TestAggregateResultsFailClosed(t *testing.T) {
	cfg := GatewayConfig{FailClosed: true, EnableNemo: true, EnablePresidio: true}
	nemo := defaultServiceDetection("timeout", "safe", nil)
	nemo.LatencyMS = 2500
	presidio := defaultServiceDetection("error", "safe", nil)
	presidio.LatencyMS = 2500

	resp := aggregateResults(cfg, "req-1", nemo, presidio, 2501)

	if resp.Decision != "block" {
		t.Fatalf("expected block decision, got %s", resp.Decision)
	}
	if !resp.Block {
		t.Fatal("expected block=true")
	}
	if resp.RiskLevel != "critical" {
		t.Fatalf("expected critical risk, got %s", resp.RiskLevel)
	}
	if len(resp.Reasons) != 1 || resp.Reasons[0] != failClosedReason {
		t.Fatalf("expected fail-closed reason, got %#v", resp.Reasons)
	}
}

func TestAggregateResultsUsesSuccessfulDetectorOnly(t *testing.T) {
	cfg := GatewayConfig{FailClosed: true, EnableNemo: true, EnablePresidio: true}
	nemo := ServiceDetection{
		Status:     "success",
		Block:      false,
		RiskLevel:  "medium",
		Confidence: 0.42,
		Reasons:    []string{"Potential email address detected."},
		Categories: []string{"email"},
		LatencyMS:  15,
	}
	presidio := defaultServiceDetection("error", "safe", nil)
	presidio.Confidence = 0.99
	presidio.LatencyMS = 2500

	resp := aggregateResults(cfg, "req-2", nemo, presidio, 2501)

	if resp.Decision != "review" {
		t.Fatalf("expected review decision, got %s", resp.Decision)
	}
	if resp.Block {
		t.Fatal("expected block=false")
	}
	if resp.Confidence != 0.42 {
		t.Fatalf("expected confidence from successful detector only, got %f", resp.Confidence)
	}
}

func TestAggregateResultsBlockPrecedence(t *testing.T) {
	cfg := GatewayConfig{FailClosed: true, EnableNemo: true, EnablePresidio: true}
	nemo := ServiceDetection{
		Status:     "success",
		Block:      true,
		RiskLevel:  "high",
		Confidence: 0.91,
		Reasons:    []string{"Prompt injection detected"},
		Categories: []string{"prompt_injection"},
		LatencyMS:  10,
	}
	presidio := ServiceDetection{
		Status:     "success",
		Block:      false,
		RiskLevel:  "medium",
		Confidence: 0.85,
		Reasons:    []string{"Potential email detected"},
		Categories: []string{"email"},
		LatencyMS:  12,
	}

	resp := aggregateResults(cfg, "req-3", nemo, presidio, 20)
	if resp.Decision != "block" {
		t.Fatalf("expected block decision, got %s", resp.Decision)
	}
	if !resp.Block {
		t.Fatal("expected block=true")
	}
	if resp.RiskLevel != "high" {
		t.Fatalf("expected highest successful risk, got %s", resp.RiskLevel)
	}
}
