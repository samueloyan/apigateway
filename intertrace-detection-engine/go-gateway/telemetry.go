package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	intertraceOrgHeader   = "X-Intertrace-Org-Id"
	intertraceAssetHeader = "X-Intertrace-Asset"
)

type TelemetryEvent struct {
	EventType      string      `json:"event_type"`
	RequestID      string      `json:"request_id"`
	OrgID          string      `json:"org_id,omitempty"`
	ProjectID      string      `json:"project_id,omitempty"`
	AssetID        string      `json:"asset_id,omitempty"`
	SessionID      string      `json:"session_id,omitempty"`
	Provider       string      `json:"provider,omitempty"`
	Model          string      `json:"model,omitempty"`
	HTTPStatusCode int         `json:"http_status_code"`
	LatencyMS      int64       `json:"latency_ms,omitempty"`
	InputHash      string      `json:"input_hash,omitempty"`
	InputChars     int         `json:"input_chars,omitempty"`
	MessageCount   int         `json:"message_count,omitempty"`
	Decision       string      `json:"decision,omitempty"`
	RiskLevel      string      `json:"risk_level,omitempty"`
	Block          bool        `json:"block"`
	Reasons        []string    `json:"reasons,omitempty"`
	Detections     interface{} `json:"detections,omitempty"`
	UpstreamError  string      `json:"upstream_error,omitempty"`
	RawResponse    interface{} `json:"raw_response,omitempty"`
}

type telemetryEnvelope struct {
	Timestamp         string         `json:"timestamp"`
	RequestID         string         `json:"request_id"`
	EventType         string         `json:"event_type"`
	IntertraceOrgID   string         `json:"intertrace_org_id,omitempty"`
	IntertraceAssetID string         `json:"intertrace_asset_id,omitempty"`
	Gateway           string         `json:"gateway"`
	Event             TelemetryEvent `json:"event"`
}

func (g *Gateway) emitTelemetryAsync(r *http.Request, event TelemetryEvent) {
	if !g.cfg.EnableTelemetry || g.cfg.TelemetryURL == "" {
		return
	}

	forwardedAuth := strings.TrimSpace(r.Header.Get("Authorization"))
	intertraceOrgID := strings.TrimSpace(r.Header.Get(intertraceOrgHeader))
	intertraceAssetID := strings.TrimSpace(r.Header.Get(intertraceAssetHeader))

	envelope := telemetryEnvelope{
		Timestamp:         time.Now().UTC().Format(time.RFC3339Nano),
		RequestID:         event.RequestID,
		EventType:         event.EventType,
		IntertraceOrgID:   intertraceOrgID,
		IntertraceAssetID: intertraceAssetID,
		Gateway:           "go-gateway",
		Event:             event,
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), g.cfg.TelemetryTimeout)
		defer cancel()
		if err := g.sendTelemetry(ctx, envelope, forwardedAuth); err != nil {
			if g.cfg.DebugDetection {
				g.logger.Warn("intertrace telemetry send failed",
					"request_id", event.RequestID,
					"error", err.Error(),
				)
			}
		}
	}()
}

func (g *Gateway) sendTelemetry(ctx context.Context, envelope telemetryEnvelope, forwardedAuth string) error {
	body, err := json.Marshal(envelope)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.cfg.TelemetryURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(requestIDHeaderName, envelope.RequestID)
	if envelope.IntertraceOrgID != "" {
		req.Header.Set(intertraceOrgHeader, envelope.IntertraceOrgID)
	}
	if envelope.IntertraceAssetID != "" {
		req.Header.Set(intertraceAssetHeader, envelope.IntertraceAssetID)
	}

	authHeader := g.telemetryAuthHeader(forwardedAuth)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		respBody, _ := io.ReadAll(resp.Body)
		if g.cfg.DebugDetection {
			return &telemetryError{statusCode: resp.StatusCode, body: strings.TrimSpace(string(respBody))}
		}
		return &telemetryError{statusCode: resp.StatusCode}
	}
	return nil
}

func (g *Gateway) telemetryAuthHeader(forwardedAuth string) string {
	if strings.TrimSpace(g.cfg.TelemetryAuth) != "" {
		token := strings.TrimSpace(g.cfg.TelemetryAuth)
		if strings.HasPrefix(strings.ToLower(token), "bearer ") {
			return token
		}
		return "Bearer " + token
	}
	if g.cfg.ForwardAuth {
		return strings.TrimSpace(forwardedAuth)
	}
	return ""
}

func hashText(input string) string {
	normalized := strings.TrimSpace(input)
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

type telemetryError struct {
	statusCode int
	body       string
}

func (e *telemetryError) Error() string {
	if e.body == "" {
		return "telemetry endpoint status " + strconv.Itoa(e.statusCode)
	}
	return "telemetry endpoint status " + strconv.Itoa(e.statusCode) + ": " + e.body
}
