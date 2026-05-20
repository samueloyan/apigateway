package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	intertraceOrgHeader   = "X-Intertrace-Org-Id"
	intertraceAssetHeader = "X-Intertrace-Asset"
	intertraceTracePath   = "/api/v1/telemetry/traces"
)

var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

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

type telemetryTracePayload struct {
	Trace  telemetryTrace         `json:"trace"`
	Spans  []telemetrySpan        `json:"spans"`
	Policy map[string]interface{} `json:"policy,omitempty"`
}

type telemetryTrace struct {
	Name     string                 `json:"name"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	AssetID  string                 `json:"asset_id,omitempty"`
	Intent   map[string]interface{} `json:"intent,omitempty"`
}

type telemetrySpan struct {
	Name       string                 `json:"name"`
	Kind       string                 `json:"kind"`
	StartTime  string                 `json:"start_time"`
	EndTime    string                 `json:"end_time"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
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
	payload := buildTelemetryTracePayload(envelope, time.Now().UTC())
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.cfg.TelemetryURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(requestIDHeaderName, envelope.RequestID)
	req.Header.Set("Idempotency-Key", envelope.RequestID)
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

func buildTelemetryTracePayload(envelope telemetryEnvelope, now time.Time) telemetryTracePayload {
	event := envelope.Event
	start := now
	if event.LatencyMS > 0 {
		start = now.Add(-time.Duration(event.LatencyMS) * time.Millisecond)
	}
	if start.After(now) {
		start = now
	}

	metadata := map[string]interface{}{
		"gateway":          envelope.Gateway,
		"request_id":       event.RequestID,
		"event_type":       event.EventType,
		"http_status_code": event.HTTPStatusCode,
		"decision":         event.Decision,
		"risk_level":       event.RiskLevel,
		"block":            event.Block,
	}
	if envelope.IntertraceOrgID != "" {
		metadata["org_id"] = envelope.IntertraceOrgID
	} else if event.OrgID != "" {
		metadata["org_id"] = event.OrgID
	}
	if envelope.IntertraceAssetID != "" {
		metadata["asset_id"] = envelope.IntertraceAssetID
	} else if event.AssetID != "" {
		metadata["asset_id"] = event.AssetID
	}
	if event.ProjectID != "" {
		metadata["project_id"] = event.ProjectID
	}
	if event.SessionID != "" {
		metadata["session_id"] = event.SessionID
	}
	if event.Provider != "" {
		metadata["provider"] = event.Provider
	}
	if event.Model != "" {
		metadata["model"] = event.Model
	}
	if event.InputHash != "" {
		metadata["input_hash"] = event.InputHash
	}
	if event.InputChars > 0 {
		metadata["input_chars"] = event.InputChars
	}
	if event.MessageCount > 0 {
		metadata["message_count"] = event.MessageCount
	}
	if len(event.Reasons) > 0 {
		metadata["reasons"] = event.Reasons
	}
	if event.UpstreamError != "" {
		metadata["upstream_error"] = event.UpstreamError
	}

	intent := map[string]interface{}{}
	if event.Decision != "" {
		intent["decision"] = event.Decision
	}
	if event.RiskLevel != "" {
		intent["risk_level"] = event.RiskLevel
	}
	if len(event.Reasons) > 0 {
		intent["reasons"] = event.Reasons
	}
	intent["block"] = event.Block

	trace := telemetryTrace{
		Name:     "gateway." + event.EventType,
		Metadata: metadata,
		Intent:   intent,
	}
	if uuidPattern.MatchString(event.AssetID) {
		trace.AssetID = event.AssetID
	} else if uuidPattern.MatchString(envelope.IntertraceAssetID) {
		trace.AssetID = envelope.IntertraceAssetID
	}

	policy := map[string]interface{}{
		"decision":   event.Decision,
		"risk_level": event.RiskLevel,
		"block":      event.Block,
	}
	if len(event.Reasons) > 0 {
		policy["reasons"] = event.Reasons
	}

	return telemetryTracePayload{
		Trace:  trace,
		Spans:  buildTelemetrySpans(event, start, now),
		Policy: policy,
	}
}

func buildTelemetrySpans(event TelemetryEvent, start, end time.Time) []telemetrySpan {
	if end.Before(start) {
		end = start
	}
	spans := []telemetrySpan{
		{
			Name:      "gateway.request",
			Kind:      "chain",
			StartTime: start.Format(time.RFC3339Nano),
			EndTime:   end.Format(time.RFC3339Nano),
			Attributes: map[string]interface{}{
				"event_type":       event.EventType,
				"http_status_code": event.HTTPStatusCode,
				"decision":         event.Decision,
				"risk_level":       event.RiskLevel,
				"block":            event.Block,
			},
		},
	}

	if breakdown, ok := event.Detections.(UnifiedDetections); ok {
		spans = append(spans, detectorSpan("detector.nemo", breakdown.Nemo, start, end))
		spans = append(spans, detectorSpan("detector.presidio", breakdown.Presidio, start, end))
	}

	return spans
}

func detectorSpan(name string, detection ServiceDetection, requestStart, requestEnd time.Time) telemetrySpan {
	start := requestStart
	end := requestEnd
	if detection.LatencyMS > 0 {
		duration := time.Duration(detection.LatencyMS) * time.Millisecond
		end = requestStart.Add(duration)
		if end.After(requestEnd) {
			end = requestEnd
		}
		if end.Before(requestStart) {
			end = requestStart
		}
	}
	attributes := map[string]interface{}{
		"status":     detection.Status,
		"risk_level": detection.RiskLevel,
		"confidence": detection.Confidence,
		"block":      detection.Block,
	}
	if len(detection.Reasons) > 0 {
		attributes["reasons"] = detection.Reasons
	}
	if detection.Error != "" {
		attributes["error"] = detection.Error
	}
	return telemetrySpan{
		Name:       name,
		Kind:       "tool",
		StartTime:  start.Format(time.RFC3339Nano),
		EndTime:    end.Format(time.RFC3339Nano),
		Attributes: attributes,
	}
}

func normalizeTelemetryURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return trimmed
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = intertraceTracePath
	}
	return u.String()
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
