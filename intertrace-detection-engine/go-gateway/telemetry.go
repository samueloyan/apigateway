package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	intertraceOrgHeader         = "X-Intertrace-Org-Id"
	intertraceAssetHeader       = "X-Intertrace-Asset"
	intertraceGatewayEventPath  = "/api/gateway/event"
	defaultUnknownProvider      = "unknown"
	defaultUnknownModel         = "unknown"
	maxRedactedContentChars     = 4000
	defaultIngestWorkerBackoff  = 150 * time.Millisecond
	defaultIngestMaxBackoff     = 2 * time.Second
	defaultIntertraceIngestPath = "/api/gateway/event"
)

var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var emailPattern = regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`)
var phonePattern = regexp.MustCompile(`\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){1,2}\d{4}\b`)
var ssnPattern = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
var bearerPattern = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._\-]+\b`)
var apiKeyPattern = regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret|token)\s*[:=]\s*[A-Za-z0-9_\-]{8,}\b`)
var cardPattern = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)

type TelemetryEvent struct {
	EventType               string      `json:"event_type"`
	RequestID               string      `json:"request_id"`
	OrgID                   string      `json:"org_id,omitempty"`
	ProjectID               string      `json:"project_id,omitempty"`
	AssetID                 string      `json:"asset_id,omitempty"`
	SessionID               string      `json:"session_id,omitempty"`
	Provider                string      `json:"provider,omitempty"`
	Model                   string      `json:"model,omitempty"`
	HTTPStatusCode          int         `json:"http_status_code"`
	LatencyMS               int64       `json:"latency_ms,omitempty"`
	ProviderLatencyMS       int64       `json:"provider_latency_ms,omitempty"`
	InputHash               string      `json:"input_hash,omitempty"`
	InputChars              int         `json:"input_chars,omitempty"`
	MessageCount            int         `json:"message_count,omitempty"`
	Decision                string      `json:"decision,omitempty"`
	RiskLevel               string      `json:"risk_level,omitempty"`
	Block                   bool        `json:"block"`
	Reasons                 []string    `json:"reasons,omitempty"`
	Detections              interface{} `json:"detections,omitempty"`
	UpstreamError           string      `json:"upstream_error,omitempty"`
	RawResponse             interface{} `json:"raw_response,omitempty"`
	GatewayRoute            string      `json:"gateway_route,omitempty"`
	PromptContent           string      `json:"prompt_content,omitempty"`
	SystemPrompt            string      `json:"system_prompt,omitempty"`
	ResponseContent         string      `json:"response_content,omitempty"`
	ClassifierUsed          string      `json:"classifier_used,omitempty"`
	ClassificationReasoning string      `json:"classification_reasoning,omitempty"`
	GuardTags               []string    `json:"guard_tags,omitempty"`
	Threats                 []Threat    `json:"threats,omitempty"`
	PIIDetected             []string    `json:"pii_detected,omitempty"`
	InboundVerdictOverride  string      `json:"inbound_verdict_override,omitempty"`
	OutboundVerdictOverride string      `json:"outbound_verdict_override,omitempty"`
	TotalLatencyMS          int64       `json:"total_latency_ms,omitempty"`
}

type Threat struct {
	Type       string   `json:"type"`
	Details    string   `json:"details,omitempty"`
	Confidence *float64 `json:"confidence,omitempty"`
}

type gatewayEventPayload struct {
	OrgID                string   `json:"org_id"`
	AssetID              string   `json:"asset_id,omitempty"`
	Provider             string   `json:"provider"`
	Model                string   `json:"model"`
	InboundVerdict       string   `json:"inbound_verdict"`
	OutboundVerdict      string   `json:"outbound_verdict"`
	Threats              []Threat `json:"threats"`
	PIIDetected          []string `json:"pii_detected"`
	LatencyGatewayMS     int64    `json:"latency_gateway_ms"`
	RequestID            string   `json:"request_id,omitempty"`
	GatewayRoute         string   `json:"gateway_route,omitempty"`
	ClassifierUsed       string   `json:"classifier_used,omitempty"`
	ClassificationReason string   `json:"classification_reasoning,omitempty"`
	GuardTags            []string `json:"guard_tags,omitempty"`
	PromptContent        string   `json:"prompt_content,omitempty"`
	SystemPrompt         string   `json:"system_prompt,omitempty"`
	ResponseContent      string   `json:"response_content,omitempty"`
	TotalLatencyMS       int64    `json:"total_latency_ms,omitempty"`
	ProviderLatencyMS    int64    `json:"provider_latency_ms,omitempty"`
}

type eventAuthMode int

const (
	authModeNone eventAuthMode = iota
	authModeSharedSecret
	authModeOrgKey
)

type intertraceEventIngestor struct {
	cfg       GatewayConfig
	logger    *slog.Logger
	client    *http.Client
	endpoint  string
	queue     chan gatewayEventPayload
	cancel    context.CancelFunc
	workersWg sync.WaitGroup
	dropped   atomic.Uint64
}

func newIntertraceEventIngestor(cfg GatewayConfig, logger *slog.Logger) *intertraceEventIngestor {
	if !cfg.EnableTelemetry || strings.TrimSpace(cfg.TelemetryURL) == "" {
		return nil
	}
	endpoint := normalizeDashboardURL(cfg.TelemetryURL)
	if endpoint == "" {
		return nil
	}

	ingestor := &intertraceEventIngestor{
		cfg:      cfg,
		logger:   logger,
		client:   &http.Client{Timeout: cfg.TelemetryTimeout},
		endpoint: ensureGatewayEventPath(endpoint),
		queue:    make(chan gatewayEventPayload, cfg.IngestQueueSize),
	}

	ctx, cancel := context.WithCancel(context.Background())
	ingestor.cancel = cancel
	for i := 0; i < cfg.IngestWorkers; i++ {
		ingestor.workersWg.Add(1)
		go ingestor.worker(ctx, i+1)
	}
	return ingestor
}

func (g *Gateway) emitTelemetryAsync(r *http.Request, event TelemetryEvent) {
	if g.eventIngestor == nil {
		return
	}

	payload := buildGatewayEventPayload(r, event)
	if strings.TrimSpace(payload.OrgID) == "" {
		g.logger.Warn("intertrace ingest skipped due to missing org_id",
			"request_id", payload.RequestID,
			"route", payload.GatewayRoute,
		)
		return
	}
	select {
	case g.eventIngestor.queue <- payload:
	default:
		dropped := g.eventIngestor.dropped.Add(1)
		g.logger.Warn("intertrace ingest queue full, dropping event",
			"request_id", payload.RequestID,
			"org_id", payload.OrgID,
			"dropped_total", dropped,
		)
	}
}

func (i *intertraceEventIngestor) worker(ctx context.Context, workerID int) {
	defer i.workersWg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case payload := <-i.queue:
			i.sendWithRetry(ctx, workerID, payload)
		}
	}
}

func (i *intertraceEventIngestor) sendWithRetry(ctx context.Context, workerID int, payload gatewayEventPayload) {
	var lastErr error
	for attempt := 0; attempt <= i.cfg.IngestRetries; attempt++ {
		if ctx.Err() != nil {
			return
		}
		statusCode, err := i.sendOnce(ctx, payload)
		if err == nil {
			i.logger.Info("intertrace ingest post succeeded",
				"request_id", payload.RequestID,
				"org_id", payload.OrgID,
				"status_code", statusCode,
				"attempt", attempt+1,
				"worker_id", workerID,
			)
			return
		}
		lastErr = err
		if attempt < i.cfg.IngestRetries {
			backoff := defaultIngestWorkerBackoff * time.Duration(1<<attempt)
			if backoff > defaultIngestMaxBackoff {
				backoff = defaultIngestMaxBackoff
			}
			time.Sleep(backoff)
		}
	}

	i.logger.Warn("intertrace ingest post failed after retries",
		"request_id", payload.RequestID,
		"org_id", payload.OrgID,
		"max_retries", i.cfg.IngestRetries,
		"error", errorString(lastErr),
	)
}

func (i *intertraceEventIngestor) sendOnce(parentCtx context.Context, payload gatewayEventPayload) (int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	ctx, cancel := context.WithTimeout(parentCtx, i.cfg.TelemetryTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if payload.RequestID != "" {
		req.Header.Set(requestIDHeaderName, payload.RequestID)
	}
	if payload.OrgID != "" {
		req.Header.Set(intertraceOrgHeader, payload.OrgID)
	}
	if payload.AssetID != "" {
		req.Header.Set(intertraceAssetHeader, payload.AssetID)
	}
	if err := i.applyAuthHeaders(req.Header, payload.OrgID, body); err != nil {
		return 0, err
	}

	resp, err := i.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		respBody, _ := io.ReadAll(resp.Body)
		if i.cfg.DebugDetection {
			return resp.StatusCode, &telemetryError{statusCode: resp.StatusCode, body: strings.TrimSpace(string(respBody))}
		}
		return resp.StatusCode, &telemetryError{statusCode: resp.StatusCode}
	}
	return resp.StatusCode, nil
}

func (i *intertraceEventIngestor) applyAuthHeaders(headers http.Header, orgID string, body []byte) error {
	nowMillis := strconv.FormatInt(time.Now().UnixMilli(), 10)
	orgKeyID, orgSecret := i.resolveOrgKeyAuth(orgID)
	if orgKeyID != "" && orgSecret != "" {
		nonce := randomNonce()
		signature := hmacHex(body, nowMillis+nonce, orgSecret)
		headers.Set("X-Intertrace-Key-Id", orgKeyID)
		headers.Set("X-Intertrace-Nonce", nonce)
		headers.Set("X-Intertrace-Timestamp", nowMillis)
		headers.Set("X-Intertrace-Signature", signature)
		return nil
	}

	secret := strings.TrimSpace(i.cfg.TelemetryAuth)
	if secret != "" {
		signature := hmacHex(body, nowMillis, secret)
		headers.Set("X-Intertrace-Internal", secret)
		headers.Set("X-Intertrace-Timestamp", nowMillis)
		headers.Set("X-Intertrace-Signature", signature)
		// Legacy mirrors
		headers.Set("X-Bastion-Internal", secret)
		headers.Set("X-Bastion-Timestamp", nowMillis)
		headers.Set("X-Bastion-Signature", signature)
		return nil
	}

	return fmt.Errorf("intertrace ingest auth is not configured for org_id=%s", orgID)
}

func (i *intertraceEventIngestor) resolveOrgKeyAuth(orgID string) (string, string) {
	normalizedOrg := strings.TrimSpace(orgID)
	keyID := strings.TrimSpace(i.cfg.OrgKeyID)
	secret := strings.TrimSpace(i.cfg.OrgSecret)
	if normalizedOrg != "" {
		if override := strings.TrimSpace(i.cfg.OrgKeyIDMap[normalizedOrg]); override != "" {
			keyID = override
		}
		if override := strings.TrimSpace(i.cfg.OrgSecretMap[normalizedOrg]); override != "" {
			secret = override
		}
	}
	return keyID, secret
}

func buildGatewayEventPayload(r *http.Request, event TelemetryEvent) gatewayEventPayload {
	orgID := strings.TrimSpace(event.OrgID)
	if orgID == "" {
		orgID = strings.TrimSpace(r.Header.Get(intertraceOrgHeader))
	}
	assetID := strings.TrimSpace(event.AssetID)
	if assetID == "" {
		assetID = strings.TrimSpace(r.Header.Get(intertraceAssetHeader))
	}

	provider := strings.TrimSpace(event.Provider)
	if provider == "" {
		provider = defaultUnknownProvider
	}
	model := strings.TrimSpace(event.Model)
	if model == "" {
		model = defaultUnknownModel
	}

	inboundVerdict := firstNonEmpty(strings.TrimSpace(event.InboundVerdictOverride), verdictFromDecision(event.Decision, event.RiskLevel, event.Block))
	outboundVerdict := firstNonEmpty(strings.TrimSpace(event.OutboundVerdictOverride), inboundVerdict)
	if event.HTTPStatusCode >= http.StatusBadRequest && !event.Block && outboundVerdict == "PASS" {
		outboundVerdict = "FLAG"
	}

	threats := event.Threats
	if len(threats) == 0 {
		threats = deriveThreats(event)
	}
	piiDetected := event.PIIDetected
	if len(piiDetected) == 0 {
		piiDetected = derivePII(event)
	}

	classificationReason := strings.TrimSpace(event.ClassificationReasoning)
	if classificationReason == "" {
		classificationReason = strings.Join(event.Reasons, "; ")
	}
	classifierUsed := strings.TrimSpace(event.ClassifierUsed)
	if classifierUsed == "" {
		classifierUsed = deriveClassifierUsed(event.Detections)
	}

	guardTags := event.GuardTags
	if len(guardTags) == 0 {
		guardTags = deriveGuardTags(event)
	}

	latencyGatewayMS := event.LatencyMS
	if latencyGatewayMS <= 0 {
		latencyGatewayMS = event.TotalLatencyMS
	}
	totalLatency := event.TotalLatencyMS
	if totalLatency <= 0 {
		totalLatency = event.LatencyMS
	}

	route := strings.TrimSpace(event.GatewayRoute)
	if route == "" {
		route = r.URL.Path
	}

	return gatewayEventPayload{
		OrgID:                orgID,
		AssetID:              assetID,
		Provider:             provider,
		Model:                model,
		InboundVerdict:       inboundVerdict,
		OutboundVerdict:      outboundVerdict,
		Threats:              threats,
		PIIDetected:          piiDetected,
		LatencyGatewayMS:     maxInt64(latencyGatewayMS, 0),
		RequestID:            strings.TrimSpace(event.RequestID),
		GatewayRoute:         route,
		ClassifierUsed:       classifierUsed,
		ClassificationReason: classificationReason,
		GuardTags:            uniqueStrings(guardTags),
		PromptContent:        redactSensitiveText(event.PromptContent),
		SystemPrompt:         redactSensitiveText(event.SystemPrompt),
		ResponseContent:      redactSensitiveText(event.ResponseContent),
		TotalLatencyMS:       maxInt64(totalLatency, 0),
		ProviderLatencyMS:    maxInt64(event.ProviderLatencyMS, 0),
	}
}

func deriveThreats(event TelemetryEvent) []Threat {
	threats := make([]Threat, 0, len(event.Reasons)+4)
	for _, reason := range event.Reasons {
		reason = strings.TrimSpace(reason)
		if reason == "" {
			continue
		}
		threats = append(threats, Threat{
			Type:    "detection_reason",
			Details: reason,
		})
	}

	if detections, ok := event.Detections.(UnifiedDetections); ok {
		appendCategoriesAsThreats := func(source string, detection ServiceDetection) {
			for _, category := range detection.Categories {
				category = strings.TrimSpace(category)
				if category == "" {
					continue
				}
				confidence := detection.Confidence
				threats = append(threats, Threat{
					Type:       source + ":" + category,
					Details:    "category flagged by " + source,
					Confidence: &confidence,
				})
			}
		}
		appendCategoriesAsThreats("nemo", detections.Nemo)
		appendCategoriesAsThreats("presidio", detections.Presidio)
		appendCategoriesAsThreats("semantic", detections.Semantic)
	}
	return dedupeThreats(threats)
}

func dedupeThreats(input []Threat) []Threat {
	seen := map[string]struct{}{}
	out := make([]Threat, 0, len(input))
	for _, threat := range input {
		key := strings.TrimSpace(strings.ToLower(threat.Type + "|" + threat.Details))
		if key == "|" || key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, threat)
	}
	return out
}

func derivePII(event TelemetryEvent) []string {
	if detections, ok := event.Detections.(UnifiedDetections); ok {
		categories := make([]string, 0, len(detections.Presidio.Categories))
		for _, category := range detections.Presidio.Categories {
			normalized := strings.ToLower(strings.TrimSpace(category))
			if normalized == "" {
				continue
			}
			if strings.Contains(normalized, "pii") ||
				strings.Contains(normalized, "email") ||
				strings.Contains(normalized, "phone") ||
				strings.Contains(normalized, "ssn") ||
				strings.Contains(normalized, "credit") ||
				strings.Contains(normalized, "api_key") ||
				strings.Contains(normalized, "token") {
				categories = append(categories, normalized)
			}
		}
		return uniqueStrings(categories)
	}
	return []string{}
}

func deriveClassifierUsed(detections interface{}) string {
	used := []string{}
	if d, ok := detections.(UnifiedDetections); ok {
		if strings.TrimSpace(d.Nemo.Status) == "success" {
			used = append(used, "nemo")
		}
		if strings.TrimSpace(d.Presidio.Status) == "success" {
			used = append(used, "presidio")
		}
		if strings.TrimSpace(d.Semantic.Status) == "success" {
			used = append(used, "semantic")
		}
	}
	if len(used) == 0 {
		return ""
	}
	return strings.Join(used, ",")
}

func deriveGuardTags(event TelemetryEvent) []string {
	tags := []string{}
	for _, reason := range event.Reasons {
		normalizedReason := strings.ToLower(strings.TrimSpace(reason))
		switch {
		case strings.Contains(normalizedReason, "fail closed"):
			tags = append(tags, "guard_fail_closed:classifier_inbound")
		case strings.Contains(normalizedReason, "timeout"):
			tags = append(tags, "guard_timeout:classifier_inbound")
		}
	}
	if d, ok := event.Detections.(UnifiedDetections); ok {
		if d.Nemo.Status == "timeout" || d.Presidio.Status == "timeout" || d.Semantic.Status == "timeout" {
			tags = append(tags, "guard_timeout:classifier_inbound")
		}
		if d.Nemo.Status == "error" || d.Presidio.Status == "error" || d.Semantic.Status == "error" {
			tags = append(tags, "guard_error:classifier_inbound")
		}
	}
	return uniqueStrings(tags)
}

func verdictFromDecision(decision, riskLevel string, block bool) string {
	if block || strings.EqualFold(strings.TrimSpace(decision), "block") {
		return "BLOCK"
	}
	normalizedDecision := strings.ToLower(strings.TrimSpace(decision))
	normalizedRisk := normalizeRiskLevel(riskLevel)
	if normalizedDecision == "review" || riskOrder[normalizedRisk] >= riskOrder["medium"] {
		return "FLAG"
	}
	return "PASS"
}

func normalizeDashboardURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return trimmed
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String()
}

func ensureGatewayEventPath(base string) string {
	trimmed := strings.TrimSpace(base)
	if trimmed == "" {
		return ""
	}
	if strings.HasSuffix(trimmed, defaultIntertraceIngestPath) {
		return trimmed
	}
	return strings.TrimRight(trimmed, "/") + intertraceGatewayEventPath
}

func hashText(input string) string {
	normalized := strings.TrimSpace(input)
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func redactSensitiveText(input string) string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return ""
	}
	if len(trimmed) > maxRedactedContentChars {
		trimmed = trimmed[:maxRedactedContentChars]
	}
	redacted := emailPattern.ReplaceAllString(trimmed, "[REDACTED_EMAIL]")
	redacted = ssnPattern.ReplaceAllString(redacted, "[REDACTED_SSN]")
	redacted = phonePattern.ReplaceAllString(redacted, "[REDACTED_PHONE]")
	redacted = bearerPattern.ReplaceAllString(redacted, "Bearer [REDACTED_TOKEN]")
	redacted = apiKeyPattern.ReplaceAllString(redacted, "key=[REDACTED_SECRET]")
	redacted = cardPattern.ReplaceAllString(redacted, "[REDACTED_CARD]")
	return redacted
}

func hmacHex(body []byte, suffix, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	mac.Write([]byte(suffix))
	return hex.EncodeToString(mac.Sum(nil))
}

func randomNonce() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36) + strconv.FormatInt(rand.Int63(), 36)
}

func maxInt64(value, min int64) int64 {
	if value < min {
		return min
	}
	return value
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func sortedUnique(values []string) []string {
	deduped := uniqueStrings(values)
	slices.Sort(deduped)
	return deduped
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
