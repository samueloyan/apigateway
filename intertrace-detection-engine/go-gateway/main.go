package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultNemoURL         = "http://localhost:8001/detect"
	defaultPresidioURL     = "http://localhost:8002/detect"
	defaultOpenAIURL       = "https://api.openai.com/v1/chat/completions"
	defaultAnthropicURL    = "https://api.anthropic.com/v1/messages"
	defaultGeminiBaseURL   = "https://generativelanguage.googleapis.com/v1beta/models"
	defaultTelemetryMS     = 1500
	defaultTimeoutMS       = 2500
	defaultLLMTimeoutMS    = 45000
	defaultFailClosed      = true
	defaultEnableNemo      = true
	defaultEnablePii       = true
	defaultDebugMode       = false
	defaultMaxBodyBytes    = int64(1 * 1024 * 1024)
	defaultGatewayPort     = "8080"
	requestIDHeaderName    = "X-Request-ID"
	failClosedReason       = "All detection engines failed. Request blocked due to fail closed policy."
	defaultProviderOpenAI  = "openai"
	defaultProviderAnthrop = "anthropic"
	defaultProviderGemini  = "gemini"
)

var riskOrder = map[string]int{
	"safe":     0,
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

type GatewayConfig struct {
	NemoServiceURL   string
	PresidioURL      string
	DetectionTimeout time.Duration
	LLMTimeout       time.Duration
	TelemetryTimeout time.Duration
	OpenAIURL        string
	AnthropicURL     string
	GeminiBaseURL    string
	OpenAIAPIKey     string
	AnthropicAPIKey  string
	GeminiAPIKey     string
	TelemetryURL     string
	TelemetryAuth    string
	FailClosed       bool
	EnableNemo       bool
	EnablePresidio   bool
	EnableTelemetry  bool
	ForwardAuth      bool
	DebugDetection   bool
	MaxBodyBytes     int64
}

type DetectRequest struct {
	OrgID     string                 `json:"org_id"`
	ProjectID string                 `json:"project_id"`
	AssetID   string                 `json:"asset_id"`
	SessionID string                 `json:"session_id"`
	Input     string                 `json:"input"`
	Context   map[string]interface{} `json:"context"`
}

type ServiceDetectRequest struct {
	Input   string                 `json:"input"`
	Context map[string]interface{} `json:"context"`
}

type ServiceDetection struct {
	Status     string   `json:"status"`
	Block      bool     `json:"block"`
	RiskLevel  string   `json:"risk_level"`
	Confidence float64  `json:"confidence"`
	Categories []string `json:"categories"`
	Reasons    []string `json:"reasons"`
	LatencyMS  int64    `json:"latency_ms"`
	Error      string   `json:"error,omitempty"`
}

type UnifiedLatency struct {
	TotalMS    int64 `json:"total_ms"`
	NemoMS     int64 `json:"nemo_ms"`
	PresidioMS int64 `json:"presidio_ms"`
}

type UnifiedDetections struct {
	Nemo     ServiceDetection `json:"nemo"`
	Presidio ServiceDetection `json:"presidio"`
}

type UnifiedResponse struct {
	RequestID  string            `json:"request_id"`
	Decision   string            `json:"decision"`
	Block      bool              `json:"block"`
	RiskLevel  string            `json:"risk_level"`
	Confidence float64           `json:"confidence"`
	Reasons    []string          `json:"reasons"`
	Detections UnifiedDetections `json:"detections"`
	Latency    UnifiedLatency    `json:"latency"`
}

type Gateway struct {
	cfg    GatewayConfig
	client *http.Client
	logger *slog.Logger
}

type detectionResult struct {
	serviceName string
	detection   ServiceDetection
}

func main() {
	cfg := loadConfig()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	gateway := &Gateway{
		cfg:    cfg,
		client: &http.Client{},
		logger: logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", gateway.healthHandler)
	mux.HandleFunc("/v1/detect", gateway.detectHandler)
	mux.HandleFunc("/v1/chat/completions", gateway.chatCompletionsHandler)

	port := strings.TrimSpace(getEnv("PORT", defaultGatewayPort))
	addr := ":" + port
	logger.Info("starting go gateway",
		slog.String("address", addr),
		slog.String("nemo_service_url", cfg.NemoServiceURL),
		slog.String("presidio_service_url", cfg.PresidioURL),
		slog.Int("detection_timeout_ms", int(cfg.DetectionTimeout/time.Millisecond)),
		slog.Int("llm_timeout_ms", int(cfg.LLMTimeout/time.Millisecond)),
		slog.Int("telemetry_timeout_ms", int(cfg.TelemetryTimeout/time.Millisecond)),
		slog.Int64("max_body_bytes", cfg.MaxBodyBytes),
		slog.Bool("fail_closed", cfg.FailClosed),
		slog.Bool("enable_nemo", cfg.EnableNemo),
		slog.Bool("enable_presidio", cfg.EnablePresidio),
		slog.Bool("enable_telemetry", cfg.EnableTelemetry),
		slog.Bool("telemetry_url_configured", cfg.TelemetryURL != ""),
		slog.Bool("debug_detection", cfg.DebugDetection),
		slog.Bool("openai_configured", cfg.OpenAIAPIKey != ""),
		slog.Bool("anthropic_configured", cfg.AnthropicAPIKey != ""),
		slog.Bool("gemini_configured", cfg.GeminiAPIKey != ""),
	)

	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Error("gateway stopped", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func (g *Gateway) healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "go-gateway",
	})
}

func (g *Gateway) detectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	requestID := strings.TrimSpace(r.Header.Get(requestIDHeaderName))
	if requestID == "" {
		requestID = generateRequestID()
	}
	w.Header().Set(requestIDHeaderName, requestID)

	r.Body = http.MaxBytesReader(w, r.Body, g.cfg.MaxBodyBytes)

	var req DetectRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		if strings.Contains(err.Error(), "http: request body too large") {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body exceeds size limit"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
		return
	}
	if strings.TrimSpace(req.OrgID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "org_id is required"})
		return
	}
	if strings.TrimSpace(req.ProjectID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "project_id is required"})
		return
	}
	if strings.TrimSpace(req.AssetID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "asset_id is required"})
		return
	}
	if strings.TrimSpace(req.Input) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "input is required"})
		return
	}
	if req.Context == nil {
		req.Context = map[string]interface{}{}
	}

	start := time.Now()
	g.logger.Info("detection request started",
		slog.String("request_id", requestID),
		slog.String("org_id", req.OrgID),
		slog.String("project_id", req.ProjectID),
		slog.String("asset_id", req.AssetID),
	)

	nemoResult := defaultServiceDetection("error", "safe", nil)
	presidioResult := defaultServiceDetection("error", "safe", nil)

	var wg sync.WaitGroup
	results := make(chan detectionResult, 2)

	payload := ServiceDetectRequest{
		Input:   req.Input,
		Context: req.Context,
	}

	if g.cfg.EnableNemo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := g.callDetectionService(r.Context(), "nemo", g.cfg.NemoServiceURL, payload, requestID)
			results <- detectionResult{serviceName: "nemo", detection: d}
		}()
	} else {
		nemoResult = defaultServiceDetection("error", "safe", nil)
		if g.cfg.DebugDetection {
			nemoResult.Error = "nemo service is disabled"
		}
	}

	if g.cfg.EnablePresidio {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := g.callDetectionService(r.Context(), "presidio", g.cfg.PresidioURL, payload, requestID)
			results <- detectionResult{serviceName: "presidio", detection: d}
		}()
	} else {
		presidioResult = defaultServiceDetection("error", "safe", nil)
		if g.cfg.DebugDetection {
			presidioResult.Error = "presidio service is disabled"
		}
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		switch result.serviceName {
		case "nemo":
			nemoResult = result.detection
		case "presidio":
			presidioResult = result.detection
		}
	}

	totalMS := time.Since(start).Milliseconds()
	response := aggregateResults(g.cfg, requestID, nemoResult, presidioResult, totalMS)
	g.emitTelemetryAsync(r, TelemetryEvent{
		EventType:      "detect",
		RequestID:      requestID,
		OrgID:          req.OrgID,
		ProjectID:      req.ProjectID,
		AssetID:        req.AssetID,
		SessionID:      req.SessionID,
		Provider:       contextString(req.Context, "provider"),
		Model:          contextString(req.Context, "model"),
		HTTPStatusCode: http.StatusOK,
		LatencyMS:      response.Latency.TotalMS,
		InputHash:      hashText(req.Input),
		InputChars:     len(req.Input),
		Decision:       response.Decision,
		RiskLevel:      response.RiskLevel,
		Block:          response.Block,
		Reasons:        response.Reasons,
		Detections:     response.Detections,
		RawResponse:    response,
	})

	g.logger.Info("detection request completed",
		slog.String("request_id", requestID),
		slog.String("org_id", req.OrgID),
		slog.String("project_id", req.ProjectID),
		slog.String("asset_id", req.AssetID),
		slog.String("decision", response.Decision),
		slog.String("risk_level", response.RiskLevel),
		slog.Int64("total_latency_ms", response.Latency.TotalMS),
		slog.String("nemo_status", response.Detections.Nemo.Status),
		slog.String("presidio_status", response.Detections.Presidio.Status),
	)

	writeJSON(w, http.StatusOK, response)
}

func (g *Gateway) callDetectionService(parentCtx context.Context, serviceName, url string, payload ServiceDetectRequest, requestID string) ServiceDetection {
	reqBody, err := json.Marshal(payload)
	if err != nil {
		return serviceFailure("error", 0, g.cfg.DebugDetection, serviceName, err.Error())
	}

	callCtx, cancel := context.WithTimeout(parentCtx, g.cfg.DetectionTimeout)
	defer cancel()

	requestStart := time.Now()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return serviceFailure("error", 0, g.cfg.DebugDetection, serviceName, err.Error())
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(requestIDHeaderName, requestID)

	resp, err := g.client.Do(httpReq)
	latencyMS := time.Since(requestStart).Milliseconds()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			return serviceFailure("timeout", latencyMS, g.cfg.DebugDetection, serviceName, "upstream timeout")
		}
		return serviceFailure("error", latencyMS, g.cfg.DebugDetection, serviceName, err.Error())
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return serviceFailure("error", latencyMS, g.cfg.DebugDetection, serviceName, err.Error())
	}

	if resp.StatusCode != http.StatusOK {
		internalErr := "unexpected upstream status " + strconv.Itoa(resp.StatusCode)
		if g.cfg.DebugDetection && len(respBody) > 0 {
			internalErr = internalErr + ": " + strings.TrimSpace(string(respBody))
		}
		return serviceFailure("error", latencyMS, g.cfg.DebugDetection, serviceName, internalErr)
	}

	var detection ServiceDetection
	if err := json.Unmarshal(respBody, &detection); err != nil {
		return serviceFailure("error", latencyMS, g.cfg.DebugDetection, serviceName, "invalid service response")
	}

	if detection.Status == "" {
		detection.Status = "success"
	}
	if detection.RiskLevel == "" {
		detection.RiskLevel = "safe"
	}
	detection.RiskLevel = normalizeRiskLevel(detection.RiskLevel)
	if detection.Categories == nil {
		detection.Categories = []string{}
	}
	if detection.Reasons == nil {
		detection.Reasons = []string{}
	}
	detection.Error = ""
	if detection.LatencyMS == 0 {
		detection.LatencyMS = latencyMS
	}

	return detection
}

func aggregateResults(cfg GatewayConfig, requestID string, nemo ServiceDetection, presidio ServiceDetection, totalMS int64) UnifiedResponse {
	enabledServices := 0
	failedServices := 0
	successfulDetections := make([]ServiceDetection, 0, 2)

	if cfg.EnableNemo && nemo.Status != "" {
		enabledServices++
		if nemo.Status != "success" {
			failedServices++
		} else {
			successfulDetections = append(successfulDetections, nemo)
		}
	}
	if cfg.EnablePresidio && presidio.Status != "" {
		enabledServices++
		if presidio.Status != "success" {
			failedServices++
		} else {
			successfulDetections = append(successfulDetections, presidio)
		}
	}

	risk := "safe"
	block := false
	reasons := make([]string, 0, 6)
	confidence := 0.0

	for _, detection := range successfulDetections {
		risk = highestRiskLevel(risk, detection.RiskLevel)
		block = block || detection.Block
		confidence = maxFloat(confidence, detection.Confidence)
		reasons = append(reasons, detection.Reasons...)
	}
	reasons = uniqueStrings(reasons)

	if enabledServices > 0 && failedServices == enabledServices && cfg.FailClosed {
		block = true
		risk = "critical"
		reasons = []string{failClosedReason}
		confidence = 1.0
	}

	decision := "allow"
	if block {
		decision = "block"
	} else if riskOrder[risk] >= riskOrder["medium"] {
		decision = "review"
	}

	if len(reasons) == 0 {
		reasons = []string{"no threats detected"}
	}

	return UnifiedResponse{
		RequestID:  requestID,
		Decision:   decision,
		Block:      block,
		RiskLevel:  risk,
		Confidence: confidence,
		Reasons:    reasons,
		Detections: UnifiedDetections{
			Nemo:     nemo,
			Presidio: presidio,
		},
		Latency: UnifiedLatency{
			TotalMS:    totalMS,
			NemoMS:     nemo.LatencyMS,
			PresidioMS: presidio.LatencyMS,
		},
	}
}

func defaultServiceDetection(status, risk string, reasons []string) ServiceDetection {
	return ServiceDetection{
		Status:     status,
		Block:      false,
		RiskLevel:  normalizeRiskLevel(risk),
		Confidence: 0,
		Categories: []string{},
		Reasons:    uniqueStrings(reasons),
		LatencyMS:  0,
		Error:      "",
	}
}

func serviceFailure(status string, latencyMS int64, debug bool, serviceName, internalErr string) ServiceDetection {
	detection := defaultServiceDetection(status, "safe", nil)
	detection.LatencyMS = latencyMS
	if debug {
		detection.Error = serviceName + ": " + strings.TrimSpace(internalErr)
	}
	return detection
}

func normalizeRiskLevel(level string) string {
	lower := strings.ToLower(strings.TrimSpace(level))
	if _, ok := riskOrder[lower]; ok {
		return lower
	}
	return "safe"
}

func highestRiskLevel(levels ...string) string {
	highest := "safe"
	for _, level := range levels {
		normalized := normalizeRiskLevel(level)
		if riskOrder[normalized] > riskOrder[highest] {
			highest = normalized
		}
	}
	return highest
}

func uniqueStrings(input []string) []string {
	seen := make(map[string]struct{}, len(input))
	output := make([]string, 0, len(input))
	for _, item := range input {
		normalized := strings.TrimSpace(item)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		output = append(output, normalized)
	}
	return output
}

func maxFloat(values ...float64) float64 {
	max := 0.0
	for _, value := range values {
		if value > max {
			max = value
		}
	}
	return max
}

func loadConfig() GatewayConfig {
	timeoutMs := parseEnvInt("DETECTION_TIMEOUT_MS", defaultTimeoutMS)
	if timeoutMs <= 0 {
		timeoutMs = defaultTimeoutMS
	}
	llmTimeoutMs := parseEnvInt("LLM_TIMEOUT_MS", defaultLLMTimeoutMS)
	if llmTimeoutMs <= 0 {
		llmTimeoutMs = defaultLLMTimeoutMS
	}
	telemetryTimeoutMS := parseEnvInt("INTERTRACE_TELEMETRY_TIMEOUT_MS", defaultTelemetryMS)
	if telemetryTimeoutMS <= 0 {
		telemetryTimeoutMS = defaultTelemetryMS
	}
	maxBodyBytes := parseEnvInt64("MAX_REQUEST_BODY_BYTES", defaultMaxBodyBytes)
	if maxBodyBytes <= 0 {
		maxBodyBytes = defaultMaxBodyBytes
	}

	return GatewayConfig{
		NemoServiceURL:   getEnv("NEMO_SERVICE_URL", defaultNemoURL),
		PresidioURL:      getEnv("PRESIDIO_SERVICE_URL", defaultPresidioURL),
		DetectionTimeout: time.Duration(timeoutMs) * time.Millisecond,
		LLMTimeout:       time.Duration(llmTimeoutMs) * time.Millisecond,
		TelemetryTimeout: time.Duration(telemetryTimeoutMS) * time.Millisecond,
		OpenAIURL:        getEnv("OPENAI_API_URL", defaultOpenAIURL),
		AnthropicURL:     getEnv("ANTHROPIC_API_URL", defaultAnthropicURL),
		GeminiBaseURL:    getEnv("GEMINI_API_BASE_URL", defaultGeminiBaseURL),
		OpenAIAPIKey:     strings.TrimSpace(os.Getenv("OPENAI_API_KEY")),
		AnthropicAPIKey:  strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")),
		GeminiAPIKey:     strings.TrimSpace(os.Getenv("GEMINI_API_KEY")),
		TelemetryURL:     normalizeTelemetryURL(strings.TrimSpace(os.Getenv("INTERTRACE_TELEMETRY_URL"))),
		TelemetryAuth:    strings.TrimSpace(os.Getenv("INTERTRACE_TELEMETRY_AUTH_TOKEN")),
		FailClosed:       parseEnvBool("FAIL_CLOSED", defaultFailClosed),
		EnableNemo:       parseEnvBool("ENABLE_NEMO", defaultEnableNemo),
		EnablePresidio:   parseEnvBool("ENABLE_PRESIDIO", defaultEnablePii),
		EnableTelemetry:  parseEnvBool("ENABLE_INTERTRACE_TELEMETRY", false),
		ForwardAuth:      parseEnvBool("INTERTRACE_TELEMETRY_FORWARD_AUTH", true),
		DebugDetection:   parseEnvBool("DEBUG_DETECTION", defaultDebugMode),
		MaxBodyBytes:     maxBodyBytes,
	}
}

func contextString(ctx map[string]interface{}, key string) string {
	value, ok := ctx[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}

func getEnv(key, defaultValue string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue
	}
	return value
}

func parseEnvInt(key string, defaultValue int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	return parsed
}

func parseEnvInt64(key string, defaultValue int64) int64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return defaultValue
	}
	return parsed
}

func parseEnvBool(key string, defaultValue bool) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if value == "" {
		return defaultValue
	}
	switch value {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return defaultValue
	}
}

func generateRequestID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err == nil {
		return hex.EncodeToString(buf)
	}
	return strconv.FormatInt(time.Now().UnixNano(), 10)
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		http.Error(w, `{"error":"failed to encode response"}`, http.StatusInternalServerError)
	}
}
