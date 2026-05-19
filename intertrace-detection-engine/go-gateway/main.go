package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	defaultNemoURL      = "http://localhost:8001/detect"
	defaultPresidioURL  = "http://localhost:8002/detect"
	defaultTimeoutMS    = 2500
	defaultFailClosed   = true
	defaultEnableNemo   = true
	defaultEnablePii    = true
	defaultGatewayPort  = "8080"
	requestIDHeaderName = "X-Request-ID"
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
	FailClosed       bool
	EnableNemo       bool
	EnablePresidio   bool
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
	Decision   string            `json:"decision"`
	Block      bool              `json:"block"`
	RiskLevel  string            `json:"risk_level"`
	Confidence float64           `json:"confidence"`
	Reasons    []string          `json:"reasons"`
	Detections UnifiedDetections `json:"detections"`
	Latency    UnifiedLatency    `json:"latency"`
	RequestID  string            `json:"request_id"`
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

	port := strings.TrimSpace(getEnv("PORT", defaultGatewayPort))
	addr := ":" + port
	logger.Info("starting go gateway",
		slog.String("address", addr),
		slog.String("nemo_service_url", cfg.NemoServiceURL),
		slog.String("presidio_service_url", cfg.PresidioURL),
		slog.Int("detection_timeout_ms", int(cfg.DetectionTimeout/time.Millisecond)),
		slog.Bool("fail_closed", cfg.FailClosed),
		slog.Bool("enable_nemo", cfg.EnableNemo),
		slog.Bool("enable_presidio", cfg.EnablePresidio),
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

	var req DetectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
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
		slog.String("session_id", req.SessionID),
	)

	nemoResult := defaultServiceDetection("error", "safe", []string{"nemo service not called"})
	presidioResult := defaultServiceDetection("error", "safe", []string{"presidio service not called"})

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
			d := g.callDetectionService(r.Context(), g.cfg.NemoServiceURL, payload)
			results <- detectionResult{serviceName: "nemo", detection: d}
		}()
	} else {
		nemoResult = defaultServiceDetection("error", "safe", []string{"nemo service is disabled"})
	}

	if g.cfg.EnablePresidio {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := g.callDetectionService(r.Context(), g.cfg.PresidioURL, payload)
			results <- detectionResult{serviceName: "presidio", detection: d}
		}()
	} else {
		presidioResult = defaultServiceDetection("error", "safe", []string{"presidio service is disabled"})
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

	g.logger.Info("detection request completed",
		slog.String("request_id", requestID),
		slog.String("decision", response.Decision),
		slog.Bool("block", response.Block),
		slog.String("risk_level", response.RiskLevel),
		slog.Int64("total_latency_ms", response.Latency.TotalMS),
		slog.String("nemo_status", response.Detections.Nemo.Status),
		slog.String("presidio_status", response.Detections.Presidio.Status),
	)

	writeJSON(w, http.StatusOK, response)
}

func (g *Gateway) callDetectionService(parentCtx context.Context, url string, payload ServiceDetectRequest) ServiceDetection {
	reqBody, err := json.Marshal(payload)
	if err != nil {
		return defaultServiceDetection("error", "safe", []string{fmt.Sprintf("failed to encode request: %v", err)})
	}

	callCtx, cancel := context.WithTimeout(parentCtx, g.cfg.DetectionTimeout)
	defer cancel()

	requestStart := time.Now()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return defaultServiceDetection("error", "safe", []string{fmt.Sprintf("failed to create request: %v", err)})
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(httpReq)
	latencyMS := time.Since(requestStart).Milliseconds()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			detection := defaultServiceDetection("timeout", "safe", []string{fmt.Sprintf("service timeout after %d ms", g.cfg.DetectionTimeout/time.Millisecond)})
			detection.LatencyMS = latencyMS
			return detection
		}
		detection := defaultServiceDetection("error", "safe", []string{fmt.Sprintf("service call failed: %v", err)})
		detection.LatencyMS = latencyMS
		return detection
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		detection := defaultServiceDetection("error", "safe", []string{fmt.Sprintf("failed to read response: %v", err)})
		detection.LatencyMS = latencyMS
		return detection
	}

	if resp.StatusCode != http.StatusOK {
		reason := fmt.Sprintf("service returned status %d", resp.StatusCode)
		if len(respBody) > 0 {
			reason = fmt.Sprintf("%s: %s", reason, strings.TrimSpace(string(respBody)))
		}
		detection := defaultServiceDetection("error", "safe", []string{reason})
		detection.LatencyMS = latencyMS
		return detection
	}

	var detection ServiceDetection
	if err := json.Unmarshal(respBody, &detection); err != nil {
		detection = defaultServiceDetection("error", "safe", []string{fmt.Sprintf("invalid detection response: %v", err)})
		detection.LatencyMS = latencyMS
		return detection
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
	if detection.LatencyMS == 0 {
		detection.LatencyMS = latencyMS
	}

	return detection
}

func aggregateResults(cfg GatewayConfig, requestID string, nemo ServiceDetection, presidio ServiceDetection, totalMS int64) UnifiedResponse {
	enabledServices := 0
	failedServices := 0
	if cfg.EnableNemo {
		enabledServices++
		if nemo.Status != "success" {
			failedServices++
		}
	}
	if cfg.EnablePresidio {
		enabledServices++
		if presidio.Status != "success" {
			failedServices++
		}
	}

	risk := normalizeRiskLevel(highestRiskLevel(nemo.RiskLevel, presidio.RiskLevel))
	block := nemo.Block || presidio.Block
	reasons := uniqueStrings(append(append([]string{}, nemo.Reasons...), presidio.Reasons...))
	confidence := maxFloat(nemo.Confidence, presidio.Confidence)

	if enabledServices > 0 && failedServices == enabledServices && cfg.FailClosed {
		block = true
		risk = "critical"
		reasons = uniqueStrings(append(reasons, "all enabled detection services failed or timed out; fail-closed enforced"))
		if confidence == 0 {
			confidence = 1.0
		}
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
		RequestID: requestID,
	}
}

func defaultServiceDetection(status, risk string, reasons []string) ServiceDetection {
	return ServiceDetection{
		Status:     status,
		Block:      false,
		RiskLevel:  normalizeRiskLevel(risk),
		Confidence: 0,
		Categories: []string{},
		Reasons:    reasons,
		LatencyMS:  0,
	}
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

	return GatewayConfig{
		NemoServiceURL:   getEnv("NEMO_SERVICE_URL", defaultNemoURL),
		PresidioURL:      getEnv("PRESIDIO_SERVICE_URL", defaultPresidioURL),
		DetectionTimeout: time.Duration(timeoutMs) * time.Millisecond,
		FailClosed:       parseEnvBool("FAIL_CLOSED", defaultFailClosed),
		EnableNemo:       parseEnvBool("ENABLE_NEMO", defaultEnableNemo),
		EnablePresidio:   parseEnvBool("ENABLE_PRESIDIO", defaultEnablePii),
	}
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
