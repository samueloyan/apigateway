package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ChatCompletionRequest struct {
	OrgID       string                  `json:"org_id"`
	ProjectID   string                  `json:"project_id"`
	AssetID     string                  `json:"asset_id"`
	SessionID   string                  `json:"session_id"`
	Provider    string                  `json:"provider"`
	Model       string                  `json:"model"`
	Messages    []ChatCompletionMessage `json:"messages"`
	Temperature *float64                `json:"temperature,omitempty"`
	MaxTokens   *int                    `json:"max_tokens,omitempty"`
	Stream      bool                    `json:"stream,omitempty"`
	Context     map[string]interface{}  `json:"context"`
}

type ChatCompletionMessage struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"`
}

type normalizedMessage struct {
	Role    string
	Content string
}

type ChatChoiceMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatChoice struct {
	Index        int               `json:"index"`
	Message      ChatChoiceMessage `json:"message"`
	FinishReason string            `json:"finish_reason,omitempty"`
}

type ChatUsage struct {
	PromptTokens     int `json:"prompt_tokens,omitempty"`
	CompletionTokens int `json:"completion_tokens,omitempty"`
	TotalTokens      int `json:"total_tokens,omitempty"`
}

type ChatCompletionResponse struct {
	ID        string           `json:"id"`
	Object    string           `json:"object"`
	Created   int64            `json:"created"`
	Model     string           `json:"model"`
	Choices   []ChatChoice     `json:"choices"`
	Usage     ChatUsage        `json:"usage,omitempty"`
	RequestID string           `json:"request_id,omitempty"`
	Detection *UnifiedResponse `json:"detection,omitempty"`
}

type chatErrorDetail struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code,omitempty"`
}

type chatErrorResponse struct {
	RequestID string           `json:"request_id"`
	Error     chatErrorDetail  `json:"error"`
	Detection *UnifiedResponse `json:"detection,omitempty"`
}

func (g *Gateway) chatCompletionsHandler(w http.ResponseWriter, r *http.Request) {
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

	var req ChatCompletionRequest
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
	if strings.TrimSpace(req.Model) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "model is required"})
		return
	}
	if len(req.Messages) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "messages are required"})
		return
	}
	if req.Stream {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "stream mode is not supported"})
		return
	}
	if req.Context == nil {
		req.Context = map[string]interface{}{}
	}

	normalizedMessages, err := normalizeMessages(req.Messages)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	provider, err := resolveProvider(req.Provider, req.Model, req.Context)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	detectionContext := cloneContext(req.Context)
	detectionContext["provider"] = provider
	detectionContext["model"] = req.Model

	detectionInput := buildDetectionInput(normalizedMessages)
	if strings.TrimSpace(detectionInput) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one text message is required"})
		return
	}
	systemPrompt := extractRoleContent(normalizedMessages, "system")

	g.logger.Info("chat completion request started",
		slog.String("request_id", requestID),
		slog.String("org_id", req.OrgID),
		slog.String("project_id", req.ProjectID),
		slog.String("asset_id", req.AssetID),
		slog.String("provider", provider),
		slog.String("model", req.Model),
	)

	detection := g.runDetectionFanout(r.Context(), detectionInput, detectionContext, requestID)
	detection = g.applyDegradedFallback(detectionInput, detection)
	runtimePolicy := evaluateRuntimePolicy(req.Context, normalizedMessages)
	detection = applyRuntimePolicyToUnified(detection, runtimePolicy)
	if detection.Block {
		g.emitTelemetryAsync(r, TelemetryEvent{
			EventType:      "chat_completions",
			RequestID:      requestID,
			OrgID:          req.OrgID,
			ProjectID:      req.ProjectID,
			AssetID:        req.AssetID,
			SessionID:      req.SessionID,
			Provider:       provider,
			Model:          req.Model,
			HTTPStatusCode: http.StatusForbidden,
			LatencyMS:      detection.Latency.TotalMS,
			InputHash:      hashText(detectionInput),
			InputChars:     len(detectionInput),
			MessageCount:   len(normalizedMessages),
			Decision:       detection.Decision,
			RiskLevel:      detection.RiskLevel,
			Block:          detection.Block,
			Reasons:        detection.Reasons,
			Detections:     detection.Detections,
			GuardTags:      runtimePolicy.GuardTags,
			GatewayRoute:   "/v1/chat/completions",
			PromptContent:  detectionInput,
			SystemPrompt:   systemPrompt,
			RawResponse: chatErrorResponse{
				RequestID: requestID,
				Error: chatErrorDetail{
					Message: "Request blocked by detection policy",
					Type:    "safety_block",
					Code:    "blocked",
				},
				Detection: &detection,
			},
		})
		writeJSON(w, http.StatusForbidden, chatErrorResponse{
			RequestID: requestID,
			Error: chatErrorDetail{
				Message: "Request blocked by detection policy",
				Type:    "safety_block",
				Code:    "blocked",
			},
			Detection: &detection,
		})
		return
	}

	providerStart := time.Now()
	completion, err := g.requestChatCompletion(r.Context(), provider, req, normalizedMessages, requestID)
	providerLatencyMS := time.Since(providerStart).Milliseconds()
	if err != nil {
		message := "upstream completion request failed"
		if g.cfg.DebugDetection {
			message = err.Error()
		}
		statusCode := http.StatusBadGateway
		if errors.Is(err, context.DeadlineExceeded) {
			statusCode = http.StatusGatewayTimeout
		}
		g.emitTelemetryAsync(r, TelemetryEvent{
			EventType:         "chat_completions",
			RequestID:         requestID,
			OrgID:             req.OrgID,
			ProjectID:         req.ProjectID,
			AssetID:           req.AssetID,
			SessionID:         req.SessionID,
			Provider:          provider,
			Model:             req.Model,
			HTTPStatusCode:    statusCode,
			LatencyMS:         detection.Latency.TotalMS,
			InputHash:         hashText(detectionInput),
			InputChars:        len(detectionInput),
			MessageCount:      len(normalizedMessages),
			Decision:          detection.Decision,
			RiskLevel:         detection.RiskLevel,
			Block:             detection.Block,
			Reasons:           detection.Reasons,
			Detections:        detection.Detections,
			GuardTags:         runtimePolicy.GuardTags,
			ProviderLatencyMS: providerLatencyMS,
			GatewayRoute:      "/v1/chat/completions",
			PromptContent:     detectionInput,
			SystemPrompt:      systemPrompt,
			UpstreamError:     err.Error(),
			RawResponse: chatErrorResponse{
				RequestID: requestID,
				Error: chatErrorDetail{
					Message: message,
					Type:    "upstream_error",
					Code:    "upstream_failure",
				},
				Detection: &detection,
			},
		})
		writeJSON(w, statusCode, chatErrorResponse{
			RequestID: requestID,
			Error: chatErrorDetail{
				Message: message,
				Type:    "upstream_error",
				Code:    "upstream_failure",
			},
			Detection: &detection,
		})
		return
	}

	completion.RequestID = requestID
	completion.Detection = &detection

	g.logger.Info("chat completion request completed",
		slog.String("request_id", requestID),
		slog.String("org_id", req.OrgID),
		slog.String("project_id", req.ProjectID),
		slog.String("asset_id", req.AssetID),
		slog.String("provider", provider),
		slog.String("model", req.Model),
		slog.String("decision", detection.Decision),
		slog.String("risk_level", detection.RiskLevel),
	)
	g.emitTelemetryAsync(r, TelemetryEvent{
		EventType:         "chat_completions",
		RequestID:         requestID,
		OrgID:             req.OrgID,
		ProjectID:         req.ProjectID,
		AssetID:           req.AssetID,
		SessionID:         req.SessionID,
		Provider:          provider,
		Model:             req.Model,
		HTTPStatusCode:    http.StatusOK,
		LatencyMS:         detection.Latency.TotalMS,
		InputHash:         hashText(detectionInput),
		InputChars:        len(detectionInput),
		MessageCount:      len(normalizedMessages),
		Decision:          detection.Decision,
		RiskLevel:         detection.RiskLevel,
		Block:             detection.Block,
		Reasons:           detection.Reasons,
		Detections:        detection.Detections,
		GuardTags:         runtimePolicy.GuardTags,
		ProviderLatencyMS: providerLatencyMS,
		GatewayRoute:      "/v1/chat/completions",
		PromptContent:     detectionInput,
		SystemPrompt:      systemPrompt,
		ResponseContent:   firstChatResponseContent(completion),
		RawResponse:       completion,
	})

	writeJSON(w, http.StatusOK, completion)
}

func (g *Gateway) runDetectionFanout(ctx context.Context, input string, contextData map[string]interface{}, requestID string) UnifiedResponse {
	start := time.Now()
	payload := ServiceDetectRequest{
		Input:   input,
		Context: contextData,
	}

	nemoResult := defaultServiceDetection("error", "safe", nil)
	presidioResult := defaultServiceDetection("error", "safe", nil)
	semanticResult := defaultServiceDetection("error", "safe", nil)

	var wg sync.WaitGroup
	results := make(chan detectionResult, 3)

	if g.cfg.EnableNemo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := g.callDetectionService(ctx, "nemo", g.cfg.NemoServiceURL, payload, requestID)
			results <- detectionResult{serviceName: "nemo", detection: d}
		}()
	}
	if g.cfg.EnablePresidio {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := g.callDetectionService(ctx, "presidio", g.cfg.PresidioURL, payload, requestID)
			results <- detectionResult{serviceName: "presidio", detection: d}
		}()
	}
	if g.cfg.EnableSemantic {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := g.callDetectionService(ctx, "semantic", g.cfg.SemanticServiceURL, payload, requestID)
			results <- detectionResult{serviceName: "semantic", detection: d}
		}()
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
		case "semantic":
			semanticResult = result.detection
		}
	}

	totalMS := time.Since(start).Milliseconds()
	return aggregateResults(g.cfg, requestID, nemoResult, presidioResult, semanticResult, totalMS)
}

func normalizeMessages(messages []ChatCompletionMessage) ([]normalizedMessage, error) {
	normalized := make([]normalizedMessage, 0, len(messages))
	for _, message := range messages {
		role := strings.ToLower(strings.TrimSpace(message.Role))
		if role == "" {
			return nil, fmt.Errorf("message role is required")
		}
		content, err := extractTextContent(message.Content)
		if err != nil {
			return nil, err
		}
		if content == "" {
			continue
		}
		normalized = append(normalized, normalizedMessage{
			Role:    role,
			Content: content,
		})
	}
	if len(normalized) == 0 {
		return nil, fmt.Errorf("at least one text message is required")
	}
	return normalized, nil
}

func extractTextContent(content interface{}) (string, error) {
	switch value := content.(type) {
	case string:
		return strings.TrimSpace(value), nil
	case map[string]interface{}:
		if text, ok := value["text"].(string); ok {
			return strings.TrimSpace(text), nil
		}
		return "", fmt.Errorf("unsupported message content object")
	case []interface{}:
		parts := make([]string, 0, len(value))
		for _, part := range value {
			partMap, ok := part.(map[string]interface{})
			if !ok {
				continue
			}
			partType, _ := partMap["type"].(string)
			if partType != "" && partType != "text" && partType != "input_text" {
				continue
			}
			text, _ := partMap["text"].(string)
			text = strings.TrimSpace(text)
			if text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "\n"), nil
	default:
		return "", fmt.Errorf("unsupported message content type")
	}
}

func buildDetectionInput(messages []normalizedMessage) string {
	lines := make([]string, 0, len(messages))
	for _, message := range messages {
		lines = append(lines, message.Role+": "+message.Content)
	}
	return strings.Join(lines, "\n")
}

func extractRoleContent(messages []normalizedMessage, role string) string {
	target := strings.ToLower(strings.TrimSpace(role))
	if target == "" {
		return ""
	}
	parts := make([]string, 0, len(messages))
	for _, message := range messages {
		if message.Role == target {
			parts = append(parts, message.Content)
		}
	}
	return strings.Join(parts, "\n")
}

func firstChatResponseContent(completion ChatCompletionResponse) string {
	if len(completion.Choices) == 0 {
		return ""
	}
	return strings.TrimSpace(completion.Choices[0].Message.Content)
}

type runtimePolicyResult struct {
	Block      bool
	Review     bool
	Reasons    []string
	GuardTags  []string
	Categories []string
}

func evaluateRuntimePolicy(contextData map[string]interface{}, messages []normalizedMessage) runtimePolicyResult {
	result := runtimePolicyResult{
		Reasons:    []string{},
		GuardTags:  []string{},
		Categories: []string{},
	}
	if contextData == nil {
		contextData = map[string]interface{}{}
	}

	allowedTools := toLowerSet(stringSliceFromAny(firstContextValue(contextData, "allowed_tools", "allowedTools")))
	requestedTools := toLowerSet(stringSliceFromAny(firstContextValue(contextData, "requested_tools", "requestedTools", "tools", "tool", "tool_name", "toolName")))
	if len(requestedTools) > 0 && len(allowedTools) > 0 {
		unauthorized := make([]string, 0, len(requestedTools))
		for tool := range requestedTools {
			if _, ok := allowedTools[tool]; !ok {
				unauthorized = append(unauthorized, tool)
			}
		}
		if len(unauthorized) > 0 {
			result.Block = true
			result.Reasons = append(result.Reasons, "Runtime policy blocked unauthorized tool request: "+strings.Join(unauthorized, ", "))
			result.GuardTags = append(result.GuardTags, "runtime_policy:unauthorized_tool")
			result.Categories = append(result.Categories, "tool_abuse")
		}
	}

	allowExternal := true
	if flag, ok := firstContextValue(contextData, "allow_external_network", "allowExternalNetwork").(bool); ok {
		allowExternal = flag
	}

	messageText := strings.ToLower(buildDetectionInput(messages))
	if !allowExternal && (strings.Contains(messageText, "http://") || strings.Contains(messageText, "https://")) {
		if strings.Contains(messageText, "send") || strings.Contains(messageText, "post") || strings.Contains(messageText, "upload") || strings.Contains(messageText, "webhook") {
			result.Block = true
			result.Reasons = append(result.Reasons, "Runtime policy blocked external data egress request.")
			result.GuardTags = append(result.GuardTags, "runtime_policy:external_egress_block")
			result.Categories = append(result.Categories, "data_exfiltration")
		}
	}

	for _, pattern := range emergencyJailbreakPatterns {
		if pattern.MatchString(messageText) {
			result.Review = true
			result.Reasons = append(result.Reasons, "Behavioral runtime check flagged jailbreak semantics.")
			result.GuardTags = append(result.GuardTags, "runtime_policy:jailbreak_semantic")
			result.Categories = append(result.Categories, "semantic_jailbreak")
			break
		}
	}

	for _, pattern := range emergencySecretPatterns {
		if pattern.MatchString(messageText) {
			result.Review = true
			result.Reasons = append(result.Reasons, "Behavioral runtime check flagged credential-seeking intent.")
			result.GuardTags = append(result.GuardTags, "runtime_policy:credential_intent")
			result.Categories = append(result.Categories, "credential_abuse")
			if credentialExfiltrationIntentPattern.MatchString(messageText) {
				result.Block = true
			}
			break
		}
	}

	for _, pattern := range emergencyMalwarePatterns {
		if pattern.MatchString(messageText) {
			result.Review = true
			result.Reasons = append(result.Reasons, "Behavioral runtime check flagged malware implementation intent.")
			result.GuardTags = append(result.GuardTags, "runtime_policy:malware_intent")
			result.Categories = append(result.Categories, "malware_abuse")
			if malwareImplementationIntentPattern.MatchString(messageText) {
				result.Block = true
			}
			break
		}
	}

	result.Reasons = uniqueStrings(result.Reasons)
	result.GuardTags = uniqueStrings(result.GuardTags)
	result.Categories = uniqueStrings(result.Categories)
	if result.Block {
		result.Review = true
	}
	return result
}

func applyRuntimePolicyToUnified(response UnifiedResponse, runtime runtimePolicyResult) UnifiedResponse {
	if !runtime.Block && !runtime.Review {
		return response
	}
	response.Reasons = uniqueStrings(append(response.Reasons, runtime.Reasons...))

	if response.Detections.Semantic.Status != "success" {
		response.Detections.Semantic = ServiceDetection{
			Status:     "success",
			Block:      false,
			RiskLevel:  "low",
			Confidence: 0.75,
			Categories: []string{},
			Reasons:    []string{},
			LatencyMS:  0,
		}
	}
	response.Detections.Semantic.Categories = uniqueStrings(append(response.Detections.Semantic.Categories, runtime.Categories...))
	response.Detections.Semantic.Reasons = uniqueStrings(append(response.Detections.Semantic.Reasons, runtime.Reasons...))

	if runtime.Block {
		response.Block = true
		response.Decision = "block"
		response.RiskLevel = highestRiskLevel(response.RiskLevel, "high")
		response.Confidence = maxFloat(response.Confidence, 0.90)
		response.Detections.Semantic.Block = true
		response.Detections.Semantic.RiskLevel = highestRiskLevel(response.Detections.Semantic.RiskLevel, "high")
		return response
	}

	if runtime.Review && response.Decision == "allow" {
		response.Decision = "review"
		response.RiskLevel = highestRiskLevel(response.RiskLevel, "medium")
		response.Confidence = maxFloat(response.Confidence, 0.70)
		response.Detections.Semantic.RiskLevel = highestRiskLevel(response.Detections.Semantic.RiskLevel, "medium")
	}
	return response
}

func firstContextValue(contextData map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		if value, ok := contextData[key]; ok {
			return value
		}
	}
	return nil
}

func stringSliceFromAny(value interface{}) []string {
	switch typed := value.(type) {
	case []string:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			trimmed := strings.TrimSpace(item)
			if trimmed != "" {
				out = append(out, trimmed)
			}
		}
		return out
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			str, ok := item.(string)
			if !ok {
				continue
			}
			trimmed := strings.TrimSpace(str)
			if trimmed != "" {
				out = append(out, trimmed)
			}
		}
		return out
	case string:
		parts := strings.Split(typed, ",")
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				out = append(out, trimmed)
			}
		}
		return out
	default:
		return []string{}
	}
}

func toLowerSet(items []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, item := range items {
		normalized := strings.ToLower(strings.TrimSpace(item))
		if normalized == "" {
			continue
		}
		out[normalized] = struct{}{}
	}
	return out
}

func cloneContext(ctx map[string]interface{}) map[string]interface{} {
	clone := make(map[string]interface{}, len(ctx))
	for key, value := range ctx {
		clone[key] = value
	}
	return clone
}

func resolveProvider(explicitProvider, model string, contextData map[string]interface{}) (string, error) {
	candidates := []string{
		strings.ToLower(strings.TrimSpace(explicitProvider)),
	}
	if contextProvider, ok := contextData["provider"].(string); ok {
		candidates = append(candidates, strings.ToLower(strings.TrimSpace(contextProvider)))
	}

	for _, candidate := range candidates {
		switch candidate {
		case "", "auto":
		case defaultProviderOpenAI, defaultProviderAnthrop, defaultProviderGemini:
			return candidate, nil
		default:
			return "", fmt.Errorf("unsupported provider: %s", candidate)
		}
	}

	lowerModel := strings.ToLower(strings.TrimSpace(model))
	switch {
	case strings.HasPrefix(lowerModel, "claude"):
		return defaultProviderAnthrop, nil
	case strings.HasPrefix(lowerModel, "gemini"):
		return defaultProviderGemini, nil
	case strings.HasPrefix(lowerModel, "gpt"), strings.HasPrefix(lowerModel, "o1"), strings.HasPrefix(lowerModel, "o3"):
		return defaultProviderOpenAI, nil
	default:
		return "", fmt.Errorf("unable to infer provider from model; set provider to openai, anthropic, or gemini")
	}
}

func (g *Gateway) requestChatCompletion(parentCtx context.Context, provider string, req ChatCompletionRequest, messages []normalizedMessage, requestID string) (ChatCompletionResponse, error) {
	callCtx, cancel := context.WithTimeout(parentCtx, g.cfg.LLMTimeout)
	defer cancel()

	switch provider {
	case defaultProviderOpenAI:
		return g.callOpenAI(callCtx, req, messages, requestID)
	case defaultProviderAnthrop:
		return g.callAnthropic(callCtx, req, messages, requestID)
	case defaultProviderGemini:
		return g.callGemini(callCtx, req, messages, requestID)
	default:
		return ChatCompletionResponse{}, fmt.Errorf("unsupported provider: %s", provider)
	}
}

func (g *Gateway) callOpenAI(ctx context.Context, req ChatCompletionRequest, messages []normalizedMessage, requestID string) (ChatCompletionResponse, error) {
	if g.cfg.OpenAIAPIKey == "" {
		return ChatCompletionResponse{}, fmt.Errorf("openai api key is not configured")
	}

	payloadMessages := make([]map[string]string, 0, len(messages))
	for _, message := range messages {
		payloadMessages = append(payloadMessages, map[string]string{
			"role":    message.Role,
			"content": message.Content,
		})
	}

	payload := map[string]interface{}{
		"model":    req.Model,
		"messages": payloadMessages,
		"stream":   false,
	}
	if req.Temperature != nil {
		payload["temperature"] = *req.Temperature
	}
	if req.MaxTokens != nil {
		payload["max_tokens"] = *req.MaxTokens
	}

	var response ChatCompletionResponse
	if err := g.postJSON(ctx, g.cfg.OpenAIURL, map[string]string{
		"Authorization":     "Bearer " + g.cfg.OpenAIAPIKey,
		"Content-Type":      "application/json",
		requestIDHeaderName: requestID,
	}, payload, &response); err != nil {
		return ChatCompletionResponse{}, err
	}

	if response.Object == "" {
		response.Object = "chat.completion"
	}
	if response.Model == "" {
		response.Model = req.Model
	}
	return response, nil
}

func (g *Gateway) callAnthropic(ctx context.Context, req ChatCompletionRequest, messages []normalizedMessage, requestID string) (ChatCompletionResponse, error) {
	if g.cfg.AnthropicAPIKey == "" {
		return ChatCompletionResponse{}, fmt.Errorf("anthropic api key is not configured")
	}

	systemPrompt := make([]string, 0, 1)
	anthropicMessages := make([]map[string]string, 0, len(messages))
	for _, message := range messages {
		if message.Role == "system" {
			systemPrompt = append(systemPrompt, message.Content)
			continue
		}
		role := message.Role
		if role != "user" && role != "assistant" {
			role = "user"
		}
		anthropicMessages = append(anthropicMessages, map[string]string{
			"role":    role,
			"content": message.Content,
		})
	}

	maxTokens := 1024
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		maxTokens = *req.MaxTokens
	}

	payload := map[string]interface{}{
		"model":      req.Model,
		"max_tokens": maxTokens,
		"messages":   anthropicMessages,
	}
	if len(systemPrompt) > 0 {
		payload["system"] = strings.Join(systemPrompt, "\n")
	}
	if req.Temperature != nil {
		payload["temperature"] = *req.Temperature
	}

	var response struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}

	if err := g.postJSON(ctx, g.cfg.AnthropicURL, map[string]string{
		"Content-Type":      "application/json",
		"X-API-Key":         g.cfg.AnthropicAPIKey,
		"Anthropic-Version": "2023-06-01",
		requestIDHeaderName: requestID,
	}, payload, &response); err != nil {
		return ChatCompletionResponse{}, err
	}

	textParts := make([]string, 0, len(response.Content))
	for _, part := range response.Content {
		if strings.TrimSpace(part.Text) != "" {
			textParts = append(textParts, strings.TrimSpace(part.Text))
		}
	}
	assistantContent := strings.Join(textParts, "\n")
	if assistantContent == "" {
		return ChatCompletionResponse{}, fmt.Errorf("anthropic returned empty completion")
	}

	return ChatCompletionResponse{
		ID:      response.ID,
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   response.Model,
		Choices: []ChatChoice{
			{
				Index: 0,
				Message: ChatChoiceMessage{
					Role:    "assistant",
					Content: assistantContent,
				},
				FinishReason: normalizeFinishReason(response.StopReason),
			},
		},
		Usage: ChatUsage{
			PromptTokens:     response.Usage.InputTokens,
			CompletionTokens: response.Usage.OutputTokens,
			TotalTokens:      response.Usage.InputTokens + response.Usage.OutputTokens,
		},
	}, nil
}

func (g *Gateway) callGemini(ctx context.Context, req ChatCompletionRequest, messages []normalizedMessage, requestID string) (ChatCompletionResponse, error) {
	if g.cfg.GeminiAPIKey == "" {
		return ChatCompletionResponse{}, fmt.Errorf("gemini api key is not configured")
	}

	systemPrompt := make([]string, 0, 1)
	contents := make([]map[string]interface{}, 0, len(messages))
	for _, message := range messages {
		if message.Role == "system" {
			systemPrompt = append(systemPrompt, message.Content)
			continue
		}
		role := "user"
		if message.Role == "assistant" {
			role = "model"
		}
		contents = append(contents, map[string]interface{}{
			"role": role,
			"parts": []map[string]string{
				{"text": message.Content},
			},
		})
	}

	payload := map[string]interface{}{
		"contents": contents,
	}
	if len(systemPrompt) > 0 {
		payload["systemInstruction"] = map[string]interface{}{
			"parts": []map[string]string{
				{"text": strings.Join(systemPrompt, "\n")},
			},
		}
	}
	generationConfig := map[string]interface{}{}
	if req.Temperature != nil {
		generationConfig["temperature"] = *req.Temperature
	}
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		generationConfig["maxOutputTokens"] = *req.MaxTokens
	}
	if len(generationConfig) > 0 {
		payload["generationConfig"] = generationConfig
	}

	endpoint := strings.TrimRight(g.cfg.GeminiBaseURL, "/") + "/" + url.PathEscape(req.Model) + ":generateContent?key=" + url.QueryEscape(g.cfg.GeminiAPIKey)
	var response struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
			FinishReason string `json:"finishReason"`
		} `json:"candidates"`
		Usage struct {
			PromptTokenCount     int `json:"promptTokenCount"`
			CandidatesTokenCount int `json:"candidatesTokenCount"`
			TotalTokenCount      int `json:"totalTokenCount"`
		} `json:"usageMetadata"`
	}
	if err := g.postJSON(ctx, endpoint, map[string]string{
		"Content-Type":      "application/json",
		requestIDHeaderName: requestID,
	}, payload, &response); err != nil {
		return ChatCompletionResponse{}, err
	}
	if len(response.Candidates) == 0 {
		return ChatCompletionResponse{}, fmt.Errorf("gemini returned no candidates")
	}

	textParts := make([]string, 0, len(response.Candidates[0].Content.Parts))
	for _, part := range response.Candidates[0].Content.Parts {
		if strings.TrimSpace(part.Text) != "" {
			textParts = append(textParts, strings.TrimSpace(part.Text))
		}
	}
	assistantContent := strings.Join(textParts, "\n")
	if assistantContent == "" {
		return ChatCompletionResponse{}, fmt.Errorf("gemini returned empty completion")
	}

	totalTokens := response.Usage.TotalTokenCount
	if totalTokens == 0 {
		totalTokens = response.Usage.PromptTokenCount + response.Usage.CandidatesTokenCount
	}

	return ChatCompletionResponse{
		ID:      "gemini-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   req.Model,
		Choices: []ChatChoice{
			{
				Index: 0,
				Message: ChatChoiceMessage{
					Role:    "assistant",
					Content: assistantContent,
				},
				FinishReason: normalizeFinishReason(response.Candidates[0].FinishReason),
			},
		},
		Usage: ChatUsage{
			PromptTokens:     response.Usage.PromptTokenCount,
			CompletionTokens: response.Usage.CandidatesTokenCount,
			TotalTokens:      totalTokens,
		},
	}, nil
}

func (g *Gateway) postJSON(ctx context.Context, endpoint string, headers map[string]string, payload interface{}, output interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode upstream payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to build upstream request: %w", err)
	}
	for key, value := range headers {
		if strings.TrimSpace(value) == "" {
			continue
		}
		req.Header.Set(key, value)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read upstream response: %w", err)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("upstream status %d", resp.StatusCode)
	}
	if err := json.Unmarshal(respBody, output); err != nil {
		return fmt.Errorf("invalid upstream response: %w", err)
	}
	return nil
}

func normalizeFinishReason(raw string) string {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	switch normalized {
	case "", "stop", "end_turn":
		return "stop"
	case "max_tokens", "max_output_tokens":
		return "length"
	default:
		return normalized
	}
}
