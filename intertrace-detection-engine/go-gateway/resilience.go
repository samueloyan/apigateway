package main

import (
	"regexp"
	"strings"
)

var emergencyJailbreakPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bignore\s+previous\s+instructions\b`),
	regexp.MustCompile(`(?i)\breveal\s+(?:your|the)\s+instructions\b`),
	regexp.MustCompile(`(?i)\bsystem\s+prompt\b`),
	regexp.MustCompile(`(?i)\b(jailbreak|bypass|override)\b`),
	regexp.MustCompile(`(?i)\b(?:disable|remove)\s+(?:safety|guardrails?)\b`),
	regexp.MustCompile(`(?i)\bact\s+as\s+dan\b`),
	regexp.MustCompile(`(?i)\bdeveloper\s+mode\b`),
}

var emergencySecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(api(?:[_\s-]?keys?)?|access(?:[_\s-]?tokens?)?|bearer(?:\s+tokens?)?|passwords?|secrets?|credentials?)\b`),
	regexp.MustCompile(`(?i)\b(aws|gcp|azure)\b.{0,20}\b(keys?|tokens?|secrets?)\b`),
}

var emergencyMalwarePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(reverse\s+shell|bind\s+shell|backdoor|command\s+and\s+control|c2)\b`),
	regexp.MustCompile(`(?i)\b(remote\s+code\s+execution|rce|exploit\s+payload)\b`),
}

var credentialExfiltrationIntentPattern = regexp.MustCompile(
	`(?i)\b(reveal|show|dump|exfiltrate|forward|send|share|provide|give|disclose|leak|expose|print|extract)\b.{0,40}\b(api(?:[_\s-]?keys?)?|access(?:[_\s-]?tokens?)?|bearer(?:\s+tokens?)?|passwords?|secrets?|credentials?)\b|\b(api(?:[_\s-]?keys?)?|access(?:[_\s-]?tokens?)?|bearer(?:\s+tokens?)?|passwords?|secrets?|credentials?)\b.{0,40}\b(reveal|show|dump|exfiltrate|forward|send|share|provide|give|disclose|leak|expose|print|extract)\b`,
)

var malwareImplementationIntentPattern = regexp.MustCompile(
	`(?i)\b(write|generate|create|build|provide)\b.{0,45}\b(code|script|payload)\b.{0,60}\b(reverse\s+shell|bind\s+shell|backdoor|command\s+and\s+control|c2|rce|remote\s+code\s+execution)\b|\b(reverse\s+shell|bind\s+shell|backdoor)\b.{0,60}\b(execute\s+commands?\s+from\s+the\s+attacker|connect\s+back)\b`,
)

type emergencyAssessment struct {
	block      bool
	riskLevel  string
	reasons    []string
	categories []string
}

func (g *Gateway) applyDegradedFallback(input string, response UnifiedResponse) UnifiedResponse {
	if !g.cfg.EnableDegradedFallback || !isFailClosedBlock(response) {
		return response
	}

	assessment := emergencyAssessInput(input)
	reasons := []string{degradedFallbackReason}
	reasons = append(reasons, assessment.reasons...)
	response.Reasons = uniqueStrings(reasons)

	if assessment.block {
		response.Block = true
		response.Decision = "block"
		response.RiskLevel = highestRiskLevel(response.RiskLevel, assessment.riskLevel, "high")
		response.Confidence = maxFloat(response.Confidence, 0.95)
		return response
	}

	response.Block = false
	response.Decision = g.cfg.DegradedSafeDecision
	if response.Decision == "allow" {
		response.RiskLevel = highestRiskLevel(response.RiskLevel, "low")
		response.Confidence = maxFloat(response.Confidence, 0.55)
		return response
	}
	response.RiskLevel = highestRiskLevel(response.RiskLevel, "medium")
	response.Confidence = maxFloat(response.Confidence, 0.65)
	return response
}

func emergencyAssessInput(input string) emergencyAssessment {
	text := strings.TrimSpace(input)
	if text == "" {
		return emergencyAssessment{
			block:      false,
			riskLevel:  "medium",
			reasons:    []string{"Emergency classifier could not assess empty input while detectors were unavailable."},
			categories: []string{"degraded_unknown"},
		}
	}

	reasons := []string{}
	categories := []string{}
	block := false
	risk := "safe"

	for _, pattern := range emergencyJailbreakPatterns {
		if pattern.MatchString(text) {
			block = true
			risk = highestRiskLevel(risk, "high")
			reasons = append(reasons, "Emergency classifier detected jailbreak or policy bypass indicators.")
			categories = append(categories, "prompt_injection")
			break
		}
	}

	for _, pattern := range emergencySecretPatterns {
		if pattern.MatchString(text) {
			risk = highestRiskLevel(risk, "medium")
			reasons = append(reasons, "Emergency classifier detected credential or secret access indicators.")
			categories = append(categories, "credential_request")
			if credentialExfiltrationIntentPattern.MatchString(text) {
				block = true
				risk = highestRiskLevel(risk, "high")
			}
			break
		}
	}

	for _, pattern := range emergencyMalwarePatterns {
		if pattern.MatchString(text) {
			risk = highestRiskLevel(risk, "high")
			reasons = append(reasons, "Emergency classifier detected malware or reverse-shell indicators.")
			categories = append(categories, "malware")
			if malwareImplementationIntentPattern.MatchString(text) {
				block = true
				risk = highestRiskLevel(risk, "critical")
			}
			break
		}
	}

	if emailPattern.MatchString(text) || phonePattern.MatchString(text) || ssnPattern.MatchString(text) || cardPattern.MatchString(text) {
		risk = highestRiskLevel(risk, "medium")
		reasons = append(reasons, "Emergency classifier detected potential sensitive data patterns.")
		categories = append(categories, "pii")
	}

	if len(reasons) == 0 {
		reasons = append(reasons, "Emergency classifier found no high-risk indicators while detectors were unavailable.")
	}

	return emergencyAssessment{
		block:      block,
		riskLevel:  risk,
		reasons:    uniqueStrings(reasons),
		categories: uniqueStrings(categories),
	}
}

func isFailClosedBlock(response UnifiedResponse) bool {
	if !response.Block || response.Decision != "block" {
		return false
	}
	for _, reason := range response.Reasons {
		if strings.TrimSpace(reason) == failClosedReason {
			return true
		}
	}
	return false
}
