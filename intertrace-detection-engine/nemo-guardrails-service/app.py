import re
import time
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field


class DetectionRequest(BaseModel):
    input: str
    context: dict[str, Any] = Field(default_factory=dict)


class DetectionResponse(BaseModel):
    status: str
    block: bool
    risk_level: str
    confidence: float
    categories: list[str]
    reasons: list[str]
    latency_ms: int


class DetectorResult(BaseModel):
    block: bool
    risk_level: str
    confidence: float
    categories: list[str]
    reasons: list[str]


class BaseGuardrailDetector:
    def detect(self, text: str, context: dict[str, Any]) -> DetectorResult:
        raise NotImplementedError


class NemoPolicyGuardrailDetector(BaseGuardrailDetector):
    """Configurable policy rails detector for high-risk prompt intent."""

    high_risk_rules: list[tuple[str, re.Pattern[str], str, float]] = [
        (
            "prompt_injection",
            re.compile(r"\bignore\s+(all\s+)?(previous|prior)\s+instructions?\b", re.IGNORECASE),
            "Prompt attempts to ignore previous instructions.",
            0.95,
        ),
        (
            "policy_violation",
            re.compile(r"\b(bypass|disable|override)\b.{0,30}\b(guardrails?|policy|safety)\b", re.IGNORECASE),
            "Prompt attempts to bypass safeguards.",
            0.94,
        ),
        (
            "jailbreak",
            re.compile(r"\b(jailbreak|developer\s*mode|dan|do\s+anything\s+now)\b", re.IGNORECASE),
            "Prompt contains jailbreak language.",
            0.93,
        ),
        (
            "prompt_injection",
            re.compile(r"\b(reveal|leak|show)\b.{0,35}\b(system|hidden)\s+prompt\b", re.IGNORECASE),
            "Prompt requests protected prompt content.",
            0.92,
        ),
        (
            "credential_exfiltration",
            re.compile(
                r"\b(reveal|show|dump|extract|print|forward|send|share|provide|give|disclose|leak|expose)\b.{0,45}\b"
                r"(api(?:[_\s-]?keys?)?|access(?:[_\s-]?tokens?)?|bearer(?:\s+tokens?)?|passwords?|secrets?|credentials?)\b|"
                r"\b(api(?:[_\s-]?keys?)?|access(?:[_\s-]?tokens?)?|bearer(?:\s+tokens?)?|passwords?|secrets?|credentials?)\b.{0,45}\b"
                r"(reveal|show|dump|extract|print|forward|send|share|provide|give|disclose|leak|expose)\b",
                re.IGNORECASE,
            ),
            "Prompt appears to request credential or secret exfiltration.",
            0.98,
        ),
        (
            "credential_exfiltration",
            re.compile(r"\b(i am|i'm)\s+the\s+(admin|owner|root|security\s+lead)\b.{0,50}\b(api(?:[_\s-]?keys?)?|secrets?|credentials?)\b", re.IGNORECASE),
            "Prompt claims privileged identity to request credentials.",
            0.92,
        ),
    ]

    medium_risk_rules: list[tuple[str, re.Pattern[str], str, float]] = [
        (
            "social_engineering",
            re.compile(r"\bpretend\s+to\s+be\b|\bimpersonate\b", re.IGNORECASE),
            "Prompt uses social-engineering impersonation language.",
            0.72,
        ),
        (
            "policy_violation",
            re.compile(r"\boverride\s+(the\s+)?polic(y|ies)\b", re.IGNORECASE),
            "Prompt attempts to override policy constraints.",
            0.76,
        ),
        (
            "prompt_injection",
            re.compile(r"\b(system|hidden)\s+prompt\b", re.IGNORECASE),
            "Prompt references protected prompt content.",
            0.74,
        ),
    ]

    def detect(self, text: str, context: dict[str, Any]) -> DetectorResult:
        _ = context
        normalized = text.strip()
        if not normalized:
            return DetectorResult(
                block=False,
                risk_level="safe",
                confidence=0.96,
                categories=[],
                reasons=[],
            )

        categories: set[str] = set()
        reasons: list[str] = []
        confidence = 0.0
        block = False

        for category, pattern, reason, score in self.high_risk_rules:
            if pattern.search(normalized):
                categories.add(category)
                reasons.append(reason)
                confidence = max(confidence, score)
                block = True

        if not block:
            for category, pattern, reason, score in self.medium_risk_rules:
                if pattern.search(normalized):
                    categories.add(category)
                    reasons.append(reason)
                    confidence = max(confidence, score)

        if block:
            return DetectorResult(
                block=True,
                risk_level="high",
                confidence=max(confidence, 0.90),
                categories=sorted(categories),
                reasons=reasons or ["Prompt appears to violate guardrail policies."],
            )

        if categories:
            return DetectorResult(
                block=False,
                risk_level="medium",
                confidence=max(confidence, 0.72),
                categories=sorted(categories),
                reasons=reasons,
            )

        return DetectorResult(
            block=False,
            risk_level="safe",
            confidence=0.98,
            categories=[],
            reasons=[],
        )


def parse_delay_ms(context: dict[str, Any]) -> int:
    raw_value = context.get("simulate_delay_ms", 0)
    try:
        delay = int(raw_value)
    except (TypeError, ValueError):
        return 0
    return max(0, delay)


app = FastAPI(title="Nemo Guardrails Detection Service", version="0.1.0")
detector: BaseGuardrailDetector = NemoPolicyGuardrailDetector()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "nemo-guardrails"}


@app.post("/detect", response_model=DetectionResponse)
def detect(payload: DetectionRequest) -> DetectionResponse:
    start = time.perf_counter()

    delay_ms = parse_delay_ms(payload.context)
    if delay_ms > 0:
        time.sleep(delay_ms / 1000)

    result = detector.detect(payload.input, payload.context)
    latency_ms = int((time.perf_counter() - start) * 1000)

    return DetectionResponse(
        status="success",
        block=result.block,
        risk_level=result.risk_level,
        confidence=result.confidence,
        categories=result.categories,
        reasons=result.reasons,
        latency_ms=latency_ms,
    )
