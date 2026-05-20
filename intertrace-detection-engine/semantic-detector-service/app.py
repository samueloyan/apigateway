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


class DetectionResult(BaseModel):
    block: bool
    risk_level: str
    confidence: float
    categories: list[str]
    reasons: list[str]


class SemanticRiskDetector:
    high_risk_patterns = [
        ("semantic_jailbreak", re.compile(r"\bignore\s+(all\s+)?(previous|prior)\s+instructions?\b", re.IGNORECASE),
         "Prompt attempts to override prior instructions."),
        ("semantic_jailbreak", re.compile(r"\b(reveal|leak|show)\s+(the\s+)?(system prompt|hidden prompt|instructions)\b", re.IGNORECASE),
         "Prompt requests protected system instructions."),
        ("adversarial_prompt", re.compile(r"\b(jailbreak|bypass|override|disable)\b.{0,30}\b(guard|policy|safety)\b", re.IGNORECASE),
         "Prompt appears to target safety controls."),
        ("credential_exfiltration", re.compile(r"\b(api[_-]?key|token|password|secret)\b.{0,25}\b(reveal|dump|extract|print)\b", re.IGNORECASE),
         "Prompt appears to request sensitive credential exfiltration."),
    ]

    medium_risk_patterns = [
        ("social_engineering", re.compile(r"\bpretend\s+to\s+be\b|\bimpersonate\b", re.IGNORECASE),
         "Prompt includes impersonation-style social engineering intent."),
        ("prompt_manipulation", re.compile(r"\broleplay\b.{0,30}\bwithout\s+restrictions\b", re.IGNORECASE),
         "Prompt includes roleplay to evade normal safeguards."),
        ("adversarial_prompt", re.compile(r"\bprompt injection\b|\badversarial prompt\b", re.IGNORECASE),
         "Prompt references adversarial prompt-injection context."),
    ]

    def detect(self, text: str) -> DetectionResult:
        categories: set[str] = set()
        reasons: list[str] = []

        for category, pattern, reason in self.high_risk_patterns:
            if pattern.search(text):
                categories.add(category)
                reasons.append(reason)

        if categories:
            return DetectionResult(
                block=True,
                risk_level="high",
                confidence=0.9,
                categories=sorted(categories),
                reasons=reasons,
            )

        for category, pattern, reason in self.medium_risk_patterns:
            if pattern.search(text):
                categories.add(category)
                reasons.append(reason)

        if categories:
            return DetectionResult(
                block=False,
                risk_level="medium",
                confidence=0.78,
                categories=sorted(categories),
                reasons=reasons,
            )

        return DetectionResult(
            block=False,
            risk_level="safe",
            confidence=0.96,
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


app = FastAPI(title="Semantic Detection Service", version="0.1.0")
detector = SemanticRiskDetector()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "semantic-detector"}


@app.post("/detect", response_model=DetectionResponse)
def detect(payload: DetectionRequest) -> DetectionResponse:
    start = time.perf_counter()

    delay_ms = parse_delay_ms(payload.context)
    if delay_ms > 0:
        time.sleep(delay_ms / 1000)

    result = detector.detect(payload.input)
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
