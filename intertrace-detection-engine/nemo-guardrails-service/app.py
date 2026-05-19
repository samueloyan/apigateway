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


class StubNemoGuardrailDetector(BaseGuardrailDetector):
    # Keep phrase mapping explicit so real NeMo guardrails can
    # replace only this detector implementation later.
    trigger_map = {
        "ignore previous instructions": "prompt_injection",
        "bypass": "policy_violation",
        "jailbreak": "jailbreak",
        "developer mode": "jailbreak",
        "system prompt": "prompt_injection",
        "reveal your instructions": "prompt_injection",
        "disable safety": "policy_violation",
        "act as dan": "jailbreak",
        "override policy": "policy_violation",
    }

    def detect(self, text: str, context: dict[str, Any]) -> DetectorResult:
        lowered = text.lower()
        categories: set[str] = set()
        reasons: list[str] = []

        for phrase, category in self.trigger_map.items():
            if phrase in lowered:
                categories.add(category)
                reasons.append(f"Detected suspicious guardrail phrase: '{phrase}'")

        if categories:
            return DetectorResult(
                block=True,
                risk_level="high",
                confidence=0.91,
                categories=sorted(categories),
                reasons=reasons or ["The prompt attempts to override system instructions."],
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
detector: BaseGuardrailDetector = StubNemoGuardrailDetector()


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
