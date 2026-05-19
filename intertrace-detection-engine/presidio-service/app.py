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


class PIIRegexDetector:
    patterns = {
        "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "phone_number": re.compile(r"\b(?:\+?\d{1,2}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"),
        "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
        "api_key": re.compile(r"\b(?:sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35})\b"),
        "bearer_token": re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b"),
    }

    reason_map = {
        "email": "Potential email address detected.",
        "phone_number": "Potential phone number detected.",
        "ssn": "Potential social security number detected.",
        "credit_card": "Potential credit card number detected.",
        "api_key": "Potential API key detected.",
        "bearer_token": "Potential bearer token detected.",
    }

    high_sensitivity_categories = {"ssn", "credit_card", "api_key", "bearer_token"}

    def detect(self, text: str) -> tuple[str, float, list[str], list[str]]:
        categories: set[str] = set()
        reasons: list[str] = []

        for category, pattern in self.patterns.items():
            if pattern.search(text):
                categories.add(category)
                reasons.append(self.reason_map[category])

        sorted_categories = sorted(categories)
        if not sorted_categories:
            return "safe", 0.98, [], []

        if categories.intersection(self.high_sensitivity_categories):
            return "high", 0.9, sorted_categories, reasons

        return "medium", 0.85, sorted_categories, reasons


def parse_delay_ms(context: dict[str, Any]) -> int:
    raw_value = context.get("simulate_delay_ms", 0)
    try:
        delay = int(raw_value)
    except (TypeError, ValueError):
        return 0
    return max(0, delay)


app = FastAPI(title="Presidio Detection Service", version="0.1.0")
detector = PIIRegexDetector()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "presidio-detector"}


@app.post("/detect", response_model=DetectionResponse)
def detect(payload: DetectionRequest) -> DetectionResponse:
    start = time.perf_counter()

    delay_ms = parse_delay_ms(payload.context)
    if delay_ms > 0:
        time.sleep(delay_ms / 1000)

    risk_level, confidence, categories, reasons = detector.detect(payload.input)
    latency_ms = int((time.perf_counter() - start) * 1000)

    return DetectionResponse(
        status="success",
        block=False,
        risk_level=risk_level,
        confidence=confidence,
        categories=categories if categories else [],
        reasons=reasons if reasons else [],
        latency_ms=latency_ms,
    )
