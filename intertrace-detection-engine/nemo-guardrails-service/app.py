import os
import time
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from policy_engine import PolicyAssessment, assess_prompt_policy, highest_risk_level

try:
    from nemoguardrails import LLMRails, RailsConfig
except Exception:  # pragma: no cover - handled via runtime fallback.
    LLMRails = None  # type: ignore[assignment]
    RailsConfig = None  # type: ignore[assignment]


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


class NemoGuardrailsRuntime:
    def __init__(self, enable_guardrails: bool, config_path: str) -> None:
        self.enabled = enable_guardrails
        self.ready = False
        self.last_error = ""
        self._rails = None
        if not enable_guardrails:
            return
        if LLMRails is None or RailsConfig is None:
            self.last_error = "nemoguardrails package is unavailable"
            return
        try:
            resolved_path = config_path
            if not os.path.isabs(resolved_path):
                resolved_path = os.path.join(os.path.dirname(__file__), resolved_path)
            cfg = RailsConfig.from_path(resolved_path)
            self._rails = LLMRails(cfg)
            self.ready = True
        except Exception as exc:  # pragma: no cover - startup environment dependent.
            self.last_error = str(exc)

    def check_input_block(self, text: str, context: dict[str, Any]) -> tuple[bool, str]:
        if not self.enabled:
            return False, "disabled"
        if not self.ready or self._rails is None:
            return False, "unavailable"
        messages = [{"role": "user", "content": text}]
        if context:
            messages.insert(0, {"role": "context", "content": context})
        try:
            result = self._rails.check(messages)
            status = self._status_name(getattr(result, "status", None))
            return status == "BLOCKED", status.lower()
        except Exception as exc:  # pragma: no cover - runtime environment dependent.
            self.last_error = str(exc)
            return False, "error"

    @staticmethod
    def _status_name(status: Any) -> str:
        if status is None:
            return "PASSED"
        name = getattr(status, "name", "")
        if name:
            return str(name).upper()
        text = str(status).upper()
        if "BLOCKED" in text:
            return "BLOCKED"
        if "MODIFIED" in text:
            return "MODIFIED"
        return "PASSED"


def parse_delay_ms(context: dict[str, Any]) -> int:
    raw_value = context.get("simulate_delay_ms", 0)
    try:
        delay = int(raw_value)
    except (TypeError, ValueError):
        return 0
    return max(0, delay)


def parse_env_bool(key: str, default: bool) -> bool:
    value = os.getenv(key, "").strip().lower()
    if not value:
        return default
    if value in {"1", "true", "yes", "on", "y"}:
        return True
    if value in {"0", "false", "no", "off", "n"}:
        return False
    return default


def to_detector_result(assessment: PolicyAssessment) -> DetectorResult:
    return DetectorResult(
        block=assessment.block,
        risk_level=assessment.risk_level,
        confidence=assessment.confidence,
        categories=assessment.categories,
        reasons=assessment.reasons,
    )


app = FastAPI(title="Nemo Guardrails Detection Service", version="0.1.0")
rails_runtime = NemoGuardrailsRuntime(
    enable_guardrails=parse_env_bool("ENABLE_NEMO_GUARDRAILS", True),
    config_path=os.getenv("NEMO_GUARDRAILS_CONFIG_PATH", "nemo_rails"),
)


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "nemo-guardrails",
        "guardrails_enabled": rails_runtime.enabled,
        "guardrails_ready": rails_runtime.ready,
        "guardrails_error": rails_runtime.last_error,
    }


@app.post("/detect", response_model=DetectionResponse)
def detect(payload: DetectionRequest) -> DetectionResponse:
    start = time.perf_counter()

    delay_ms = parse_delay_ms(payload.context)
    if delay_ms > 0:
        time.sleep(delay_ms / 1000)

    base_assessment = assess_prompt_policy(payload.input)
    rails_blocked, rails_status = rails_runtime.check_input_block(payload.input, payload.context)

    result = to_detector_result(base_assessment)
    if rails_blocked:
        result.block = True
        result.risk_level = highest_risk_level(result.risk_level, "high")
        result.confidence = max(result.confidence, 0.95)
        result.categories = sorted(set(result.categories + ["nemo_guardrails_input"]))
        result.reasons = sorted(set(result.reasons + ["Blocked by NeMo Guardrails input rail policy."]))
    elif rails_status == "error":
        result.categories = sorted(set(result.categories + ["nemo_guardrails_runtime"]))
        result.reasons = sorted(set(result.reasons + ["NeMo Guardrails runtime error; local policy fallback applied."]))

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
