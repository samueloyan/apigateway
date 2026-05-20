import re
from dataclasses import dataclass


@dataclass
class PolicyAssessment:
    block: bool
    risk_level: str
    confidence: float
    categories: list[str]
    reasons: list[str]


def highest_risk_level(*levels: str) -> str:
    order = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    highest = "safe"
    for level in levels:
        normalized = normalize_risk_level(level)
        if order[normalized] > order[highest]:
            highest = normalized
    return highest


def normalize_risk_level(level: str) -> str:
    normalized = (level or "").strip().lower()
    if normalized in {"safe", "low", "medium", "high", "critical"}:
        return normalized
    return "safe"


HIGH_RISK_RULES: list[tuple[str, re.Pattern[str], str, float]] = [
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
    (
        "malware",
        re.compile(
            r"\b(write|generate|create|build|provide)\b.{0,45}\b(code|script|payload)\b.{0,60}\b"
            r"(reverse\s+shell|bind\s+shell|backdoor|c2|command\s+and\s+control|rce|remote\s+code\s+execution)\b|"
            r"\b(reverse\s+shell|bind\s+shell|backdoor)\b.{0,60}\b(execute\s+commands?\s+from\s+the\s+attacker|connect\s+back)\b",
            re.IGNORECASE,
        ),
        "Prompt appears to request malware or reverse-shell implementation guidance.",
        0.99,
    ),
]

MEDIUM_RISK_RULES: list[tuple[str, re.Pattern[str], str, float]] = [
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


def assess_prompt_policy(text: str) -> PolicyAssessment:
    normalized = text.strip()
    if not normalized:
        return PolicyAssessment(
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

    for category, pattern, reason, score in HIGH_RISK_RULES:
        if pattern.search(normalized):
            categories.add(category)
            reasons.append(reason)
            confidence = max(confidence, score)
            block = True

    if not block:
        for category, pattern, reason, score in MEDIUM_RISK_RULES:
            if pattern.search(normalized):
                categories.add(category)
                reasons.append(reason)
                confidence = max(confidence, score)

    if block:
        return PolicyAssessment(
            block=True,
            risk_level="high",
            confidence=max(confidence, 0.90),
            categories=sorted(categories),
            reasons=sorted(set(reasons or ["Prompt appears to violate guardrail policies."])),
        )

    if categories:
        return PolicyAssessment(
            block=False,
            risk_level="medium",
            confidence=max(confidence, 0.72),
            categories=sorted(categories),
            reasons=sorted(set(reasons)),
        )

    return PolicyAssessment(
        block=False,
        risk_level="safe",
        confidence=0.98,
        categories=[],
        reasons=[],
    )
