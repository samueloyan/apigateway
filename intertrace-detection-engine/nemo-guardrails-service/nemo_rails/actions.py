from typing import Any, Optional

from nemoguardrails.actions import action

from policy_engine import assess_prompt_policy


@action(is_system_action=True)
async def is_prompt_policy_blocked(context: Optional[dict] = None, events: Optional[list[dict[str, Any]]] = None) -> bool:
    user_message = ""
    context_data = context or {}
    for key in ("last_user_message", "user_message", "input", "prompt", "last_message"):
        value = context_data.get(key)
        if isinstance(value, str) and value.strip():
            user_message = value.strip()
            break

    if not user_message and events:
        for event in reversed(events):
            if not isinstance(event, dict):
                continue
            if str(event.get("type", "")).strip() == "UtteranceUserActionFinished":
                value = event.get("final_transcript") or event.get("content") or event.get("text")
                if isinstance(value, str) and value.strip():
                    user_message = value.strip()
                    break

    if not user_message:
        return False
    assessment = assess_prompt_policy(user_message)
    return assessment.block
