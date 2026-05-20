from typing import Optional

from nemoguardrails.actions import action

from policy_engine import assess_prompt_policy


@action(is_system_action=True)
async def is_prompt_policy_blocked(context: Optional[dict] = None) -> bool:
    user_message = ((context or {}).get("last_user_message", "") or "").strip()
    if not user_message:
        return False
    assessment = assess_prompt_policy(user_message)
    return assessment.block
