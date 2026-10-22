import os
import logging
import httpx
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

async def send_escalation_webhook(
    delegation_id: str,
    recipient: str,
    topic_desc: str,
    target_url: Optional[str] = None,
) -> bool:
    """
    Sends an out-of-band escalation notification payload to Slack, Discord, or generic HTTP webhook.
    """
    url = target_url or os.environ.get("ESCALATION_WEBHOOK_URL", "https://httpbin.org/post")
    if not url:
        logger.info("No escalation webhook URL configured; skipping external dispatch.")
        return False

    message_text = (
        f"🚨 *[Alexa+ Delegation Alert]* Missed Deadline!\n"
        f"Recipient *{recipient}* has not checked in for delegation `{delegation_id}`.\n"
        f"Topic: _{topic_desc}_\n"
        f"An urgent briefing has been queued for their next Alexa+ turn."
    )

    payload = {
        "text": message_text,
        "content": message_text,  # Discord compatibility
        "delegation_id": delegation_id,
        "recipient": recipient,
        "topic": topic_desc,
        "event": "delegation_expired_unanswered",
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(url, json=payload)
            logger.info(f"Escalation webhook dispatched to {url}, status code: {resp.status_code}")
            return resp.is_success
    except Exception as exc:
        logger.error(f"Failed to deliver escalation webhook to {url}: {exc}")
        return False
