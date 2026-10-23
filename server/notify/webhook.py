import os
import logging
import httpx
from typing import Optional

logger = logging.getLogger(__name__)

# P1-5: Retry config for transient webhook failures
_MAX_RETRIES = 2
_RETRY_BACKOFF_SECS = [1.0, 3.0]  # delays between retries

async def send_escalation_webhook(
    delegation_id: str,
    recipient: str,
    topic_desc: str,
    target_url: Optional[str] = None,
) -> bool:
    """
    Sends an out-of-band escalation notification to Slack, Discord, or generic HTTP webhook.
    P0-5: Falls back to ESCALATION_WEBHOOK_URL env; if unset, silently skips (no httpbin default).
    P1-5: Retries up to _MAX_RETRIES times on transient HTTP errors (5xx, network timeouts).
    """
    url = target_url or os.environ.get("ESCALATION_WEBHOOK_URL", "")
    if not url:
        logger.info("No ESCALATION_WEBHOOK_URL configured — skipping out-of-band dispatch.")
        return False

    # Payload contains NO secret values (P0-3)
    message_text = (
        f"\U0001F6A8 *[Alexa+ Delegation Alert]* Missed Deadline!\n"
        f"Recipient *{recipient}* did not check in for delegation `{delegation_id}`.\n"
        f"Topic: _{topic_desc}_\n"
        f"An urgent briefing has been queued for their next Alexa+ session.\n"
        f"Note: No secret content is included in this notification."
    )

    payload = {
        "text": message_text,
        "content": message_text,       # Discord compatibility
        "delegation_id": delegation_id,
        "recipient": recipient,
        "topic": topic_desc,
        "event": "delegation_expired_unanswered",
    }

    import asyncio
    for attempt in range(_MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(url, json=payload)
                if resp.is_success:
                    logger.info(f"Escalation webhook delivered to {url} (attempt {attempt + 1}), status: {resp.status_code}")
                    return True
                elif resp.status_code >= 500:
                    # Server error — retry
                    logger.warning(f"Escalation webhook returned {resp.status_code} on attempt {attempt + 1}. {'Retrying.' if attempt < _MAX_RETRIES else 'No more retries.'}")
                    if attempt < _MAX_RETRIES:
                        await asyncio.sleep(_RETRY_BACKOFF_SECS[attempt])
                        continue
                else:
                    # 4xx — not retryable
                    logger.error(f"Escalation webhook failed with {resp.status_code} (not retrying): {resp.text[:200]}")
                    return False
        except httpx.TimeoutException as exc:
            logger.warning(f"Escalation webhook timeout (attempt {attempt + 1}/{_MAX_RETRIES + 1}): {exc}")
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(_RETRY_BACKOFF_SECS[attempt])
                continue
        except Exception as exc:
            logger.error(f"Escalation webhook failed (attempt {attempt + 1}): {exc}")
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(_RETRY_BACKOFF_SECS[attempt])
                continue
            break

    logger.error(f"Escalation webhook delivery failed after {_MAX_RETRIES + 1} attempts to {url}")
    return False
