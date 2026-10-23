import asyncio
import logging
from typing import Optional
from server.store.db import (
    get_db,
    now,
    parse_iso,
    update_delegation_status,
    log_audit_event,
    create_pending_briefing,
    fast_forward_delegation_time,
    purge_delegation_payload,
)
from server.notify.webhook import send_escalation_webhook

logger = logging.getLogger(__name__)

class DelegationScheduler:
    def __init__(self, interval_seconds: float = 2.0):
        self.interval_seconds = interval_seconds
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("DelegationScheduler background engine started.")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("DelegationScheduler background engine stopped.")

    async def _run_loop(self):
        while self._running:
            try:
                await self.tick()
            except Exception as e:
                logger.error(f"Error in scheduler tick: {e}", exc_info=True)
            await asyncio.sleep(self.interval_seconds)

    async def tick(self):
        """
        Executes one evaluation cycle across all active delegations.
        P0-6: Each row is wrapped in try/except so one bad row never stops others.
        """
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM delegations WHERE status = 'active'")
        active_delegations = [dict(r) for r in cur.fetchall()]
        conn.close()

        current_time = now()

        for d in active_delegations:
            try:
                self._process_delegation(d, current_time)
            except Exception as e:
                logger.error(
                    f"Scheduler error processing delegation {d.get('id', '?')}: {e}",
                    exc_info=True,
                )

    def _process_delegation(self, d: dict, current_time) -> None:
        """P0-6: Wrapped per-row processing so exceptions don't abort the scan."""
        expires_at_str = d.get("expires_at")
        if not expires_at_str:
            return

        expires_at = parse_iso(expires_at_str)
        if current_time < expires_at:
            return

        delegation_id = d["id"]
        recipient = d["recipient"]
        topic_desc = d["topic_desc"]
        uses = d["uses"]
        escalate_to = d.get("escalate_to")

        logger.info(f"Delegation {delegation_id} expired (uses: {uses}). Transitioning state.")
        update_delegation_status(delegation_id, "expired")
        purge_delegation_payload(delegation_id)  # F0: ephemeral purge on expiry

        if uses == 0:
            # Deadline missed without any check-in — escalate
            log_audit_event(
                actor="system",
                action="escalated",
                delegation_id=delegation_id,
                note=f"Deadline missed with 0 uses. Multi-channel escalation triggered for {recipient}.",
            )
            # Queue high-priority briefing for User B's next session
            briefing_msg = (
                f"Priority Briefing: An authorized delegation regarding '{topic_desc}' "
                f"expired before you checked in. Please connect with your administrator."
            )
            create_pending_briefing(
                delegation_id=delegation_id,
                recipient=recipient,
                message=briefing_msg,
                priority="high",
            )
            # Fire multi-channel escalation: Webhook + AWS Lambda serverless execution
            asyncio.create_task(
                send_escalation_webhook(
                    delegation_id=delegation_id,
                    recipient=recipient,
                    topic_desc=topic_desc,
                    target_url=escalate_to,
                )
            )
            try:
                from server.aws.lambda_escalation import dispatch_lambda_escalation
                asyncio.create_task(
                    dispatch_lambda_escalation(
                        delegation_id=delegation_id,
                        recipient=recipient,
                        topic_desc=topic_desc,
                        escalate_to=escalate_to,
                    )
                )
            except Exception:
                pass
        else:
            log_audit_event(
                actor="system",
                action="expired",
                delegation_id=delegation_id,
                note=f"Delegation expired after {uses} use(s). Payload purged.",
            )

        log_audit_event(
            actor="system",
            action="purged",
            delegation_id=delegation_id,
            note="Payload purged on expiration. Secret self-destructed.",
        )

    async def fast_forward(self, delegation_id: str) -> bool:
        """
        Sets expiration to 1 second in the past and immediately executes a scheduler tick.
        Runs through the exact production code path (DEMO_MODE only).
        """
        res = fast_forward_delegation_time(delegation_id, seconds_in_past=1)
        if res:
            await self.tick()
            return True
        return False

# Global singleton scheduler instance
scheduler = DelegationScheduler()
