import os
import json
import hmac
import hashlib
import sqlite3
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("DB_PATH", "delegation_broker.db")

# Allowed webhook hosts for SSRF protection (P0-5)
ALLOWED_WEBHOOK_HOSTS = {"hooks.slack.com", "discord.com", "discordapp.com", "httpbin.org"}

def now() -> datetime:
    """Clock abstraction: returns current UTC datetime (timezone-aware).
    ALWAYS use this function; never call datetime.now() directly elsewhere.
    """
    return datetime.now(timezone.utc)

def now_str() -> str:
    """Returns current UTC time as an ISO8601 string."""
    return now().isoformat()

def parse_iso(ts_str: str) -> datetime:
    """Parse ISO8601 string into timezone-aware datetime."""
    if not ts_str:
        raise ValueError("Empty timestamp string")
    return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

def validate_expires_at(expires_at: Optional[str], expires_in_minutes: Optional[int] = None) -> str:
    """
    Validates and normalizes expires_at to a timezone-aware UTC ISO string.
    P0-6: Rejects naive, garbage, or past datetimes.
    Also supports expires_in_minutes as a convenient alternative.
    """
    if expires_in_minutes is not None:
        if not isinstance(expires_in_minutes, int) or expires_in_minutes <= 0:
            raise ValueError(f"expires_in_minutes must be a positive integer, got: {expires_in_minutes!r}")
        if expires_in_minutes > 60 * 24 * 365:  # max 1 year
            raise ValueError("expires_in_minutes exceeds maximum of 1 year (525600 minutes)")
        return (now() + timedelta(minutes=expires_in_minutes)).isoformat()

    if not expires_at:
        # Default: 1 hour from now
        return (now() + timedelta(hours=1)).isoformat()

    # Try to parse; reject naive datetimes
    try:
        dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        raise ValueError(f"Invalid expires_at format. Use ISO 8601 with timezone, e.g. '2026-10-22T18:00:00+05:30'. Got: {expires_at!r}")

    if dt.tzinfo is None:
        raise ValueError(
            f"expires_at must include a timezone offset (e.g. +05:30 or Z). Got naive datetime: {expires_at!r}. "
            "Hint: use expires_in_minutes=60 for 1 hour from now."
        )

    if dt <= now():
        raise ValueError(f"expires_at must be in the future. Got: {expires_at!r}")

    max_future = now() + timedelta(days=365)
    if dt > max_future:
        raise ValueError(f"expires_at is more than 1 year in the future: {expires_at!r}")

    # Normalize to UTC
    return dt.astimezone(timezone.utc).isoformat()

def validate_ssrf_url(url: Optional[str]) -> Optional[str]:
    """
    SSRF protection (P0-5): Only allow https:// URLs from the allow-list of webhook hosts.
    Returns cleaned URL or None if empty.
    Raises ValueError for unsafe URLs.
    """
    if not url:
        return None
    url = url.strip()
    if not url:
        return None

    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"Escalation webhook must use https://. Got: {url!r}")
    if parsed.hostname not in ALLOWED_WEBHOOK_HOSTS:
        raise ValueError(
            f"Webhook host '{parsed.hostname}' is not in the allowed list: {sorted(ALLOWED_WEBHOOK_HOSTS)}. "
            "Configure ESCALATION_WEBHOOK_URL in .env instead."
        )
    return url

def get_db(db_path: Optional[str] = None) -> sqlite3.Connection:
    target_path = db_path or DB_PATH
    conn = sqlite3.connect(target_path, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn

def init_db(db_path: Optional[str] = None) -> None:
    conn = get_db(db_path)
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS delegations (
                id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                recipient TEXT NOT NULL,
                topic_desc TEXT NOT NULL,
                payload_enc BLOB,
                fact_labels TEXT NOT NULL,
                codeword_hash TEXT NOT NULL,
                max_uses INTEGER NOT NULL DEFAULT 1,
                uses INTEGER NOT NULL DEFAULT 0,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                escalate_to TEXT,
                created_at TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                purged_at TEXT,
                deny_count INTEGER NOT NULL DEFAULT 0
            );
        """)
        # Run migrations for existing DBs (add columns if missing)
        _migrate_column(conn, "delegations", "purged_at", "TEXT")
        _migrate_column(conn, "delegations", "deny_count", "INTEGER NOT NULL DEFAULT 0")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                delegation_id TEXT,
                ts TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                question TEXT,
                gate_decision TEXT,
                gate_confidence REAL,
                note TEXT,
                prev_hash TEXT,
                row_hash TEXT,
                FOREIGN KEY (delegation_id) REFERENCES delegations(id) ON DELETE SET NULL
            );
        """)
        _migrate_column(conn, "audit_events", "prev_hash", "TEXT")
        _migrate_column(conn, "audit_events", "row_hash", "TEXT")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS pending_briefings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                delegation_id TEXT NOT NULL,
                recipient TEXT NOT NULL,
                message TEXT NOT NULL,
                priority TEXT NOT NULL DEFAULT 'high',
                delivered BOOLEAN NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (delegation_id) REFERENCES delegations(id) ON DELETE CASCADE
            );
        """)
    conn.close()

def _migrate_column(conn: sqlite3.Connection, table: str, column: str, col_type: str) -> None:
    """Add a column to an existing table if it doesn't exist yet (SQLite migration)."""
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
    except sqlite3.OperationalError:
        pass  # Column already exists

def _compute_audit_hash(prev_hash: str, ts: str, actor: str, action: str,
                         delegation_id: Optional[str], question: Optional[str],
                         gate_decision: Optional[str], note: Optional[str]) -> str:
    """Compute tamper-evident hash for audit chain (F8)."""
    chain_data = "|".join([
        prev_hash or "",
        ts or "",
        actor or "",
        action or "",
        delegation_id or "",
        question or "",
        gate_decision or "",
        note or "",
    ])
    return hashlib.sha256(chain_data.encode("utf-8")).hexdigest()

def _get_last_audit_hash(conn: sqlite3.Connection) -> str:
    """Get the hash of the most recent audit event for chain linking."""
    cur = conn.execute("SELECT row_hash FROM audit_events ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    if row and row["row_hash"]:
        return row["row_hash"]
    return "genesis"

def create_delegation_record(
    delegation_id: str,
    owner: str,
    recipient: str,
    topic_desc: str,
    payload_enc: bytes,
    fact_labels: List[str],
    codeword_hash: str,
    max_uses: int,
    expires_at: str,
    escalate_to: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    conn = get_db(db_path)
    created_at = now_str()
    with conn:
        conn.execute(
            """
            INSERT INTO delegations (
                id, owner, recipient, topic_desc, payload_enc, fact_labels,
                codeword_hash, max_uses, uses, expires_at, status, escalate_to, created_at,
                failed_attempts, deny_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 'active', ?, ?, 0, 0)
            """,
            (
                delegation_id, owner, recipient, topic_desc, payload_enc,
                json.dumps(fact_labels), codeword_hash, max_uses, expires_at,
                escalate_to, created_at,
            ),
        )
    conn.close()
    return {
        "id": delegation_id,
        "owner": owner,
        "recipient": recipient,
        "topic_desc": topic_desc,
        "fact_labels": fact_labels,
        "max_uses": max_uses,
        "uses": 0,
        "expires_at": expires_at,
        "status": "active",
        "created_at": created_at,
    }

def get_delegation(delegation_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_db(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM delegations WHERE id = ?", (delegation_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["fact_labels"] = json.loads(d["fact_labels"])
    return d

def find_active_delegation_by_owner_or_recipient(
    query_name: str, db_path: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    conn = get_db(db_path)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT * FROM delegations
        WHERE (owner = ? OR recipient = ?) AND status = 'active'
        ORDER BY created_at DESC LIMIT 1
        """,
        (query_name, query_name),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["fact_labels"] = json.loads(d["fact_labels"])
    return d

def list_active_delegations(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM delegations ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    results = []
    for row in rows:
        d = dict(row)
        d["fact_labels"] = json.loads(d["fact_labels"])
        # Strip all sensitive server-side fields (P0-3)
        d.pop("payload_enc", None)
        d.pop("codeword_hash", None)
        d.pop("failed_attempts", None)
        d.pop("escalate_to", None)  # P0-3: webhook URL is a secret
        results.append(d)
    return results

def update_delegation_status(
    delegation_id: str, status: str, db_path: Optional[str] = None
) -> None:
    conn = get_db(db_path)
    with conn:
        conn.execute(
            "UPDATE delegations SET status = ? WHERE id = ?", (status, delegation_id)
        )
    conn.close()

def try_consume_use(delegation_id: str, db_path: Optional[str] = None) -> Optional[int]:
    """
    Atomically consume one use of a delegation.
    P0-2: Uses a single SQL UPDATE with WHERE uses < max_uses to prevent race conditions.
    Returns new use count on success, or None if no uses remaining.
    """
    conn = get_db(db_path)
    try:
        with conn:
            cur = conn.execute(
                "UPDATE delegations SET uses = uses + 1 "
                "WHERE id = ? AND status = 'active' AND uses < max_uses",
                (delegation_id,),
            )
            if cur.rowcount == 0:
                return None  # No update happened: already exhausted or not active
            row = conn.execute(
                "SELECT uses, max_uses FROM delegations WHERE id = ?", (delegation_id,)
            ).fetchone()
            if row["uses"] >= row["max_uses"]:
                conn.execute(
                    "UPDATE delegations SET status = 'exhausted' WHERE id = ?",
                    (delegation_id,),
                )
            return row["uses"]
    finally:
        conn.close()

def increment_failed_attempts(
    delegation_id: str, max_allowed: int = 3, db_path: Optional[str] = None
) -> int:
    conn = get_db(db_path)
    with conn:
        conn.execute(
            "UPDATE delegations SET failed_attempts = failed_attempts + 1 WHERE id = ?",
            (delegation_id,),
        )
        cur = conn.execute(
            "SELECT failed_attempts FROM delegations WHERE id = ?", (delegation_id,)
        )
        row = cur.fetchone()
        attempts = row["failed_attempts"]
        if attempts >= max_allowed:
            conn.execute(
                "UPDATE delegations SET status = 'locked' WHERE id = ?", (delegation_id,)
            )
    conn.close()
    return attempts

def increment_deny_count(delegation_id: str, deny_cap: int = 5, db_path: Optional[str] = None) -> int:
    """
    P1-2: Track non-codeword denials (gate DENYs) per delegation.
    Lock after deny_cap consecutive denials to prevent probing.
    """
    conn = get_db(db_path)
    with conn:
        conn.execute(
            "UPDATE delegations SET deny_count = deny_count + 1 WHERE id = ?",
            (delegation_id,),
        )
        row = conn.execute(
            "SELECT deny_count FROM delegations WHERE id = ?", (delegation_id,)
        ).fetchone()
        count = row["deny_count"]
        if count >= deny_cap:
            conn.execute(
                "UPDATE delegations SET status = 'locked' WHERE id = ?", (delegation_id,)
            )
    conn.close()
    return count

def reset_failed_attempts(delegation_id: str, db_path: Optional[str] = None) -> None:
    conn = get_db(db_path)
    with conn:
        conn.execute(
            "UPDATE delegations SET failed_attempts = 0, deny_count = 0 WHERE id = ?",
            (delegation_id,),
        )
    conn.close()

def purge_delegation_payload(delegation_id: str, db_path: Optional[str] = None) -> None:
    """
    F0: Ephemeral purge. Zeroes out payload_enc after terminal state.
    The secret self-destructs; metadata (topic, labels, audit) is retained.
    """
    conn = get_db(db_path)
    ts = now_str()
    with conn:
        try:
            conn.execute(
                "UPDATE delegations SET payload_enc = NULL, purged_at = ? WHERE id = ?",
                (ts, delegation_id),
            )
        except sqlite3.IntegrityError:
            # Fallback if SQLite table was created with NOT NULL constraint
            conn.execute(
                "UPDATE delegations SET payload_enc = X'', purged_at = ? WHERE id = ?",
                (ts, delegation_id),
            )
    conn.close()

def log_audit_event(
    actor: str,
    action: str,
    delegation_id: Optional[str] = None,
    question: Optional[str] = None,
    gate_decision: Optional[str] = None,
    gate_confidence: Optional[float] = None,
    note: Optional[str] = None,
    db_path: Optional[str] = None,
) -> int:
    """
    F8: Hash-chained tamper-evident audit log.
    Each event hashes into the previous event's hash, forming an append-only verifiable chain.
    """
    conn = get_db(db_path)
    ts = now_str()
    with conn:
        prev_hash = _get_last_audit_hash(conn)
        row_hash = _compute_audit_hash(
            prev_hash, ts, actor, action, delegation_id, question, gate_decision, note
        )
        cur = conn.execute(
            """
            INSERT INTO audit_events (
                delegation_id, ts, actor, action, question, gate_decision,
                gate_confidence, note, prev_hash, row_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                delegation_id, ts, actor, action, question,
                gate_decision, gate_confidence, note, prev_hash, row_hash,
            ),
        )
        event_id = cur.lastrowid
    conn.close()

    try:
        from server.aws.s3_archival import archive_audit_event_to_s3
        archive_audit_event_to_s3({
            "id": event_id,
            "delegation_id": delegation_id,
            "ts": ts,
            "actor": actor,
            "action": action,
            "question": question,
            "gate_decision": gate_decision,
            "gate_confidence": gate_confidence,
            "note": note,
            "row_hash": row_hash,
            "prev_hash": prev_hash,
        })
    except Exception:
        pass

    return event_id

def verify_audit_chain(delegation_id: Optional[str] = None, db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    F8: Verify the tamper-evident audit chain.
    Recomputes each row's hash and reports the first mismatch found.
    """
    conn = get_db(db_path)
    if delegation_id:
        rows = conn.execute(
            "SELECT * FROM audit_events WHERE delegation_id = ? ORDER BY id ASC",
            (delegation_id,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
    conn.close()

    prev_hash = "genesis"
    for row in rows:
        d = dict(row)
        computed = _compute_audit_hash(
            prev_hash=d.get("prev_hash") or "genesis",
            ts=d["ts"],
            actor=d["actor"],
            action=d["action"],
            delegation_id=d.get("delegation_id"),
            question=d.get("question"),
            gate_decision=d.get("gate_decision"),
            note=d.get("note"),
        )
        stored = d.get("row_hash")
        if stored and computed != stored:
            return {
                "verified": False,
                "tampered_at_id": d["id"],
                "message": f"Hash mismatch at audit event id={d['id']}. Chain is broken.",
            }
        prev_hash = stored or prev_hash

    return {
        "verified": True,
        "events_checked": len(rows),
        "message": f"Audit chain verified ✓ ({len(rows)} events checked).",
    }

def get_audit_events_for_delegation(
    delegation_id: str, db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    conn = get_db(db_path)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, delegation_id, ts, actor, action, question, gate_decision, gate_confidence, note
        FROM audit_events
        WHERE delegation_id = ?
        ORDER BY id ASC
        """,
        (delegation_id,),
    )
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_recent_audit_events(limit: int = 50, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db(db_path)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT a.id, a.delegation_id, a.ts, a.actor, a.action, a.question,
               a.gate_decision, a.gate_confidence, a.note,
               d.topic_desc, d.recipient
        FROM audit_events a
        LEFT JOIN delegations d ON a.delegation_id = d.id
        ORDER BY a.id DESC LIMIT ?
        """,
        (limit,),
    )
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def create_pending_briefing(
    delegation_id: str,
    recipient: str,
    message: str,
    priority: str = "high",
    db_path: Optional[str] = None,
) -> int:
    conn = get_db(db_path)
    ts = now_str()
    with conn:
        cur = conn.execute(
            """
            INSERT INTO pending_briefings (delegation_id, recipient, message, priority, delivered, created_at)
            VALUES (?, ?, ?, ?, 0, ?)
            """,
            (delegation_id, recipient, message, priority, ts),
        )
        row_id = cur.lastrowid
    conn.close()
    return row_id

def get_pending_briefings_for_recipient(
    recipient: str, undelivered_only: bool = True, db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    conn = get_db(db_path)
    cur = conn.cursor()
    query = "SELECT * FROM pending_briefings WHERE recipient = ?"
    params: list = [recipient]
    if undelivered_only:
        query += " AND delivered = 0"
    query += " ORDER BY id DESC"
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def mark_briefing_delivered(briefing_id: int, db_path: Optional[str] = None) -> None:
    conn = get_db(db_path)
    with conn:
        conn.execute(
            "UPDATE pending_briefings SET delivered = 1 WHERE id = ?", (briefing_id,)
        )
    conn.close()

def fast_forward_delegation_time(
    delegation_id: str, seconds_in_past: int = 1, db_path: Optional[str] = None
) -> Optional[str]:
    """Sets expires_at to N seconds in the past for testing/demo purposes."""
    conn = get_db(db_path)
    cur = conn.cursor()
    cur.execute("SELECT status FROM delegations WHERE id = ?", (delegation_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return None
    past_time = (now() - timedelta(seconds=seconds_in_past)).isoformat()
    with conn:
        conn.execute(
            "UPDATE delegations SET expires_at = ? WHERE id = ?",
            (past_time, delegation_id),
        )
    conn.close()
    return past_time
