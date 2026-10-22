import os
import sqlite3
import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

DB_PATH = os.environ.get("DB_PATH", "delegation_broker.db")

def now() -> str:
    """Clock abstraction: returns current UTC time as an ISO8601 string."""
    return datetime.now(timezone.utc).isoformat()

def parse_iso(ts_str: str) -> datetime:
    """Parse ISO8601 string into timezone-aware datetime."""
    return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

def get_db(db_path: Optional[str] = None) -> sqlite3.Connection:
    target_path = db_path or DB_PATH
    conn = sqlite3.connect(target_path, check_same_thread=False)
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
                payload_enc BLOB NOT NULL,
                fact_labels TEXT NOT NULL,
                codeword_hash TEXT NOT NULL,
                max_uses INTEGER NOT NULL DEFAULT 1,
                uses INTEGER NOT NULL DEFAULT 0,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                escalate_to TEXT,
                created_at TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0
            );
        """)
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
                FOREIGN KEY (delegation_id) REFERENCES delegations(id) ON DELETE SET NULL
            );
        """)
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
    created_at = now()
    with conn:
        conn.execute(
            """
            INSERT INTO delegations (
                id, owner, recipient, topic_desc, payload_enc, fact_labels,
                codeword_hash, max_uses, uses, expires_at, status, escalate_to, created_at, failed_attempts
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 'active', ?, ?, 0)
            """,
            (
                delegation_id,
                owner,
                recipient,
                topic_desc,
                payload_enc,
                json.dumps(fact_labels),
                codeword_hash,
                max_uses,
                expires_at,
                escalate_to,
                created_at,
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
        # Do not expose raw payload_enc in general listings
        d.pop("payload_enc", None)
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

def increment_delegation_uses(
    delegation_id: str, db_path: Optional[str] = None
) -> int:
    conn = get_db(db_path)
    with conn:
        conn.execute(
            "UPDATE delegations SET uses = uses + 1 WHERE id = ?", (delegation_id,)
        )
        cur = conn.execute("SELECT uses, max_uses FROM delegations WHERE id = ?", (delegation_id,))
        row = cur.fetchone()
        new_uses = row["uses"]
        if new_uses >= row["max_uses"]:
            conn.execute("UPDATE delegations SET status = 'exhausted' WHERE id = ?", (delegation_id,))
    conn.close()
    return new_uses

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

def reset_failed_attempts(delegation_id: str, db_path: Optional[str] = None) -> None:
    conn = get_db(db_path)
    with conn:
        conn.execute(
            "UPDATE delegations SET failed_attempts = 0 WHERE id = ?", (delegation_id,)
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
    conn = get_db(db_path)
    ts = now()
    with conn:
        cur = conn.execute(
            """
            INSERT INTO audit_events (
                delegation_id, ts, actor, action, question, gate_decision, gate_confidence, note
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                delegation_id,
                ts,
                actor,
                action,
                question,
                gate_decision,
                gate_confidence,
                note,
            ),
        )
        event_id = cur.lastrowid
    conn.close()
    return event_id

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
    ts = now()
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
    params = [recipient]
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
    from datetime import timedelta
    past_time = (datetime.now(timezone.utc) - timedelta(seconds=seconds_in_past)).isoformat()
    with conn:
        conn.execute(
            "UPDATE delegations SET expires_at = ? WHERE id = ?",
            (past_time, delegation_id),
        )
    conn.close()
    return past_time
