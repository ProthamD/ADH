#!/usr/bin/env python3
"""
scripts/seed_demo.py — Seed realistic delegations for demo recording and testing.

Usage:
    python scripts/seed_demo.py [--reset]

Populates the database with 3 realistic scenarios:
1. On-Call DevOps Engineer (payments rollback)
2. House Sitter (spare key & alarm code)
3. Elder Caretaker (medication schedule & emergency contact)
"""
import sys
import argparse
from pathlib import Path
from dotenv import load_dotenv

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

load_dotenv()

from server.store.db import init_db, get_db
from server.tools.delegation_tools import handle_create_delegation

def seed(reset: bool = False):
    init_db()
    if reset:
        conn = get_db()
        with conn:
            conn.execute("DELETE FROM delegations")
            conn.execute("DELETE FROM audit_events")
            conn.execute("DELETE FROM pending_briefings")
        conn.close()
        print("[DEMO SEED] Cleared existing delegations, audit events, and briefings.")

    scenarios = [
        {
            "recipient": "userB",
            "topic_desc": "rollback steps for payments service",
            "facts": [
                {"label": "rollback command", "value": "kubectl rollout undo deployment/payments-api -n prod"},
                {"label": "database rollback", "value": "flyway -target=3.2.1 undo"}
            ],
            "codeword": "blue falcon",
            "max_uses": 2,
            "expires_in_minutes": 60,
            "escalate_to": "https://hooks.slack.com/services/T00/B00/MOCK_DEV_ALERTS",
            "owner": "userA"
        },
        {
            "recipient": "userB",
            "topic_desc": "where the spare key is and the alarm code",
            "facts": [
                {"label": "spare key location", "value": "Under the blue terracotta planter on the back porch"},
                {"label": "alarm code", "value": "4491"}
            ],
            "codeword": "copper pine",
            "max_uses": 1,
            "expires_in_minutes": 120,
            "escalate_to": "https://hooks.slack.com/services/T00/B00/MOCK_FAMILY",
            "owner": "userA"
        },
        {
            "recipient": "userB",
            "topic_desc": "evening medication schedule and emergency contact",
            "facts": [
                {"label": "medication schedule", "value": "One 10mg Lisinopril tablet at 8:00 PM with water"},
                {"label": "emergency contact", "value": "Dr. Sarah Chen at +1-555-0199"}
            ],
            "codeword": "silver lake",
            "max_uses": 3,
            "expires_in_minutes": 180,
            "owner": "userA"
        }
    ]

    print("\n[DEMO SEED] Seeding delegations...")
    for s in scenarios:
        res = handle_create_delegation(
            recipient=s["recipient"],
            topic_desc=s["topic_desc"],
            facts=s["facts"],
            codeword=s["codeword"],
            max_uses=s["max_uses"],
            expires_in_minutes=s.get("expires_in_minutes"),
            escalate_to=s.get("escalate_to"),
            owner=s["owner"],
        )
        print(f"  + Created: {res.get('delegation_id')} | Recipient: {s['recipient']} | Codeword: '{s['codeword']}' | Topic: \"{s['topic_desc']}\"")

    print("\n[DEMO SEED] Seeding complete! Database is ready for demo.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed demo delegations")
    parser.add_argument("--reset", action="store_true", help="Clear existing DB records before seeding")
    args = parser.parse_args()
    seed(reset=args.reset)
