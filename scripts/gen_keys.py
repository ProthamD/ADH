#!/usr/bin/env python3
"""
scripts/gen_keys.py — Generate secure cryptographic keys for the Alexa+ Delegation Broker.

Usage:
    python scripts/gen_keys.py

Outputs the values to add to your .env file.
"""
import secrets
from cryptography.fernet import Fernet

def main():
    fernet_key = Fernet.generate_key().decode()
    hmac_secret = secrets.token_hex(32)

    print("=" * 60)
    print("Alexa+ Delegation Broker — Generated Secrets")
    print("=" * 60)
    print("Add these to your .env file (keep them secret, never commit):\n")
    print(f"ENCRYPTION_KEY={fernet_key}")
    print(f"HMAC_SECRET={hmac_secret}")
    print()
    print("=" * 60)
    print("Security notes:")
    print(" - ENCRYPTION_KEY: encrypts fact payloads at rest (Fernet AES-128-CBC)")
    print(" - HMAC_SECRET: keys the codeword hash (HMAC-SHA256)")
    print(" - If either key changes, all existing delegations become unreadable.")
    print(" - Store a backup in a secrets manager (e.g. AWS Secrets Manager).")
    print("=" * 60)

if __name__ == "__main__":
    main()
