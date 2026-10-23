import os
import hmac
import hashlib
import json
import secrets
import unicodedata
from typing import List, Dict, Any, Optional
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

load_dotenv()

_FERNET_KEY = os.environ.get("ENCRYPTION_KEY")
_HMAC_SECRET = os.environ.get("HMAC_SECRET", "")  # P0-5: no hardcoded fallback
MAX_FACTS_PER_ANSWER = int(os.environ.get("MAX_FACTS_PER_ANSWER", "2"))

def get_fernet() -> Fernet:
    global _FERNET_KEY
    if not _FERNET_KEY:
        raise RuntimeError(
            "ENCRYPTION_KEY is not set. Run 'python scripts/gen_keys.py' and set it in .env"
        )
    return Fernet(_FERNET_KEY.encode() if isinstance(_FERNET_KEY, str) else _FERNET_KEY)

def normalize_codeword(cw: str) -> str:
    """
    Normalizes voice/typed codewords for consistent hashing.
    P1-6: Unicode NFKC normalization + casefold() handles voice transcription variants.
    Strips leading/trailing whitespace, surrounding quotes, and trailing punctuation.
    e.g. 'Solaris.', ' "SOLARIS" ', 'ｓｏｌａｒｉｓ' all → 'solaris'
    """
    if not cw:
        return ""
    # Unicode NFKC normalizes fullwidth and compatibility characters
    normalized = unicodedata.normalize("NFKC", cw)
    # casefold() is more aggressive than lower() for Unicode
    normalized = normalized.casefold()
    # Strip outer whitespace, then quotes, then punctuation
    normalized = normalized.strip()
    normalized = normalized.strip("\"'")
    normalized = normalized.rstrip(".!,?;:").strip()
    return normalized

def hash_codeword(codeword: str, hmac_secret: Optional[str] = None) -> str:
    """
    Computes a keyed HMAC-SHA256 hash of the normalized codeword.
    A keyed hash prevents rainbow-table and brute-force attacks on low-entropy spoken words.
    """
    secret = (hmac_secret or _HMAC_SECRET)
    if not secret:
        raise RuntimeError("HMAC_SECRET is not set. Cannot hash codeword securely.")
    normalized = normalize_codeword(codeword).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), normalized, hashlib.sha256).hexdigest()

def verify_codeword(candidate: str, stored_hash: str, hmac_secret: Optional[str] = None) -> bool:
    """
    Constant-time comparison between candidate codeword and stored hash.
    """
    if not candidate or not stored_hash:
        return False
    try:
        candidate_hash = hash_codeword(candidate, hmac_secret)
        return secrets.compare_digest(candidate_hash, stored_hash)
    except Exception:
        return False

def encrypt_payload(facts: List[Dict[str, str]]) -> bytes:
    """
    Encrypts a list of labeled facts [{label, value}] using Fernet symmetric encryption.
    """
    fernet = get_fernet()
    data = json.dumps(facts).encode("utf-8")
    return fernet.encrypt(data)

def decrypt_payload(payload_enc: Optional[bytes]) -> List[Dict[str, str]]:
    """
    Decrypts the stored payload into a list of labeled facts.
    F0: payload_enc may be None/empty after purge — returns empty list in that case.
    """
    if not payload_enc:
        return []
    fernet = get_fernet()
    try:
        decrypted = fernet.decrypt(payload_enc)
        return json.loads(decrypted.decode("utf-8"))
    except (InvalidToken, Exception) as e:
        raise ValueError(f"Payload decryption failed: {e}") from e

def slice_facts(
    all_facts: List[Dict[str, str]],
    allowed_labels: List[str],
    max_facts: int = MAX_FACTS_PER_ANSWER,
) -> List[Dict[str, str]]:
    """
    Semantic slicing: returns only facts whose labels are present in both
    all_facts and allowed_labels. Strictly limits total facts released to max_facts.
    Even if the gatekeeper ALLOW'd 10 labels, only max_facts are ever returned.
    """
    allowed_set = {lbl.strip().lower() for lbl in allowed_labels if lbl}
    selected: List[Dict[str, str]] = []
    for fact in all_facts:
        fact_label = fact.get("label", "").strip().lower()
        if fact_label in allowed_set:
            selected.append(fact)
            if len(selected) >= max_facts:
                break
    return selected
