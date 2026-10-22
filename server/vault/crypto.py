import os
import hmac
import hashlib
import json
import secrets
from typing import List, Dict, Any, Optional
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

_FERNET_KEY = os.environ.get("ENCRYPTION_KEY")
_HMAC_SECRET = os.environ.get("HMAC_SECRET", "default_secret_key_change_me_in_production")
MAX_FACTS_PER_ANSWER = int(os.environ.get("MAX_FACTS_PER_ANSWER", "2"))

def get_fernet() -> Fernet:
    global _FERNET_KEY
    if not _FERNET_KEY:
        _FERNET_KEY = Fernet.generate_key().decode()
    return Fernet(_FERNET_KEY.encode() if isinstance(_FERNET_KEY, str) else _FERNET_KEY)

def normalize_codeword(cw: str) -> str:
    """
    Normalizes voice/typed codewords:
    Lowercases, strips leading/trailing whitespace, and strips ending punctuation
    common in speech recognition transcripts (e.g. 'Solaris.' -> 'solaris').
    """
    if not cw:
        return ""
    return cw.strip().lower().rstrip(".!,?")

def hash_codeword(codeword: str, hmac_secret: Optional[str] = None) -> str:
    """
    Computes a keyed HMAC-SHA256 hash of the normalized codeword.
    A keyed hash prevents rainbow table and brute-force attacks on low-entropy spoken words.
    """
    secret = (hmac_secret or _HMAC_SECRET).encode("utf-8")
    normalized = normalize_codeword(codeword).encode("utf-8")
    return hmac.new(secret, normalized, hashlib.sha256).hexdigest()

def verify_codeword(candidate: str, stored_hash: str, hmac_secret: Optional[str] = None) -> bool:
    """
    Constant-time comparison between candidate codeword and stored hash.
    """
    if not candidate or not stored_hash:
        return False
    candidate_hash = hash_codeword(candidate, hmac_secret)
    return secrets.compare_digest(candidate_hash, stored_hash)

def encrypt_payload(facts: List[Dict[str, str]]) -> bytes:
    """
    Encrypts a list of labeled facts [{label, value}] using Fernet.
    """
    fernet = get_fernet()
    data = json.dumps(facts).encode("utf-8")
    return fernet.encrypt(data)

def decrypt_payload(payload_enc: bytes) -> List[Dict[str, str]]:
    """
    Decrypts the stored payload into a list of labeled facts.
    """
    fernet = get_fernet()
    decrypted = fernet.decrypt(payload_enc)
    return json.loads(decrypted.decode("utf-8"))

def slice_facts(
    all_facts: List[Dict[str, str]],
    allowed_labels: List[str],
    max_facts: int = MAX_FACTS_PER_ANSWER,
) -> List[Dict[str, str]]:
    """
    Semantic slicing: returns only facts whose labels are present in both
    all_facts and allowed_labels. Strictly limits total facts released to max_facts.
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
