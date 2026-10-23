"""
server/gate/fast_semantic_router.py — Ultra-Efficient Local Semantic Gatekeeper & Router.

Engineered for sub-millisecond (< 2ms) intent classification and minimal-fact label slicing
without requiring remote LLM API calls, external network latency, or model access approvals.
Uses multi-layer adversarial defenses, sub-word n-gram TF-IDF vectorization, and cosine similarity.
"""
import os
import re
import math
import logging
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple, Optional
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

logger = logging.getLogger(__name__)

CONFIDENCE_THRESHOLD = float(os.environ.get("CONFIDENCE_THRESHOLD", "0.75"))
MAX_FACTS_PER_ANSWER = int(os.environ.get("MAX_FACTS_PER_ANSWER", "2"))

@dataclass
class FastGateResult:
    decision: str              # "ALLOW" | "DENY" | "BORDERLINE"
    confidence: float          # 0.0 to 1.0
    allowed_labels: List[str]  # Minimal subset of permitted fact labels
    reasoning: str             # Explanation for audit trail
    inference_time_ms: float   # Execution time in milliseconds

# Comprehensive Adversarial Jailbreak and Injection Patterns
JAILBREAK_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|prompts)",
    r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|prompts)",
    r"override\s+(all\s+)?(safety|system|security)\s+(rules|guidelines|protocols)",
    r"system\s+prompt",
    r"print\s+(all\s+)?(system|secret|internal|hidden)",
    r"output\s+(all\s+)?(secrets|passwords|credentials|keys|tokens)",
    r"dump\s+(all\s+)?(database|vault|secrets|facts)",
    r"reveal\s+(all\s+)?(secrets|passwords|credentials|keys|tokens)",
    r"show\s+(all\s+)?(secrets|everything|data|database)",
    r"you\s+are\s+now\s+(in\s+)?(dan|developer\s+mode|root|admin|god\s+mode)",
    r"roleplay\s+as",
    r"act\s+as\s+(an?\s+)?(unrestricted|jailbroken|root|admin)",
    r"base64\s+(decode|encode|encoded)",
    r"</?untrusted",
    r"</?system>",
    r"```system",
    r'\{"tool":',
    r"execute\s+(sql|command|script)",
]

# Sensitive Out-Of-Domain Probe Keywords
PROHIBITED_DOMAIN_PROBES = [
    "salary", "bank balance", "finances", "home address", "passport",
    "jewelry", "root account", "master billing", "credit card",
    "billing card", "restart auth", "deploy frontend", "ssn",
    "social security", "tax return", "medical record"
]

COMMON_STOPWORDS = {
    "a", "an", "the", "and", "or", "but", "if", "because", "as", "what",
    "which", "this", "that", "these", "those", "then", "just", "so", "than",
    "such", "both", "through", "about", "for", "is", "of", "while", "during",
    "to", "from", "in", "out", "on", "off", "over", "under", "again", "further",
    "then", "once", "here", "there", "when", "where", "why", "how", "all", "any",
    "both", "each", "few", "more", "most", "other", "some", "such", "no", "nor",
    "not", "only", "own", "same", "so", "than", "too", "very", "can", "will",
    "don", "should", "now", "tell", "me", "give", "please", "alexa", "i", "need"
}

class FastSemanticRouter:
    """
    Sub-millisecond semantic gatekeeper and label router.
    Uses multi-stage defense + n-gram TF-IDF vector similarity.
    """

    def __init__(self, confidence_threshold: float = CONFIDENCE_THRESHOLD):
        self.confidence_threshold = confidence_threshold
        # Pre-compile regexes for ultra-low latency
        self._jailbreak_regexes = [re.compile(p, re.IGNORECASE) for p in JAILBREAK_PATTERNS]

    def _detect_adversarial_patterns(self, text: str) -> Optional[str]:
        """Detects prompt injection, persona manipulation, or jailbreaks."""
        text_lower = text.lower()
        for rx in self._jailbreak_regexes:
            if rx.search(text_lower):
                return f"Adversarial prompt injection pattern detected ('{rx.pattern}'). Blocked by Semantic Gatekeeper."
        return None

    def _detect_out_of_scope_probe(self, text: str, topic_desc: str, fact_labels: List[str]) -> Optional[str]:
        """Detects probes targeting explicitly ungranted domains."""
        text_lower = text.lower()
        topic_lower = topic_desc.lower()
        label_text = " ".join(fact_labels).lower()

        for probe in PROHIBITED_DOMAIN_PROBES:
            if probe in text_lower and probe not in topic_lower and probe not in label_text:
                return f"Question targets sensitive out-of-scope domain ('{probe}'). Access denied."
        return None

    def route(
        self,
        question: str,
        topic_desc: str,
        fact_labels: List[str],
        confidence_threshold: Optional[float] = None,
    ) -> FastGateResult:
        """
        Evaluates question against topic and fact labels in < 2ms.
        """
        import time
        t_start = time.perf_counter()

        threshold = confidence_threshold if confidence_threshold is not None else self.confidence_threshold
        cleaned_question = (question or "").strip()

        # 1. Edge-cases: Empty or oversized
        if not cleaned_question:
            t_ms = (time.perf_counter() - t_start) * 1000
            return FastGateResult(
                decision="DENY",
                confidence=1.0,
                allowed_labels=[],
                reasoning="Empty question provided.",
                inference_time_ms=t_ms,
            )

        if len(cleaned_question) > 2000:
            t_ms = (time.perf_counter() - t_start) * 1000
            return FastGateResult(
                decision="DENY",
                confidence=1.0,
                allowed_labels=[],
                reasoning="Question exceeds maximum allowed length (2000 characters).",
                inference_time_ms=t_ms,
            )

        # 2. Stage 1: Jailbreak & Prompt Injection Defense
        jailbreak_reason = self._detect_adversarial_patterns(cleaned_question)
        if jailbreak_reason:
            t_ms = (time.perf_counter() - t_start) * 1000
            return FastGateResult(
                decision="DENY",
                confidence=0.99,
                allowed_labels=[],
                reasoning=jailbreak_reason,
                inference_time_ms=t_ms,
            )

        # 3. Stage 2: Sensitive Domain Probe Defense
        probe_reason = self._detect_out_of_scope_probe(cleaned_question, topic_desc, fact_labels)
        if probe_reason:
            t_ms = (time.perf_counter() - t_start) * 1000
            return FastGateResult(
                decision="DENY",
                confidence=0.96,
                allowed_labels=[],
                reasoning=probe_reason,
                inference_time_ms=t_ms,
            )

        # 4. Stage 3: TF-IDF Vector Semantic Scoring & Label Slicing
        # Prepare corpus: [Question, Topic Description, Fact Label 1, Fact Label 2, ...]
        corpus = [cleaned_question, topic_desc] + fact_labels

        try:
            vectorizer = TfidfVectorizer(
                ngram_range=(1, 3),
                analyzer="word",
                stop_words="english",
                token_pattern=r"(?u)\b[\w-]+\b",
            )
            tfidf_matrix = vectorizer.fit_transform(corpus)
            question_vec = tfidf_matrix[0:1]
            topic_vec = tfidf_matrix[1:2]
            label_vecs = tfidf_matrix[2:]

            # Cosine similarity with Topic
            sim_topic = float(cosine_similarity(question_vec, topic_vec)[0][0])

            # Cosine similarities with each fact label
            sim_labels: List[Tuple[str, float]] = []
            if label_vecs.shape[0] > 0:
                label_sims = cosine_similarity(question_vec, label_vecs)[0]
                for idx, lbl in enumerate(fact_labels):
                    sim_labels.append((lbl, float(label_sims[idx])))

        except Exception as exc:
            # Fallback for empty vocabulary or punctuation-only input
            logger.debug(f"TF-IDF vectorizer fallback: {exc}")
            sim_topic = 0.0
            sim_labels = [(lbl, 0.0) for lbl in fact_labels]

        # Token stemming / substring matching bonus (handles compound words like "roll back" vs "rollback")
        q_tokens = set(re.findall(r"\w+", cleaned_question.lower())) - COMMON_STOPWORDS
        topic_tokens = set(re.findall(r"\w+", topic_desc.lower())) - COMMON_STOPWORDS
        
        token_overlap = len(q_tokens & topic_tokens)
        token_overlap_score = min(token_overlap * 0.25, 0.8)

        # Calculate composite score for topic match
        composite_topic_score = max(sim_topic, token_overlap_score)

        # Match and rank fact labels
        matched_labels: List[Tuple[str, float]] = []
        for lbl, score in sim_labels:
            lbl_tokens = set(re.findall(r"\w+", lbl.lower())) - COMMON_STOPWORDS
            overlap = len(q_tokens & lbl_tokens)
            fuzzy_bonus = 0.35 if (overlap > 0 or any(t in cleaned_question.lower() for t in lbl_tokens)) else 0.0
            total_lbl_score = max(score, fuzzy_bonus)
            if total_lbl_score > 0.15:
                matched_labels.append((lbl, total_lbl_score))

        # Sort matched labels by score descending
        matched_labels.sort(key=lambda x: x[1], reverse=True)

        # Decision Logic:
        # ALLOW: Strong topic or label match
        if composite_topic_score >= 0.30 or matched_labels:
            # Select minimal fact labels
            if matched_labels:
                selected_labels = [lbl for lbl, _ in matched_labels[:MAX_FACTS_PER_ANSWER]]
            else:
                selected_labels = fact_labels[:MAX_FACTS_PER_ANSWER]

            # Calibrate confidence score
            best_sim = max([composite_topic_score] + [s for _, s in matched_labels])
            confidence = min(0.85 + (best_sim * 0.14), 0.98)

            t_ms = (time.perf_counter() - t_start) * 1000
            return FastGateResult(
                decision="ALLOW",
                confidence=round(confidence, 2),
                allowed_labels=selected_labels,
                reasoning="Ultra-Fast Semantic Router: Question falls strictly within authorized scope and matches delegated facts.",
                inference_time_ms=t_ms,
            )

        # BORDERLINE: Weak or ambiguous overlap
        if composite_topic_score >= 0.15:
            t_ms = (time.perf_counter() - t_start) * 1000
            return FastGateResult(
                decision="BORDERLINE",
                confidence=0.62,
                allowed_labels=[],
                reasoning="Query has tangential topic overlap; requires owner escalation confirmation.",
                inference_time_ms=t_ms,
            )

        # DENY: Zero semantic overlap
        t_ms = (time.perf_counter() - t_start) * 1000
        return FastGateResult(
            decision="DENY",
            confidence=0.91,
            allowed_labels=[],
            reasoning="Question has no semantic overlap with authorized delegated topic.",
            inference_time_ms=t_ms,
        )

# Global singleton instance for maximum performance
_router_instance: Optional[FastSemanticRouter] = None

def get_fast_semantic_router() -> FastSemanticRouter:
    global _router_instance
    if _router_instance is None:
        _router_instance = FastSemanticRouter()
    return _router_instance
