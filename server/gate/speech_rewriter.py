import os
import json
import logging
from typing import List, Dict, Any
from dotenv import load_dotenv
from .bedrock_gate import get_bedrock_client, BEDROCK_MODEL_ID

load_dotenv()
logger = logging.getLogger(__name__)

SPEECH_SYSTEM_PROMPT = """You are an Alexa+ voice response formatter.
Your task is to take a small list of retrieved facts (labels and values) and formulate a clear,
concise, conversational spoken response (1 to 2 sentences maximum) suitable for an Echo smart speaker.

CRITICAL INSTRUCTIONS:
1. Speak directly and naturally to the user. No markdown, no bullet points.
2. State the fact values ACCURATELY — every value from the facts must appear verbatim in the response.
3. Keep the output under 40 words so it can be spoken quickly and comfortably.
4. Do NOT add disclaimers, preamble, or commentary beyond conveying the facts.
"""

def fallback_format_facts(facts: List[Dict[str, str]]) -> str:
    """Natural conversational speech template used if Bedrock is unavailable or output fails verification."""
    if not facts:
        return "I found no relevant details."
    if len(facts) == 1:
        f = facts[0]
        return f"For {f.get('label')}, the details are: {f.get('value')}."
    parts = [f"for {f.get('label')}, {f.get('value')}" for f in facts if f.get("label") and f.get("value")]
    return "Here are the details: " + "; and ".join(parts) + "."

def _verify_values_in_output(output: str, facts: List[Dict[str, str]]) -> bool:
    """
    P0-4: Verify that every released fact value appears verbatim in the spoken output.
    Prevents the speech rewriter from mangling, dropping, or altering critical values
    (e.g. turning '4491' into 'four thousand...' or dropping a digit).
    """
    for fact in facts:
        value = fact.get("value", "")
        if value and value not in output:
            logger.warning(
                f"Speech rewriter dropped or altered value '{value}' — "
                "falling back to deterministic template."
            )
            return False
    return True

def rewrite_facts_for_speech(facts: List[Dict[str, str]]) -> str:
    """
    Calls Bedrock Runtime or Fast Alexa Voice Formatter to turn retrieved facts
    into a conversational Alexa+ voice answer.
    Sees ONLY the already-sliced facts (never the user question or unreleased secrets).
    P0-4: Verifies all released values appear verbatim; falls back to template if not.
    """
    if not facts:
        return fallback_format_facts(facts)

    if os.environ.get("USE_SEMANTIC_CLASSIFIER", "false").lower() in ("true", "1", "yes"):
        return fallback_format_facts(facts)

    facts_summary = "\n".join([f"- {f.get('label')}: {f.get('value')}" for f in facts])
    prompt = f"Facts to speak:\n{facts_summary}\n\nFormat as a natural Alexa+ spoken response (1-2 sentences, under 40 words):"

    try:
        client = get_bedrock_client()
        response = client.converse(
            modelId=BEDROCK_MODEL_ID,
            system=[{"text": SPEECH_SYSTEM_PROMPT}],
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": 100, "temperature": 0.2},
        )
        output_message = response.get("output", {}).get("message", {})
        content_blocks = output_message.get("content", [])
        for block in content_blocks:
            text = block.get("text")
            if text and text.strip():
                text = text.strip()
                # P0-4: Verify all values appear verbatim
                if _verify_values_in_output(text, facts):
                    return text
                else:
                    # Value was mangled — use safe fallback
                    return fallback_format_facts(facts)
    except Exception as exc:
        logger.warning(f"Bedrock speech rewrite error, using fallback template: {exc}")

    return fallback_format_facts(facts)
