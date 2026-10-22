import os
import json
import logging
from typing import List, Dict, Any
from dotenv import load_dotenv
from .bedrock_gate import get_bedrock_client, BEDROCK_MODEL_ID

load_dotenv()
logger = logging.getLogger(__name__)

SPEECH_SYSTEM_PROMPT = """You are an Alexa+ voice response formatter.
Your task is to take a small list of retrieved facts (labels and values) and formulate a clear, concise, conversational spoken response (1 to 2 sentences maximum) suitable for an Echo smart speaker.

CRITICAL INSTRUCTIONS:
1. Speak directly and naturally to the user.
2. State the fact values accurately without adding disclaimers, preamble, or extraneous commentary.
3. Keep the output under 35 words so it can be spoken quickly and comfortably.
"""

def fallback_format_facts(facts: List[Dict[str, str]]) -> str:
    """Fixed deterministic template used if Bedrock call is unavailable or fails."""
    if not facts:
        return "I found no relevant details."
    parts = [f"{f.get('label')}: {f.get('value')}" for f in facts if f.get('label') and f.get('value')]
    return "Here is what was shared with you: " + "; ".join(parts) + "."

def rewrite_facts_for_speech(facts: List[Dict[str, str]]) -> str:
    """
    Calls Bedrock Runtime to turn the retrieved facts into a conversational Alexa+ voice answer.
    Sees ONLY the already-sliced facts (never the user question or unreleased secrets).
    """
    if not facts:
        return fallback_format_facts(facts)

    facts_summary = "\n".join([f"- {f.get('label')}: {f.get('value')}" for f in facts])
    prompt = f"Facts to speak:\n{facts_summary}\n\nFormat as a natural Alexa+ spoken response:"

    try:
        client = get_bedrock_client()
        response = client.converse(
            modelId=BEDROCK_MODEL_ID,
            system=[{"text": SPEECH_SYSTEM_PROMPT}],
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": 80, "temperature": 0.2},
        )
        output_message = response.get("output", {}).get("message", {})
        content_blocks = output_message.get("content", [])
        for block in content_blocks:
            text = block.get("text")
            if text:
                return text.strip()
    except Exception as exc:
        logger.warning(f"Bedrock speech rewrite error, using fallback template: {exc}")

    return fallback_format_facts(facts)
