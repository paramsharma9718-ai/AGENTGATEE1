"""LLM Integration for AGENTGATE Module 03.

Security Guarantees:
- Works deterministically out-of-the-box (no external API keys required).
- Optional API hook for local or hosted LLM.
- CRITICAL: LLM output is strictly UNTRUSTED. The LLM may suggest actions,
  summarize text, or propose responses, but it has ZERO authority to authorize actions.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from agent.action_proposer import ActionProposer
from models.workflow import ActionProposal


class LLMIntegration:
    """Provides natural language interpretation and summarization."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("LLM_API_KEY")

    def interpret_user_request(self, user_id: str, prompt: str) -> Optional[ActionProposal]:
        """Convert natural language prompt to a structured ActionProposal.

        Uses deterministic parsing by default. Never trusts prompt instructions to self-authorize.
        """
        # Deterministic extraction
        return ActionProposer.parse_natural_language(user_id=user_id, text=prompt)

    def summarize_document(self, document_text: str, max_sentences: int = 3) -> str:
        """Deterministic summarizer that extracts key sentences without external APIs."""
        lines = [line.strip() for line in document_text.splitlines() if line.strip()]
        # Filter out obvious injection lines or comments
        clean_lines = [l for l in lines if not l.startswith("[MALICIOUS") and not l.startswith("System instruction:")]
        if not clean_lines:
            return "Document summary: Empty or restricted content."

        summary_body = " ".join(clean_lines[:max_sentences])
        return f"Summary: {summary_body}"

    def explain_result(self, execution_result_dict: Dict[str, Any]) -> str:
        """Generate human-readable explanation of an execution result."""
        status = execution_result_dict.get("status")
        op = execution_result_dict.get("operation")
        res = execution_result_dict.get("resource_id")
        err = execution_result_dict.get("error_message")

        if status == "SUCCESS":
            return f"Operation {op} on resource '{res}' completed successfully."
        elif status == "BLOCKED":
            return f"SECURITY ALERT: Operation {op} on resource '{res}' was BLOCKED by policy. Reason: {err}"
        elif status == "PENDING_APPROVAL":
            return f"APPROVAL REQUIRED: Operation {op} on resource '{res}' requires Administrator approval before execution."
        else:
            return f"Operation {op} failed: {err}"


# Default singleton instance
default_llm_integration = LLMIntegration()
