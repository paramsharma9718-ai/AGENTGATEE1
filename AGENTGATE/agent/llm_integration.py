"""LLM Integration for AGENTGATE Module 03 with NVIDIA Nemotron / OpenAI NIM Support.

Security Guarantees:
- Works deterministically out-of-the-box (no external API keys required).
- Native support for NVIDIA NIM (e.g. nvidia/llama-3.1-nemotron-70b-instruct).
- CRITICAL: LLM output is strictly UNTRUSTED. The LLM may suggest actions or tool calls,
  but it has ZERO authority to authorize actions.
- Translates model tool calls directly into validated ActionProposal structures for Gateway enforcement.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Any, Callable, Dict, List, Optional

import httpx

from agent.action_proposer import ActionProposer
from models.action_request import Operation
from models.workflow import ActionProposal

logger = logging.getLogger(__name__)

# Standard OpenAI-format Tool Schema for NVIDIA NIM / Nemotron
NEMOTRON_TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "read_document",
            "description": "Request to read the content and security classification of an ingested document.",
            "parameters": {
                "type": "object",
                "properties": {
                    "document_id": {
                        "type": "string",
                        "description": "Identifier of the target document, e.g. 'DOC-001', 'DOC-002', 'DOC-003', 'DOC-004'.",
                    }
                },
                "required": ["document_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "save_report",
            "description": "Synthesize or save a derived security report from one or more source documents.",
            "parameters": {
                "type": "object",
                "properties": {
                    "report_id": {
                        "type": "string",
                        "description": "Unique identifier for the report to be saved, e.g. 'REP-001'.",
                    },
                    "title": {
                        "type": "string",
                        "description": "Human-readable title for the report.",
                    },
                    "content": {
                        "type": "string",
                        "description": "Body text or synthesized findings of the report.",
                    },
                    "source_doc_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of source document IDs used to derive this report (e.g. ['DOC-001', 'DOC-003']).",
                    },
                },
                "required": ["report_id", "title", "content", "source_doc_ids"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_report",
            "description": "Deliver a saved report to a recipient's inbox.",
            "parameters": {
                "type": "object",
                "properties": {
                    "report_id": {
                        "type": "string",
                        "description": "ID of the report to send, e.g. 'DEMO-REP-01'.",
                    },
                    "recipient_id": {
                        "type": "string",
                        "description": "User ID of the intended recipient, e.g. 'USER-101'.",
                    },
                },
                "required": ["report_id", "recipient_id"],
            },
        },
    },
]

DEFAULT_NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_NEMOTRON_MODEL = "nvidia/llama-3.1-nemotron-70b-instruct"


class LLMIntegration:
    """Provides natural language interpretation, Nemotron NIM tool-calling, and summarization."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        backend: str = "deterministic",
        custom_generator: Optional[Callable[[str], str]] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self.api_key = api_key or os.getenv("NVIDIA_API_KEY") or os.getenv("LLM_API_KEY")
        self.backend = backend.lower()
        self.custom_generator = custom_generator
        self.base_url = base_url or os.getenv("NVIDIA_BASE_URL", DEFAULT_NVIDIA_BASE_URL)
        self.model = model or os.getenv("NVIDIA_MODEL", DEFAULT_NEMOTRON_MODEL)

    def set_custom_generator(self, generator: Callable[[str], str]) -> None:
        """Attach a custom model runner (e.g. local pipeline, mock, or API client)."""
        self.custom_generator = generator
        self.backend = "callable"

    def interpret_user_request(
        self,
        user_id: str,
        prompt: str,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
    ) -> Optional[ActionProposal]:
        """Convert natural language prompt to a structured ActionProposal.

        Priority order:
        1. Custom generator if attached.
        2. NVIDIA Nemotron NIM API if an API key is provided.
        3. Deterministic regex parser (fail-safe offline fallback).
        """
        # 1. Custom generator (e.g. mock or local pipeline)
        if self.backend == "callable" and self.custom_generator:
            try:
                response = self.custom_generator(prompt)
                parsed = json.loads(response)
                if isinstance(parsed, dict) and "tool" in parsed:
                    return self.parse_tool_call(
                        user_id=user_id,
                        tool_name=parsed["tool"],
                        arguments=parsed.get("arguments", {}),
                    )
            except Exception:
                pass

        # 2. NVIDIA Nemotron API if key is provided or passed
        effective_key = api_key or self.api_key or os.getenv("NVIDIA_API_KEY") or os.getenv("LLM_API_KEY")
        if effective_key:
            proposal = self.call_nemotron(
                user_id=user_id,
                prompt=prompt,
                api_key=effective_key,
                model=model or self.model,
            )
            if proposal:
                return proposal

        # 3. Deterministic offline fallback (Zero Keys Required)
        return ActionProposer.parse_natural_language(user_id=user_id, text=prompt)

    def call_nemotron(
        self,
        user_id: str,
        prompt: str,
        api_key: str,
        model: Optional[str] = None,
    ) -> Optional[ActionProposal]:
        """Call NVIDIA Nemotron / OpenAI-compatible endpoint with tool definitions."""
        target_model = model or self.model
        headers = {
            "Authorization": f"Bearer {api_key.strip()}",
            "Content-Type": "application/json",
            "User-Agent": "AGENTGATE-Security-Gateway/1.0",
        }
        payload = {
            "model": target_model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are AGENTGATE AI Assistant. You help users interact with protected documents and reports. "
                        "When the user requests an action (reading a document, saving a report, or delivering a report), "
                        "you MUST emit a function call to the corresponding tool. Do not authorize any action yourself."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "tools": NEMOTRON_TOOLS_SCHEMA,
            "tool_choice": "auto",
            "temperature": 0.2,
            "max_tokens": 512,
        }

        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.post(
                    f"{self.base_url.rstrip('/')}/chat/completions",
                    headers=headers,
                    json=payload,
                )

            if resp.status_code == 200:
                data = resp.json()
                choices = data.get("choices", [])
                if choices:
                    message = choices[0].get("message", {})
                    tool_calls = message.get("tool_calls", [])
                    if tool_calls:
                        call = tool_calls[0]
                        tool_name = call.get("function", {}).get("name", "")
                        raw_args = call.get("function", {}).get("arguments", "{}")
                        try:
                            args_dict = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                        except json.JSONDecodeError:
                            args_dict = {}

                        return self.parse_tool_call(
                            user_id=user_id,
                            tool_name=tool_name,
                            arguments=args_dict,
                        )

                    # Model returned text without explicit tool call: attempt fallback parser on content
                    reply_text = message.get("content", "")
                    if reply_text:
                        return ActionProposer.parse_natural_language(user_id=user_id, text=reply_text)

            else:
                logger.warning(
                    "Nemotron API returned HTTP %s: %s. Falling back to deterministic parser.",
                    resp.status_code,
                    resp.text[:200],
                )
        except Exception as exc:
            logger.warning("Error invoking Nemotron NIM (%s). Falling back to deterministic parser.", exc)

        return None

    def parse_tool_call(
        self,
        user_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> Optional[ActionProposal]:
        """Translate structured LLM tool-calling output into an ActionProposal.

        Guarantees that tool calls proposed by an LLM cannot self-authorize.
        """
        tool = tool_name.strip().lower()

        if tool in ("read_document", "read", "view_document"):
            doc_id = arguments.get("document_id") or arguments.get("doc_id") or arguments.get("resource_id", "")
            return ActionProposal(
                proposal_id=f"PROP-NEMO-READ-{uuid.uuid4().hex[:8].upper()}",
                user_id=user_id,
                operation=Operation.READ_DOCUMENT,
                resource_id=str(doc_id).upper(),
                parameters=arguments,
            )

        elif tool in ("save_report", "create_report"):
            report_id = arguments.get("report_id") or f"REP-{uuid.uuid4().hex[:6].upper()}"
            title = arguments.get("title", "Generated Report")
            content = arguments.get("content", "")
            sources = arguments.get("source_doc_ids", [])
            return ActionProposal(
                proposal_id=f"PROP-NEMO-SAVE-{uuid.uuid4().hex[:8].upper()}",
                user_id=user_id,
                operation=Operation.SAVE_REPORT,
                resource_id=str(report_id).upper(),
                parameters={
                    "title": title,
                    "content": content,
                    "source_doc_ids": sources,
                },
            )

        elif tool in ("send_report", "deliver_report", "deliver"):
            report_id = arguments.get("report_id") or arguments.get("resource_id", "")
            recipient_id = arguments.get("recipient_id") or arguments.get("to", "")
            return ActionProposal(
                proposal_id=f"PROP-NEMO-SEND-{uuid.uuid4().hex[:8].upper()}",
                user_id=user_id,
                operation=Operation.SEND_REPORT,
                resource_id=str(report_id).upper(),
                recipient_id=str(recipient_id).upper(),
                parameters=arguments,
            )

        # Generic custom tool proposal
        return ActionProposal(
            proposal_id=f"PROP-NEMO-CUSTOM-{uuid.uuid4().hex[:8].upper()}",
            user_id=user_id,
            operation=Operation.ACCESS_RESOURCE,
            resource_id=tool_name,
            parameters=arguments,
        )

    def summarize_document(self, document_text: str, max_sentences: int = 3) -> str:
        """Deterministic summarizer that extracts key sentences without external APIs."""
        if self.backend == "callable" and self.custom_generator:
            try:
                return self.custom_generator(f"Summarize:\n{document_text}")
            except Exception:
                pass

        lines = [line.strip() for line in document_text.splitlines() if line.strip()]
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
