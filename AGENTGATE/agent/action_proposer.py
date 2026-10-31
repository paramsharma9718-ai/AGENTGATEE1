"""Action Proposal Generator for AGENTGATE Module 03.

Security Guarantees:
- Translates user intent into validated ActionProposal structures.
- NEVER authorizes actions. Action proposals contain NO authorization decisions.
- Untrusted prompts (e.g. prompt injections in documents) cannot insert trusted authorization.
"""

from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List, Optional

from models.action_request import Operation
from models.workflow import ActionProposal


class ActionProposer:
    """Translates user requests into structured action proposals without authorization."""

    @staticmethod
    def propose_read(user_id: str, document_id: str) -> ActionProposal:
        """Create a structured proposal to read a document."""
        return ActionProposal(
            proposal_id=f"PROP-READ-{uuid.uuid4().hex[:8].upper()}",
            user_id=user_id,
            operation=Operation.READ_DOCUMENT,
            resource_id=document_id,
        )

    @staticmethod
    def propose_save_report(
        user_id: str,
        report_id: str,
        title: str,
        content: str,
        source_doc_ids: List[str],
    ) -> ActionProposal:
        """Create a structured proposal to save a derived report."""
        return ActionProposal(
            proposal_id=f"PROP-SAVE-{uuid.uuid4().hex[:8].upper()}",
            user_id=user_id,
            operation=Operation.SAVE_REPORT,
            resource_id=report_id,
            parameters={
                "title": title,
                "content": content,
                "source_doc_ids": source_doc_ids,
            },
        )

    @staticmethod
    def propose_send_report(
        user_id: str,
        report_id: str,
        recipient_id: str,
    ) -> ActionProposal:
        """Create a structured proposal to deliver a report to a recipient."""
        return ActionProposal(
            proposal_id=f"PROP-SEND-{uuid.uuid4().hex[:8].upper()}",
            user_id=user_id,
            operation=Operation.SEND_REPORT,
            resource_id=report_id,
            recipient_id=recipient_id,
        )

    @classmethod
    def parse_natural_language(cls, user_id: str, text: str) -> Optional[ActionProposal]:
        """Deterministic natural-language intent parser.
        
        Extracts structured intent without granting authorization.
        """
        lower = text.strip().lower()

        # Pattern: read document / doc <id>
        read_match = re.search(r"(?:read|view|get)\s+(?:document|doc)?\s*([a-zA-Z0-9_\-]+)", lower)
        if read_match and not ("save" in lower or "send" in lower or "deliver" in lower):
            doc_id = read_match.group(1).upper()
            return cls.propose_read(user_id=user_id, document_id=doc_id)

        # Pattern: deliver / send report <id> to <recipient>
        send_match = re.search(
            r"(?:send|deliver)\s+(?:report\s+)?([a-zA-Z0-9_\-]+)\s+to\s+([a-zA-Z0-9_\-]+)",
            lower,
        )
        if send_match:
            report_id = send_match.group(1).upper()
            recipient_id = send_match.group(2).upper()
            return cls.propose_send_report(
                user_id=user_id,
                report_id=report_id,
                recipient_id=recipient_id,
            )

        # Pattern: save report <id> from <source_id>
        save_match = re.search(
            r"save\s+(?:report\s+)?([a-zA-Z0-9_\-]+)\s+from\s+([a-zA-Z0-9_\-]+)",
            lower,
        )
        if save_match:
            report_id = save_match.group(1).upper()
            source_id = save_match.group(2).upper()
            return cls.propose_save_report(
                user_id=user_id,
                report_id=report_id,
                title=f"Report {report_id}",
                content=f"Summary of document {source_id}",
                source_doc_ids=[source_id],
            )

        return None
