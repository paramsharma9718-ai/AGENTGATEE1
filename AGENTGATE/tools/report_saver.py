"""Protected Report Saver Tool for AGENTGATE.

Security Guarantees:
- Saving a report CANNOT bypass the Centralized Execution Gateway.
- Preserves security classification and provenance metadata via Module 02 (Information-Flow Control).
- A derived report inherits the strictest classification from its source documents.
- A BLOCKED save operation never writes files or updates persistence (no side-effects).
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from models.action_request import Operation
from models.document_security import (
    Classification,
    DocumentSecurityMetadata,
    TransformationType,
)
from models.workflow import ActionProposal, ExecutionResult
from security.dlp_engine import inspect_content
from security.provenance import register_derivation
from storage.audit_logger import AuditLogger, default_audit_logger
from storage.document_registry import DocumentRegistry, default_document_registry
from tools.execution_gateway import ExecutionGateway, default_execution_gateway


class ReportSaver:
    """Protected tool for saving derived reports through the Execution Gateway."""

    def __init__(
        self,
        gateway: Optional[ExecutionGateway] = None,
        registry: Optional[DocumentRegistry] = None,
        audit_logger: Optional[AuditLogger] = None,
        storage_dir: Optional[str] = None,
    ):
        self.gateway = gateway or default_execution_gateway
        self.registry = registry or default_document_registry
        self.audit_logger = audit_logger or default_audit_logger

        if storage_dir is None:
            self.storage_dir = Path(__file__).resolve().parent.parent / "data" / "reports"
        else:
            self.storage_dir = Path(storage_dir)

        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def save_report(
        self,
        user_id: str,
        report_id: str,
        title: str,
        content: str,
        source_doc_ids: List[str],
        transformation_type: TransformationType = TransformationType.SUMMARIZATION,
    ) -> ExecutionResult:
        """Derive security classification and save report via the security gateway."""
        # 1. Retrieve source metadata for strict provenance and inheritance
        sources_meta: List[DocumentSecurityMetadata] = []
        for s_id in source_doc_ids:
            s_meta = self.registry.get_document_metadata(s_id)
            if not s_meta:
                # Check if it was a previously saved report
                saved = self.audit_logger.get_saved_report(s_id)
                if saved:
                    s_meta = DocumentSecurityMetadata(
                        document_id=s_id,
                        classification=Classification(saved["classification"].upper()),
                    )
            if s_meta:
                sources_meta.append(s_meta)

        if not sources_meta:
            # If no sources provided, treat as empty or invalid sources
            return ExecutionResult(
                proposal_id=f"PROP-SAVE-{uuid.uuid4().hex[:8].upper()}",
                status=ExecutionStatus.FAILED,
                operation=Operation.SAVE_REPORT,
                resource_id=report_id,
                user_id=user_id,
                error_message="Cannot save report: At least one valid source document is required for derivation.",
            )

        # 2. Derive classification and lineage record via Module 02
        derived_artifact = register_derivation(
            report_id=report_id,
            sources=sources_meta,
            transformation_type=transformation_type,
        )

        # 3. Perform DLP Content Inspection (defense-in-depth)
        dlp_result = inspect_content(content)

        # 4. Create ActionProposal with verified classification
        proposal = ActionProposal(
            proposal_id=f"PROP-SAVE-{uuid.uuid4().hex[:8].upper()}",
            user_id=user_id,
            operation=Operation.SAVE_REPORT,
            resource_id=report_id,
            parameters={
                "title": title,
                "verified_classification": derived_artifact.security.classification,
                "source_doc_ids": source_doc_ids,
                "dlp_status": dlp_result.status.value,
            },
        )

        # 5. Define protected callback for writing to disk and SQLite
        def _protected_save_callback() -> Dict[str, Any]:
            report_file = self.storage_dir / f"{report_id}.json"
            report_data = {
                "report_id": report_id,
                "title": title,
                "content": content,
                "classification": derived_artifact.security.classification.value,
                "created_by": user_id,
                "sources": source_doc_ids,
                "provenance": derived_artifact.provenance.model_dump(mode="json"),
                "security_metadata": derived_artifact.security.model_dump(mode="json"),
            }

            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)

            self.audit_logger.record_saved_report(
                report_id=report_id,
                title=title,
                file_path=str(report_file),
                classification=derived_artifact.security.classification.value,
                created_by=user_id,
                sources=source_doc_ids,
                provenance_dict=derived_artifact.provenance.model_dump(mode="json"),
            )

            return {
                "report_id": report_id,
                "file_path": str(report_file),
                "classification": derived_artifact.security.classification.value,
                "status": "SAVED",
            }

        return self.gateway.execute_proposal(proposal, _protected_save_callback)


# Default singleton instance
default_report_saver = ReportSaver()
