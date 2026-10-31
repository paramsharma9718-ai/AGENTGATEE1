"""Document Management and Ingestion Service for AGENTGATE.

Module 04: Application, Database, Dashboard & Monitoring (Param)

Features:
- Secure ingestion of PDF, DOCX, and TXT files.
- Automated Data Loss Prevention (DLP) inspection via Module 02 DLPEngine.
- Automated security classification suggestion based on detected risk.
- Path-traversal proof storage outside web roots.
- Integration with DocumentRegistry and ExecutionGateway for authorization.
"""

from __future__ import annotations

import io
import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from models.action_request import Operation
from models.document_security import Classification, DocumentSecurityMetadata, LabelOrigin
from models.workflow import ActionProposal, ExecutionStatus
from security.dlp_engine import inspect_content, redact_text
from storage.document_registry import DocumentRegistry, default_document_registry
from tools.execution_gateway import ExecutionGateway, default_execution_gateway

# Parsers
try:
    import pypdf
except ImportError:
    pypdf = None

try:
    import docx
except ImportError:
    docx = None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DocumentService:
    """Manages document uploads, automated DLP scanning, and metadata persistence."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        registry: Optional[DocumentRegistry] = None,
        gateway: Optional[ExecutionGateway] = None,
    ):
        if db_path is None:
            base_dir = Path(__file__).resolve().parent.parent / "data"
            base_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = str(base_dir / "agentgate.db")
        else:
            self.db_path = db_path

        self.registry = registry or default_document_registry
        self.gateway = gateway or default_execution_gateway
        self._lock = threading.RLock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS documents_metadata (
                        document_id TEXT PRIMARY KEY,
                        original_filename TEXT NOT NULL,
                        file_type TEXT NOT NULL,
                        file_size_bytes INTEGER NOT NULL,
                        classification TEXT NOT NULL,
                        uploaded_by TEXT NOT NULL,
                        upload_date TEXT NOT NULL,
                        description TEXT,
                        dlp_findings_count INTEGER NOT NULL,
                        dlp_summary_json TEXT,
                        stored_path TEXT NOT NULL
                    )
                """)
                conn.commit()
            self._sync_default_documents()

    def _sync_default_documents(self) -> None:
        """Ensure initial seed documents are tracked in metadata table."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                for doc_id, meta in self.registry._metadata_registry.items():
                    cursor.execute("SELECT document_id FROM documents_metadata WHERE document_id = ?", (doc_id,))
                    if not cursor.fetchone():
                        doc_path = self.registry.storage_dir / f"{doc_id}.txt"
                        size = doc_path.stat().st_size if doc_path.exists() else 0
                        cursor.execute(
                            """
                            INSERT INTO documents_metadata (
                                document_id, original_filename, file_type, file_size_bytes,
                                classification, uploaded_by, upload_date, description,
                                dlp_findings_count, dlp_summary_json, stored_path
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                doc_id,
                                f"{doc_id}.txt",
                                "TXT",
                                size,
                                meta.classification.value,
                                "SYSTEM",
                                utc_now_iso(),
                                f"System Default {meta.classification.value} Document",
                                0,
                                "[]",
                                str(doc_path),
                            ),
                        )
                conn.commit()

    def extract_text(self, filename: str, file_bytes: bytes) -> str:
        """Safely extract plain text from TXT, PDF, or DOCX bytes."""
        ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""

        if ext == "txt":
            try:
                return file_bytes.decode("utf-8")
            except UnicodeDecodeError:
                return file_bytes.decode("latin-1", errors="replace")

        elif ext == "pdf":
            if not pypdf:
                raise RuntimeError("pypdf is not installed on system.")
            reader = pypdf.PdfReader(io.BytesIO(file_bytes))
            text_parts = []
            for page in reader.pages:
                extracted = page.extract_text()
                if extracted:
                    text_parts.append(extracted)
            return "\n\n".join(text_parts)

        elif ext == "docx":
            if not docx:
                raise RuntimeError("python-docx is not installed on system.")
            doc = docx.Document(io.BytesIO(file_bytes))
            return "\n".join([p.text for p in doc.paragraphs if p.text])

        else:
            raise ValueError(f"Unsupported file format '.{ext}'. Supported: TXT, PDF, DOCX")

    def inspect_and_suggest_classification(self, text: str) -> Tuple[Classification, List[Dict[str, Any]]]:
        """Run Module 02 DLP inspection and suggest classification level."""
        dlp_result = inspect_content(text)
        findings = []

        has_credentials = False
        has_pii_or_financial = False
        has_confidential_marking = False
        has_restricted_marking = False

        for f in dlp_result.findings:
            findings.append({
                "rule_id": f.rule_id,
                "category": f.category.value if hasattr(f.category, "value") else str(f.category),
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "confidence": f.confidence.value if hasattr(f.confidence, "value") else f.confidence,
                "line": f.line,
                "redacted": getattr(f, "redacted_preview", getattr(f, "redacted_value", "")),
            })
            cat = str(f.category.value if hasattr(f.category, "value") else f.category).lower()
            rule = f.rule_id.lower()

            if "credential" in cat or "key" in rule or "secret" in rule:
                has_credentials = True
            elif "pii" in cat or "financial" in cat or "ssn" in rule or "pan" in rule or "aadhaar" in rule:
                has_pii_or_financial = True
            elif "restricted" in rule or "restricted" in cat:
                has_restricted_marking = True
            elif "confidential" in rule or "confidential" in cat:
                has_confidential_marking = True

        # Classification Hierarchy: PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED
        if has_credentials or has_restricted_marking:
            suggested = Classification.RESTRICTED
        elif has_pii_or_financial or has_confidential_marking:
            suggested = Classification.CONFIDENTIAL
        elif len(findings) > 0:
            suggested = Classification.INTERNAL
        else:
            suggested = Classification.PUBLIC

        return suggested, findings

    def upload_document(
        self,
        filename: str,
        file_bytes: bytes,
        uploaded_by: str,
        user_role: str,
        description: str = "",
        override_classification: Optional[Classification] = None,
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Validate, inspect, store and register a new document."""
        if not file_bytes:
            return False, "File is empty.", None

        if len(file_bytes) > 10 * 1024 * 1024:
            return False, "File exceeds maximum size limit of 10MB.", None

        # Sanitize filename
        safe_name = os.path.basename(filename)
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", safe_name)

        try:
            text_content = self.extract_text(safe_name, file_bytes)
        except Exception as e:
            return False, f"Failed to extract document content: {str(e)}", None

        # Run DLP Scan
        suggested_class, dlp_findings = self.inspect_and_suggest_classification(text_content)

        # Final classification selection
        final_class = override_classification or suggested_class

        # Generate Document ID
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT count(*) as count FROM documents_metadata")
                cnt = cursor.fetchone()["count"]
                doc_id = f"DOC-{100 + cnt}"

        # Register in DocumentRegistry (Safe Storage)
        meta = self.registry.register_document(
            document_id=doc_id,
            classification=final_class,
            content=text_content,
        )

        doc_path = self.registry.storage_dir / f"{doc_id}.txt"
        now_str = utc_now_iso()

        # Record in SQLite Metadata table
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO documents_metadata (
                        document_id, original_filename, file_type, file_size_bytes,
                        classification, uploaded_by, upload_date, description,
                        dlp_findings_count, dlp_summary_json, stored_path
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        doc_id,
                        safe_name,
                        safe_name.rsplit(".", 1)[-1].upper(),
                        len(file_bytes),
                        final_class.value,
                        uploaded_by,
                        now_str,
                        description,
                        len(dlp_findings),
                        json.dumps(dlp_findings),
                        str(doc_path),
                    ),
                )
                conn.commit()

        redacted_text = ""
        if dlp_findings:
            try:
                dlp_res = inspect_content(text_content)
                redacted_text = redact_text(text_content, dlp_res)
            except Exception:
                pass

        result_dict = {
            "document_id": doc_id,
            "filename": safe_name,
            "classification": final_class.value,
            "suggested_classification": suggested_class.value,
            "dlp_findings": dlp_findings,
            "redacted_content": redacted_text,
            "uploaded_by": uploaded_by,
            "upload_date": now_str,
        }
        return True, f"Document '{safe_name}' uploaded and classified as {final_class.value}!", result_dict

    def list_documents(self) -> List[Dict[str, Any]]:
        """Return all documents with complete security metadata."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM documents_metadata ORDER BY upload_date DESC")
                rows = cursor.fetchall()
                results = []
                for row in rows:
                    item = dict(row)
                    if item.get("dlp_summary_json"):
                        try:
                            item["dlp_findings"] = json.loads(item["dlp_summary_json"])
                        except Exception:
                            item["dlp_findings"] = []
                    else:
                        item["dlp_findings"] = []
                    results.append(item)
                return results

    def get_document_content(self, document_id: str, requesting_user_id: str) -> Tuple[bool, str, str, str]:
        """Authorize and retrieve document content through ExecutionGateway."""
        import uuid
        proposal = ActionProposal(
            proposal_id=f"PROP-READ-{uuid.uuid4().hex[:8].upper()}",
            user_id=requesting_user_id,
            operation=Operation.READ_DOCUMENT,
            resource_id=document_id,
        )

        def _read_cb():
            content, meta = self.registry.read_document_content(document_id)
            return {"content": content, "classification": meta.classification.value}

        exec_res = self.gateway.execute_proposal(proposal, _read_cb)

        if exec_res.status == ExecutionStatus.SUCCESS:
            return True, exec_res.output["content"], exec_res.output["classification"], "ALLOW"

        expl = exec_res.authorization_response.explanation if exec_res.authorization_response else exec_res.error_message
        dec = exec_res.authorization_response.decision.value if exec_res.authorization_response else "BLOCK"
        return False, f"ACCESS DENIED: Role not authorized to read {document_id}. Reason: {expl}", "", dec

    def delete_document(self, document_id: str, requesting_user_id: str, user_role: str) -> Tuple[bool, str]:
        """Delete document with authorization check."""
        if user_role != "ADMINISTRATOR":
            return False, "Access Denied: Only administrators can delete registered documents."

        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT stored_path FROM documents_metadata WHERE document_id = ?", (document_id,))
                row = cursor.fetchone()
                if not row:
                    return False, f"Document '{document_id}' not found."

                stored_path = row["stored_path"]
                cursor.execute("DELETE FROM documents_metadata WHERE document_id = ?", (document_id,))
                conn.commit()

            # Remove from registry dict
            self.registry._metadata_registry.pop(document_id, None)

            # Remove file if exists
            try:
                p = Path(stored_path)
                if p.exists():
                    p.unlink()
            except Exception:
                pass

            return True, f"Document '{document_id}' successfully deleted."


# Default singleton instance
default_document_service = DocumentService()
