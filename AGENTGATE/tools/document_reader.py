"""Protected Document Reader Tool for AGENTGATE.

Security Guarantees:
- Document reading CANNOT bypass the Centralized Execution Gateway.
- Does not trust user-supplied paths; relies exclusively on the Document Registry.
- A BLOCKED read operation never touches the filesystem or reads raw bytes.
- Returns content along with the verified DocumentSecurityMetadata from Module 02.
"""

from __future__ import annotations

import uuid
from typing import Optional, Tuple

from models.action_request import Operation
from models.document_security import DocumentSecurityMetadata
from models.workflow import ActionProposal, ExecutionResult
from storage.document_registry import DocumentRegistry, default_document_registry
from tools.execution_gateway import ExecutionGateway, default_execution_gateway


class DocumentReader:
    """Protected tool for reading documents through the Execution Gateway."""

    def __init__(
        self,
        gateway: Optional[ExecutionGateway] = None,
        registry: Optional[DocumentRegistry] = None,
    ):
        self.gateway = gateway or default_execution_gateway
        self.registry = registry or default_document_registry

    def read_document(self, user_id: str, document_id: str) -> ExecutionResult:
        """Attempt to read a document through the security gateway.
        
        The underlying filesystem read is encapsulated in a protected callback
        that the gateway ONLY invokes if authorization permits.
        """
        proposal = ActionProposal(
            proposal_id=f"PROP-READ-{uuid.uuid4().hex[:8].upper()}",
            user_id=user_id,
            operation=Operation.READ_DOCUMENT,
            resource_id=document_id,
        )

        def _protected_read_callback() -> Tuple[str, DocumentSecurityMetadata]:
            # This line will NEVER run if the gateway rejects or holds the request
            content, metadata = self.registry.read_document_content(document_id)
            return {
                "document_id": document_id,
                "content": content,
                "classification": metadata.classification.value,
                "metadata": metadata.model_dump(mode="json"),
            }

        return self.gateway.execute_proposal(proposal, _protected_read_callback)


# Default singleton instance
default_document_reader = DocumentReader()
