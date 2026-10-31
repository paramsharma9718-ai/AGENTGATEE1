"""Unified models package for AGENTGATE.
Combines:
- Module 01: ActionRequest, AuthorizationResponse, AuthorizationDecision, Operation, RiskLevel, UserRole
- Module 02: Classification, DocumentSecurityMetadata, ProvenanceRecord, DLPFinding, etc.
- Module 03: ActionProposal, ExecutionResult, ExecutionStatus, WorkflowState, WorkflowStatus, WorkflowStep
"""

from models.action_request import (
    ActionRequest,
    AuthorizationResponse,
    AuthorizationDecision,
    Operation,
    RiskLevel,
    UserRole,
)
from models.policy import (
    RoleConfig,
    ResourceClassificationConfig,
    RecipientAuthorizationConfig,
    ApprovalRequiredConfig,
    PolicyConfig,
)
from models.document_security import (
    Classification,
    DocumentSecurityMetadata,
    SourceReference,
    ProvenanceRecord,
    TransformationType,
    DLPFinding,
    DLPInspectionResult,
    Severity,
    InspectionStatus,
    DLPCategory,
    ClassificationChangeRequest,
    ClassificationChangeDecision,
    TrustedAuthorizationResult,
    ChangeReason,
    ChangeStatus,
)
from models.workflow import (
    ActionProposal,
    ExecutionResult,
    ExecutionStatus,
    WorkflowState,
    WorkflowStatus,
    WorkflowStep,
)

__all__ = [
    # Module 01
    "ActionRequest",
    "AuthorizationResponse",
    "AuthorizationDecision",
    "Operation",
    "RiskLevel",
    "UserRole",
    "RoleConfig",
    "ResourceClassificationConfig",
    "RecipientAuthorizationConfig",
    "ApprovalRequiredConfig",
    "PolicyConfig",
    # Module 02
    "Classification",
    "DocumentSecurityMetadata",
    "SourceReference",
    "ProvenanceRecord",
    "TransformationType",
    "DLPFinding",
    "DLPInspectionResult",
    "Severity",
    "InspectionStatus",
    "DLPCategory",
    "ClassificationChangeRequest",
    "ClassificationChangeDecision",
    "TrustedAuthorizationResult",
    "ChangeReason",
    "ChangeStatus",
    # Module 03
    "ActionProposal",
    "ExecutionResult",
    "ExecutionStatus",
    "WorkflowState",
    "WorkflowStatus",
    "WorkflowStep",
]
