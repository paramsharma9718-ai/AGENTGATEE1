import enum
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator

class UserRole(str, enum.Enum):
    ADMINISTRATOR = "ADMINISTRATOR"
    AUTHORIZED_USER = "AUTHORIZED_USER"
    RESTRICTED_USER = "RESTRICTED_USER"

class Operation(str, enum.Enum):
    READ_DOCUMENT = "READ_DOCUMENT"
    SAVE_REPORT = "SAVE_REPORT"
    SEND_REPORT = "SEND_REPORT"
    ACCESS_RESOURCE = "ACCESS_RESOURCE"
    MODIFY_CLASSIFICATION = "MODIFY_CLASSIFICATION"

class RiskLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AuthorizationDecision(str, enum.Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"

class ActionRequest(BaseModel):
    request_id: str = Field(..., description="Unique identifier for the request")
    user_id: str = Field(..., description="Identifier of the requesting user")
    operation: Operation = Field(..., description="Requested operation")
    resource_id: str = Field(..., description="Target resource identifier")
    recipient_id: Optional[str] = Field(None, description="Recipient identifier when applicable")
    requested_at: datetime = Field(default_factory=datetime.utcnow, description="Timestamp of request creation")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Optional additional metadata")

    @field_validator("request_id", "user_id", "resource_id")
    def non_empty_strings(cls, v, info):
        field_name = info.field_name
        if not v or not isinstance(v, str) or not v.strip():
            raise ValueError(f"{field_name} must be a non‑empty string")
        return v

class AuthorizationResponse(BaseModel):
    request_id: str
    decision: AuthorizationDecision
    risk_level: RiskLevel
    explanation: str
    approval_required: bool = False
    policy_reference: Optional[str] = None
    user_id: str
    operation: Operation
    resource_id: str
    # optional fields for future extensions
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None

    @field_validator("explanation")
    def non_empty_explanation(cls, v, info):
        if not v or not v.strip():
            raise ValueError("explanation must be a non‑empty string")
        return v
