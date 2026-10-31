import json
import os
from pathlib import Path
from typing import Dict, List, Any

from pydantic import BaseModel, Field, RootModel, field_validator

class RoleConfig(BaseModel):
    allowed_operations: List[str] = Field(..., description="Operations permitted for this role")

    @field_validator("allowed_operations", mode="before")
    def validate_operation(cls, v):
        if not isinstance(v, list) or not v:
            raise ValueError("allowed_operations must be a non-empty list")
        for item in v:
            if not item or not isinstance(item, str):
                raise ValueError("operation names must be non‑empty strings")
        return v

class ResourceClassificationConfig(BaseModel):
    allowed_roles: List[str] = Field(..., description="Roles that may access resources of this classification")

    @field_validator("allowed_roles", mode="before")
    def validate_role(cls, v):
        if not isinstance(v, list) or not v:
            raise ValueError("allowed_roles must be a non-empty list")
        for item in v:
            if not item or not isinstance(item, str):
                raise ValueError("role names must be non‑empty strings")
        return v

class RecipientAuthorizationConfig(BaseModel):
    authorized_recipients: List[str] = Field(..., description="Identifiers of recipients allowed to receive reports")

    @field_validator("authorized_recipients", mode="before")
    def validate_recipient(cls, v):
        if not isinstance(v, list) or not v:
            raise ValueError("authorized_recipients must be a non-empty list")
        for item in v:
            if not item or not isinstance(item, str):
                raise ValueError("recipient ids must be non‑empty strings")
        return v

# Approval mapping: operation -> list of classifications needing approval
class ApprovalRequiredConfig(RootModel[Dict[str, List[str]]]):
    @property
    def approvals(self) -> Dict[str, List[str]]:
        return self.root

    def get(self, item: str, default=None) -> List[str]:
        return self.root.get(item, default or [])

    def __getitem__(self, item: str) -> List[str]:
        return self.root.get(item, [])

class PolicyConfig(BaseModel):
    roles: Dict[str, RoleConfig]
    resource_classifications: Dict[str, ResourceClassificationConfig]
    recipient_authorizations: RecipientAuthorizationConfig
    approval_required: ApprovalRequiredConfig

    @field_validator("roles", "resource_classifications", "recipient_authorizations", "approval_required", mode="before")
    def non_empty(cls, v, info):
        if not v:
            raise ValueError(f"{info.field_name} must not be empty")
        return v
