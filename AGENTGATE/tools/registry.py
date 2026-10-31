"""Extensible Protected Tool Registry for AGENTGATE.

Enables developers and agents to register custom tools with declarative
security policies, automatic ExecutionGateway enforcement, and audit persistence.
"""

from __future__ import annotations

import functools
import inspect
import uuid
from typing import Any, Callable, Dict, List, Optional

from models.action_request import Operation
from models.document_security import Classification
from models.workflow import ActionProposal, ExecutionResult, ExecutionStatus
from tools.execution_gateway import ExecutionGateway, default_execution_gateway


class ToolMetadata:
    """Metadata describing a registered protected tool."""

    def __init__(
        self,
        name: str,
        func: Callable[..., Any],
        operation: Operation,
        required_classification: Classification,
        description: str = "",
    ):
        self.name = name
        self.func = func
        self.operation = operation
        self.required_classification = required_classification
        self.description = description or func.__doc__ or ""
        self.signature = inspect.signature(func)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "operation": self.operation.value,
            "required_classification": self.required_classification.value,
            "description": self.description,
            "parameters": [
                {
                    "name": param.name,
                    "default": None if param.default is inspect.Parameter.empty else str(param.default),
                    "annotation": str(param.annotation) if param.annotation is not inspect.Parameter.empty else "Any",
                }
                for param in self.signature.parameters.values()
            ],
        }


class ProtectedToolRegistry:
    """Central registry for gateway-protected tools."""

    def __init__(self, gateway: Optional[ExecutionGateway] = None):
        self.gateway = gateway or default_execution_gateway
        self._tools: Dict[str, ToolMetadata] = {}

    def register(
        self,
        func: Optional[Callable[..., Any]] = None,
        *,
        name: Optional[str] = None,
        operation: Operation = Operation.ACCESS_RESOURCE,
        required_classification: Classification = Classification.INTERNAL,
        description: str = "",
    ) -> Any:
        """Register a function as a gateway-protected tool."""

        def decorator(f: Callable[..., Any]) -> Callable[..., ExecutionResult]:
            tool_name = name or f.__name__
            meta = ToolMetadata(
                name=tool_name,
                func=f,
                operation=operation,
                required_classification=required_classification,
                description=description,
            )
            self._tools[tool_name] = meta

            @functools.wraps(f)
            def wrapper(*args: Any, **kwargs: Any) -> ExecutionResult:
                # Bind arguments to find user_id if present
                bound = meta.signature.bind_partial(*args, **kwargs)
                bound.apply_defaults()
                user_id = bound.arguments.get("user_id", "UNKNOWN_USER")

                # Build action proposal
                proposal = ActionProposal(
                    proposal_id=f"PROP-TOOL-{uuid.uuid4().hex[:8].upper()}",
                    user_id=user_id,
                    operation=operation,
                    resource_id=tool_name,
                    parameters={
                        "verified_classification": required_classification,
                        "arguments": {k: v for k, v in bound.arguments.items() if k != "user_id"},
                    },
                )

                def _protected_callback() -> Any:
                    return f(*args, **kwargs)

                # Gatekeeper check – fails closed if unauthorized
                return self.gateway.execute_proposal(proposal, _protected_callback)

            wrapper.tool_metadata = meta  # type: ignore[attr-defined]
            return wrapper

        if func is not None:
            return decorator(func)
        return decorator

    def get_tool(self, name: str) -> Optional[ToolMetadata]:
        return self._tools.get(name)

    def list_tools(self) -> List[Dict[str, Any]]:
        return [tool.to_dict() for tool in self._tools.values()]


# Global default registry and decorator
default_tool_registry = ProtectedToolRegistry()
protected_tool = default_tool_registry.register
