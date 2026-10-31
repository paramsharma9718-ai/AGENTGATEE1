"""Central Authorization Interface for AGENTGATE Core Security Module.

This module provides the public ``authorize_action`` function that the rest of the
system (protected tools, playground, etc.) will call. It orchestrates the full
authorisation workflow:

1. Validate the incoming :class:`models.action_request.ActionRequest` (Pydantic
   already performed basic validation at construction time).
2. Resolve the *trusted* user role via :func:`security.policy_manager.get_user_role`.
3. Retrieve the resource classification from the request metadata – the caller
   must supply a trustworthy ``classification`` field (e.g. ``"public"``,
   ``"internal"`` or ``"confidential"``). If the classification is missing or
   unknown, the engine fails closed.
4. Invoke the deterministic :class:`security.policy_engine.PolicyEngine` to
   obtain the decision components (decision, risk level, explanation, approval
   flag, optional policy reference).
5. Populate and return a :class:`models.action_request.AuthorizationResponse`
   that includes all relevant fields for downstream consumers.

The function never trusts any role or decision provided by the AI‑generated
request – only the trusted policy manager and the static policy configuration
are used.
"""

from typing import Optional

from models.action_request import ActionRequest, AuthorizationResponse, AuthorizationDecision, RiskLevel
from security import policy_engine


def _extract_classification(request: ActionRequest) -> Optional[str]:
    """Extract a trusted resource classification from the request.

    The calling code must provide ``request.metadata['classification']`` – this
    value is considered trusted because the request originates from the
    protected tool layer, not from an untrusted LLM output. If the field is
    missing or empty, the request is blocked.
    """
    if not request.metadata:
        return None
    classification = request.metadata.get("classification")
    if isinstance(classification, str) and classification.strip():
        return classification.strip()
    return None


def authorize_action(request: ActionRequest) -> AuthorizationResponse:
    """Public entry point – evaluate an :class:`ActionRequest`.

    Returns an :class:`AuthorizationResponse` containing the decision, risk
    level, human‑readable explanation, and additional context.
    """
    # 1️⃣ Resolve classification – required for policy and risk evaluation.
    classification = _extract_classification(request)
    if not classification:
        # Missing classification => fail closed.
        return AuthorizationResponse(
            request_id=request.request_id,
            decision=AuthorizationDecision.BLOCK,
            risk_level=RiskLevel.CRITICAL,
            explanation="Resource classification missing or invalid – request blocked.",
            approval_required=False,
            policy_reference=None,
            user_id=request.user_id,
            operation=request.operation,
            resource_id=request.resource_id,
        )

    # 2️⃣ Perform policy evaluation via the singleton engine.
    decision, risk_level, explanation, approval_required, policy_ref = policy_engine.policy_engine.evaluate(
        request, classification
    )

    # 3️⃣ Build the response object.
    response = AuthorizationResponse(
        request_id=request.request_id,
        decision=decision,
        risk_level=risk_level,
        explanation=explanation,
        approval_required=approval_required,
        policy_reference=policy_ref,
        user_id=request.user_id,
        operation=request.operation,
        resource_id=request.resource_id,
    )
    return response

# Export the function for external modules.
__all__ = ["authorize_action"]
