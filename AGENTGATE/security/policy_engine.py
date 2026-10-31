"""Policy Engine – core deterministic policy evaluation.

The engine receives a validated :class:`models.action_request.ActionRequest` and, using the
trusted :mod:`security.policy_manager` and :mod:`security.risk_engine`, determines:

1. Whether the requester's identity and role are known.
2. Whether the requested operation is permitted for that role (RBAC).
3. Whether the target resource's classification allows the role.
4. Whether the recipient (for SEND_REPORT) is authorized.
5. Whether any mandatory prohibitions apply (e.g., modifying classifications).
6. Whether the operation requires additional approval.
7. The risk level/score for the operation.

The result is a tuple ``(decision, risk_level, explanation, approval_required, policy_ref)``
that the higher‑level ``authorization`` module turns into an
:class:`models.action_request.AuthorizationResponse`.

The evaluation follows a **deny‑overrides** strategy:

* Missing/invalid data → ``BLOCK``.
* Any mandatory prohibition → ``BLOCK``.
* If approval is required → ``REQUIRE_APPROVAL``.
* Only when *all* checks pass → ``ALLOW``.
"""

from typing import Tuple, List, Optional

from models.action_request import (
    ActionRequest,
    AuthorizationDecision,
    RiskLevel,
    Operation,
)
from security.policy_manager import (
    get_user_role,
    get_allowed_operations_for_role,
    get_allowed_roles_for_classification,
    is_recipient_authorized,
    get_approval_required_operations,
    validate_policy_integrity,
)
from security.risk_engine import RiskEngine


class PolicyEngine:
    """Encapsulates the deterministic policy evaluation.

    The public method :meth:`evaluate` returns the decision components needed by
    the top‑level authorization function.
    """

    def __init__(self) -> None:
        # Load once; raise if the policy is malformed – fail‑closed.
        if not validate_policy_integrity():
            raise RuntimeError("Policy integrity validation failed – refusing to authorize any request.")
        self.risk_engine = RiskEngine()
        # Mapping of operation -> classifications that need approval (from policy).
        self.approval_map = get_approval_required_operations()

    # ---------------------------------------------------------------------
    # Helper utilities
    # ---------------------------------------------------------------------
    def _resolve_user_role(self, user_id: str) -> Optional[str]:
        return get_user_role(user_id)

    def _is_operation_allowed_for_role(self, role: str, operation: str) -> bool:
        allowed_ops = get_allowed_operations_for_role(role)
        return operation in allowed_ops

    def _is_role_allowed_for_classification(self, role: str, classification: str) -> bool:
        allowed_roles = get_allowed_roles_for_classification(classification)
        return role in allowed_roles

    def _requires_approval(self, operation: str, classification: str) -> bool:
        # The policy may declare that *certain* classifications of an operation need approval.
        classifications = self.approval_map.get(operation, [])
        return classification in classifications

    # ---------------------------------------------------------------------
    # Core evaluation
    # ---------------------------------------------------------------------
    def evaluate(self, request: ActionRequest, resource_classification: str) -> Tuple[
        AuthorizationDecision,
        RiskLevel,
        str,
        bool,
        Optional[str],
    ]:
        """Perform full policy evaluation.

        Parameters
        ----------
        request: ActionRequest
            The incoming request (already validated by Pydantic).
        resource_classification: str
            Classification of the target resource – e.g. ``"public"``, ``"internal"``
            or ``"confidential"``. The caller (policy_engine) is responsible for
            retrieving this metadata from a trusted source.

        Returns
        -------
        tuple
            ``(decision, risk_level, explanation, approval_required, policy_ref)``
        """
        # 1️⃣ Identity validation ------------------------------------------------
        role = self._resolve_user_role(request.user_id)
        if not role:
            return (
                AuthorizationDecision.BLOCK,
                RiskLevel.CRITICAL,
                f"Identity validation failed – unknown user '{request.user_id}'.",
                False,
                None,
            )

        # 2️⃣ Mandatory prohibitions ---------------------------------------------
        if request.operation == Operation.MODIFY_CLASSIFICATION:
            if role != "ADMINISTRATOR":
                return (
                    AuthorizationDecision.BLOCK,
                    RiskLevel.CRITICAL,
                    "Only administrators may modify classifications.",
                    False,
                    None,
                )
            return (
                AuthorizationDecision.REQUIRE_APPROVAL,
                RiskLevel.CRITICAL,
                "Classification modification requires administrator approval.",
                True,
                "policy:modify_classification",
            )

        # 3️⃣ RBAC check -------------------------------------------------------
        if not self._is_operation_allowed_for_role(role, request.operation.value):
            return (
                AuthorizationDecision.BLOCK,
                RiskLevel.HIGH,
                f"Operation '{request.operation.value}' is not permitted for role '{role}'.",
                False,
                None,
            )

        # 4️⃣ Recipient authorization (only relevant for SEND_REPORT) -----------
        if request.operation == Operation.SEND_REPORT:
            if not request.recipient_id:
                return (
                    AuthorizationDecision.BLOCK,
                    RiskLevel.HIGH,
                    "SEND_REPORT operation requires a recipient_id.",
                    False,
                    None,
                )
            if not is_recipient_authorized(request.recipient_id):
                return (
                    AuthorizationDecision.BLOCK,
                    RiskLevel.CRITICAL,
                    f"Recipient '{request.recipient_id}' is not authorized to receive reports.",
                    False,
                    None,
                )

        # 5️⃣ Approval requirement based on policy matrix -----------------------
        approval_needed = self._requires_approval(request.operation.value, resource_classification)

        # 6️⃣ Resource classification check ------------------------------------
        if not self._is_role_allowed_for_classification(role, resource_classification):
            if not approval_needed:
                return (
                    AuthorizationDecision.BLOCK,
                    RiskLevel.CRITICAL,
                    f"Role '{role}' is not authorized to access a '{resource_classification}' resource.",
                    False,
                    None,
                )

        # 7️⃣ Risk evaluation ---------------------------------------------------
        score, level_str, risk_expl, factors = self.risk_engine.evaluate(
            request.operation, resource_classification
        )
        risk_level = RiskLevel[level_str]

        if approval_needed:
            return (
                AuthorizationDecision.REQUIRE_APPROVAL,
                risk_level,
                f"Operation requires additional approval (risk {level_str}).",
                True,
                f"policy:approval:{request.operation.value}:{resource_classification}",
            )

        # 8️⃣ If we reached here, everything is permitted ----------------------
        explanation = (
            f"ALLOW – user '{request.user_id}' (role {role}) is permitted to "
            f"{request.operation.value} on a {resource_classification} resource. "
            f"Risk assessment: {risk_expl}"
        )
        return (
            AuthorizationDecision.ALLOW,
            risk_level,
            explanation,
            False,
            None,
        )

# Export a singleton for ease of use by the top‑level authorization module.
policy_engine = PolicyEngine()
