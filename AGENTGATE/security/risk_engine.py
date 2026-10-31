"""Risk evaluation engine for AGENTGATE core security module.

Provides a deterministic risk scoring based on operation type, resource
classification and other factors. The engine never overrides mandatory
policy prohibitions – it only adds a *risk level* that influences whether the
final decision may be ALLOW, BLOCK or REQUIRE_APPROVAL.
"""

from enum import Enum
from typing import Tuple, List

from models.action_request import Operation

# Mapping of (operation, classification) -> (numeric score, risk level, factors)
_RISK_MATRIX = {
    (Operation.READ_DOCUMENT, "public"): (10, "LOW", ["public document read"]),
    (Operation.READ_DOCUMENT, "internal"): (30, "MEDIUM", ["internal document read"]),
    (Operation.READ_DOCUMENT, "confidential"): (70, "HIGH", ["confidential document read"]),
    (Operation.SAVE_REPORT, "public"): (15, "LOW", ["public report save"]),
    (Operation.SAVE_REPORT, "internal"): (35, "MEDIUM", ["internal report save"]),
    (Operation.SAVE_REPORT, "confidential"): (75, "HIGH", ["confidential report save"]),
    (Operation.SEND_REPORT, "public"): (20, "LOW", ["public report send"]),
    (Operation.SEND_REPORT, "internal"): (45, "MEDIUM", ["internal report send"]),
    (Operation.SEND_REPORT, "confidential"): (90, "CRITICAL", ["confidential report send"]),
    (Operation.ACCESS_RESOURCE, "public"): (10, "LOW", ["public resource access"]),
    (Operation.ACCESS_RESOURCE, "internal"): (40, "MEDIUM", ["internal resource access"]),
    (Operation.ACCESS_RESOURCE, "confidential"): (85, "HIGH", ["confidential resource access"]),
    (Operation.MODIFY_CLASSIFICATION, "any"): (95, "CRITICAL", ["classification modification"]),
}

class RiskEngine:
    """Encapsulates risk calculation logic.

    The public method :meth:`evaluate` returns a tuple of (score, level, explanation,
    factors). All inputs are validated by the caller.
    """

    @staticmethod
    def _lookup(operation: Operation, classification: str) -> Tuple[int, str, List[str]]:
        key = (operation, classification)
        if key not in _RISK_MATRIX:
            # Fallback for unknown combos – treat as high risk.
            return 80, "HIGH", ["unknown operation/classification combo"]
        return _RISK_MATRIX[key]

    def evaluate(self, operation: Operation, classification: str) -> Tuple[int, str, str, List[str]]:
        """Calculate risk for a given operation and resource classification.

        Returns:
            score (int): numeric risk score 0‑100.
            level (str): one of ``LOW``, ``MEDIUM``, ``HIGH`` or ``CRITICAL``.
            explanation (str): human‑readable description.
            factors (list[str]): list of risk factors that contributed.
        """
        score, level, factors = self._lookup(operation, classification)
        explanation = f"Risk {level} (score {score}) for operation {operation.value} on {classification} resource."
        return score, level, explanation, factors
