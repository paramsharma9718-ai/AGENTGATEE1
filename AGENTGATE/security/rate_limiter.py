"""Rate Limiting & Agent Loop Breaker (Denial-of-Wallet Defense) for AGENTGATE.

Module 03 / Core Security:
- Sliding-Window Rate Limiting per user/session.
- Agent Infinite Loop Detection:
    * Repetitive identical invocation loops (calling Op+Resource >= N times).
    * Ping-pong alternation loops (Op A <-> Op B).
- Automated Circuit Breaker:
    * Trips open for a cooldown window upon loop detection.
    * Stops cascading LLM tool-calling costs and resource exhaustion.
- Fail-Closed: Blocks unauthorized or looping proposals before tool execution.
"""

from __future__ import annotations

import collections
import hashlib
import json
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from models.workflow import ActionProposal


class RateLimiter:
    """Thread-safe Rate Limiter and Agent Infinite Loop Circuit Breaker."""

    def __init__(
        self,
        max_requests_per_window: int = 120,
        window_seconds: float = 60.0,
        loop_threshold: int = 4,
        loop_window_seconds: float = 5.0,
        circuit_cooldown_seconds: float = 10.0,
    ):
        self.max_requests_per_window = max_requests_per_window
        self.window_seconds = window_seconds
        self.loop_threshold = loop_threshold
        self.loop_window_seconds = loop_window_seconds
        self.circuit_cooldown_seconds = circuit_cooldown_seconds

        self._lock = threading.RLock()
        # user_id -> deque of timestamps
        self._request_timestamps: Dict[str, collections.deque] = collections.defaultdict(collections.deque)
        # user_id -> deque of (timestamp, operation_str, resource_id, param_hash)
        self._call_history: Dict[str, collections.deque] = collections.defaultdict(
            lambda: collections.deque(maxlen=20)
        )
        # user_id -> cooldown_expiry_timestamp
        self._circuit_open_until: Dict[str, float] = {}
        # Global metrics
        self._total_requests_tracked: int = 0
        self._rate_limits_tripped: int = 0
        self._loops_detected: int = 0

    def _hash_parameters(self, params: Dict[str, Any]) -> str:
        """Create deterministic short hash of parameters for repeat matching."""
        try:
            serialized = json.dumps(params, sort_keys=True, default=str)
            return hashlib.md5(serialized.encode("utf-8")).hexdigest()[:8]
        except Exception:
            return "nohash"

    def is_circuit_open(self, user_id: str, now: Optional[float] = None) -> Tuple[bool, float]:
        """Check if circuit breaker is currently open for user.
        
        Returns (is_open, seconds_remaining).
        """
        now = now or time.time()
        with self._lock:
            expiry = self._circuit_open_until.get(user_id, 0.0)
            if now < expiry:
                return True, round(expiry - now, 2)
            elif user_id in self._circuit_open_until:
                # Expired -> auto reset circuit
                del self._circuit_open_until[user_id]
            return False, 0.0

    def check_proposal(
        self,
        proposal: ActionProposal,
        now: Optional[float] = None,
    ) -> Tuple[bool, Optional[str], str]:
        """Inspect proposal against circuit breaker, loop detection, and rate limits.
        
        Returns:
            (allowed: bool, explanation: Optional[str], reason_code: str)
            reason_code is one of: "ALLOW", "CIRCUIT_BREAKER_OPEN", "RATE_LIMIT_EXCEEDED", "LOOP_DETECTED"
        """
        now = now or time.time()
        user_id = proposal.user_id
        op_val = proposal.operation.value if hasattr(proposal.operation, "value") else str(proposal.operation)
        res_id = proposal.resource_id
        param_hash = self._hash_parameters(proposal.parameters)

        with self._lock:
            # 1. Check if Circuit Breaker is active
            is_open, remaining = self.is_circuit_open(user_id, now)
            if is_open:
                return (
                    False,
                    f"Denial-of-Wallet Defense: Circuit breaker is OPEN for user '{user_id}'. "
                    f"Execution locked for {remaining}s due to detected recursive loop.",
                    "CIRCUIT_BREAKER_OPEN",
                )

            # 2. Check Sliding-Window Rate Limit
            ts_queue = self._request_timestamps[user_id]
            # Prune old timestamps
            cutoff = now - self.window_seconds
            while ts_queue and ts_queue[0] < cutoff:
                ts_queue.popleft()

            if len(ts_queue) >= self.max_requests_per_window:
                self._rate_limits_tripped += 1
                return (
                    False,
                    f"Rate limit exceeded: user '{user_id}' has submitted {len(ts_queue)} requests "
                    f"in the last {int(self.window_seconds)}s (max {self.max_requests_per_window}).",
                    "RATE_LIMIT_EXCEEDED",
                )

            # 3. Check for Agent Infinite Loops
            history = self._call_history[user_id]
            recent_loop_window = now - self.loop_window_seconds

            # Filter calls within loop window
            recent_calls = [c for c in history if c[0] >= recent_loop_window]

            # 3A. Identical Repeated Call Loop
            # Count how many consecutive calls match current (op, resource)
            consecutive_matches = 0
            for ts, past_op, past_res, past_hash in reversed(recent_calls):
                if past_op == op_val and past_res == res_id:
                    consecutive_matches += 1
                else:
                    break

            # If current call would be the loop_threshold-th identical call
            if consecutive_matches + 1 >= self.loop_threshold:
                self._loops_detected += 1
                self._circuit_open_until[user_id] = now + self.circuit_cooldown_seconds
                return (
                    False,
                    f"Denial-of-Wallet Defense: Agent execution loop detected. "
                    f"Operation '{op_val}' on resource '{res_id}' called {consecutive_matches + 1} times "
                    f"within {self.loop_window_seconds}s. Circuit breaker tripped for {int(self.circuit_cooldown_seconds)}s.",
                    "LOOP_DETECTED",
                )

            # 3B. Ping-Pong Loop Detection (e.g. A -> B -> A -> B)
            if len(recent_calls) >= 3:
                last_3 = recent_calls[-3:]
                call_minus_2 = (last_3[0][1], last_3[0][2])  # A
                call_minus_1 = (last_3[1][1], last_3[1][2])  # B
                call_minus_0 = (last_3[2][1], last_3[2][2])  # A
                current_call = (op_val, res_id)              # B

                if (
                    call_minus_1 == current_call
                    and call_minus_2 == call_minus_0
                    and call_minus_0 != current_call
                ):
                    self._loops_detected += 1
                    self._circuit_open_until[user_id] = now + self.circuit_cooldown_seconds
                    return (
                        False,
                        f"Denial-of-Wallet Defense: Ping-pong agent loop detected between '{op_val}' and '{call_minus_0[0]}'. "
                        f"Circuit breaker tripped for {int(self.circuit_cooldown_seconds)}s.",
                        "LOOP_DETECTED",
                    )

            # 4. All checks passed -> Record and allow
            ts_queue.append(now)
            history.append((now, op_val, res_id, param_hash))
            self._total_requests_tracked += 1
            return True, None, "ALLOW"

    def get_metrics(self) -> Dict[str, Any]:
        """Return live telemetry metrics for monitoring dashboards."""
        with self._lock:
            now = time.time()
            active_breakers = {
                uid: round(expiry - now, 1)
                for uid, expiry in self._circuit_open_until.items()
                if expiry > now
            }
            return {
                "total_requests_tracked": self._total_requests_tracked,
                "rate_limits_tripped": self._rate_limits_tripped,
                "loops_detected": self._loops_detected,
                "active_circuit_breakers": active_breakers,
                "config": {
                    "max_requests_per_window": self.max_requests_per_window,
                    "window_seconds": self.window_seconds,
                    "loop_threshold": self.loop_threshold,
                    "loop_window_seconds": self.loop_window_seconds,
                    "circuit_cooldown_seconds": self.circuit_cooldown_seconds,
                },
            }

    def reset(self) -> None:
        """Reset all rate limiting and loop history (for testing)."""
        with self._lock:
            self._request_timestamps.clear()
            self._call_history.clear()
            self._circuit_open_until.clear()
            self._total_requests_tracked = 0
            self._rate_limits_tripped = 0
            self._loops_detected = 0

    def reset_user(self, user_id: str) -> None:
        """Reset history for single user."""
        with self._lock:
            self._request_timestamps.pop(user_id, None)
            self._call_history.pop(user_id, None)
            self._circuit_open_until.pop(user_id, None)


# Default singleton instance
default_rate_limiter = RateLimiter()
