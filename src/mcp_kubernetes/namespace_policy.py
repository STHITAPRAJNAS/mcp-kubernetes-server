"""
Namespace-level write scoping policy.

Problem with a single ClusterRole
──────────────────────────────────
The Kubernetes RBAC ClusterRole grants blanket write access to all namespaces.
In a financial firm you want:
  - App engineers for team A → can write only to team-a-* namespaces
  - SRE on-call → can write to all namespaces except prod
  - Prod deploy pipeline → can write to prod-* but requires approval for deletes

This module enforces a second layer of access control at the MCP layer,
BEFORE the Kubernetes API is ever called.

Configuration
─────────────
Loaded from the MCP_K8S_NAMESPACE_POLICY env var as a JSON array, or from
a file at MCP_K8S_NAMESPACE_POLICY_FILE.

Policy schema (JSON):
[
  {
    "identity_patterns": ["arn:aws:iam::*/role/AppEngineer-TeamA"],
    "allowed_namespaces": ["team-a-*", "team-a-dev"],
    "allowed_operations": ["READ", "WRITE"],
    "require_approval_for": ["DELETE", "SCALE_TO_ZERO"]
  },
  {
    "identity_patterns": ["arn:aws:iam::*/role/SREOnCall", "*sre*"],
    "allowed_namespaces": ["*"],
    "denied_namespaces": ["prod-*"],
    "allowed_operations": ["READ", "WRITE", "DELETE", "EXEC"],
    "require_approval_for": []
  }
]

Matching rules
──────────────
- identity_patterns: fnmatch-style glob against the IAM ARN or kubeconfig user
- allowed_namespaces: fnmatch globs; "*" matches all
- denied_namespaces: explicit overrides that always deny even if allowed_namespaces matches
- allowed_operations: READ | WRITE | DELETE | EXEC | SCALE_TO_ZERO
- If no policy matches the identity, the default_policy applies
  (default: READ only for unrecognized identities)
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class Operation(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"
    EXEC = "EXEC"
    SCALE_TO_ZERO = "SCALE_TO_ZERO"


@dataclass
class NamespacePolicy:
    """Single policy rule binding identity patterns to allowed operations."""

    identity_patterns: list[str]
    allowed_namespaces: list[str]
    allowed_operations: list[Operation]
    denied_namespaces: list[str] = field(default_factory=list)
    require_approval_for: list[Operation] = field(default_factory=list)
    description: str = ""

    def matches_identity(self, identity: str) -> bool:
        for pattern in self.identity_patterns:
            if fnmatch.fnmatch(identity, pattern) or fnmatch.fnmatch(identity.lower(), pattern.lower()):
                return True
        return False

    def allows_namespace(self, namespace: str | None) -> bool:
        """Check if this policy permits access to the namespace."""
        if namespace is None:
            # Cluster-scoped resource — check with special sentinel
            namespace = "__cluster__"

        # Denied namespaces take precedence
        for pattern in self.denied_namespaces:
            if fnmatch.fnmatch(namespace, pattern):
                return False

        for pattern in self.allowed_namespaces:
            if pattern == "*" or fnmatch.fnmatch(namespace, pattern):
                return True

        return False

    def allows_operation(self, operation: Operation) -> bool:
        return operation in self.allowed_operations

    def needs_approval(self, operation: Operation) -> bool:
        return operation in self.require_approval_for


@dataclass
class PolicyDecision:
    allowed: bool
    needs_approval: bool = False
    reason: str = ""
    matched_policy: NamespacePolicy | None = None

    @classmethod
    def permit(cls, policy: NamespacePolicy | None = None) -> "PolicyDecision":
        return cls(allowed=True, needs_approval=False, matched_policy=policy)

    @classmethod
    def permit_with_approval(cls, policy: NamespacePolicy) -> "PolicyDecision":
        return cls(
            allowed=True,
            needs_approval=True,
            reason="Operation requires approval per namespace policy",
            matched_policy=policy,
        )

    @classmethod
    def deny(cls, reason: str) -> "PolicyDecision":
        return cls(allowed=False, needs_approval=False, reason=reason)


class NamespacePolicyEngine:
    """
    Evaluates namespace-level access policies for a given identity.

    Policy evaluation order:
    1. Find all matching policies (identity pattern match)
    2. Use the FIRST matching policy (most specific wins — put specific roles first)
    3. If no policy matches, apply default_policy
    """

    # Safe read-only default — unrecognised identities get read only
    _DEFAULT_POLICY = NamespacePolicy(
        identity_patterns=["*"],
        allowed_namespaces=["*"],
        denied_namespaces=[],
        allowed_operations=[Operation.READ],
        require_approval_for=[],
        description="Default: read-only for unrecognized identities",
    )

    def __init__(self, policies: list[NamespacePolicy], deny_unknown: bool = False) -> None:
        self._policies = policies
        # If deny_unknown=True, unknown identities get nothing (not even reads)
        self._deny_unknown = deny_unknown

    def evaluate(
        self,
        identity: str,
        namespace: str | None,
        operation: Operation,
    ) -> PolicyDecision:
        """
        Evaluate whether identity can perform operation on namespace.

        Returns a PolicyDecision with allowed, needs_approval, and reason.
        """
        # Find first matching policy
        matched = None
        for policy in self._policies:
            if policy.matches_identity(identity):
                matched = policy
                break

        if matched is None:
            if self._deny_unknown:
                return PolicyDecision.deny(
                    f"Identity '{identity}' does not match any namespace policy. "
                    "Access denied."
                )
            else:
                matched = self._DEFAULT_POLICY

        # Check namespace access
        if not matched.allows_namespace(namespace):
            ns_str = namespace or "cluster-scoped"
            return PolicyDecision.deny(
                f"Identity '{identity}' is not permitted to access namespace "
                f"'{ns_str}' per policy: {matched.description or 'unnamed policy'}. "
                f"Allowed namespace patterns: {matched.allowed_namespaces}"
            )

        # Check operation permission
        if not matched.allows_operation(operation):
            return PolicyDecision.deny(
                f"Identity '{identity}' is not permitted to perform "
                f"'{operation.value}' operations. "
                f"Allowed: {[op.value for op in matched.allowed_operations]}"
            )

        # Check if approval is required
        if matched.needs_approval(operation):
            return PolicyDecision.permit_with_approval(matched)

        return PolicyDecision.permit(matched)

    @classmethod
    def from_json(cls, json_data: list[dict], deny_unknown: bool = False) -> "NamespacePolicyEngine":
        policies = []
        for entry in json_data:
            try:
                policy = NamespacePolicy(
                    identity_patterns=entry.get("identity_patterns", ["*"]),
                    allowed_namespaces=entry.get("allowed_namespaces", ["*"]),
                    denied_namespaces=entry.get("denied_namespaces", []),
                    allowed_operations=[
                        Operation(op) for op in entry.get("allowed_operations", ["READ"])
                    ],
                    require_approval_for=[
                        Operation(op) for op in entry.get("require_approval_for", [])
                    ],
                    description=entry.get("description", ""),
                )
                policies.append(policy)
            except (KeyError, ValueError) as exc:
                logger.warning("Skipping invalid policy entry: %s — %s", entry, exc)
        return cls(policies, deny_unknown=deny_unknown)

    @classmethod
    def from_config(cls, settings: Any) -> "NamespacePolicyEngine":
        """Load policy from settings (env var or file)."""
        raw_json = getattr(settings, "namespace_policy", "") or ""
        policy_file = getattr(settings, "namespace_policy_file", "") or ""

        if policy_file and Path(policy_file).exists():
            raw_json = Path(policy_file).read_text()
            logger.info("Loaded namespace policy from file: %s", policy_file)

        if raw_json:
            try:
                data = json.loads(raw_json)
                engine = cls.from_json(data, deny_unknown=getattr(settings, "namespace_policy_deny_unknown", False))
                logger.info("Loaded %d namespace policy rule(s)", len(engine._policies))
                return engine
            except json.JSONDecodeError as exc:
                logger.error("Invalid namespace policy JSON: %s", exc)

        # No policy configured — permissive (rely on Kubernetes RBAC)
        logger.info("No namespace policy configured — relying on Kubernetes RBAC only")
        return cls([], deny_unknown=False)


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------
_policy_engine: NamespacePolicyEngine | None = None


def get_policy_engine() -> NamespacePolicyEngine:
    global _policy_engine
    if _policy_engine is None:
        # Return permissive engine if not initialized
        _policy_engine = NamespacePolicyEngine([])
    return _policy_engine


def initialize_policy_engine(settings: Any) -> NamespacePolicyEngine:
    global _policy_engine
    _policy_engine = NamespacePolicyEngine.from_config(settings)
    return _policy_engine


def check_namespace_access(
    identity: str,
    namespace: str | None,
    operation: Operation,
) -> PolicyDecision:
    """Convenience function used by tools."""
    return get_policy_engine().evaluate(identity, namespace, operation)
