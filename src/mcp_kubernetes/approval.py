"""
Approval workflow for destructive Kubernetes operations.

Two modes
─────────
INLINE (default):
  The approval prompt is returned directly in the MCP conversation.
  The agent surfaces it to the human user who says yes/no.
  The agent then calls approve_operation() or deny_operation().
  No external systems needed. The HUMAN is the approver; the agent is
  just the messenger between the tool and the user.

  Flow:
    1. Agent calls delete_deployment(...)
    2. Server returns a structured approval prompt with approval_id
    3. Agent shows it to the human: "I need your approval. Proceed? (yes/no)"
    4. Human says yes → agent calls approve_operation(approval_id=...)
    5. Agent calls delete_deployment(..., approval_id=...) → executes

WEBHOOK (optional add-on):
  Also send a notification to Slack/Teams/generic HTTP so a team channel
  gets visibility even when approval happens inline. Set
  MCP_K8S_APPROVAL_WEBHOOK_URL to enable.

Configuration
─────────────
MCP_K8S_REQUIRE_APPROVAL=true          # Enable approval gate
MCP_K8S_APPROVAL_TTL_SECONDS=1800      # Approvals expire after 30 min
MCP_K8S_APPROVAL_WEBHOOK_URL=          # Optional: Slack/Teams/SNS for visibility
MCP_K8S_APPROVAL_WEBHOOK_TYPE=slack    # slack | teams | generic
MCP_K8S_APPROVAL_ALLOW_SELF_APPROVE=true  # Default true for inline mode
                                           # (human in loop = effective approval)
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)


@dataclass
class PendingApproval:
    approval_id: str
    operation: str
    resource_kind: str
    resource_name: str
    namespace: str | None
    cluster: str
    requester_identity: str
    requested_at: datetime
    expires_at: datetime
    approver_identity: str | None = None
    approved_at: datetime | None = None
    denied_at: datetime | None = None
    denial_reason: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        return datetime.now(tz=timezone.utc) >= self.expires_at

    @property
    def is_approved(self) -> bool:
        return self.approved_at is not None and not self.is_expired

    @property
    def is_denied(self) -> bool:
        return self.denied_at is not None

    @property
    def status(self) -> str:
        if self.is_denied:
            return "denied"
        if self.is_expired:
            return "expired"
        if self.is_approved:
            return "approved"
        return "pending"

    def to_display(self) -> str:
        lines = [
            f"Approval ID: {self.approval_id}",
            f"  Status:    {self.status.upper()}",
            f"  Operation: {self.operation}",
            f"  Resource:  {self.resource_kind}/{self.resource_name}"
            + (f" in '{self.namespace}'" if self.namespace else ""),
            f"  Cluster:   {self.cluster}",
            f"  Requester: {self.requester_identity}",
            f"  Requested: {self.requested_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"  Expires:   {self.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        ]
        if self.approver_identity:
            lines.append(f"  Approver:  {self.approver_identity}")
        if self.denial_reason:
            lines.append(f"  Reason:    {self.denial_reason}")
        return "\n".join(lines)

    def to_inline_prompt(self) -> str:
        """
        Returns the structured approval prompt surfaced directly in the
        MCP conversation. The agent must show this to the human user and
        wait for explicit confirmation before calling approve_operation().
        """
        resource = f"{self.resource_kind}/{self.resource_name}"
        ns_str = f" in namespace '{self.namespace}'" if self.namespace else " (cluster-scoped)"
        cluster_str = self.cluster
        ttl_min = int((self.expires_at - datetime.now(tz=timezone.utc)).total_seconds() // 60)

        impact = _describe_impact(self.operation, self.resource_kind)

        lines = [
            "━" * 60,
            "⚠️  APPROVAL REQUIRED — DESTRUCTIVE OPERATION",
            "━" * 60,
            f"  Operation : {self.operation.upper()}",
            f"  Resource  : {resource}{ns_str}",
            f"  Cluster   : {cluster_str}",
            f"  Requested by: {self.requester_identity}",
            "",
        ]
        if impact:
            lines += [f"  Impact    : {impact}", ""]
        lines += [
            f"  Approval ID : {self.approval_id}",
            f"  Expires in  : {ttl_min} minutes",
            "",
            "  To APPROVE → call: approve_operation(approval_id='%s')" % self.approval_id,
            "  To DENY    → call: deny_operation(approval_id='%s')" % self.approval_id,
            "",
            "  ⚠️  Ask the human user for explicit confirmation before approving.",
            "━" * 60,
        ]
        return "\n".join(lines)


def _describe_impact(operation: str, resource_kind: str) -> str:
    """Return a plain-English impact description for common operations."""
    op = operation.lower()
    kind = resource_kind.lower()
    if "delete" in op:
        impacts = {
            "namespace": "ALL resources in this namespace will be permanently deleted (pods, deployments, services, secrets, PVCs).",
            "deployment": "All pods for this deployment will be terminated. The application will become unavailable.",
            "pod": "Pod will be terminated. It will be recreated by its controller unless it is standalone.",
            "service": "Network connectivity to the associated pods will be broken. LoadBalancer resources will be deleted.",
            "configmap": "Applications referencing this ConfigMap may fail to start or crash.",
        }
        return impacts.get(kind, f"The {resource_kind} will be permanently removed.")
    if "scale" in op:
        return "Replica count will change. Scaling to 0 makes the application unavailable."
    if "rollback" in op:
        return "Deployment will be rolled back to a previous revision. Current pods will be replaced."
    return ""


class ApprovalError(Exception):
    """Raised when an approval operation fails."""


class ApprovalStore:
    """Thread-safe in-memory store for pending approvals with TTL eviction."""

    def __init__(self) -> None:
        self._store: dict[str, PendingApproval] = {}
        self._lock = threading.Lock()

    def create(
        self,
        operation: str,
        resource_kind: str,
        resource_name: str,
        namespace: str | None,
        cluster: str,
        requester_identity: str,
        ttl_seconds: int = 1800,
        extra: dict | None = None,
    ) -> PendingApproval:
        now = datetime.now(tz=timezone.utc)
        approval = PendingApproval(
            approval_id=str(uuid4()),
            operation=operation,
            resource_kind=resource_kind,
            resource_name=resource_name,
            namespace=namespace,
            cluster=cluster,
            requester_identity=requester_identity,
            requested_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            extra=extra or {},
        )
        with self._lock:
            self._evict_expired()
            self._store[approval.approval_id] = approval

        logger.info(
            "Created approval request %s for %s %s/%s by %s",
            approval.approval_id, operation, resource_kind, resource_name, requester_identity,
        )
        return approval

    def get(self, approval_id: str) -> PendingApproval | None:
        with self._lock:
            return self._store.get(approval_id)

    def approve(self, approval_id: str, approver_identity: str, allow_self_approve: bool = True) -> PendingApproval:
        with self._lock:
            approval = self._store.get(approval_id)
            if not approval:
                raise ApprovalError(f"Approval ID '{approval_id}' not found or has expired.")
            if approval.is_expired:
                raise ApprovalError(f"Approval ID '{approval_id}' has expired. Request a new approval.")
            if approval.is_denied:
                raise ApprovalError(f"Approval ID '{approval_id}' was already denied.")
            if approval.is_approved:
                raise ApprovalError(f"Approval ID '{approval_id}' is already approved.")
            # Self-approval check: only block if explicitly configured AND this is an
            # external workflow. In inline mode (human-in-the-loop), the agent calling
            # approve() on behalf of the human is always allowed.
            if not allow_self_approve and approver_identity == approval.requester_identity:
                raise ApprovalError(
                    "Self-approval is not permitted. "
                    "A different identity must approve this request."
                )
            approval.approver_identity = approver_identity
            approval.approved_at = datetime.now(tz=timezone.utc)
            logger.info("Approval %s approved by %s", approval_id, approver_identity)
            return approval

    def deny(self, approval_id: str, approver_identity: str, reason: str = "") -> PendingApproval:
        with self._lock:
            approval = self._store.get(approval_id)
            if not approval:
                raise ApprovalError(f"Approval ID '{approval_id}' not found.")
            if approval.is_expired:
                raise ApprovalError(f"Approval ID '{approval_id}' has expired.")
            if approval.is_approved:
                raise ApprovalError(f"Approval '{approval_id}' is already approved and cannot be denied.")
            approval.denied_at = datetime.now(tz=timezone.utc)
            approval.denial_reason = reason
            logger.info("Approval %s denied by %s: %s", approval_id, approver_identity, reason)
            return approval

    def consume(self, approval_id: str) -> PendingApproval | None:
        """Remove approval after use — approvals are single-use."""
        with self._lock:
            return self._store.pop(approval_id, None)

    def list_pending(self) -> list[PendingApproval]:
        with self._lock:
            self._evict_expired()
            return [a for a in self._store.values() if a.status == "pending"]

    def _evict_expired(self) -> None:
        now = datetime.now(tz=timezone.utc)
        expired = [k for k, v in self._store.items() if v.expires_at <= now]
        for k in expired:
            del self._store[k]


class WebhookNotifier:
    """
    Optional: send approval notifications to Slack/Teams/generic HTTP.
    Used for team visibility even when approval happens inline in the conversation.
    """

    def __init__(self, webhook_url: str, webhook_type: str = "slack") -> None:
        self._webhook_url = webhook_url
        self._webhook_type = webhook_type.lower()

    def notify_requested(self, approval: PendingApproval) -> None:
        if not self._webhook_url:
            return
        try:
            self._post(self._build_payload(approval, "requested"))
        except Exception as exc:
            logger.warning("Failed to send approval webhook notification: %s", exc)

    def notify_approved(self, approval: PendingApproval) -> None:
        if not self._webhook_url:
            return
        try:
            self._post(self._build_payload(approval, "approved"))
        except Exception as exc:
            logger.warning("Failed to send approval webhook notification: %s", exc)

    def notify_denied(self, approval: PendingApproval) -> None:
        if not self._webhook_url:
            return
        try:
            self._post(self._build_payload(approval, "denied"))
        except Exception as exc:
            logger.warning("Failed to send approval webhook notification: %s", exc)

    def _build_payload(self, approval: PendingApproval, event: str) -> dict:
        icons = {"requested": "⚠️", "approved": "✅", "denied": "❌"}
        icon = icons.get(event, "ℹ️")
        resource = f"{approval.resource_kind}/{approval.resource_name}"
        ns = f" in `{approval.namespace}`" if approval.namespace else ""

        if self._webhook_type == "slack":
            color = {"requested": "warning", "approved": "good", "denied": "danger"}.get(event, "#999")
            return {
                "attachments": [{
                    "color": color,
                    "title": f"{icon} Kubernetes Approval {event.upper()} (inline conversation)",
                    "fields": [
                        {"title": "Operation", "value": approval.operation, "short": True},
                        {"title": "Resource", "value": f"`{resource}`{ns}", "short": True},
                        {"title": "Cluster", "value": approval.cluster, "short": True},
                        {"title": "Requester", "value": approval.requester_identity, "short": True},
                        {"title": "Approval ID", "value": f"`{approval.approval_id}`", "short": False},
                        {"title": "Approver", "value": approval.approver_identity or "—", "short": True},
                    ],
                    "footer": "MCP Kubernetes Server | Human-in-the-loop approval",
                }]
            }
        elif self._webhook_type == "teams":
            return {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": {"requested": "FF8C00", "approved": "00CC00", "denied": "CC0000"}.get(event, "999999"),
                "summary": f"Kubernetes Approval {event.upper()}",
                "sections": [{
                    "activityTitle": f"{icon} Kubernetes Approval {event.upper()}",
                    "facts": [
                        {"name": "Operation", "value": approval.operation},
                        {"name": "Resource", "value": f"{resource}{ns}"},
                        {"name": "Cluster", "value": approval.cluster},
                        {"name": "Requester", "value": approval.requester_identity},
                        {"name": "Approval ID", "value": approval.approval_id},
                        {"name": "Approver", "value": approval.approver_identity or "—"},
                    ],
                }],
            }
        else:
            return {
                "event": event,
                "approval_id": approval.approval_id,
                "operation": approval.operation,
                "resource_kind": approval.resource_kind,
                "resource_name": approval.resource_name,
                "namespace": approval.namespace,
                "cluster": approval.cluster,
                "requester": approval.requester_identity,
                "approver": approval.approver_identity,
                "expires_at": approval.expires_at.isoformat(),
            }

    def _post(self, payload: dict) -> None:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self._webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5):
            pass


class ApprovalManager:
    """
    High-level approval workflow manager used by destructive tools.

    In inline mode (default):
    - Approval prompt is returned directly in the MCP conversation
    - The agent surfaces it to the human user
    - Human says yes → agent calls approve_operation()
    - self_approve=True because the agent IS acting on behalf of the human

    In webhook mode (optional add-on):
    - Also sends notification to configured channel for team visibility
    - Approval still happens inline (the channel notification is informational)
    """

    def __init__(
        self,
        require_approval: bool,
        ttl_seconds: int,
        webhook_url: str,
        webhook_type: str,
        allow_self_approve: bool,
    ) -> None:
        self._require_approval = require_approval
        self._ttl = ttl_seconds
        # In inline (human-in-loop) mode self-approve is always True.
        # The human is the real approver; the agent is just calling the API on their behalf.
        self._allow_self_approve = allow_self_approve
        self._store = ApprovalStore()
        self._notifier = WebhookNotifier(webhook_url, webhook_type) if webhook_url else None

    @property
    def require_approval(self) -> bool:
        return self._require_approval

    def request_approval(
        self,
        operation: str,
        resource_kind: str,
        resource_name: str,
        namespace: str | None,
        cluster: str,
        requester_identity: str,
        extra: dict | None = None,
    ) -> PendingApproval:
        """Create an approval request. Returns a PendingApproval whose
        to_inline_prompt() is surfaced directly in the MCP conversation."""
        approval = self._store.create(
            operation=operation,
            resource_kind=resource_kind,
            resource_name=resource_name,
            namespace=namespace,
            cluster=cluster,
            requester_identity=requester_identity,
            ttl_seconds=self._ttl,
            extra=extra,
        )
        # Optional: also notify webhook for team visibility
        if self._notifier:
            self._notifier.notify_requested(approval)
        return approval

    def validate_approval(
        self,
        approval_id: str,
        operation: str,
        resource_name: str,
        namespace: str | None,
        cluster: str,
    ) -> tuple[bool, str]:
        """Check that an approval_id is valid for this specific operation."""
        approval = self._store.get(approval_id)
        if not approval:
            return False, f"Approval ID '{approval_id}' not found or has expired."
        if not approval.is_approved:
            return False, (
                f"Approval '{approval_id}' is in '{approval.status}' state. "
                "It must be approved first via approve_operation()."
            )
        # Verify it matches exactly — prevent approval reuse across different operations
        if approval.operation != operation:
            return False, f"Approval was granted for '{approval.operation}', not '{operation}'."
        if approval.resource_name != resource_name:
            return False, f"Approval was granted for resource '{approval.resource_name}', not '{resource_name}'."
        if approval.namespace != namespace:
            return False, f"Approval was granted for namespace '{approval.namespace}', not '{namespace}'."
        if approval.cluster != cluster:
            return False, f"Approval was granted for cluster '{approval.cluster}', not '{cluster}'."
        return True, ""

    def consume_approval(self, approval_id: str) -> None:
        """Remove approval after use (single-use)."""
        self._store.consume(approval_id)

    def approve(self, approval_id: str, approver_identity: str) -> PendingApproval:
        approval = self._store.approve(approval_id, approver_identity, self._allow_self_approve)
        if self._notifier:
            self._notifier.notify_approved(approval)
        return approval

    def deny(self, approval_id: str, approver_identity: str, reason: str = "") -> PendingApproval:
        approval = self._store.deny(approval_id, approver_identity, reason)
        if self._notifier:
            self._notifier.notify_denied(approval)
        return approval

    def list_pending(self) -> list[PendingApproval]:
        return self._store.list_pending()

    def get(self, approval_id: str) -> PendingApproval | None:
        return self._store.get(approval_id)


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------
_approval_manager: ApprovalManager | None = None


def get_approval_manager() -> ApprovalManager:
    if _approval_manager is None:
        raise RuntimeError("ApprovalManager not initialized.")
    return _approval_manager


def initialize_approval_manager(
    require_approval: bool = False,
    ttl_seconds: int = 1800,
    webhook_url: str = "",
    webhook_type: str = "slack",
    allow_self_approve: bool = True,  # Default True for inline human-in-loop mode
) -> ApprovalManager:
    global _approval_manager
    _approval_manager = ApprovalManager(
        require_approval=require_approval,
        ttl_seconds=ttl_seconds,
        webhook_url=webhook_url,
        webhook_type=webhook_type,
        allow_self_approve=allow_self_approve,
    )
    return _approval_manager
