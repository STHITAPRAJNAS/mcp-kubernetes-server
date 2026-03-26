"""
Approval workflow for destructive Kubernetes operations.

Design for financial-grade two-person integrity:
─────────────────────────────────────────────────
1. Requester calls a destructive tool → system creates a PendingApproval
   with a short-lived UUID, stores it, and notifies approver(s) via webhook.
2. Server returns: "Approval required. ID=<uuid>. Request sent to #ops-approvals."
3. An approver (different identity) calls approve_operation(approval_id=<uuid>).
4. Requester calls the original destructive tool again with approval_id=<uuid>.
   System validates the approval (not self-approved, not expired) and executes.

Configuration
─────────────
MCP_K8S_REQUIRE_APPROVAL=true          # Enable approval gate
MCP_K8S_APPROVAL_TTL_SECONDS=1800      # Approvals expire after 30 min
MCP_K8S_APPROVAL_WEBHOOK_URL=          # Slack/Teams/SNS endpoint
MCP_K8S_APPROVAL_WEBHOOK_TYPE=slack    # slack | teams | generic
MCP_K8S_APPROVAL_SELF_APPROVE=false    # Allow requester to approve own request

Self-approval is always disabled in production mode regardless of config.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)


@dataclass
class PendingApproval:
    approval_id: str
    operation: str          # e.g. "delete_deployment"
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


class ApprovalError(Exception):
    """Raised when an approval operation fails."""


class ApprovalStore:
    """
    In-memory store for pending approvals with TTL-based eviction.
    For distributed deployments, replace with a Redis or DynamoDB backend.
    """

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
        from datetime import timedelta

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
            approval.approval_id,
            operation,
            resource_kind,
            resource_name,
            requester_identity,
        )
        return approval

    def get(self, approval_id: str) -> PendingApproval | None:
        with self._lock:
            return self._store.get(approval_id)

    def approve(
        self,
        approval_id: str,
        approver_identity: str,
        allow_self_approve: bool = False,
    ) -> PendingApproval:
        with self._lock:
            approval = self._store.get(approval_id)
            if not approval:
                raise ApprovalError(f"Approval ID '{approval_id}' not found.")
            if approval.is_expired:
                raise ApprovalError(
                    f"Approval ID '{approval_id}' has expired. "
                    "Request a new approval."
                )
            if approval.is_denied:
                raise ApprovalError(
                    f"Approval ID '{approval_id}' was already denied."
                )
            if approval.is_approved:
                raise ApprovalError(
                    f"Approval ID '{approval_id}' is already approved."
                )
            if not allow_self_approve and approver_identity == approval.requester_identity:
                raise ApprovalError(
                    "Self-approval is not permitted. "
                    "A different identity must approve this request."
                )
            approval.approver_identity = approver_identity
            approval.approved_at = datetime.now(tz=timezone.utc)
            logger.info(
                "Approval %s approved by %s", approval_id, approver_identity
            )
            return approval

    def deny(
        self,
        approval_id: str,
        approver_identity: str,
        reason: str = "",
    ) -> PendingApproval:
        with self._lock:
            approval = self._store.get(approval_id)
            if not approval:
                raise ApprovalError(f"Approval ID '{approval_id}' not found.")
            if approval.is_expired:
                raise ApprovalError(f"Approval ID '{approval_id}' has expired.")
            if approval.is_approved:
                raise ApprovalError(
                    f"Approval ID '{approval_id}' is already approved and cannot be denied."
                )
            approval.denied_at = datetime.now(tz=timezone.utc)
            approval.denial_reason = reason
            logger.info(
                "Approval %s denied by %s: %s", approval_id, approver_identity, reason
            )
            return approval

    def consume(self, approval_id: str) -> PendingApproval | None:
        """Remove an approval from the store after it has been used."""
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
    Sends approval request notifications to Slack, Teams, or a generic HTTP endpoint.
    """

    def __init__(self, webhook_url: str, webhook_type: str = "slack") -> None:
        self._webhook_url = webhook_url
        self._webhook_type = webhook_type.lower()

    def notify_requested(self, approval: PendingApproval) -> None:
        if not self._webhook_url:
            return
        try:
            payload = self._build_payload(approval, event="requested")
            self._post(payload)
        except Exception as exc:
            logger.warning("Failed to send approval notification: %s", exc)

    def notify_approved(self, approval: PendingApproval) -> None:
        if not self._webhook_url:
            return
        try:
            payload = self._build_payload(approval, event="approved")
            self._post(payload)
        except Exception as exc:
            logger.warning("Failed to send approval notification: %s", exc)

    def notify_denied(self, approval: PendingApproval) -> None:
        if not self._webhook_url:
            return
        try:
            payload = self._build_payload(approval, event="denied")
            self._post(payload)
        except Exception as exc:
            logger.warning("Failed to send approval notification: %s", exc)

    def _build_payload(self, approval: PendingApproval, event: str) -> dict:
        icons = {"requested": "⚠️", "approved": "✅", "denied": "❌"}
        icon = icons.get(event, "ℹ️")
        resource = f"{approval.resource_kind}/{approval.resource_name}"
        ns = f" in `{approval.namespace}`" if approval.namespace else ""
        cluster = approval.cluster

        if self._webhook_type == "slack":
            color = {"requested": "warning", "approved": "good", "denied": "danger"}.get(event, "#999")
            return {
                "attachments": [{
                    "color": color,
                    "title": f"{icon} Kubernetes Approval {event.upper()}",
                    "fields": [
                        {"title": "Operation", "value": approval.operation, "short": True},
                        {"title": "Resource", "value": f"`{resource}`{ns}", "short": True},
                        {"title": "Cluster", "value": cluster, "short": True},
                        {"title": "Requester", "value": approval.requester_identity, "short": True},
                        {"title": "Approval ID", "value": f"`{approval.approval_id}`", "short": False},
                        {"title": "Expires", "value": approval.expires_at.strftime("%Y-%m-%d %H:%M UTC"), "short": True},
                    ],
                    "footer": "MCP Kubernetes Server | Approval Workflow",
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
                        {"name": "Cluster", "value": cluster},
                        {"name": "Requester", "value": approval.requester_identity},
                        {"name": "Approval ID", "value": approval.approval_id},
                        {"name": "Expires", "value": approval.expires_at.strftime("%Y-%m-%d %H:%M UTC")},
                    ],
                }],
            }
        else:
            # Generic JSON
            return {
                "event": event,
                "approval_id": approval.approval_id,
                "operation": approval.operation,
                "resource_kind": approval.resource_kind,
                "resource_name": approval.resource_name,
                "namespace": approval.namespace,
                "cluster": cluster,
                "requester": approval.requester_identity,
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
        """Create an approval request and notify approvers."""
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
        """
        Check that an approval_id is valid for this specific operation.
        Returns (is_valid, error_message).
        """
        approval = self._store.get(approval_id)
        if not approval:
            return False, f"Approval ID '{approval_id}' not found or has expired."
        if not approval.is_approved:
            return False, (
                f"Approval '{approval_id}' status is '{approval.status}'. "
                "Approval must be in 'approved' state."
            )
        # Verify it matches the requested operation (prevent approval reuse)
        if approval.operation != operation:
            return False, (
                f"Approval '{approval_id}' was granted for operation '{approval.operation}', "
                f"not '{operation}'."
            )
        if approval.resource_name != resource_name:
            return False, (
                f"Approval '{approval_id}' was granted for resource '{approval.resource_name}', "
                f"not '{resource_name}'."
            )
        if approval.namespace != namespace:
            return False, (
                f"Approval '{approval_id}' was granted for namespace '{approval.namespace}', "
                f"not '{namespace}'."
            )
        if approval.cluster != cluster:
            return False, (
                f"Approval '{approval_id}' was granted for cluster '{approval.cluster}', "
                f"not '{cluster}'."
            )
        return True, ""

    def consume_approval(self, approval_id: str) -> None:
        """Remove approval after use (one-time use)."""
        self._store.consume(approval_id)

    def approve(self, approval_id: str, approver_identity: str) -> PendingApproval:
        approval = self._store.approve(
            approval_id, approver_identity, self._allow_self_approve
        )
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
    allow_self_approve: bool = False,
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
