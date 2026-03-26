"""
Destructive operation tools with enterprise-grade safety guards.

SAFETY LAYERS (applied in order):
──────────────────────────────────
1. Global kill switch      MCP_K8S_ALLOW_DESTRUCTIVE=false → blocks everything
2. Protected namespace     kube-system etc. always blocked
3. Namespace policy        Identity → namespace scope check (MCP layer RBAC)
4. Confirmation token      confirm_name must equal resource name exactly
5. Approval workflow       MCP_K8S_REQUIRE_APPROVAL=true → out-of-band approval
6. Kubernetes RBAC         Final enforcement by the API server itself

Any layer can veto. All operations are audit-logged.
"""

from __future__ import annotations

import logging
from typing import Annotated

from kubernetes.client.rest import ApiException

from ..approval import get_approval_manager, ApprovalError
from ..audit import get_audit_logger
from ..cluster_pool import resolve_manager
from ..config import get_settings
from ..k8s_client import handle_k8s_api_error
from ..models import OperationResult
from ..namespace_policy import check_namespace_access, Operation

logger = logging.getLogger(__name__)


def _run_safety_checks(
    settings,
    namespace: str | None,
    resource_kind: str,
    resource_name: str,
    confirm_name: str,
    dry_run: bool,
    identity: str,
    cluster: str,
    operation: Operation,
    approval_id: str = "",
) -> str | None:
    """
    Run all safety layers. Returns an error string if blocked, None if allowed.
    Also returns a special sentinel "__needs_approval__:<uuid>" when an approval
    request was created.
    """
    # Layer 1: Global kill switch
    if not settings.allow_destructive and not dry_run:
        return (
            "Destructive operations are disabled globally. "
            "Set MCP_K8S_ALLOW_DESTRUCTIVE=true to enable."
        )

    # Layer 2: Protected namespaces
    if namespace and settings.is_protected_namespace(namespace):
        return (
            f"Namespace '{namespace}' is in the protected list "
            f"({', '.join(settings.protected_namespaces)}). "
            "Destructive operations are blocked."
        )

    # Layer 3: Namespace-level write scoping policy
    if not dry_run:
        decision = check_namespace_access(identity, namespace, operation)
        if not decision.allowed:
            return f"Namespace policy denied: {decision.reason}"
        # If policy says approval required, fall through to approval layer

    # Layer 4: Confirmation token
    if settings.require_destructive_confirmation and not dry_run:
        if confirm_name != resource_name:
            return (
                f"Confirmation required: pass confirm_name='{resource_name}' "
                f"(the exact resource name). You passed: '{confirm_name}'"
            )

    # Layer 5: Approval workflow
    if settings.require_approval and not dry_run:
        approval_mgr = get_approval_manager()

        if approval_id:
            # Validate the provided approval
            valid, err = approval_mgr.validate_approval(
                approval_id,
                operation=_operation_tool_name(operation, resource_kind),
                resource_name=resource_name,
                namespace=namespace,
                cluster=cluster,
            )
            if not valid:
                return f"Approval validation failed: {err}"
            # Consume approval (one-time use)
            approval_mgr.consume_approval(approval_id)
        else:
            # Also check if namespace policy requires approval
            policy_decision = check_namespace_access(identity, namespace, operation)

            if approval_mgr.require_approval or policy_decision.needs_approval:
                # Create a new approval request
                approval = approval_mgr.request_approval(
                    operation=_operation_tool_name(operation, resource_kind),
                    resource_kind=resource_kind,
                    resource_name=resource_name,
                    namespace=namespace,
                    cluster=cluster,
                    requester_identity=identity,
                )
                return (
                    f"__needs_approval__:{approval.approval_id}:"
                    f"Approval required for {operation.value} on "
                    f"{resource_kind}/{resource_name}"
                    + (f" in '{namespace}'" if namespace else "")
                    + f". Approval ID: {approval.approval_id}\n"
                    f"An approval request has been sent to your configured channel.\n"
                    f"Once approved, re-run this command with approval_id='{approval.approval_id}'."
                )

    return None  # All checks passed


def _operation_tool_name(operation: Operation, resource_kind: str) -> str:
    return f"{operation.value.lower()}_{resource_kind.lower()}"


def _format_approval_needed(sentinel: str) -> str:
    """Convert the internal sentinel into a user-facing message."""
    # sentinel format: "__needs_approval__:<uuid>:<message>"
    parts = sentinel.split(":", 2)
    if len(parts) == 3:
        return parts[2]
    return sentinel


def register_destructive_tools(mcp) -> None:
    """Register destructive operation MCP tools with all safety guards."""

    @mcp.tool
    def delete_pod(
        name: Annotated[str, "Name of the pod to delete"],
        namespace: Annotated[str, "Namespace of the pod"] = "default",
        confirm_name: Annotated[str, "SAFETY: Re-enter the pod name to confirm deletion"] = "",
        dry_run: Annotated[bool, "If true, simulate without deleting"] = False,
        grace_period_seconds: Annotated[int, "Graceful termination period (0 = force delete)"] = 30,
        approval_id: Annotated[str, "Approval ID from a prior approval request (if required)"] = "",
        cluster: Annotated[str, "Target cluster name or alias (uses default if empty)"] = "",
    ) -> str:
        """
        Delete a pod. The pod will be recreated by its controller unless standalone.

        DESTRUCTIVE — requires all safety layers to pass:
        1. confirm_name must match pod name exactly
        2. Namespace must not be protected
        3. Namespace policy must permit DELETE for your identity
        4. approval_id required if approval workflow is enabled

        Tip: use dry_run=true first to verify the operation.
        """
        settings = get_settings()
        manager = resolve_manager(cluster)
        audit = get_audit_logger()
        is_dry_run = dry_run or settings.dry_run

        error = _run_safety_checks(
            settings, namespace, "Pod", name, confirm_name, is_dry_run,
            manager.current_identity, manager.current_cluster,
            Operation.DELETE, approval_id,
        )
        if error:
            if error.startswith("__needs_approval__"):
                msg = _format_approval_needed(error)
                audit.log_delete("delete_pod", "Pod", name, namespace, manager.current_identity, manager.current_cluster, False, error="pending_approval")
                return msg
            audit.log_delete("delete_pod", "Pod", name, namespace, manager.current_identity, manager.current_cluster, False, error=error)
            return f"Error: {error}"

        try:
            from kubernetes import client as k8s_client
            core = manager.core_v1()
            dry_run_param = ["All"] if is_dry_run else None
            delete_options = k8s_client.V1DeleteOptions(grace_period_seconds=grace_period_seconds)
            core.delete_namespaced_pod(name=name, namespace=namespace, body=delete_options, dry_run=dry_run_param)

            result = OperationResult(
                success=True, operation="delete", resource_kind="Pod",
                resource_name=name, namespace=namespace,
                message=f"Pod '{name}' deleted (grace period: {grace_period_seconds}s)",
                dry_run=is_dry_run,
            )
            audit.log_delete("delete_pod", "Pod", name, namespace, manager.current_identity, manager.current_cluster, True, dry_run=is_dry_run)
            return result.to_text()

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "delete_pod")
            audit.log_delete("delete_pod", "Pod", name, namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def delete_deployment(
        name: Annotated[str, "Name of the deployment to delete"],
        namespace: Annotated[str, "Namespace of the deployment"] = "default",
        confirm_name: Annotated[str, "SAFETY: Re-enter the deployment name to confirm"] = "",
        dry_run: Annotated[bool, "If true, simulate without deleting"] = False,
        approval_id: Annotated[str, "Approval ID from a prior approval request (if required)"] = "",
        cluster: Annotated[str, "Target cluster name or alias"] = "",
    ) -> str:
        """
        Delete a deployment and all pods it manages.

        WARNING: Application becomes unavailable immediately.
        Consider scale_deployment to 0 as a safer alternative.

        DESTRUCTIVE — requires confirmation + optional approval workflow.
        """
        settings = get_settings()
        manager = resolve_manager(cluster)
        audit = get_audit_logger()
        is_dry_run = dry_run or settings.dry_run

        error = _run_safety_checks(
            settings, namespace, "Deployment", name, confirm_name, is_dry_run,
            manager.current_identity, manager.current_cluster,
            Operation.DELETE, approval_id,
        )
        if error:
            if error.startswith("__needs_approval__"):
                return _format_approval_needed(error)
            audit.log_delete("delete_deployment", "Deployment", name, namespace, manager.current_identity, manager.current_cluster, False, error=error)
            return f"Error: {error}"

        try:
            apps = manager.apps_v1()
            current_replicas = 0
            try:
                current = apps.read_namespaced_deployment(name=name, namespace=namespace)
                current_replicas = current.spec.replicas or 0
            except Exception:
                pass

            if current_replicas > 0 and not is_dry_run:
                logger.warning("Deleting deployment with %d active replicas: %s/%s", current_replicas, namespace, name)

            dry_run_param = ["All"] if is_dry_run else None
            apps.delete_namespaced_deployment(name=name, namespace=namespace, dry_run=dry_run_param)

            result = OperationResult(
                success=True, operation="delete", resource_kind="Deployment",
                resource_name=name, namespace=namespace,
                message=f"Deployment '{name}' deleted (had {current_replicas} replicas)",
                dry_run=is_dry_run,
            )
            audit.log_delete("delete_deployment", "Deployment", name, namespace, manager.current_identity, manager.current_cluster, True, dry_run=is_dry_run)
            return result.to_text()

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "delete_deployment")
            audit.log_delete("delete_deployment", "Deployment", name, namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def delete_namespace(
        name: Annotated[str, "Name of the namespace to delete"],
        confirm_name: Annotated[str, "SAFETY: Re-enter the EXACT namespace name. Deletes ALL resources inside."] = "",
        dry_run: Annotated[bool, "If true, simulate without deleting"] = False,
        approval_id: Annotated[str, "Approval ID (almost always required for namespace deletion)"] = "",
        cluster: Annotated[str, "Target cluster name or alias"] = "",
    ) -> str:
        """
        Delete a namespace and ALL resources within it.

        !! HIGHEST IMPACT OPERATION !!
        Deletes: all pods, deployments, services, configmaps, secrets,
                 PVCs (data may be lost), and every other resource in the namespace.

        All safety layers apply with maximum strictness.
        """
        settings = get_settings()
        manager = resolve_manager(cluster)
        audit = get_audit_logger()
        is_dry_run = dry_run or settings.dry_run

        ALWAYS_BLOCKED = {"default", "kube-system", "kube-public", "kube-node-lease"}
        if name in ALWAYS_BLOCKED:
            msg = f"Namespace '{name}' is a reserved system namespace and can never be deleted."
            audit.log_delete("delete_namespace", "Namespace", name, None, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

        error = _run_safety_checks(
            settings, name, "Namespace", name, confirm_name, is_dry_run,
            manager.current_identity, manager.current_cluster,
            Operation.DELETE, approval_id,
        )
        if error:
            if error.startswith("__needs_approval__"):
                return _format_approval_needed(error)
            audit.log_delete("delete_namespace", "Namespace", name, None, manager.current_identity, manager.current_cluster, False, error=error)
            return f"Error: {error}"

        if is_dry_run:
            summary = _get_namespace_summary(manager, name)
            return f"[DRY RUN] Would delete namespace '{name}' containing:\n{summary}"

        try:
            manager.core_v1().delete_namespace(name=name)
            result = OperationResult(
                success=True, operation="delete", resource_kind="Namespace",
                resource_name=name, message="Namespace deletion initiated. Resources are being terminated.",
            )
            audit.log_delete("delete_namespace", "Namespace", name, None, manager.current_identity, manager.current_cluster, True)
            return result.to_text()

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "delete_namespace")
            audit.log_delete("delete_namespace", "Namespace", name, None, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def delete_configmap(
        name: Annotated[str, "Name of the configmap to delete"],
        namespace: Annotated[str, "Namespace of the configmap"] = "default",
        confirm_name: Annotated[str, "SAFETY: Re-enter the configmap name to confirm"] = "",
        dry_run: Annotated[bool, "If true, simulate without deleting"] = False,
        approval_id: Annotated[str, "Approval ID from a prior approval request (if required)"] = "",
        cluster: Annotated[str, "Target cluster name or alias"] = "",
    ) -> str:
        """Delete a ConfigMap. Apps using it may fail to start. DESTRUCTIVE."""
        settings = get_settings()
        manager = resolve_manager(cluster)
        audit = get_audit_logger()
        is_dry_run = dry_run or settings.dry_run

        error = _run_safety_checks(
            settings, namespace, "ConfigMap", name, confirm_name, is_dry_run,
            manager.current_identity, manager.current_cluster,
            Operation.DELETE, approval_id,
        )
        if error:
            if error.startswith("__needs_approval__"):
                return _format_approval_needed(error)
            audit.log_delete("delete_configmap", "ConfigMap", name, namespace, manager.current_identity, manager.current_cluster, False, error=error)
            return f"Error: {error}"

        try:
            dry_run_param = ["All"] if is_dry_run else None
            manager.core_v1().delete_namespaced_config_map(name=name, namespace=namespace, dry_run=dry_run_param)
            result = OperationResult(success=True, operation="delete", resource_kind="ConfigMap", resource_name=name, namespace=namespace, message=f"ConfigMap '{name}' deleted", dry_run=is_dry_run)
            audit.log_delete("delete_configmap", "ConfigMap", name, namespace, manager.current_identity, manager.current_cluster, True, dry_run=is_dry_run)
            return result.to_text()
        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "delete_configmap")
            audit.log_delete("delete_configmap", "ConfigMap", name, namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def delete_service(
        name: Annotated[str, "Name of the service to delete"],
        namespace: Annotated[str, "Namespace of the service"] = "default",
        confirm_name: Annotated[str, "SAFETY: Re-enter the service name to confirm"] = "",
        dry_run: Annotated[bool, "If true, simulate without deleting"] = False,
        approval_id: Annotated[str, "Approval ID from a prior approval request (if required)"] = "",
        cluster: Annotated[str, "Target cluster name or alias"] = "",
    ) -> str:
        """
        Delete a Service. Breaks network connectivity to associated pods.
        LoadBalancer services also delete the cloud load balancer. DESTRUCTIVE.
        """
        settings = get_settings()
        manager = resolve_manager(cluster)
        audit = get_audit_logger()
        is_dry_run = dry_run or settings.dry_run

        if name == "kubernetes" and namespace == "default":
            return "Error: The 'kubernetes' service in 'default' cannot be deleted."

        error = _run_safety_checks(
            settings, namespace, "Service", name, confirm_name, is_dry_run,
            manager.current_identity, manager.current_cluster,
            Operation.DELETE, approval_id,
        )
        if error:
            if error.startswith("__needs_approval__"):
                return _format_approval_needed(error)
            audit.log_delete("delete_service", "Service", name, namespace, manager.current_identity, manager.current_cluster, False, error=error)
            return f"Error: {error}"

        try:
            dry_run_param = ["All"] if is_dry_run else None
            manager.core_v1().delete_namespaced_service(name=name, namespace=namespace, dry_run=dry_run_param)
            result = OperationResult(success=True, operation="delete", resource_kind="Service", resource_name=name, namespace=namespace, message=f"Service '{name}' deleted", dry_run=is_dry_run)
            audit.log_delete("delete_service", "Service", name, namespace, manager.current_identity, manager.current_cluster, True, dry_run=is_dry_run)
            return result.to_text()
        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "delete_service")
            audit.log_delete("delete_service", "Service", name, namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def rollback_deployment(
        name: Annotated[str, "Name of the deployment to roll back"],
        namespace: Annotated[str, "Namespace of the deployment"] = "default",
        revision: Annotated[int, "Target revision (0 = previous)"] = 0,
        dry_run: Annotated[bool, "If true, simulate without making changes"] = False,
        cluster: Annotated[str, "Target cluster name or alias"] = "",
    ) -> str:
        """Roll back a deployment to a previous revision. Use get_deployment_history first."""
        settings = get_settings()
        manager = resolve_manager(cluster)
        audit = get_audit_logger()
        is_dry_run = dry_run or settings.dry_run

        if settings.is_protected_namespace(namespace):
            return f"Error: Namespace '{namespace}' is protected. Rollback denied."

        decision = check_namespace_access(manager.current_identity, namespace, Operation.WRITE)
        if not decision.allowed:
            return f"Error: Namespace policy denied: {decision.reason}"

        try:
            apps = manager.apps_v1()
            dry_run_param = ["All"] if is_dry_run else None
            deploy = apps.read_namespaced_deployment(name=name, namespace=namespace)
            selector = deploy.spec.selector.match_labels if deploy.spec.selector else {}
            label_selector = ",".join(f"{k}={v}" for k, v in selector.items())
            rs_list = apps.list_namespaced_replica_set(namespace=namespace, label_selector=label_selector)

            current_rev = int((deploy.metadata.annotations or {}).get("deployment.kubernetes.io/revision", "1"))
            target_rev = str(revision if revision > 0 else current_rev - 1)

            target_rs = next(
                (rs for rs in rs_list.items
                 if (rs.metadata.annotations or {}).get("deployment.kubernetes.io/revision") == target_rev),
                None,
            )
            if not target_rs:
                return (
                    f"Error: Could not find revision {target_rev} for '{namespace}/{name}'. "
                    "Use get_deployment_history to check available revisions."
                )

            rollback_patch = {"spec": {"template": target_rs.spec.template.to_dict()}}
            apps.patch_namespaced_deployment(name=name, namespace=namespace, body=rollback_patch, dry_run=dry_run_param)

            result = OperationResult(success=True, operation="rollback", resource_kind="Deployment", resource_name=name, namespace=namespace, message=f"Rolled back to revision {target_rev}", dry_run=is_dry_run)
            audit.log_write("rollback_deployment", "Deployment", name, namespace, manager.current_identity, manager.current_cluster, True, dry_run=is_dry_run, extra={"target_revision": target_rev})
            return result.to_text()

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "rollback_deployment")
            audit.log_write("rollback_deployment", "Deployment", name, namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    # -------------------------------------------------------------------------
    # Approval workflow tools
    # -------------------------------------------------------------------------

    @mcp.tool
    def list_pending_approvals(
        cluster: Annotated[str, "Filter by cluster name or alias (empty = all)"] = "",
    ) -> str:
        """
        List all pending approval requests for destructive operations.
        Approvers use this to see what requires their attention.
        """
        try:
            approval_mgr = get_approval_manager()
        except RuntimeError:
            return "Approval workflow is not enabled (MCP_K8S_REQUIRE_APPROVAL=false)."

        pending = approval_mgr.list_pending()
        if cluster:
            resolved = get_settings().cluster_map.get(cluster, cluster)
            pending = [a for a in pending if a.cluster == resolved or a.cluster == cluster]

        if not pending:
            return "No pending approvals."

        return f"Pending approvals ({len(pending)}):\n\n" + "\n\n".join(
            a.to_display() for a in pending
        )

    @mcp.tool
    def approve_operation(
        approval_id: Annotated[str, "The approval ID from the pending approval notification"],
        notes: Annotated[str, "Optional notes explaining approval decision"] = "",
    ) -> str:
        """
        Approve a pending destructive operation.

        The approver must be a DIFFERENT identity from the requester (no self-approval).
        After approval, the requester can re-run the original command with approval_id=<id>.

        This approval is single-use and expires after the configured TTL.
        """
        try:
            approval_mgr = get_approval_manager()
        except RuntimeError:
            return "Error: Approval workflow is not enabled."

        # Determine approver identity from the current cluster manager
        # (we use default cluster for identity lookup)
        try:
            from ..cluster_pool import get_cluster_pool
            pool = get_cluster_pool()
            managers = pool.list_connected_clusters()
            approver_identity = managers[0]["identity"] if managers else "unknown-approver"
        except Exception:
            approver_identity = "unknown-approver"

        try:
            approval = approval_mgr.approve(approval_id, approver_identity)
            lines = [
                f"Approval GRANTED for ID: {approval_id}",
                f"  Approver: {approver_identity}",
                f"  Operation: {approval.operation}",
                f"  Resource: {approval.resource_kind}/{approval.resource_name}",
            ]
            if approval.namespace:
                lines.append(f"  Namespace: {approval.namespace}")
            lines.append(f"  Cluster: {approval.cluster}")
            if notes:
                lines.append(f"  Notes: {notes}")
            lines.append(
                f"\nThe requester can now re-run their command with "
                f"approval_id='{approval_id}'"
            )
            return "\n".join(lines)
        except ApprovalError as exc:
            return f"Error: {exc}"

    @mcp.tool
    def deny_operation(
        approval_id: Annotated[str, "The approval ID to deny"],
        reason: Annotated[str, "Reason for denial (will be logged and sent to requester)"] = "",
    ) -> str:
        """
        Deny a pending destructive operation.
        The requester will need to submit a new request if they still want to proceed.
        """
        try:
            approval_mgr = get_approval_manager()
        except RuntimeError:
            return "Error: Approval workflow is not enabled."

        try:
            from ..cluster_pool import get_cluster_pool
            pool = get_cluster_pool()
            managers = pool.list_connected_clusters()
            denier_identity = managers[0]["identity"] if managers else "unknown"
        except Exception:
            denier_identity = "unknown"

        try:
            approval = approval_mgr.deny(approval_id, denier_identity, reason)
            return (
                f"Approval DENIED for ID: {approval_id}\n"
                f"  Denied by: {denier_identity}\n"
                f"  Reason: {reason or '(none provided)'}\n"
                f"  Operation: {approval.operation} "
                f"{approval.resource_kind}/{approval.resource_name}"
            )
        except ApprovalError as exc:
            return f"Error: {exc}"


def _get_namespace_summary(manager, namespace: str) -> str:
    lines = []
    core = manager.core_v1()
    apps = manager.apps_v1()
    for getter, label in [
        (lambda: core.list_namespaced_pod(namespace=namespace), "pods"),
        (lambda: apps.list_namespaced_deployment(namespace=namespace), "deployments"),
        (lambda: core.list_namespaced_service(namespace=namespace), "services"),
        (lambda: core.list_namespaced_config_map(namespace=namespace), "configmaps"),
        (lambda: core.list_namespaced_secret(namespace=namespace), "secrets"),
    ]:
        try:
            items = getter()
            lines.append(f"  - {len(items.items)} {label}")
        except Exception:
            lines.append(f"  - {label}: (could not count)")
    return "\n".join(lines) if lines else "  (empty namespace)"
