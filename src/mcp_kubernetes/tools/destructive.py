"""
Destructive operation tools with enterprise-grade safety guards.

DESIGN PHILOSOPHY:
- Destructive operations are those that permanently remove or irreversibly modify cluster state
- Every destructive operation has MULTIPLE layers of protection:
  1. Global kill switch (MCP_K8S_ALLOW_DESTRUCTIVE=false disables everything)
  2. Protected namespace list (kube-system etc. are always blocked)
  3. Confirmation token: caller must pass the EXACT resource name to confirm
  4. Dry-run always available for pre-flight checks
  5. All operations are audit-logged with full context

- Namespace deletion gets extra guards (it's the most impactful single operation)
- Batch deletes are capped to prevent accidental mass deletion
"""

from __future__ import annotations

import logging
from typing import Annotated

from kubernetes.client.rest import ApiException

from ..audit import get_audit_logger
from ..config import get_settings
from ..k8s_client import get_client_manager, handle_k8s_api_error
from ..models import OperationResult

logger = logging.getLogger(__name__)


def _check_destructive_allowed(settings, namespace: str | None, resource_kind: str, resource_name: str, confirm_name: str, dry_run: bool) -> str | None:
    """
    Run all safety checks for destructive operations.
    Returns an error string if blocked, None if allowed.
    """
    if not settings.allow_destructive and not dry_run:
        return (
            "Destructive operations are disabled globally. "
            "Set MCP_K8S_ALLOW_DESTRUCTIVE=true to enable."
        )

    if namespace and settings.is_protected_namespace(namespace):
        return (
            f"Namespace '{namespace}' is in the protected namespace list "
            f"({', '.join(settings.protected_namespaces)}). "
            f"Destructive operations are blocked."
        )

    if settings.require_destructive_confirmation and not dry_run:
        if confirm_name != resource_name:
            return (
                f"Confirmation required: pass confirm_name='{resource_name}' "
                f"(the exact resource name) to confirm this destructive operation. "
                f"You passed: '{confirm_name}'"
            )

    return None


def register_destructive_tools(mcp) -> None:
    """Register destructive operation MCP tools with safety guards."""

    @mcp.tool
    def delete_pod(
        name: Annotated[str, "Name of the pod to delete"],
        namespace: Annotated[str, "Namespace of the pod"] = "default",
        confirm_name: Annotated[str, "SAFETY: Re-enter the pod name to confirm deletion"] = "",
        dry_run: Annotated[bool, "If true, simulate without deleting"] = False,
        grace_period_seconds: Annotated[int, "Graceful termination period in seconds (0 = force delete, default 30)"] = 30,
    ) -> str:
        """
        Delete a pod. The pod will be recreated by its controller (Deployment, ReplicaSet, etc.)
        unless it is a standalone pod.

        DESTRUCTIVE OPERATION - requires:
        - confirm_name must match the pod name exactly
        - Namespace must not be in protected list
        - Global allow_destructive must be enabled

        Use dry_run=true to verify without deleting.
        Set grace_period_seconds=0 only for stuck/zombie pods.
        """
        settings = get_settings()
        manager = get_client_manager()
        audit = get_audit_logger()
        is_dry_run = dry_run or settings.dry_run

        error = _check_destructive_allowed(settings, namespace, "Pod", name, confirm_name, is_dry_run)
        if error:
            audit.log_delete("delete_pod", "Pod", name, namespace, manager.current_identity, manager.current_cluster, False, error=error)
            return f"Error: {error}"

        try:
            core = manager.core_v1()
            dry_run_param = ["All"] if is_dry_run else None

            from kubernetes import client as k8s_client
            delete_options = k8s_client.V1DeleteOptions(
                grace_period_seconds=grace_period_seconds,
            )

            core.delete_namespaced_pod(
                name=name,
                namespace=namespace,
                body=delete_options,
                dry_run=dry_run_param,
            )

            result = OperationResult(
                success=True,
                operation="delete",
                resource_kind="Pod",
                resource_name=name,
                namespace=namespace,
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
        confirm_name: Annotated[str, "SAFETY: Re-enter the deployment name to confirm deletion"] = "",
        dry_run: Annotated[bool, "If true, simulate without deleting"] = False,
    ) -> str:
        """
        Delete a deployment and all pods managed by it.

        WARNING: This will terminate all running pods for this deployment.
        The application will become unavailable.

        DESTRUCTIVE OPERATION - requires confirmation token.
        Use dry_run=true first to verify.
        Consider scale_deployment to 0 as a safer alternative.
        """
        settings = get_settings()
        manager = get_client_manager()
        audit = get_audit_logger()
        is_dry_run = dry_run or settings.dry_run

        error = _check_destructive_allowed(settings, namespace, "Deployment", name, confirm_name, is_dry_run)
        if error:
            audit.log_delete("delete_deployment", "Deployment", name, namespace, manager.current_identity, manager.current_cluster, False, error=error)
            return f"Error: {error}"

        try:
            apps = manager.apps_v1()
            dry_run_param = ["All"] if is_dry_run else None

            # Check current replica count for warning
            current_replicas = 0
            try:
                current = apps.read_namespaced_deployment(name=name, namespace=namespace)
                current_replicas = current.spec.replicas or 0
            except Exception:
                pass

            if current_replicas > 0 and not is_dry_run:
                logger.warning(
                    "Deleting deployment with %d active replicas: %s/%s",
                    current_replicas, namespace, name,
                )

            apps.delete_namespaced_deployment(
                name=name,
                namespace=namespace,
                dry_run=dry_run_param,
            )

            result = OperationResult(
                success=True,
                operation="delete",
                resource_kind="Deployment",
                resource_name=name,
                namespace=namespace,
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
        confirm_name: Annotated[str, "SAFETY: Re-enter the EXACT namespace name to confirm. This deletes ALL resources in the namespace."] = "",
        dry_run: Annotated[bool, "If true, simulate without deleting"] = False,
    ) -> str:
        """
        Delete a namespace and ALL resources within it (pods, deployments, services, secrets, etc.)

        !! EXTREME CAUTION !!
        This is one of the most destructive operations available.
        It will permanently delete:
        - All pods and their logs
        - All deployments, services, configmaps, secrets
        - All persistent volume claims (data may be lost)
        - All other resources in the namespace

        Requirements:
        - confirm_name must match the namespace name EXACTLY
        - Namespace must not be in the protected list
        - Global allow_destructive must be enabled

        Strongly recommended: Use dry_run=true first.
        """
        settings = get_settings()
        manager = get_client_manager()
        audit = get_audit_logger()
        is_dry_run = dry_run or settings.dry_run

        # Namespace deletion gets the strictest checks
        error = _check_destructive_allowed(settings, name, "Namespace", name, confirm_name, is_dry_run)
        if error:
            audit.log_delete("delete_namespace", "Namespace", name, None, manager.current_identity, manager.current_cluster, False, error=error)
            return f"Error: {error}"

        # Extra check: never delete system-critical namespaces even if somehow unprotected
        ALWAYS_PROTECTED = {"default", "kube-system", "kube-public", "kube-node-lease"}
        if name in ALWAYS_PROTECTED:
            msg = f"Namespace '{name}' cannot be deleted - it is a reserved system namespace."
            audit.log_delete("delete_namespace", "Namespace", name, None, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

        if is_dry_run:
            # Show what would be deleted
            summary = _get_namespace_summary(manager, name)
            return (
                f"[DRY RUN] Would delete namespace '{name}' containing:\n"
                + summary
            )

        try:
            core = manager.core_v1()
            core.delete_namespace(name=name)

            result = OperationResult(
                success=True,
                operation="delete",
                resource_kind="Namespace",
                resource_name=name,
                message=f"Namespace '{name}' deletion initiated. Resources are being terminated.",
                dry_run=False,
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
        confirm_name: Annotated[str, "SAFETY: Re-enter the configmap name to confirm deletion"] = "",
        dry_run: Annotated[bool, "If true, simulate without deleting"] = False,
    ) -> str:
        """
        Delete a ConfigMap.

        WARNING: Applications depending on this ConfigMap will fail to start
        or may crash if the ConfigMap is deleted while in use.

        DESTRUCTIVE OPERATION - requires confirmation token.
        """
        settings = get_settings()
        manager = get_client_manager()
        audit = get_audit_logger()
        is_dry_run = dry_run or settings.dry_run

        error = _check_destructive_allowed(settings, namespace, "ConfigMap", name, confirm_name, is_dry_run)
        if error:
            audit.log_delete("delete_configmap", "ConfigMap", name, namespace, manager.current_identity, manager.current_cluster, False, error=error)
            return f"Error: {error}"

        try:
            core = manager.core_v1()
            dry_run_param = ["All"] if is_dry_run else None
            core.delete_namespaced_config_map(name=name, namespace=namespace, dry_run=dry_run_param)

            result = OperationResult(
                success=True,
                operation="delete",
                resource_kind="ConfigMap",
                resource_name=name,
                namespace=namespace,
                message=f"ConfigMap '{name}' deleted",
                dry_run=is_dry_run,
            )
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
        confirm_name: Annotated[str, "SAFETY: Re-enter the service name to confirm deletion"] = "",
        dry_run: Annotated[bool, "If true, simulate without deleting"] = False,
    ) -> str:
        """
        Delete a Kubernetes Service.

        WARNING: This will break network connectivity to the associated pods.
        For LoadBalancer services, the cloud load balancer will also be deleted.

        DESTRUCTIVE OPERATION - requires confirmation token.
        """
        settings = get_settings()
        manager = get_client_manager()
        audit = get_audit_logger()
        is_dry_run = dry_run or settings.dry_run

        error = _check_destructive_allowed(settings, namespace, "Service", name, confirm_name, is_dry_run)
        if error:
            audit.log_delete("delete_service", "Service", name, namespace, manager.current_identity, manager.current_cluster, False, error=error)
            return f"Error: {error}"

        # Extra protection for kubernetes service itself
        if name == "kubernetes" and namespace == "default":
            return "Error: The 'kubernetes' service in the default namespace cannot be deleted."

        try:
            core = manager.core_v1()
            dry_run_param = ["All"] if is_dry_run else None
            core.delete_namespaced_service(name=name, namespace=namespace, dry_run=dry_run_param)

            result = OperationResult(
                success=True,
                operation="delete",
                resource_kind="Service",
                resource_name=name,
                namespace=namespace,
                message=f"Service '{name}' deleted",
                dry_run=is_dry_run,
            )
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
        revision: Annotated[int, "Target revision number to roll back to (0 = previous revision)"] = 0,
        dry_run: Annotated[bool, "If true, simulate without making changes"] = False,
    ) -> str:
        """
        Roll back a deployment to a previous revision.
        Use get_deployment_history to see available revisions.

        This is a write operation that modifies the deployment spec.
        The rollback happens as a rolling update.
        """
        settings = get_settings()
        manager = get_client_manager()
        audit = get_audit_logger()
        is_dry_run = dry_run or settings.dry_run

        if settings.is_protected_namespace(namespace):
            return f"Error: Namespace '{namespace}' is protected. Rollback denied."

        try:
            apps = manager.apps_v1()
            dry_run_param = ["All"] if is_dry_run else None

            # Undo via annotation (like kubectl rollout undo)
            patch: dict = {}
            if revision > 0:
                patch = {
                    "metadata": {
                        "annotations": {
                            "deployment.kubernetes.io/revision": str(revision - 1)
                        }
                    }
                }

            # The canonical rollback is to patch the deployment to use the previous RS template
            # We do this by finding the target ReplicaSet and applying its template
            deploy = apps.read_namespaced_deployment(name=name, namespace=namespace)
            selector = deploy.spec.selector.match_labels if deploy.spec.selector else {}
            label_selector = ",".join(f"{k}={v}" for k, v in selector.items())
            rs_list = apps.list_namespaced_replica_set(namespace=namespace, label_selector=label_selector)

            # Find target RS by revision
            target_rs = None
            if revision == 0:
                # Roll back to previous (current - 1)
                current_rev = int(
                    (deploy.metadata.annotations or {}).get(
                        "deployment.kubernetes.io/revision", "1"
                    )
                )
                target_rev = str(current_rev - 1)
            else:
                target_rev = str(revision)

            for rs in rs_list.items:
                rs_rev = (rs.metadata.annotations or {}).get(
                    "deployment.kubernetes.io/revision"
                )
                if rs_rev == target_rev:
                    target_rs = rs
                    break

            if not target_rs:
                return (
                    f"Error: Could not find revision {revision or 'previous'} "
                    f"for deployment '{namespace}/{name}'. "
                    f"Use get_deployment_history to check available revisions."
                )

            # Apply target RS template to the deployment
            rollback_patch = {
                "spec": {
                    "template": target_rs.spec.template.to_dict()
                }
            }
            apps.patch_namespaced_deployment(
                name=name,
                namespace=namespace,
                body=rollback_patch,
                dry_run=dry_run_param,
            )

            result = OperationResult(
                success=True,
                operation="rollback",
                resource_kind="Deployment",
                resource_name=name,
                namespace=namespace,
                message=f"Rolled back to revision {target_rev}",
                dry_run=is_dry_run,
            )
            audit.log_write("rollback_deployment", "Deployment", name, namespace, manager.current_identity, manager.current_cluster, True, dry_run=is_dry_run, extra={"target_revision": target_rev})
            return result.to_text()

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "rollback_deployment")
            audit.log_write("rollback_deployment", "Deployment", name, namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"


def _get_namespace_summary(manager, namespace: str) -> str:
    """Get a summary of resources in a namespace for dry-run output."""
    lines = []
    core = manager.core_v1()
    apps = manager.apps_v1()

    try:
        pods = core.list_namespaced_pod(namespace=namespace)
        lines.append(f"  - {len(pods.items)} pods")
    except Exception:
        lines.append("  - pods: (could not count)")

    try:
        deploys = apps.list_namespaced_deployment(namespace=namespace)
        lines.append(f"  - {len(deploys.items)} deployments")
    except Exception:
        pass

    try:
        svcs = core.list_namespaced_service(namespace=namespace)
        user_svcs = [s for s in svcs.items if s.metadata.name != "kubernetes"]
        lines.append(f"  - {len(user_svcs)} services")
    except Exception:
        pass

    try:
        cms = core.list_namespaced_config_map(namespace=namespace)
        lines.append(f"  - {len(cms.items)} configmaps")
    except Exception:
        pass

    try:
        secrets = core.list_namespaced_secret(namespace=namespace)
        user_secrets = [s for s in secrets.items if s.type != "kubernetes.io/service-account-token"]
        lines.append(f"  - {len(user_secrets)} secrets")
    except Exception:
        pass

    return "\n".join(lines) if lines else "  (empty namespace)"
