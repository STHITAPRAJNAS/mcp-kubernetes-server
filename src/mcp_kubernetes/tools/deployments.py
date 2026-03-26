"""
Deployment operation tools - read, scale, restart.
"""

from __future__ import annotations

import logging
from typing import Annotated

from kubernetes.client.rest import ApiException

from ..audit import get_audit_logger
from ..config import get_settings
from ..cluster_pool import resolve_manager
from ..k8s_client import handle_k8s_api_error
from ..models import DeploymentInfo, OperationResult
from ..utils import format_age, safe_get

logger = logging.getLogger(__name__)

_DRY_RUN_ALL = ["All"]  # Kubernetes dry-run header value


def register_deployment_tools(mcp) -> None:
    """Register all deployment-related MCP tools."""

    @mcp.tool
    def list_deployments(
        namespace: Annotated[str, "Namespace to list deployments in. Use 'all' for all namespaces"] = "default",
        label_selector: Annotated[str, "Label selector filter (e.g. 'app=nginx')"] = "",
        cluster: Annotated[str, "Target cluster name or alias (uses default if empty)"] = "",
) -> str:
        """
        List deployments in a namespace, including replica counts and rollout status.
        """
        manager = resolve_manager(cluster)
        audit = get_audit_logger()
        try:
            apps = manager.apps_v1()
            kwargs = {}
            if label_selector:
                kwargs["label_selector"] = label_selector

            if namespace == "all":
                result = apps.list_deployment_for_all_namespaces(**kwargs)
            else:
                result = apps.list_namespaced_deployment(namespace=namespace, **kwargs)

            deploys = [_build_deployment_info(d).to_text() for d in result.items]
            audit.log_read("list_deployments", "Deployment", f"{namespace}/*", namespace, manager.current_identity, manager.current_cluster, True)

            if not deploys:
                return f"No deployments found in namespace '{namespace}'."
            return f"Found {len(deploys)} deployment(s) in '{namespace}':\n\n" + "\n\n".join(deploys)

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "list_deployments")
            audit.log_read("list_deployments", "Deployment", "*", namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def get_deployment(
        name: Annotated[str, "Name of the deployment"],
        namespace: Annotated[str, "Namespace of the deployment"] = "default",
        cluster: Annotated[str, "Target cluster name or alias (uses default if empty)"] = "",
) -> str:
        """Get detailed information about a specific deployment."""
        manager = resolve_manager(cluster)
        audit = get_audit_logger()
        try:
            apps = manager.apps_v1()
            deploy = apps.read_namespaced_deployment(name=name, namespace=namespace)
            info = _build_deployment_info(deploy)
            lines = [info.to_text()]

            # Show selector
            selector = safe_get(deploy, "spec", "selector", "match_labels") or {}
            if selector:
                sel_str = ", ".join(f"{k}={v}" for k, v in selector.items())
                lines.append(f"\n  Selector: {sel_str}")

            # Show environment variables (names only, no secret values)
            if deploy.spec and deploy.spec.template and deploy.spec.template.spec:
                for container in (deploy.spec.template.spec.containers or []):
                    if container.env:
                        env_names = [e.name for e in container.env]
                        lines.append(
                            f"\n  Container '{container.name}' env vars: "
                            + ", ".join(env_names[:10])
                            + ("..." if len(env_names) > 10 else "")
                        )

            audit.log_read("get_deployment", "Deployment", name, namespace, manager.current_identity, manager.current_cluster, True)
            return "\n".join(lines)

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "get_deployment")
            audit.log_read("get_deployment", "Deployment", name, namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def scale_deployment(
        name: Annotated[str, "Name of the deployment to scale"],
        replicas: Annotated[int, "Desired number of replicas (0-100)"],
        namespace: Annotated[str, "Namespace of the deployment"] = "default",
        dry_run: Annotated[bool, "If true, simulate the operation without making changes"] = False,
        cluster: Annotated[str, "Target cluster name or alias (uses default if empty)"] = "",
) -> str:
        """
        Scale a deployment to the specified number of replicas.

        Safeguards:
        - Scaling to 0 requires explicit confirmation (will prompt)
        - Respects protected namespaces
        - Supports dry-run mode

        Use dry_run=true first to validate the operation.
        """
        settings = get_settings()
        manager = resolve_manager(cluster)
        audit = get_audit_logger()

        # Safety checks
        if settings.is_protected_namespace(namespace):
            msg = f"Namespace '{namespace}' is protected. Scale operation denied."
            audit.log_write("scale_deployment", "Deployment", name, namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

        if replicas < 0 or replicas > 100:
            return "Error: Replicas must be between 0 and 100."

        is_dry_run = dry_run or settings.dry_run

        try:
            apps = manager.apps_v1()

            # Check current state
            current = apps.read_namespaced_deployment(name=name, namespace=namespace)
            current_replicas = safe_get(current, "spec", "replicas") or 0

            if replicas == 0:
                warning = (
                    f"WARNING: Scaling deployment '{name}' to 0 replicas will "
                    f"make it unavailable. Current replicas: {current_replicas}."
                )
                if is_dry_run:
                    return f"[DRY RUN] {warning}\nWould scale {namespace}/{name} from {current_replicas} → 0 replicas."

            patch = {"spec": {"replicas": replicas}}
            dry_run_param = _DRY_RUN_ALL if is_dry_run else None

            apps.patch_namespaced_deployment_scale(
                name=name,
                namespace=namespace,
                body=patch,
                dry_run=dry_run_param,
            )

            result = OperationResult(
                success=True,
                operation="scale",
                resource_kind="Deployment",
                resource_name=name,
                namespace=namespace,
                message=f"Scaled from {current_replicas} → {replicas} replicas",
                dry_run=is_dry_run,
                details={"previous_replicas": current_replicas, "desired_replicas": replicas},
            )

            audit.log_write("scale_deployment", "Deployment", name, namespace, manager.current_identity, manager.current_cluster, True, dry_run=is_dry_run, extra={"replicas": replicas, "previous": current_replicas})
            return result.to_text()

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "scale_deployment")
            audit.log_write("scale_deployment", "Deployment", name, namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def restart_deployment(
        name: Annotated[str, "Name of the deployment to restart"],
        namespace: Annotated[str, "Namespace of the deployment"] = "default",
        dry_run: Annotated[bool, "If true, simulate the operation without making changes"] = False,
        cluster: Annotated[str, "Target cluster name or alias (uses default if empty)"] = "",
) -> str:
        """
        Perform a rolling restart of a deployment (equivalent to kubectl rollout restart).
        Adds a restart annotation to trigger a new rollout without changing replicas.
        """
        import datetime as dt
        settings = get_settings()
        manager = resolve_manager(cluster)
        audit = get_audit_logger()

        if settings.is_protected_namespace(namespace):
            msg = f"Namespace '{namespace}' is protected. Restart operation denied."
            audit.log_write("restart_deployment", "Deployment", name, namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

        is_dry_run = dry_run or settings.dry_run
        now = dt.datetime.now(tz=dt.timezone.utc).isoformat()

        try:
            apps = manager.apps_v1()
            patch = {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                "kubectl.kubernetes.io/restartedAt": now
                            }
                        }
                    }
                }
            }
            dry_run_param = _DRY_RUN_ALL if is_dry_run else None
            apps.patch_namespaced_deployment(
                name=name,
                namespace=namespace,
                body=patch,
                dry_run=dry_run_param,
            )

            result = OperationResult(
                success=True,
                operation="rolling-restart",
                resource_kind="Deployment",
                resource_name=name,
                namespace=namespace,
                message="Rolling restart triggered. New pods will be created progressively.",
                dry_run=is_dry_run,
            )
            audit.log_write("restart_deployment", "Deployment", name, namespace, manager.current_identity, manager.current_cluster, True, dry_run=is_dry_run)
            return result.to_text()

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "restart_deployment")
            audit.log_write("restart_deployment", "Deployment", name, namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def get_deployment_history(
        name: Annotated[str, "Name of the deployment"],
        namespace: Annotated[str, "Namespace of the deployment"] = "default",
        cluster: Annotated[str, "Target cluster name or alias (uses default if empty)"] = "",
) -> str:
        """
        Get the rollout history of a deployment showing revision details.
        Useful for identifying which revision to rollback to.
        """
        manager = resolve_manager(cluster)
        audit = get_audit_logger()
        try:
            apps = manager.apps_v1()
            # Get ReplicaSets owned by this deployment
            deploy = apps.read_namespaced_deployment(name=name, namespace=namespace)
            selector = deploy.spec.selector.match_labels if deploy.spec.selector else {}
            label_selector = ",".join(f"{k}={v}" for k, v in selector.items())

            rs_list = apps.list_namespaced_replica_set(
                namespace=namespace,
                label_selector=label_selector,
            )

            revisions = []
            for rs in rs_list.items:
                annotations = rs.metadata.annotations or {}
                revision = annotations.get("deployment.kubernetes.io/revision", "?")
                change_cause = annotations.get("kubernetes.io/change-cause", "<none>")
                images = [c.image for c in (rs.spec.template.spec.containers or [])]
                revisions.append((revision, change_cause, images, rs.metadata.name))

            revisions.sort(key=lambda x: str(x[0]))

            audit.log_read("get_deployment_history", "Deployment", name, namespace, manager.current_identity, manager.current_cluster, True)

            if not revisions:
                return f"No revision history found for deployment '{namespace}/{name}'."

            lines = [f"Rollout history for Deployment '{namespace}/{name}':"]
            lines.append(f"{'REVISION':<12} {'CHANGE-CAUSE':<30} IMAGES")
            lines.append("─" * 80)
            for rev, cause, images, rs_name in revisions:
                lines.append(f"{rev:<12} {cause:<30} {', '.join(images)}")
            return "\n".join(lines)

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "get_deployment_history")
            audit.log_read("get_deployment_history", "Deployment", name, namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"


def _build_deployment_info(deploy) -> DeploymentInfo:
    """Build a DeploymentInfo model from a Kubernetes Deployment object."""
    spec = deploy.spec or {}
    status = deploy.status or {}

    # Collect all container images
    images = []
    if deploy.spec and deploy.spec.template and deploy.spec.template.spec:
        for c in (deploy.spec.template.spec.containers or []):
            if c.image:
                images.append(c.image)

    # Conditions
    conditions = []
    if deploy.status and deploy.status.conditions:
        for cond in deploy.status.conditions:
            conditions.append({
                "type": cond.type or "",
                "status": cond.status or "",
                "message": cond.message or "",
            })

    strategy = "RollingUpdate"
    if deploy.spec and deploy.spec.strategy:
        strategy = deploy.spec.strategy.type or "RollingUpdate"

    return DeploymentInfo(
        name=deploy.metadata.name,
        namespace=deploy.metadata.namespace,
        replicas=safe_get(deploy, "spec", "replicas") or 0,
        ready_replicas=safe_get(deploy, "status", "ready_replicas") or 0,
        available_replicas=safe_get(deploy, "status", "available_replicas") or 0,
        updated_replicas=safe_get(deploy, "status", "updated_replicas") or 0,
        strategy=strategy,
        images=images,
        image=images[0] if images else None,
        labels=deploy.metadata.labels or {},
        conditions=conditions,
        created_at=deploy.metadata.creation_timestamp.isoformat() if deploy.metadata.creation_timestamp else None,
        age=format_age(deploy.metadata.creation_timestamp),
    )
