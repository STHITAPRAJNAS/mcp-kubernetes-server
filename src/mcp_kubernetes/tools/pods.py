"""
Pod operation tools - read-only and exec (with guards).
"""

from __future__ import annotations

import logging
from typing import Annotated

from kubernetes.client.rest import ApiException
from kubernetes.stream import stream

from ..audit import get_audit_logger
from ..k8s_client import get_client_manager, handle_k8s_api_error
from ..models import PodInfo, ContainerStatus
from ..utils import (
    extract_container_state,
    format_age,
    sanitize_for_display,
    safe_get,
)

logger = logging.getLogger(__name__)


def register_pod_tools(mcp) -> None:
    """Register all pod-related MCP tools."""

    @mcp.tool
    def list_pods(
        namespace: Annotated[str, "Namespace to list pods in. Use 'all' for all namespaces"] = "default",
        label_selector: Annotated[str, "Label selector filter (e.g. 'app=nginx,env=prod')"] = "",
        field_selector: Annotated[str, "Field selector filter (e.g. 'status.phase=Running')"] = "",
    ) -> str:
        """
        List pods in a namespace or across all namespaces.
        Returns pod status, phase, node assignment, IP, and container states.
        """
        manager = get_client_manager()
        audit = get_audit_logger()
        try:
            core = manager.core_v1()
            kwargs = {}
            if label_selector:
                kwargs["label_selector"] = label_selector
            if field_selector:
                kwargs["field_selector"] = field_selector

            if namespace == "all":
                result = core.list_pod_for_all_namespaces(**kwargs)
            else:
                result = core.list_namespaced_pod(namespace=namespace, **kwargs)

            pods = []
            for pod in result.items:
                pod_info = _build_pod_info(pod)
                pods.append(pod_info.to_text())

            audit.log_read(
                "list_pods", "Pod", f"{namespace}/*", namespace,
                manager.current_identity, manager.current_cluster, True,
            )

            if not pods:
                return f"No pods found in namespace '{namespace}'."
            return f"Found {len(pods)} pod(s) in '{namespace}':\n\n" + "\n\n".join(pods)

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "list_pods")
            audit.log_read("list_pods", "Pod", "*", namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def get_pod(
        name: Annotated[str, "Name of the pod"],
        namespace: Annotated[str, "Namespace of the pod"] = "default",
    ) -> str:
        """
        Get detailed information about a specific pod including all container statuses,
        conditions, resource requests/limits, and recent events.
        """
        manager = get_client_manager()
        audit = get_audit_logger()
        try:
            core = manager.core_v1()
            pod = core.read_namespaced_pod(name=name, namespace=namespace)
            pod_info = _build_pod_info(pod)

            # Add extra detail for single pod view
            lines = [pod_info.to_text()]

            # Resource requests/limits
            if pod.spec and pod.spec.containers:
                lines.append("\n  Resource Requests/Limits:")
                for container in pod.spec.containers:
                    res = container.resources
                    if res:
                        req = res.requests or {}
                        lim = res.limits or {}
                        lines.append(
                            f"    {container.name}: "
                            f"cpu={req.get('cpu', '?')}/{lim.get('cpu', '?')}, "
                            f"mem={req.get('memory', '?')}/{lim.get('memory', '?')}"
                        )

            # Conditions
            if pod.status and pod.status.conditions:
                lines.append("\n  Conditions:")
                for cond in pod.status.conditions:
                    lines.append(f"    {cond.type}={cond.status}: {cond.message or ''}")

            # Volumes
            if pod.spec and pod.spec.volumes:
                vol_names = [v.name for v in pod.spec.volumes[:5]]
                if len(pod.spec.volumes) > 5:
                    vol_names.append(f"... +{len(pod.spec.volumes) - 5} more")
                lines.append(f"\n  Volumes: {', '.join(vol_names)}")

            audit.log_read(
                "get_pod", "Pod", name, namespace,
                manager.current_identity, manager.current_cluster, True,
            )
            return "\n".join(lines)

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "get_pod")
            audit.log_read("get_pod", "Pod", name, namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def get_pod_logs(
        name: Annotated[str, "Name of the pod"],
        namespace: Annotated[str, "Namespace of the pod"] = "default",
        container: Annotated[str, "Container name (required for multi-container pods)"] = "",
        tail_lines: Annotated[int, "Number of log lines to return (default 100, max 1000)"] = 100,
        previous: Annotated[bool, "Return logs from previous container instance (useful for crash investigation)"] = False,
        since_seconds: Annotated[int, "Only return logs newer than this many seconds (0 = all)"] = 0,
    ) -> str:
        """
        Retrieve logs from a pod container.
        Supports multi-container pods, previous instance logs for crash debugging,
        and time-based filtering.
        """
        manager = get_client_manager()
        audit = get_audit_logger()

        # Cap tail lines for safety
        tail_lines = min(max(1, tail_lines), 1000)

        try:
            core = manager.core_v1()
            kwargs: dict = {
                "name": name,
                "namespace": namespace,
                "tail_lines": tail_lines,
                "timestamps": True,
                "previous": previous,
            }
            if container:
                kwargs["container"] = container
            if since_seconds > 0:
                kwargs["since_seconds"] = since_seconds

            logs = core.read_namespaced_pod_log(**kwargs)

            audit.log_read(
                "get_pod_logs", "Pod", name, namespace,
                manager.current_identity, manager.current_cluster, True,
            )

            header = f"Logs from pod '{namespace}/{name}'"
            if container:
                header += f" container '{container}'"
            if previous:
                header += " (previous instance)"
            header += f" [last {tail_lines} lines]:\n"
            header += "─" * 60 + "\n"

            return header + sanitize_for_display(logs or "(no logs available)")

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "get_pod_logs")
            audit.log_read("get_pod_logs", "Pod", name, namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def exec_pod_command(
        name: Annotated[str, "Name of the pod"],
        command: Annotated[str, "Shell command to execute (e.g. 'ls -la /app', 'cat /etc/hosts')"],
        namespace: Annotated[str, "Namespace of the pod"] = "default",
        container: Annotated[str, "Container name (required for multi-container pods)"] = "",
        timeout: Annotated[int, "Command timeout in seconds (max 60)"] = 30,
    ) -> str:
        """
        Execute a command inside a running pod container.

        IMPORTANT RESTRICTIONS:
        - Commands are run as the container's process user
        - Standard output and stderr are captured
        - Interactive commands (vim, less, top) are not supported
        - For diagnostic commands only - avoid modifying container state via exec
        """
        manager = get_client_manager()
        audit = get_audit_logger()

        # Safety: cap timeout
        timeout = min(max(1, timeout), 60)

        # Warn about potentially destructive exec commands
        dangerous_patterns = ["rm -rf", "dd if=", "mkfs", "> /dev/", "format", "fdisk"]
        cmd_lower = command.lower()
        for pattern in dangerous_patterns:
            if pattern in cmd_lower:
                audit.log_exec(
                    "exec_pod_command", name, namespace, command,
                    manager.current_identity, manager.current_cluster, False,
                    error=f"Blocked: potentially destructive command pattern '{pattern}'",
                )
                return (
                    f"Error: Command blocked. The pattern '{pattern}' is not permitted "
                    f"in exec commands for safety. Use kubectl directly for destructive "
                    f"in-pod operations."
                )

        try:
            core = manager.core_v1()
            exec_kwargs: dict = {
                "name": name,
                "namespace": namespace,
                "command": ["/bin/sh", "-c", command],
                "stderr": True,
                "stdin": False,
                "stdout": True,
                "tty": False,
            }
            if container:
                exec_kwargs["container"] = container

            response = stream(
                core.connect_get_namespaced_pod_exec,
                **exec_kwargs,
                _request_timeout=timeout,
            )

            audit.log_exec(
                "exec_pod_command", name, namespace, command,
                manager.current_identity, manager.current_cluster, True,
            )

            return (
                f"Command: {command}\n"
                f"Pod: {namespace}/{name}"
                + (f" [{container}]" if container else "")
                + f"\n{'─' * 60}\n"
                + sanitize_for_display(response or "(no output)")
            )

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "exec_pod_command")
            audit.log_exec("exec_pod_command", name, namespace, command, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"


def _build_pod_info(pod) -> PodInfo:
    """Build a PodInfo model from a Kubernetes Pod object."""
    containers = []
    if pod.status and pod.status.container_statuses:
        for cs in pod.status.container_statuses:
            state, reason = extract_container_state(cs)
            # Find image from spec
            image = ""
            if pod.spec and pod.spec.containers:
                for c in pod.spec.containers:
                    if c.name == cs.name:
                        image = c.image or ""
                        break
            containers.append(ContainerStatus(
                name=cs.name,
                image=image,
                ready=cs.ready or False,
                restart_count=cs.restart_count or 0,
                state=state,
                reason=reason,
            ))
    elif pod.spec and pod.spec.containers:
        # No status yet (e.g., pending pod)
        for c in pod.spec.containers:
            containers.append(ContainerStatus(
                name=c.name,
                image=c.image or "",
                ready=False,
                restart_count=0,
                state="pending",
                reason=None,
            ))

    # Extract owner reference
    owner_kind = owner_name = None
    if pod.metadata.owner_references:
        owner = pod.metadata.owner_references[0]
        owner_kind = owner.kind
        owner_name = owner.name

    phase = safe_get(pod, "status", "phase") or "Unknown"
    conditions = pod.status.conditions or [] if pod.status else []
    ready_condition = next((c for c in conditions if c.type == "Ready"), None)
    if ready_condition:
        status = "Ready" if ready_condition.status == "True" else "NotReady"
    else:
        status = phase

    return PodInfo(
        name=pod.metadata.name,
        namespace=pod.metadata.namespace,
        status=status,
        phase=phase,
        node=safe_get(pod, "spec", "node_name"),
        ip=safe_get(pod, "status", "pod_ip"),
        containers=containers,
        labels=pod.metadata.labels or {},
        annotations={
            k: v for k, v in (pod.metadata.annotations or {}).items()
            if not k.startswith("kubectl.kubernetes.io/last-applied")
        },
        created_at=pod.metadata.creation_timestamp.isoformat() if pod.metadata.creation_timestamp else None,
        age=format_age(pod.metadata.creation_timestamp),
        owner_kind=owner_kind,
        owner_name=owner_name,
    )
