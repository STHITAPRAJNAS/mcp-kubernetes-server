"""
Node operation tools (read-only).
"""

from __future__ import annotations

import logging
from typing import Annotated

from kubernetes.client.rest import ApiException

from ..audit import get_audit_logger
from ..cluster_pool import resolve_manager
from ..k8s_client import handle_k8s_api_error
from ..models import NodeInfo, NodeCondition
from ..utils import extract_node_roles, format_age, format_resource_quantity, safe_get

logger = logging.getLogger(__name__)


def register_node_tools(mcp) -> None:
    """Register node-related MCP tools."""

    @mcp.tool
    def list_nodes(
        label_selector: Annotated[str, "Label selector filter (e.g. 'node-role.kubernetes.io/worker=')"] = "",
        cluster: Annotated[str, "Target cluster name or alias (uses default if empty)"] = "",
) -> str:
        """
        List all nodes in the cluster with their status, roles, versions, and resource capacity.
        """
        manager = resolve_manager(cluster)
        audit = get_audit_logger()
        try:
            core = manager.core_v1()
            kwargs = {}
            if label_selector:
                kwargs["label_selector"] = label_selector

            result = core.list_node(**kwargs)
            nodes = [_build_node_info(n).to_text() for n in result.items]
            audit.log_read("list_nodes", "Node", "*", None, manager.current_identity, manager.current_cluster, True)

            if not nodes:
                return "No nodes found."
            return f"Found {len(nodes)} node(s):\n\n" + "\n\n".join(nodes)

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "list_nodes")
            audit.log_read("list_nodes", "Node", "*", None, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def get_node(
        name: Annotated[str, "Name of the node"],
        cluster: Annotated[str, "Target cluster name or alias (uses default if empty)"] = "",
) -> str:
        """
        Get detailed information about a specific node including conditions,
        allocatable resources, taints, and running pod count.
        """
        manager = resolve_manager(cluster)
        audit = get_audit_logger()
        try:
            core = manager.core_v1()
            node = core.read_node(name=name)
            info = _build_node_info(node)
            lines = [info.to_text()]

            # Allocatable resources
            if node.status and node.status.allocatable:
                alloc = node.status.allocatable
                lines.append(
                    f"\n  Allocatable: cpu={alloc.get('cpu', 'N/A')}, "
                    f"memory={alloc.get('memory', 'N/A')}, "
                    f"pods={alloc.get('pods', 'N/A')}"
                )

            # Conditions detail
            if node.status and node.status.conditions:
                lines.append("\n  Conditions:")
                for cond in node.status.conditions:
                    icon = "✓" if cond.status == "True" else "✗"
                    lines.append(f"    {icon} {cond.type}={cond.status}: {cond.message or ''}")

            # Count running pods on this node
            try:
                pods = core.list_pod_for_all_namespaces(
                    field_selector=f"spec.nodeName={name},status.phase=Running"
                )
                lines.append(f"\n  Running Pods: {len(pods.items)}")
            except Exception:
                pass

            audit.log_read("get_node", "Node", name, None, manager.current_identity, manager.current_cluster, True)
            return "\n".join(lines)

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "get_node")
            audit.log_read("get_node", "Node", name, None, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def describe_node_pods(
        name: Annotated[str, "Name of the node"],
        namespace: Annotated[str, "Filter by namespace. Use 'all' for all namespaces"] = "all",
        cluster: Annotated[str, "Target cluster name or alias (uses default if empty)"] = "",
) -> str:
        """
        List all pods running on a specific node.
        Useful for understanding node utilization and planning maintenance.
        """
        manager = resolve_manager(cluster)
        audit = get_audit_logger()
        try:
            core = manager.core_v1()
            field_selector = f"spec.nodeName={name}"

            if namespace == "all":
                result = core.list_pod_for_all_namespaces(field_selector=field_selector)
            else:
                result = core.list_namespaced_pod(namespace=namespace, field_selector=field_selector)

            lines = [f"Pods on node '{name}':"]
            lines.append(f"{'NAMESPACE':<20} {'NAME':<45} {'STATUS':<12} {'PHASE'}")
            lines.append("─" * 100)
            for pod in result.items:
                phase = safe_get(pod, "status", "phase") or "Unknown"
                lines.append(
                    f"{pod.metadata.namespace:<20} "
                    f"{pod.metadata.name:<45} "
                    f"{phase:<12}"
                )

            audit.log_read("describe_node_pods", "Pod", f"{name}/*", None, manager.current_identity, manager.current_cluster, True)
            return "\n".join(lines)

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "describe_node_pods")
            audit.log_read("describe_node_pods", "Pod", f"{name}/*", None, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"


def _build_node_info(node) -> NodeInfo:
    """Build NodeInfo from a Kubernetes Node object."""
    roles = extract_node_roles(node)
    labels = node.metadata.labels or {}

    # Node status from conditions
    status = "Unknown"
    conditions = []
    if node.status and node.status.conditions:
        for cond in node.status.conditions:
            conditions.append(NodeCondition(
                type=cond.type,
                status=cond.status,
                message=cond.message,
            ))
            if cond.type == "Ready":
                status = "Ready" if cond.status == "True" else "NotReady"

    # Node info
    node_info = safe_get(node, "status", "node_info")
    version = safe_get(node_info, "kubelet_version") if node_info else None
    os_image = safe_get(node_info, "os_image") if node_info else None
    arch = safe_get(node_info, "architecture") if node_info else None

    # Capacity
    capacity = safe_get(node, "status", "capacity") or {}
    cpu = format_resource_quantity(capacity.get("cpu"))
    memory = format_resource_quantity(capacity.get("memory"))
    pods_capacity = format_resource_quantity(capacity.get("pods"))

    # Internal IP
    internal_ip = None
    if node.status and node.status.addresses:
        for addr in node.status.addresses:
            if addr.type == "InternalIP":
                internal_ip = addr.address
                break

    # Taints
    taints = []
    if node.spec and node.spec.taints:
        for t in node.spec.taints:
            taint_str = f"{t.key}={t.value}:{t.effect}" if t.value else f"{t.key}:{t.effect}"
            taints.append(taint_str)

    # AWS instance type label
    instance_type = labels.get("beta.kubernetes.io/instance-type") or labels.get("node.kubernetes.io/instance-type")

    return NodeInfo(
        name=node.metadata.name,
        status=status,
        roles=roles,
        version=version,
        os=os_image,
        arch=arch,
        cpu=cpu,
        memory=memory,
        pods_capacity=pods_capacity,
        internal_ip=internal_ip,
        conditions=conditions,
        labels=labels,
        taints=taints,
        age=format_age(node.metadata.creation_timestamp),
        instance_type=instance_type,
    )
