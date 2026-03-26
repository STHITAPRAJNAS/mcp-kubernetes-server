"""
MCP Resources for cluster information.
Resources are read-only data entities exposed for LLM context.
"""

from __future__ import annotations

import json
import logging

from kubernetes.client.rest import ApiException

from ..cluster_pool import resolve_manager
from ..k8s_client import handle_k8s_api_error
from ..models import ClusterInfo
from ..utils import format_age

logger = logging.getLogger(__name__)


def register_cluster_resources(mcp) -> None:
    """Register cluster info MCP resources."""

    @mcp.resource("k8s://cluster/info")
    def cluster_info() -> str:
        """
        Current Kubernetes cluster information including version, node count,
        namespace count, and authentication context.
        """
        manager = resolve_manager()
        try:
            version_api = manager.version_api()
            version_info = version_api.get_code()
            server_version = f"{version_info.major}.{version_info.minor}"
            platform = version_info.platform

            core = manager.core_v1()
            nodes = core.list_node()
            namespaces = core.list_namespace()

            auth_meta = manager.get_auth_metadata()

            info = ClusterInfo(
                server_version=server_version,
                platform=platform,
                cluster_name=manager.current_cluster,
                environment=manager.environment,
                identity=manager.current_identity,
                node_count=len(nodes.items),
                namespace_count=len(namespaces.items),
                region=auth_meta.get("region"),
                auth_metadata=auth_meta,
            )

            return info.to_text()

        except ApiException as exc:
            return f"Error fetching cluster info: {handle_k8s_api_error(exc, 'cluster_info')}"
        except Exception as exc:
            logger.warning("Could not fetch cluster info: %s", exc)
            return f"Cluster: {manager.current_cluster} | Environment: {manager.environment} | Identity: {manager.current_identity}"

    @mcp.resource("k8s://cluster/namespaces")
    def cluster_namespaces() -> str:
        """List of all namespaces in the cluster."""
        manager = resolve_manager()
        try:
            core = manager.core_v1()
            namespaces = core.list_namespace()
            ns_names = [ns.metadata.name for ns in namespaces.items]
            return "Namespaces:\n" + "\n".join(f"  - {ns}" for ns in sorted(ns_names))
        except ApiException as exc:
            return f"Error: {handle_k8s_api_error(exc, 'cluster_namespaces')}"

    @mcp.resource("k8s://cluster/nodes")
    def cluster_nodes() -> str:
        """List of all nodes in the cluster with their status."""
        manager = resolve_manager()
        try:
            core = manager.core_v1()
            nodes = core.list_node()
            lines = ["Nodes:"]
            for node in nodes.items:
                status = "Ready"
                if node.status and node.status.conditions:
                    for cond in node.status.conditions:
                        if cond.type == "Ready":
                            status = "Ready" if cond.status == "True" else "NotReady"
                version = ""
                if node.status and node.status.node_info:
                    version = node.status.node_info.kubelet_version or ""
                lines.append(f"  - {node.metadata.name} ({status}) k8s={version}")
            return "\n".join(lines)
        except ApiException as exc:
            return f"Error: {handle_k8s_api_error(exc, 'cluster_nodes')}"

    @mcp.resource("k8s://cluster/health")
    def cluster_health() -> str:
        """
        Overall cluster health summary: warning events, not-ready pods, not-ready nodes.
        """
        manager = resolve_manager()
        try:
            core = manager.core_v1()

            # Not-ready nodes
            nodes = core.list_node()
            not_ready_nodes = []
            for node in nodes.items:
                if node.status and node.status.conditions:
                    for cond in node.status.conditions:
                        if cond.type == "Ready" and cond.status != "True":
                            not_ready_nodes.append(node.metadata.name)

            # Not-ready pods
            pods = core.list_pod_for_all_namespaces(
                field_selector="status.phase!=Running,status.phase!=Succeeded"
            )
            problem_pods = [
                f"{p.metadata.namespace}/{p.metadata.name}"
                for p in pods.items
                if p.status and p.status.phase not in ("Succeeded", "Running", None)
            ][:20]

            # Warning events (recent)
            try:
                events = core.list_event_for_all_namespaces(
                    field_selector="type=Warning", limit=20
                )
                warning_events = [
                    f"[{e.metadata.namespace}] {e.reason}: {e.message[:80]}"
                    for e in events.items
                ]
            except Exception:
                warning_events = []

            lines = ["Cluster Health Summary:"]
            lines.append(f"\nNodes: {len(nodes.items)} total, {len(not_ready_nodes)} not ready")
            if not_ready_nodes:
                lines.extend(f"  NOT READY: {n}" for n in not_ready_nodes)

            lines.append(f"\nProblem Pods (non-Running/Succeeded): {len(problem_pods)}")
            if problem_pods:
                lines.extend(f"  {p}" for p in problem_pods)

            lines.append(f"\nRecent Warning Events: {len(warning_events)}")
            if warning_events:
                lines.extend(f"  {e}" for e in warning_events[:10])

            return "\n".join(lines)

        except ApiException as exc:
            return f"Error: {handle_k8s_api_error(exc, 'cluster_health')}"
