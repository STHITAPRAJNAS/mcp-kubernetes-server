"""
MCP Kubernetes Server - Main entrypoint.

Enterprise-grade MCP server for Kubernetes operations using FastMCP.
Supports:
- Local kubeconfig authentication (for application engineers)
- AWS EKS IAM role authentication (for AWS-deployed workloads)
- Comprehensive audit logging
- Destructive operation guards
- Multi-cluster support
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
from fastmcp import FastMCP

from .audit import initialize_audit_logger
from .auth.factory import create_auth_provider
from .config import Settings, get_settings
from .k8s_client import KubernetesClientManager, initialize_client_manager

# Tool registrars
from .tools.pods import register_pod_tools
from .tools.deployments import register_deployment_tools
from .tools.namespaces import register_namespace_tools
from .tools.services import register_service_tools
from .tools.nodes import register_node_tools
from .tools.configmaps_secrets import register_configmap_secret_tools
from .tools.events import register_event_tools
from .tools.apply import register_apply_tools
from .tools.destructive import register_destructive_tools

# Resource registrars
from .resources.cluster import register_cluster_resources

# Prompt registrars
from .prompts.diagnose import register_diagnostic_prompts


def configure_logging(settings: Settings) -> None:
    """Configure structured logging."""
    log_level = getattr(logging, settings.log_level.value, logging.INFO)

    if settings.json_logs:
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
        )
    else:
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            stream=sys.stderr,
        )

    # Set log levels
    logging.getLogger("kubernetes").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("mcp_kubernetes").setLevel(log_level)


def create_server(settings: Settings | None = None) -> FastMCP:
    """
    Create and configure the FastMCP server with all tools, resources, and prompts.

    This is the factory function - it builds the server object but does not start it.
    """
    s = settings or get_settings()

    mcp = FastMCP(
        name="mcp-kubernetes-server",
        instructions="""
You are connected to a Kubernetes cluster via the MCP Kubernetes Server.

Available capabilities:
- READ: List and inspect pods, deployments, services, namespaces, nodes, events, logs
- WRITE: Scale deployments, restart workloads, create namespaces/configmaps, apply manifests
- DESTRUCTIVE: Delete pods, deployments, namespaces, configmaps, services (with guards)
- EXEC: Run commands inside pods for diagnostics

Safety rules enforced automatically:
1. Protected namespaces (kube-system, kube-public, kube-node-lease) cannot be modified
2. Destructive operations require a confirmation token (confirm_name must match resource name)
3. All operations are audit-logged
4. Dry-run mode is available for all write/delete operations

Best practices:
- Always use dry_run=true before destructive operations
- Check cluster health with the k8s://cluster/health resource
- Use the diagnose_pod or diagnose_deployment prompts for troubleshooting
- Secret values are NEVER returned - only key names are shown
""",
    )

    # -------------------------------------------------------------------------
    # Register all tools
    # -------------------------------------------------------------------------
    register_pod_tools(mcp)
    register_deployment_tools(mcp)
    register_namespace_tools(mcp)
    register_service_tools(mcp)
    register_node_tools(mcp)
    register_configmap_secret_tools(mcp)
    register_event_tools(mcp)
    register_apply_tools(mcp)
    register_destructive_tools(mcp)

    # -------------------------------------------------------------------------
    # Register additional utility tools directly on the server
    # -------------------------------------------------------------------------

    @mcp.tool
    def get_cluster_info() -> str:
        """
        Get current cluster connection information: cluster name, identity,
        server version, node count, and authentication mode.
        """
        from .k8s_client import get_client_manager, handle_k8s_api_error
        from .models import ClusterInfo
        from kubernetes.client.rest import ApiException

        manager = get_client_manager()
        try:
            version_api = manager.version_api()
            version_info = version_api.get_code()
            server_version = f"{version_info.major}.{version_info.minor}"

            core = manager.core_v1()
            nodes = core.list_node()
            namespaces = core.list_namespace()

            auth_meta = manager.get_auth_metadata()
            info = ClusterInfo(
                server_version=server_version,
                platform=version_info.platform,
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
            return f"Error: {handle_k8s_api_error(exc, 'get_cluster_info')}"

    @mcp.tool
    def switch_cluster(
        cluster: str,
    ) -> str:
        """
        Switch the active cluster connection.

        In LOCAL mode: switches kubeconfig context.
        In AWS mode: connects to a different EKS cluster by name or alias.

        Use get_cluster_info to verify the current connection after switching.
        """
        import asyncio
        from .k8s_client import initialize_client_manager
        from .auth.factory import create_auth_provider

        settings = get_settings()
        auth_provider = create_auth_provider(settings)

        try:
            loop = asyncio.get_event_loop()
            loop.run_until_complete(initialize_client_manager(auth_provider, settings, cluster=cluster))
            from .k8s_client import get_client_manager
            manager = get_client_manager()
            return (
                f"Switched to cluster '{cluster}'\n"
                f"Identity: {manager.current_identity}\n"
                f"Cluster: {manager.current_cluster}"
            )
        except Exception as exc:
            return f"Error switching cluster: {exc}"

    @mcp.tool
    def list_available_contexts() -> str:
        """
        List available kubeconfig contexts (LOCAL mode) or configured cluster aliases (AWS mode).
        """
        settings = get_settings()
        from .config import EnvironmentMode
        from .auth.local import LocalAuthProvider

        lines = []
        if settings.env in (settings.env.LOCAL, settings.env.AUTO):
            try:
                provider = LocalAuthProvider(
                    kubeconfig_path=settings.kubeconfig,
                    default_context=settings.default_context,
                )
                contexts = provider.list_available_contexts()
                lines.append("Available kubeconfig contexts:")
                for ctx in contexts:
                    name = ctx.get("name", "unknown")
                    cluster = ctx.get("context", {}).get("cluster", "?")
                    user = ctx.get("context", {}).get("user", "?")
                    lines.append(f"  - {name} (cluster={cluster}, user={user})")
            except Exception as exc:
                lines.append(f"Could not list kubeconfig contexts: {exc}")

        if settings.cluster_map:
            lines.append("\nConfigured cluster aliases (AWS):")
            for alias, cluster_name in settings.cluster_map.items():
                lines.append(f"  - {alias} → {cluster_name}")

        if not lines:
            lines.append("No contexts or cluster aliases configured.")
            lines.append("Set KUBECONFIG (local) or MCP_K8S_CLUSTER_MAP (AWS).")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Register resources
    # -------------------------------------------------------------------------
    register_cluster_resources(mcp)

    # -------------------------------------------------------------------------
    # Register prompts
    # -------------------------------------------------------------------------
    register_diagnostic_prompts(mcp)

    return mcp


async def startup(settings: Settings) -> None:
    """Initialize authentication and Kubernetes client on startup."""
    logger = logging.getLogger(__name__)

    logger.info(
        "Starting MCP Kubernetes Server",
        extra={
            "environment": settings.env.value,
            "transport": settings.transport.value,
            "allow_destructive": settings.allow_destructive,
            "dry_run": settings.dry_run,
        }
    )

    # Initialize audit logging
    audit = initialize_audit_logger(settings.audit_log_file)

    # Initialize authentication and connect to cluster
    auth_provider = create_auth_provider(settings)
    default_cluster = settings.default_cluster or settings.eks_cluster_name or None

    try:
        manager = await initialize_client_manager(
            auth_provider,
            settings,
            cluster=default_cluster,
        )
        logger.info(
            "Connected to cluster",
            extra={
                "cluster": manager.current_cluster,
                "identity": manager.current_identity,
                "environment": manager.environment,
            }
        )

        audit.log(
            audit.__class__.__module__ and __import__("mcp_kubernetes.audit", fromlist=["OperationType"]).OperationType.AUTH,
            "server_startup", "Cluster", manager.current_cluster, None,
            manager.current_identity, manager.current_cluster, True,
        )

    except Exception as exc:
        logger.error("Failed to authenticate to Kubernetes cluster: %s", exc)
        logger.error(
            "Check your configuration:\n"
            "  - Local: verify kubeconfig at ~/.kube/config or $KUBECONFIG\n"
            "  - AWS: verify MCP_K8S_EKS_CLUSTER_NAME and AWS credentials"
        )
        # Don't crash on startup - allow the server to start and report errors per-tool


def main() -> None:
    """Main entrypoint for the MCP Kubernetes Server."""
    settings = get_settings()
    configure_logging(settings)

    logger = logging.getLogger(__name__)

    # Perform async startup (auth + cluster connection)
    try:
        asyncio.run(startup(settings))
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as exc:
        logger.warning("Startup had errors (server will still start): %s", exc)

    # Create and run the MCP server
    mcp = create_server(settings)

    # Handle graceful shutdown
    def handle_shutdown(signum, frame):
        logger.info("Shutting down MCP Kubernetes Server...")
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    logger.info(
        "MCP Kubernetes Server started",
        extra={"transport": settings.transport.value}
    )

    mcp.run(transport=settings.transport.value)


if __name__ == "__main__":
    main()
