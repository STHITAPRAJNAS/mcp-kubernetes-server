"""
MCP Kubernetes Server - Main entrypoint.

Enterprise-grade MCP server for Kubernetes operations using FastMCP.
Supports simultaneous connections to multiple EKS clusters via ClusterConnectionPool.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
from typing import Annotated

import structlog
from fastmcp import FastMCP

from .approval import initialize_approval_manager
from .audit import initialize_audit_logger
from .auth.factory import create_auth_provider
from .cluster_pool import initialize_cluster_pool, get_cluster_pool, resolve_manager
from .config import Settings, get_settings
from .namespace_policy import initialize_policy_engine

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
    logging.getLogger("kubernetes").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("mcp_kubernetes").setLevel(log_level)


def create_server(settings: Settings | None = None) -> FastMCP:
    """Create and configure the FastMCP server."""
    s = settings or get_settings()

    mcp = FastMCP(
        name="mcp-kubernetes-server",
        instructions="""
You are connected to one or more Kubernetes clusters via the MCP Kubernetes Server.

MULTI-CLUSTER: All tools accept an optional `cluster` parameter (name or alias).
  - Omit it to use the default cluster
  - Use list_connected_clusters to see available clusters
  - Use switch_cluster to connect to additional clusters

SAFETY LAYERS on destructive operations (applied in order):
  1. MCP_K8S_ALLOW_DESTRUCTIVE must be true
  2. Protected namespaces (kube-system etc.) always blocked
  3. Namespace policy: your identity must have permission for that namespace
  4. confirm_name must equal the resource name exactly
  5. approval_id required if approval workflow is enabled
     - If blocked by approval: you get an approval_id back
     - An approver calls approve_operation(approval_id=...)
     - You re-run with approval_id=<the_id>

SECRETS: Values are NEVER returned. Only key names and metadata.
DRY-RUN: Available on all write/delete operations — always try this first.
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
    # Cluster management tools
    # -------------------------------------------------------------------------

    @mcp.tool
    def list_connected_clusters() -> str:
        """
        List all clusters currently connected in the pool.
        Shows cluster name, identity, and environment for each.
        """
        try:
            pool = get_cluster_pool()
            clusters = pool.list_connected_clusters()
        except RuntimeError:
            return "Cluster pool not initialized."

        if not clusters:
            return "No clusters connected."

        s = get_settings()
        lines = [f"Connected clusters ({len(clusters)}):"]
        for c in clusters:
            aliases = [alias for alias, name in s.cluster_map.items() if name == c["cluster"]]
            alias_str = f" [aliases: {', '.join(aliases)}]" if aliases else ""
            lines.append(
                f"  - {c['cluster']}{alias_str}\n"
                f"      Identity: {c['identity']}\n"
                f"      Environment: {c['environment']}"
            )
        return "\n".join(lines)

    @mcp.tool
    def connect_cluster(
        cluster: Annotated[str, "Cluster name or alias to connect to"],
    ) -> str:
        """
        Connect to an additional cluster and add it to the pool.
        In AWS mode: accepts an EKS cluster name or a configured alias.
        In local mode: accepts a kubeconfig context name.
        After connecting, specify cluster=<name> in any tool call to target it.
        """
        try:
            manager = resolve_manager(cluster)
            return (
                f"Connected to cluster '{manager.current_cluster}'\n"
                f"  Identity: {manager.current_identity}\n"
                f"  Environment: {manager.environment}"
            )
        except Exception as exc:
            return f"Error connecting to cluster '{cluster}': {exc}"

    @mcp.tool
    def get_cluster_info(
        cluster: Annotated[str, "Target cluster (uses default if empty)"] = "",
    ) -> str:
        """
        Get current cluster connection info: version, node/namespace counts, identity.
        """
        from .k8s_client import handle_k8s_api_error
        from .models import ClusterInfo
        from kubernetes.client.rest import ApiException

        manager = resolve_manager(cluster)
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
    def list_available_contexts() -> str:
        """List kubeconfig contexts (local) or configured cluster aliases (AWS)."""
        settings = get_settings()
        lines = []
        from .config import EnvironmentMode
        if settings.env in (EnvironmentMode.LOCAL, EnvironmentMode.AUTO):
            try:
                from .auth.local import LocalAuthProvider
                provider = LocalAuthProvider(
                    kubeconfig_path=settings.kubeconfig,
                    default_context=settings.default_context,
                )
                contexts = provider.list_available_contexts()
                lines.append("Kubeconfig contexts:")
                for ctx in contexts:
                    name = ctx.get("name", "unknown")
                    cluster = ctx.get("context", {}).get("cluster", "?")
                    user = ctx.get("context", {}).get("user", "?")
                    lines.append(f"  - {name} (cluster={cluster}, user={user})")
            except Exception as exc:
                lines.append(f"Could not list contexts: {exc}")

        if settings.cluster_map:
            lines.append("\nConfigured cluster aliases (AWS):")
            for alias, cluster_name in settings.cluster_map.items():
                lines.append(f"  - {alias} → {cluster_name}")

        if not lines:
            lines.append("No contexts or cluster aliases configured.")

        return "\n".join(lines)

    @mcp.tool
    def show_namespace_policy(
        identity: Annotated[str, "IAM ARN or kubeconfig user to evaluate (empty = your own identity)"] = "",
        namespace: Annotated[str, "Namespace to check access for"] = "default",
        cluster: Annotated[str, "Target cluster (uses default if empty)"] = "",
    ) -> str:
        """
        Show what namespace access a given identity has according to the namespace policy.
        Useful for debugging access issues and understanding permission boundaries.
        """
        from .namespace_policy import get_policy_engine, Operation

        manager = resolve_manager(cluster)
        check_identity = identity or manager.current_identity

        engine = get_policy_engine()
        lines = [f"Namespace policy for identity: {check_identity}"]
        lines.append(f"Checking namespace: {namespace}")
        lines.append("")

        for op in Operation:
            decision = engine.evaluate(check_identity, namespace, op)
            if decision.allowed:
                status = "ALLOWED" + (" (requires approval)" if decision.needs_approval else "")
            else:
                status = f"DENIED: {decision.reason}"
            lines.append(f"  {op.value:<15} {status}")

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
    logger = logging.getLogger(__name__)
    logger.info(
        "Starting MCP Kubernetes Server v1.0",
        extra={
            "environment": settings.env.value,
            "transport": settings.transport.value,
            "allow_destructive": settings.allow_destructive,
            "require_approval": settings.require_approval,
            "dry_run": settings.dry_run,
        },
    )

    # Initialize audit logging
    initialize_audit_logger(settings.audit_log_file)

    # Initialize approval workflow
    initialize_approval_manager(
        require_approval=settings.require_approval,
        ttl_seconds=settings.approval_ttl_seconds,
        webhook_url=settings.approval_webhook_url,
        webhook_type=settings.approval_webhook_type,
        allow_self_approve=settings.approval_allow_self_approve,
    )

    # Initialize namespace policy engine
    initialize_policy_engine(settings)

    # Initialize cluster connection pool (pre-connects to all configured clusters)
    try:
        pool = await initialize_cluster_pool(settings)
        connected = pool.list_connected_clusters()
        for c in connected:
            logger.info(
                "Connected to cluster '%s' as '%s' (%s)",
                c["cluster"], c["identity"], c["environment"],
            )
    except Exception as exc:
        logger.warning(
            "Could not pre-connect to cluster(s): %s. "
            "The server will still start — connections will be retried per-request.",
            exc,
        )


def main() -> None:
    settings = get_settings()
    configure_logging(settings)
    logger = logging.getLogger(__name__)

    try:
        asyncio.run(startup(settings))
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as exc:
        logger.warning("Startup errors (server will still start): %s", exc)

    mcp = create_server(settings)

    def handle_shutdown(signum, frame):
        logger.info("Shutting down MCP Kubernetes Server...")
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    logger.info("MCP Kubernetes Server started (transport=%s)", settings.transport.value)
    mcp.run(transport=settings.transport.value)


if __name__ == "__main__":
    main()
