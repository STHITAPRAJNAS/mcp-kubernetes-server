"""
ClusterConnectionPool — manages simultaneous connections to multiple EKS clusters.

Design:
- Each cluster gets its own KubernetesClientManager with an isolated ApiClient.
- No process-global kubernetes config is mutated; clusters coexist safely.
- Connections are created lazily on first use and cached.
- Tokens are refreshed transparently before they expire.
- All tools accept an optional `cluster` parameter to target a specific cluster.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable

from .auth.base import AuthProvider
from .auth.factory import create_auth_provider
from .config import Settings, get_settings
from .k8s_client import KubernetesClientManager

logger = logging.getLogger(__name__)


class ClusterConnectionPool:
    """
    Thread-safe pool of authenticated Kubernetes cluster connections.

    Lifecycle
    ---------
    - On server startup, pre-connect to the default cluster (and any clusters
      listed in settings.cluster_map).
    - On first use of an unknown cluster alias/name, connect lazily.
    - Background token refresh is handled by KubernetesClientManager.ensure_connected().
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        # key → KubernetesClientManager
        self._connections: dict[str, KubernetesClientManager] = {}
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """
        Pre-connect to all clusters defined in settings.
        Called once at server startup; individual failures are logged but do not
        prevent the server from starting.
        """
        # Determine clusters to pre-connect
        clusters_to_init: list[str | None] = []

        if self._settings.default_cluster:
            clusters_to_init.append(self._settings.default_cluster)
        elif self._settings.eks_cluster_name:
            # In AWS mode the cluster name is the default
            clusters_to_init.append(None)  # None → use default from auth provider
        else:
            # Local mode — connect to current-context
            clusters_to_init.append(None)

        # Also pre-connect all aliases in cluster_map
        for alias in self._settings.cluster_map:
            if alias not in clusters_to_init:
                clusters_to_init.append(alias)

        for cluster in clusters_to_init:
            try:
                await self.get(cluster)
                logger.info("Pre-connected to cluster: %s", cluster or "default")
            except Exception as exc:
                logger.warning(
                    "Could not pre-connect to cluster '%s': %s",
                    cluster or "default",
                    exc,
                )

    async def get(self, cluster: str | None = None) -> KubernetesClientManager:
        """
        Return the KubernetesClientManager for the given cluster.

        Args:
            cluster: Cluster alias (from cluster_map), EKS cluster name, or
                     kubeconfig context name. None → default cluster.

        Raises:
            AuthenticationError: If connection to the cluster fails.
        """
        key = self._resolve_key(cluster)

        async with self._lock:
            if key in self._connections:
                mgr = self._connections[key]
            else:
                mgr = await self._connect(cluster, key)
                self._connections[key] = mgr

        # Refresh outside the lock (avoid blocking other callers during token refresh)
        await mgr.ensure_connected()
        return mgr

    def get_sync(self, cluster: str | None = None) -> KubernetesClientManager:
        """
        Synchronous wrapper used by MCP tool functions (which are sync).
        Uses the running event loop if available, otherwise creates one.
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # We're inside an async context (e.g. pytest-asyncio) — use run_coroutine_threadsafe
                import concurrent.futures
                future = asyncio.run_coroutine_threadsafe(self.get(cluster), loop)
                return future.result(timeout=30)
            else:
                return loop.run_until_complete(self.get(cluster))
        except RuntimeError:
            return asyncio.run(self.get(cluster))

    def list_connected_clusters(self) -> list[dict]:
        """Return info about all currently connected clusters."""
        return [
            {
                "key": key,
                "cluster": mgr.current_cluster,
                "identity": mgr.current_identity,
                "environment": mgr.environment,
            }
            for key, mgr in self._connections.items()
        ]

    async def disconnect(self, cluster: str) -> bool:
        """Remove and close a cluster connection."""
        key = self._resolve_key(cluster)
        async with self._lock:
            if key in self._connections:
                mgr = self._connections.pop(key)
                if mgr.api_client:
                    mgr.api_client.rest_client.pool_manager.clear()
                return True
        return False

    async def _connect(self, cluster: str | None, key: str) -> KubernetesClientManager:
        """Create a new authenticated connection to a cluster."""
        settings = self._settings
        auth_provider = create_auth_provider(settings)
        mgr = KubernetesClientManager(auth_provider, settings)
        await mgr.initialize(cluster)
        logger.info(
            "Connected to cluster '%s' as '%s'",
            mgr.current_cluster,
            mgr.current_identity,
        )
        return mgr

    def _resolve_key(self, cluster: str | None) -> str:
        """
        Produce a stable cache key for a cluster reference.
        Resolves aliases to their canonical names.
        """
        if not cluster:
            return (
                self._settings.default_cluster
                or self._settings.eks_cluster_name
                or "__default__"
            )
        # If it's an alias in the cluster_map, resolve it
        resolved = self._settings.cluster_map.get(cluster, cluster)
        return resolved


# ---------------------------------------------------------------------------
# Global singleton pool
# ---------------------------------------------------------------------------
_pool: ClusterConnectionPool | None = None


def get_cluster_pool() -> ClusterConnectionPool:
    if _pool is None:
        raise RuntimeError(
            "ClusterConnectionPool not initialized. "
            "Call initialize_cluster_pool() at server startup."
        )
    return _pool


async def initialize_cluster_pool(settings: Settings | None = None) -> ClusterConnectionPool:
    global _pool
    s = settings or get_settings()
    pool = ClusterConnectionPool(s)
    await pool.initialize()
    _pool = pool
    return pool


# ---------------------------------------------------------------------------
# Convenience helper used by all MCP tool functions
# ---------------------------------------------------------------------------

def resolve_manager(cluster: str = "") -> KubernetesClientManager:
    """
    Get the KubernetesClientManager for a cluster.
    This is the single call every MCP tool makes — it handles everything:
    lazy connect, token refresh, alias resolution.
    """
    return get_cluster_pool().get_sync(cluster or None)
