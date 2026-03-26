"""
Kubernetes client manager with connection lifecycle and credential refresh.
Acts as the central access point for all Kubernetes API operations.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncIterator

from kubernetes import client as k8s_client
from kubernetes.client.rest import ApiException

from .auth.base import AuthProvider, AuthResult
from .config import Settings, get_settings

logger = logging.getLogger(__name__)


class KubernetesClientManager:
    """
    Manages Kubernetes API client instances with automatic credential refresh.

    Provides access to all Kubernetes API groups:
    - CoreV1Api:    pods, services, configmaps, secrets, namespaces, nodes, events
    - AppsV1Api:    deployments, statefulsets, daemonsets, replicasets
    - BatchV1Api:   jobs, cronjobs
    - NetworkingV1Api: ingresses, networkpolicies
    - RbacAuthorizationV1Api: roles, rolebindings, clusterroles
    - StorageV1Api: storageclasses, persistentvolumes
    """

    def __init__(self, auth_provider: AuthProvider, settings: Settings) -> None:
        self._auth_provider = auth_provider
        self._settings = settings
        self._auth_result: AuthResult | None = None
        self._lock = asyncio.Lock()
        self._initialized = False

    async def initialize(self, cluster: str | None = None) -> AuthResult:
        """Authenticate and prepare the Kubernetes client."""
        async with self._lock:
            self._auth_result = await self._auth_provider.authenticate(cluster)
            self._initialized = True
            return self._auth_result

    async def ensure_connected(self) -> None:
        """Ensure a live connection; refresh credentials if expired."""
        if not self._initialized:
            await self.initialize()
            return

        # Refresh credentials if needed (e.g., EKS tokens, OIDC tokens)
        refreshed = await self._auth_provider.refresh_if_needed()
        if refreshed:
            logger.info("Credentials refreshed successfully")

    # -------------------------------------------------------------------------
    # API client accessors
    # -------------------------------------------------------------------------

    def core_v1(self) -> k8s_client.CoreV1Api:
        return k8s_client.CoreV1Api()

    def apps_v1(self) -> k8s_client.AppsV1Api:
        return k8s_client.AppsV1Api()

    def batch_v1(self) -> k8s_client.BatchV1Api:
        return k8s_client.BatchV1Api()

    def networking_v1(self) -> k8s_client.NetworkingV1Api:
        return k8s_client.NetworkingV1Api()

    def rbac_v1(self) -> k8s_client.RbacAuthorizationV1Api:
        return k8s_client.RbacAuthorizationV1Api()

    def storage_v1(self) -> k8s_client.StorageV1Api:
        return k8s_client.StorageV1Api()

    def autoscaling_v2(self) -> k8s_client.AutoscalingV2Api:
        return k8s_client.AutoscalingV2Api()

    def custom_objects(self) -> k8s_client.CustomObjectsApi:
        return k8s_client.CustomObjectsApi()

    def version_api(self) -> k8s_client.VersionApi:
        return k8s_client.VersionApi()

    # -------------------------------------------------------------------------
    # Convenience helpers
    # -------------------------------------------------------------------------

    @property
    def current_identity(self) -> str:
        return self._auth_provider.get_current_identity()

    @property
    def current_cluster(self) -> str:
        if self._auth_result:
            return self._auth_result.cluster_name
        return "unknown"

    @property
    def environment(self) -> str:
        if self._auth_result:
            return self._auth_result.environment
        return "unknown"

    def get_auth_metadata(self) -> dict:
        if self._auth_result:
            return {
                "environment": self._auth_result.environment,
                "identity": self._auth_result.identity,
                "cluster": self._auth_result.cluster_name,
                "expires_at": (
                    self._auth_result.expires_at.isoformat()
                    if self._auth_result.expires_at
                    else None
                ),
                **self._auth_result.metadata,
            }
        return {}


def handle_k8s_api_error(exc: ApiException, operation: str = "") -> str:
    """
    Convert a Kubernetes ApiException into a human-readable error message.
    Avoids leaking raw Kubernetes error bodies which may contain sensitive info.
    """
    status_code = exc.status
    reason = exc.reason or "Unknown error"

    messages = {
        400: f"Bad request during {operation}: {reason}",
        401: f"Unauthorized - check your credentials/RBAC permissions for {operation}",
        403: f"Forbidden - insufficient permissions for {operation}: {reason}",
        404: f"Resource not found during {operation}: {reason}",
        405: f"Method not allowed for {operation}",
        409: f"Conflict during {operation} - resource may already exist: {reason}",
        422: f"Invalid resource specification for {operation}: {reason}",
        429: f"Rate limited by Kubernetes API during {operation}. Retry later.",
        500: f"Kubernetes API server error during {operation}: {reason}",
        503: f"Kubernetes API server unavailable during {operation}",
    }

    return messages.get(status_code, f"Kubernetes API error ({status_code}) during {operation}: {reason}")


# ---------------------------------------------------------------------------
# Global singleton client manager
# ---------------------------------------------------------------------------
_client_manager: KubernetesClientManager | None = None


def get_client_manager() -> KubernetesClientManager:
    """Return the global Kubernetes client manager (must be initialized first)."""
    if _client_manager is None:
        raise RuntimeError(
            "KubernetesClientManager not initialized. "
            "Call initialize_client_manager() first."
        )
    return _client_manager


async def initialize_client_manager(
    auth_provider: AuthProvider,
    settings: Settings | None = None,
    cluster: str | None = None,
) -> KubernetesClientManager:
    """Create and initialize the global client manager."""
    global _client_manager
    s = settings or get_settings()
    manager = KubernetesClientManager(auth_provider, s)
    await manager.initialize(cluster)
    _client_manager = manager
    return manager
