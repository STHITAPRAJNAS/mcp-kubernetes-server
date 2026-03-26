"""
Kubernetes client manager with per-cluster ApiClient instances.

Each KubernetesClientManager holds its own ApiClient, meaning multiple
clusters can be connected simultaneously without interfering with each other.
The ClusterConnectionPool manages a pool of these managers.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from kubernetes import client as k8s_client
from kubernetes.client.rest import ApiException

from .auth.base import AuthProvider, AuthResult
from .config import Settings, get_settings

logger = logging.getLogger(__name__)


class KubernetesClientManager:
    """
    Manages a single cluster connection via its own ApiClient.
    Never touches the process-global kubernetes configuration.
    """

    def __init__(self, auth_provider: AuthProvider, settings: Settings) -> None:
        self._auth_provider = auth_provider
        self._settings = settings
        self._auth_result: AuthResult | None = None
        self._api_client: k8s_client.ApiClient | None = None
        self._lock = asyncio.Lock()
        self._initialized = False

    async def initialize(self, cluster: str | None = None) -> AuthResult:
        async with self._lock:
            self._auth_result = await self._auth_provider.authenticate(cluster)
            self._api_client = self._auth_result.api_client
            self._initialized = True
            return self._auth_result

    async def ensure_connected(self) -> None:
        if not self._initialized:
            await self.initialize()
            return
        refreshed = await self._auth_provider.refresh_if_needed()
        if refreshed:
            # Re-authenticate to get a fresh ApiClient with new token
            self._auth_result = await self._auth_provider.authenticate(
                self._auth_result.cluster_name if self._auth_result else None
            )
            self._api_client = self._auth_result.api_client
            logger.info("Credentials refreshed for cluster %s", self.current_cluster)

    # -------------------------------------------------------------------------
    # API client accessors — each takes the per-cluster api_client
    # -------------------------------------------------------------------------

    def core_v1(self) -> k8s_client.CoreV1Api:
        return k8s_client.CoreV1Api(api_client=self._api_client)

    def apps_v1(self) -> k8s_client.AppsV1Api:
        return k8s_client.AppsV1Api(api_client=self._api_client)

    def batch_v1(self) -> k8s_client.BatchV1Api:
        return k8s_client.BatchV1Api(api_client=self._api_client)

    def networking_v1(self) -> k8s_client.NetworkingV1Api:
        return k8s_client.NetworkingV1Api(api_client=self._api_client)

    def rbac_v1(self) -> k8s_client.RbacAuthorizationV1Api:
        return k8s_client.RbacAuthorizationV1Api(api_client=self._api_client)

    def storage_v1(self) -> k8s_client.StorageV1Api:
        return k8s_client.StorageV1Api(api_client=self._api_client)

    def autoscaling_v2(self) -> k8s_client.AutoscalingV2Api:
        return k8s_client.AutoscalingV2Api(api_client=self._api_client)

    def custom_objects(self) -> k8s_client.CustomObjectsApi:
        return k8s_client.CustomObjectsApi(api_client=self._api_client)

    def version_api(self) -> k8s_client.VersionApi:
        return k8s_client.VersionApi(api_client=self._api_client)

    @property
    def api_client(self) -> k8s_client.ApiClient | None:
        return self._api_client

    @property
    def current_identity(self) -> str:
        return self._auth_provider.get_current_identity()

    @property
    def current_cluster(self) -> str:
        return self._auth_result.cluster_name if self._auth_result else "unknown"

    @property
    def environment(self) -> str:
        return self._auth_result.environment if self._auth_result else "unknown"

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
    status_code = exc.status
    reason = exc.reason or "Unknown error"
    messages = {
        400: f"Bad request during {operation}: {reason}",
        401: f"Unauthorized - check credentials/RBAC for {operation}",
        403: f"Forbidden - insufficient permissions for {operation}: {reason}",
        404: f"Resource not found during {operation}: {reason}",
        409: f"Conflict during {operation} - resource may already exist: {reason}",
        422: f"Invalid resource specification for {operation}: {reason}",
        429: f"Rate limited by Kubernetes API during {operation}. Retry later.",
        500: f"Kubernetes API server error during {operation}: {reason}",
        503: f"Kubernetes API server unavailable during {operation}",
    }
    return messages.get(
        status_code,
        f"Kubernetes API error ({status_code}) during {operation}: {reason}",
    )
