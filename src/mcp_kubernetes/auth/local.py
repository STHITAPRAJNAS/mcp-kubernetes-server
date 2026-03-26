"""
Local authentication provider.
Uses kubeconfig file - suitable for application engineers running locally
who have assumed their team's Kubernetes RBAC role.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from kubernetes import client, config
from kubernetes.config.config_exception import ConfigException

from .base import AuthProvider, AuthResult, AuthenticationError

logger = logging.getLogger(__name__)


class LocalAuthProvider(AuthProvider):
    """
    Authenticates using a local kubeconfig file.

    Supports:
    - Default kubeconfig at ~/.kube/config
    - Custom kubeconfig path via KUBECONFIG env var or explicit path
    - Context switching for multi-cluster local setups
    - All kubeconfig auth mechanisms: certificates, tokens, OIDC, exec plugins
    """

    def __init__(
        self,
        kubeconfig_path: str = "",
        default_context: str = "",
    ) -> None:
        self._kubeconfig_path = kubeconfig_path or None
        self._default_context = default_context or None
        self._current_result: AuthResult | None = None

    async def authenticate(self, cluster: str | None = None) -> AuthResult:
        """Load kubeconfig and configure the Kubernetes client."""
        context = cluster or self._default_context

        try:
            config.load_kube_config(
                config_file=self._kubeconfig_path,
                context=context,
            )
        except ConfigException as exc:
            raise AuthenticationError(
                f"Failed to load kubeconfig: {exc}",
                provider="local",
                cluster=context or "default",
            ) from exc
        except FileNotFoundError as exc:
            kubeconfig_location = self._kubeconfig_path or "~/.kube/config"
            raise AuthenticationError(
                f"Kubeconfig not found at {kubeconfig_location}: {exc}",
                provider="local",
                cluster=context or "default",
            ) from exc

        # Determine which context is actually active
        active_context = self._get_active_context()
        identity = self._get_identity_from_context(active_context)
        cluster_name = active_context.get("context", {}).get("cluster", "unknown")

        logger.info(
            "Local authentication successful",
            extra={
                "context": active_context.get("name"),
                "cluster": cluster_name,
                "identity": identity,
            },
        )

        self._current_result = AuthResult(
            environment="local",
            identity=identity,
            cluster_name=cluster_name,
            expires_at=None,  # kubeconfig tokens may have their own expiry
            metadata={
                "context": active_context.get("name"),
                "kubeconfig": str(self._kubeconfig_path or Path.home() / ".kube" / "config"),
            },
        )
        return self._current_result

    async def refresh_if_needed(self) -> bool:
        """
        Re-load kubeconfig. Useful when exec-based credentials (OIDC, etc.) expire.
        The kubernetes client handles token refresh for most auth plugins automatically.
        """
        # The kubernetes Python client handles token refresh internally for most
        # exec-based plugins (aws, oidc, etc.). We only need to explicitly refresh
        # if using static token files that have rotated.
        return False

    def get_current_identity(self) -> str:
        if self._current_result:
            return self._current_result.identity
        return "unauthenticated"

    def list_available_contexts(self) -> list[dict]:
        """Return all contexts defined in the kubeconfig."""
        try:
            contexts, active_context = config.list_kube_config_contexts(
                config_file=self._kubeconfig_path
            )
            return contexts
        except Exception:
            return []

    def _get_active_context(self) -> dict:
        try:
            _, active_context = config.list_kube_config_contexts(
                config_file=self._kubeconfig_path
            )
            return active_context or {}
        except Exception:
            return {}

    def _get_identity_from_context(self, context: dict) -> str:
        """Extract a human-readable identity from the kubeconfig context."""
        ctx_data = context.get("context", {})
        user = ctx_data.get("user", "unknown-user")
        cluster = ctx_data.get("cluster", "unknown-cluster")
        namespace = ctx_data.get("namespace", "default")
        return f"{user}@{cluster}/{namespace}"
