"""Base authentication provider interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kubernetes import client as k8s_client


@dataclass
class AuthResult:
    """Result of a successful authentication attempt."""

    environment: str  # "local" or "aws"
    identity: str  # Human-readable identity (username, role ARN, etc.)
    cluster_name: str  # Kubernetes cluster name or context
    # Each AuthResult carries its own ApiClient so multiple clusters can
    # coexist simultaneously without touching the global configuration.
    api_client: "k8s_client.ApiClient | None" = None
    expires_at: datetime | None = None
    metadata: dict = field(default_factory=dict)

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.utcnow() >= self.expires_at


class AuthProvider(ABC):
    """Abstract base class for Kubernetes authentication providers."""

    @abstractmethod
    async def authenticate(self, cluster: str | None = None) -> AuthResult:
        """
        Authenticate and configure the Kubernetes client.

        Args:
            cluster: Cluster alias or name to connect to. Uses default if None.

        Returns:
            AuthResult with identity and connection metadata.

        Raises:
            AuthenticationError: If authentication fails.
        """
        ...

    @abstractmethod
    async def refresh_if_needed(self) -> bool:
        """
        Refresh credentials if they are expired or near expiry.

        Returns:
            True if credentials were refreshed, False if still valid.
        """
        ...

    @abstractmethod
    def get_current_identity(self) -> str:
        """Return a human-readable string identifying the current principal."""
        ...


class AuthenticationError(Exception):
    """Raised when authentication to a Kubernetes cluster fails."""

    def __init__(self, message: str, provider: str = "", cluster: str = ""):
        super().__init__(message)
        self.provider = provider
        self.cluster = cluster


class ClusterNotFoundError(AuthenticationError):
    """Raised when the specified cluster cannot be found."""
