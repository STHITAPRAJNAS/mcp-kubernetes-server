"""
Configuration management for MCP Kubernetes Server.
Supports loading from environment variables and .env files.
"""

from __future__ import annotations

import json
import os
from enum import Enum
from typing import Any

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class EnvironmentMode(str, Enum):
    LOCAL = "local"
    AWS = "aws"
    AUTO = "auto"


class TransportMode(str, Enum):
    STDIO = "stdio"
    SSE = "sse"


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Settings(BaseSettings):
    """
    Central configuration for the MCP Kubernetes Server.
    All settings can be set via environment variables with the MCP_K8S_ prefix.
    """

    model_config = SettingsConfigDict(
        env_prefix="MCP_K8S_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -------------------------------------------------------------------------
    # Environment
    # -------------------------------------------------------------------------
    env: EnvironmentMode = Field(
        default=EnvironmentMode.AUTO,
        description="Runtime environment: local, aws, or auto-detect",
    )

    # -------------------------------------------------------------------------
    # Server
    # -------------------------------------------------------------------------
    transport: TransportMode = Field(default=TransportMode.STDIO)
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8080, ge=1, le=65535)
    log_level: LogLevel = Field(default=LogLevel.INFO)
    json_logs: bool = Field(default=False)
    audit_log_file: str = Field(default="")

    # -------------------------------------------------------------------------
    # Local auth
    # -------------------------------------------------------------------------
    kubeconfig: str = Field(default="", alias="KUBECONFIG")
    default_context: str = Field(default="")

    # -------------------------------------------------------------------------
    # AWS auth
    # -------------------------------------------------------------------------
    aws_region: str = Field(default="us-east-1", alias="AWS_DEFAULT_REGION")
    aws_profile: str = Field(default="", alias="AWS_PROFILE")
    eks_cluster_name: str = Field(default="")
    aws_role_arn: str = Field(default="")
    aws_role_session_duration: int = Field(default=3600, ge=900, le=43200)
    aws_role_session_name: str = Field(default="mcp-kubernetes-server")

    # -------------------------------------------------------------------------
    # Security & safety
    # -------------------------------------------------------------------------
    allow_destructive: bool = Field(default=True)
    protected_namespaces: list[str] = Field(
        default=["kube-system", "kube-public", "kube-node-lease"]
    )
    require_destructive_confirmation: bool = Field(default=True)
    max_batch_delete: int = Field(default=5, ge=1, le=50)
    dry_run: bool = Field(default=False)
    mask_secrets: bool = Field(default=True)

    # -------------------------------------------------------------------------
    # Rate limiting
    # -------------------------------------------------------------------------
    rate_limit_per_minute: int = Field(default=120, ge=0)
    max_concurrent_requests: int = Field(default=10, ge=1)
    request_timeout: int = Field(default=30, ge=5, le=300)

    # -------------------------------------------------------------------------
    # Multi-cluster
    # -------------------------------------------------------------------------
    cluster_map: dict[str, str] = Field(default_factory=dict)
    default_cluster: str = Field(default="")

    # -------------------------------------------------------------------------
    # Approval workflow
    # -------------------------------------------------------------------------
    # Require out-of-band approval for destructive operations
    require_approval: bool = Field(default=False)
    # Approval TTL in seconds (default 30 min)
    approval_ttl_seconds: int = Field(default=1800, ge=60, le=86400)
    # Webhook URL for approval notifications (Slack/Teams/generic)
    approval_webhook_url: str = Field(default="")
    # Webhook type: "slack" | "teams" | "generic"
    approval_webhook_type: str = Field(default="slack")
    # Allow the requester to approve their own request (always False in production)
    approval_allow_self_approve: bool = Field(default=False)

    # -------------------------------------------------------------------------
    # Namespace-level write scoping policy
    # -------------------------------------------------------------------------
    # JSON array of policy rules (see namespace_policy.py for schema)
    namespace_policy: str = Field(default="")
    # Path to a JSON file containing namespace policy rules
    namespace_policy_file: str = Field(default="")
    # If true, identities with no matching policy are denied entirely
    namespace_policy_deny_unknown: bool = Field(default=False)

    # -------------------------------------------------------------------------
    # Validators
    # -------------------------------------------------------------------------
    @field_validator("protected_namespaces", mode="before")
    @classmethod
    def parse_namespaces(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return [ns.strip() for ns in v.split(",") if ns.strip()]
        return v

    @field_validator("cluster_map", mode="before")
    @classmethod
    def parse_cluster_map(cls, v: Any) -> dict[str, str]:
        if isinstance(v, str):
            if not v:
                return {}
            return json.loads(v)
        return v or {}

    @model_validator(mode="after")
    def resolve_kubeconfig(self) -> Settings:
        # Allow KUBECONFIG env var override from shell environment
        env_kubeconfig = os.environ.get("KUBECONFIG", "")
        if env_kubeconfig and not self.kubeconfig:
            self.kubeconfig = env_kubeconfig
        return self

    def is_protected_namespace(self, namespace: str) -> bool:
        return namespace in self.protected_namespaces

    def get_eks_cluster_for_alias(self, alias: str) -> str | None:
        if alias in self.cluster_map:
            return self.cluster_map[alias]
        return None


# Singleton settings instance
_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
