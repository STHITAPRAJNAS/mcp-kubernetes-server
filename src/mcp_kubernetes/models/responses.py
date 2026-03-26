"""
Pydantic response models for MCP Kubernetes Server tools.
All models are designed for human-readable MCP tool output.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class OperationResult(BaseModel):
    """Generic result for write/mutating operations."""

    success: bool
    operation: str
    resource_kind: str
    resource_name: str
    namespace: str | None = None
    message: str = ""
    dry_run: bool = False
    details: dict[str, Any] = Field(default_factory=dict)

    def to_text(self) -> str:
        status = "SUCCESS" if self.success else "FAILED"
        dr = " [DRY RUN]" if self.dry_run else ""
        parts = [f"[{status}]{dr} {self.operation} {self.resource_kind}/{self.resource_name}"]
        if self.namespace:
            parts.append(f"  Namespace: {self.namespace}")
        if self.message:
            parts.append(f"  Message: {self.message}")
        for k, v in self.details.items():
            parts.append(f"  {k}: {v}")
        return "\n".join(parts)


class ContainerStatus(BaseModel):
    name: str
    image: str
    ready: bool
    restart_count: int
    state: str
    reason: str | None = None


class PodInfo(BaseModel):
    name: str
    namespace: str
    status: str
    phase: str
    node: str | None = None
    ip: str | None = None
    containers: list[ContainerStatus] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    created_at: str | None = None
    age: str | None = None
    owner_kind: str | None = None
    owner_name: str | None = None

    def to_text(self) -> str:
        lines = [
            f"Pod: {self.namespace}/{self.name}",
            f"  Status: {self.status} | Phase: {self.phase}",
            f"  Node: {self.node or 'N/A'} | IP: {self.ip or 'N/A'}",
            f"  Age: {self.age or 'N/A'}",
        ]
        if self.owner_kind:
            lines.append(f"  Owner: {self.owner_kind}/{self.owner_name}")
        if self.containers:
            lines.append("  Containers:")
            for c in self.containers:
                ready_str = "Ready" if c.ready else "NotReady"
                lines.append(
                    f"    - {c.name}: {c.state} ({ready_str}, "
                    f"restarts={c.restart_count})"
                )
        return "\n".join(lines)


class DeploymentInfo(BaseModel):
    name: str
    namespace: str
    replicas: int
    ready_replicas: int
    available_replicas: int
    updated_replicas: int
    strategy: str
    image: str | None = None
    images: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    conditions: list[dict[str, str]] = Field(default_factory=list)
    created_at: str | None = None
    age: str | None = None

    def to_text(self) -> str:
        lines = [
            f"Deployment: {self.namespace}/{self.name}",
            f"  Replicas: {self.ready_replicas}/{self.replicas} ready, "
            f"{self.available_replicas} available, {self.updated_replicas} updated",
            f"  Strategy: {self.strategy}",
            f"  Age: {self.age or 'N/A'}",
        ]
        if self.images:
            lines.append(f"  Images: {', '.join(self.images)}")
        for cond in self.conditions:
            lines.append(
                f"  Condition: {cond.get('type')}={cond.get('status')} - "
                f"{cond.get('message', '')}"
            )
        return "\n".join(lines)


class ServiceInfo(BaseModel):
    name: str
    namespace: str
    type: str
    cluster_ip: str | None = None
    external_ip: str | None = None
    ports: list[str] = Field(default_factory=list)
    selector: dict[str, str] = Field(default_factory=dict)
    labels: dict[str, str] = Field(default_factory=dict)
    age: str | None = None

    def to_text(self) -> str:
        lines = [
            f"Service: {self.namespace}/{self.name}",
            f"  Type: {self.type}",
            f"  ClusterIP: {self.cluster_ip or 'None'}",
            f"  ExternalIP: {self.external_ip or '<none>'}",
            f"  Ports: {', '.join(self.ports) or 'none'}",
            f"  Age: {self.age or 'N/A'}",
        ]
        return "\n".join(lines)


class NamespaceInfo(BaseModel):
    name: str
    status: str
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    age: str | None = None

    def to_text(self) -> str:
        return f"Namespace: {self.name} | Status: {self.status} | Age: {self.age or 'N/A'}"


class NodeCondition(BaseModel):
    type: str
    status: str
    message: str | None = None


class NodeInfo(BaseModel):
    name: str
    status: str
    roles: list[str] = Field(default_factory=list)
    version: str | None = None
    os: str | None = None
    arch: str | None = None
    cpu: str | None = None
    memory: str | None = None
    pods_capacity: str | None = None
    internal_ip: str | None = None
    conditions: list[NodeCondition] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    taints: list[str] = Field(default_factory=list)
    age: str | None = None
    instance_type: str | None = None

    def to_text(self) -> str:
        lines = [
            f"Node: {self.name}",
            f"  Status: {self.status} | Roles: {', '.join(self.roles) or 'none'}",
            f"  Version: {self.version or 'N/A'} | OS: {self.os or 'N/A'} | Arch: {self.arch or 'N/A'}",
            f"  CPU: {self.cpu or 'N/A'} | Memory: {self.memory or 'N/A'} | Max Pods: {self.pods_capacity or 'N/A'}",
            f"  Internal IP: {self.internal_ip or 'N/A'}",
        ]
        if self.instance_type:
            lines.append(f"  Instance Type: {self.instance_type}")
        if self.taints:
            lines.append(f"  Taints: {', '.join(self.taints)}")
        return "\n".join(lines)


class ConfigMapInfo(BaseModel):
    name: str
    namespace: str
    data_keys: list[str] = Field(default_factory=list)
    age: str | None = None

    def to_text(self) -> str:
        return (
            f"ConfigMap: {self.namespace}/{self.name} | "
            f"Keys: {', '.join(self.data_keys) or 'none'} | Age: {self.age or 'N/A'}"
        )


class SecretInfo(BaseModel):
    name: str
    namespace: str
    secret_type: str
    data_keys: list[str] = Field(default_factory=list)
    age: str | None = None
    # Values are NEVER included - this is intentional for security

    def to_text(self) -> str:
        return (
            f"Secret: {self.namespace}/{self.name} | "
            f"Type: {self.secret_type} | "
            f"Keys: {', '.join(self.data_keys) or 'none'} | "
            f"Age: {self.age or 'N/A'} | "
            f"[VALUES REDACTED]"
        )


class IngressRule(BaseModel):
    host: str | None = None
    paths: list[str] = Field(default_factory=list)


class IngressInfo(BaseModel):
    name: str
    namespace: str
    rules: list[IngressRule] = Field(default_factory=list)
    tls_hosts: list[str] = Field(default_factory=list)
    class_name: str | None = None
    load_balancer_ip: str | None = None
    age: str | None = None

    def to_text(self) -> str:
        lines = [f"Ingress: {self.namespace}/{self.name}"]
        if self.class_name:
            lines.append(f"  Class: {self.class_name}")
        if self.load_balancer_ip:
            lines.append(f"  LoadBalancer: {self.load_balancer_ip}")
        for rule in self.rules:
            host = rule.host or "*"
            lines.append(f"  Host: {host}")
            for path in rule.paths:
                lines.append(f"    Path: {path}")
        if self.tls_hosts:
            lines.append(f"  TLS Hosts: {', '.join(self.tls_hosts)}")
        return "\n".join(lines)


class JobInfo(BaseModel):
    name: str
    namespace: str
    status: str
    completions: int | None = None
    succeeded: int = 0
    failed: int = 0
    active: int = 0
    start_time: str | None = None
    completion_time: str | None = None
    age: str | None = None

    def to_text(self) -> str:
        return (
            f"Job: {self.namespace}/{self.name} | Status: {self.status} | "
            f"Succeeded: {self.succeeded}/{self.completions or '?'} | "
            f"Failed: {self.failed} | Active: {self.active} | Age: {self.age or 'N/A'}"
        )


class EventInfo(BaseModel):
    namespace: str
    name: str
    reason: str
    message: str
    type: str  # Normal or Warning
    count: int = 1
    involved_object_kind: str | None = None
    involved_object_name: str | None = None
    source: str | None = None
    first_time: str | None = None
    last_time: str | None = None

    def to_text(self) -> str:
        obj = ""
        if self.involved_object_kind and self.involved_object_name:
            obj = f" [{self.involved_object_kind}/{self.involved_object_name}]"
        return (
            f"[{self.type}]{obj} {self.reason}: {self.message} "
            f"(count={self.count}, last={self.last_time or 'N/A'})"
        )


class ClusterInfo(BaseModel):
    server_version: str
    platform: str | None = None
    cluster_name: str
    environment: str
    identity: str
    node_count: int = 0
    namespace_count: int = 0
    region: str | None = None
    auth_metadata: dict[str, Any] = Field(default_factory=dict)

    def to_text(self) -> str:
        lines = [
            f"Cluster: {self.cluster_name}",
            f"  Environment: {self.environment}",
            f"  Identity: {self.identity}",
            f"  Server Version: {self.server_version}",
            f"  Nodes: {self.node_count} | Namespaces: {self.namespace_count}",
        ]
        if self.region:
            lines.append(f"  Region: {self.region}")
        if self.platform:
            lines.append(f"  Platform: {self.platform}")
        return "\n".join(lines)


class HelmRelease(BaseModel):
    name: str
    namespace: str
    chart: str
    chart_version: str | None = None
    app_version: str | None = None
    status: str
    updated: str | None = None
    revision: int = 0

    def to_text(self) -> str:
        return (
            f"Release: {self.namespace}/{self.name} | Chart: {self.chart} "
            f"v{self.chart_version or '?'} | App: {self.app_version or '?'} | "
            f"Status: {self.status} | Rev: {self.revision} | Updated: {self.updated or 'N/A'}"
        )
