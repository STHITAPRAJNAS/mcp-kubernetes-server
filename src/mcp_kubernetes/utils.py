"""
Utility functions shared across MCP Kubernetes Server tools.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


def format_age(created_at: datetime | str | None) -> str:
    """Return a human-readable age string (e.g., '2d3h', '45m', '12s')."""
    if not created_at:
        return "unknown"

    if isinstance(created_at, str):
        # Parse ISO 8601 / RFC 3339
        try:
            # Handle trailing Z
            ts = created_at.replace("Z", "+00:00")
            created_at = datetime.fromisoformat(ts)
        except ValueError:
            return "unknown"

    now = datetime.now(tz=timezone.utc)
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)

    delta = now - created_at
    total_seconds = int(delta.total_seconds())

    if total_seconds < 0:
        return "just now"
    if total_seconds < 60:
        return f"{total_seconds}s"
    if total_seconds < 3600:
        return f"{total_seconds // 60}m{total_seconds % 60}s"
    if total_seconds < 86400:
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        return f"{hours}h{minutes}m"

    days = total_seconds // 86400
    hours = (total_seconds % 86400) // 3600
    return f"{days}d{hours}h"


def mask_secret_value(value: str | bytes | None) -> str:
    """Replace a secret value with a masked placeholder."""
    if value is None:
        return "<null>"
    length = len(value) if isinstance(value, str) else len(value)
    return f"<redacted:{length}bytes>"


def extract_container_state(container_status: Any) -> tuple[str, str | None]:
    """Extract state string and reason from a Kubernetes ContainerStatus."""
    if not container_status or not container_status.state:
        return "unknown", None

    state = container_status.state
    if state.running:
        return "running", None
    if state.waiting:
        return "waiting", state.waiting.reason
    if state.terminated:
        reason = state.terminated.reason or "Completed"
        exit_code = state.terminated.exit_code
        return f"terminated(exit={exit_code})", reason

    return "unknown", None


def extract_node_roles(node: Any) -> list[str]:
    """Extract node roles from labels."""
    roles = []
    labels = node.metadata.labels or {}
    for key in labels:
        if key.startswith("node-role.kubernetes.io/"):
            role = key.split("/", 1)[1]
            roles.append(role)
    if not roles:
        roles = ["worker"]
    return sorted(roles)


def format_resource_quantity(quantity: str | None) -> str:
    """Format a Kubernetes resource quantity string."""
    if not quantity:
        return "N/A"
    return quantity


def sanitize_for_display(text: str, max_length: int = 5000) -> str:
    """Truncate and sanitize text for safe MCP display."""
    if len(text) > max_length:
        return text[:max_length] + f"\n... [truncated, {len(text)} total chars]"
    return text


def validate_resource_name(name: str) -> bool:
    """Validate a Kubernetes resource name against DNS subdomain rules."""
    if not name or len(name) > 253:
        return False
    pattern = r"^[a-z0-9][a-z0-9\-\.]*[a-z0-9]$|^[a-z0-9]$"
    return bool(re.match(pattern, name))


def validate_namespace(namespace: str) -> bool:
    """Validate a Kubernetes namespace name."""
    if not namespace or len(namespace) > 63:
        return False
    pattern = r"^[a-z0-9][a-z0-9\-]*[a-z0-9]$|^[a-z0-9]$"
    return bool(re.match(pattern, namespace))


def format_labels(labels: dict[str, str] | None) -> str:
    """Format labels dict as a compact string."""
    if not labels:
        return "<none>"
    return ", ".join(f"{k}={v}" for k, v in sorted(labels.items()))


def safe_get(obj: Any, *attrs: str, default: Any = None) -> Any:
    """Safely navigate nested object attributes."""
    current = obj
    for attr in attrs:
        if current is None:
            return default
        try:
            current = getattr(current, attr)
        except AttributeError:
            return default
    return current if current is not None else default
