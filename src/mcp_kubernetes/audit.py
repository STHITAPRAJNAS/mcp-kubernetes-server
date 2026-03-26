"""
Audit logging for all Kubernetes operations performed via MCP.
Provides an immutable trail of who did what, when.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger("mcp_kubernetes.audit")


class OperationType(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"
    EXEC = "EXEC"
    SCALE = "SCALE"
    AUTH = "AUTH"


class AuditLogger:
    """
    Structured audit logger for Kubernetes operations.

    Each audit record contains:
    - timestamp (ISO 8601 UTC)
    - operation type (READ/WRITE/DELETE/EXEC/SCALE/AUTH)
    - tool name (the MCP tool that was called)
    - resource kind and name
    - namespace
    - identity (who performed the operation)
    - cluster name
    - success/failure
    - dry_run flag
    - any additional context
    """

    def __init__(self, log_file: str = "") -> None:
        self._file_handler: logging.FileHandler | None = None

        if log_file:
            os.makedirs(os.path.dirname(log_file) if os.path.dirname(log_file) else ".", exist_ok=True)
            self._file_handler = logging.FileHandler(log_file)
            self._file_handler.setLevel(logging.INFO)
            audit_file_logger = logging.getLogger("mcp_kubernetes.audit.file")
            audit_file_logger.addHandler(self._file_handler)
            audit_file_logger.setLevel(logging.INFO)
            audit_file_logger.propagate = False
            self._file_logger = audit_file_logger
        else:
            self._file_logger = None

    def log(
        self,
        operation_type: OperationType,
        tool: str,
        resource_kind: str,
        resource_name: str,
        namespace: str | None,
        identity: str,
        cluster: str,
        success: bool,
        dry_run: bool = False,
        error: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Record a single audit event."""
        record = {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "operation_type": operation_type.value,
            "tool": tool,
            "resource_kind": resource_kind,
            "resource_name": resource_name,
            "namespace": namespace,
            "identity": identity,
            "cluster": cluster,
            "success": success,
            "dry_run": dry_run,
        }
        if error:
            record["error"] = error
        if extra:
            record["extra"] = extra

        log_line = json.dumps(record)

        # Always log to the standard audit logger
        if success:
            logger.info(log_line)
        else:
            logger.warning(log_line)

        # Also write to dedicated audit file if configured
        if self._file_logger:
            self._file_logger.info(log_line)

    def log_read(
        self,
        tool: str,
        resource_kind: str,
        resource_name: str,
        namespace: str | None,
        identity: str,
        cluster: str,
        success: bool,
        error: str | None = None,
    ) -> None:
        self.log(
            OperationType.READ,
            tool, resource_kind, resource_name,
            namespace, identity, cluster, success, error=error,
        )

    def log_write(
        self,
        tool: str,
        resource_kind: str,
        resource_name: str,
        namespace: str | None,
        identity: str,
        cluster: str,
        success: bool,
        dry_run: bool = False,
        error: str | None = None,
        extra: dict | None = None,
    ) -> None:
        self.log(
            OperationType.WRITE,
            tool, resource_kind, resource_name,
            namespace, identity, cluster, success,
            dry_run=dry_run, error=error, extra=extra,
        )

    def log_delete(
        self,
        tool: str,
        resource_kind: str,
        resource_name: str,
        namespace: str | None,
        identity: str,
        cluster: str,
        success: bool,
        dry_run: bool = False,
        error: str | None = None,
    ) -> None:
        self.log(
            OperationType.DELETE,
            tool, resource_kind, resource_name,
            namespace, identity, cluster, success,
            dry_run=dry_run, error=error,
        )

    def log_exec(
        self,
        tool: str,
        pod_name: str,
        namespace: str,
        command: str,
        identity: str,
        cluster: str,
        success: bool,
        error: str | None = None,
    ) -> None:
        self.log(
            OperationType.EXEC,
            tool, "Pod", pod_name,
            namespace, identity, cluster, success,
            extra={"command": command[:200]},  # Truncate long commands
            error=error,
        )


# Global audit logger instance
_audit_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def initialize_audit_logger(log_file: str = "") -> AuditLogger:
    global _audit_logger
    _audit_logger = AuditLogger(log_file)
    return _audit_logger
