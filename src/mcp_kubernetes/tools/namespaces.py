"""
Namespace operation tools.
"""

from __future__ import annotations

import logging
from typing import Annotated

from kubernetes.client.rest import ApiException

from ..audit import get_audit_logger
from ..config import get_settings
from ..k8s_client import get_client_manager, handle_k8s_api_error
from ..models import NamespaceInfo, OperationResult
from ..utils import format_age

logger = logging.getLogger(__name__)


def register_namespace_tools(mcp) -> None:
    """Register namespace-related MCP tools."""

    @mcp.tool
    def list_namespaces(
        label_selector: Annotated[str, "Label selector filter"] = "",
    ) -> str:
        """
        List all namespaces in the cluster with their status and age.
        """
        manager = get_client_manager()
        audit = get_audit_logger()
        try:
            core = manager.core_v1()
            kwargs = {}
            if label_selector:
                kwargs["label_selector"] = label_selector

            result = core.list_namespace(**kwargs)
            ns_list = []
            for ns in result.items:
                info = NamespaceInfo(
                    name=ns.metadata.name,
                    status=ns.status.phase if ns.status else "Unknown",
                    labels=ns.metadata.labels or {},
                    annotations={
                        k: v for k, v in (ns.metadata.annotations or {}).items()
                        if not k.startswith("kubectl.kubernetes.io")
                    },
                    age=format_age(ns.metadata.creation_timestamp),
                )
                ns_list.append(info.to_text())

            audit.log_read("list_namespaces", "Namespace", "*", None, manager.current_identity, manager.current_cluster, True)

            if not ns_list:
                return "No namespaces found."
            return f"Found {len(ns_list)} namespace(s):\n\n" + "\n".join(ns_list)

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "list_namespaces")
            audit.log_read("list_namespaces", "Namespace", "*", None, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def create_namespace(
        name: Annotated[str, "Name of the namespace to create"],
        labels: Annotated[str, "Comma-separated key=value labels (e.g. 'env=staging,team=backend')"] = "",
        dry_run: Annotated[bool, "If true, simulate the operation without making changes"] = False,
    ) -> str:
        """
        Create a new namespace with optional labels.
        Namespace names must comply with DNS label rules.
        """
        from kubernetes import client as k8s_client

        settings = get_settings()
        manager = get_client_manager()
        audit = get_audit_logger()

        from ..utils import validate_namespace
        if not validate_namespace(name):
            return (
                f"Error: '{name}' is not a valid namespace name. "
                "Must be lowercase alphanumeric and hyphens, max 63 chars."
            )

        is_dry_run = dry_run or settings.dry_run

        # Parse labels
        parsed_labels: dict[str, str] = {}
        if labels:
            for item in labels.split(","):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    parsed_labels[k.strip()] = v.strip()

        try:
            core = manager.core_v1()
            body = k8s_client.V1Namespace(
                metadata=k8s_client.V1ObjectMeta(
                    name=name,
                    labels=parsed_labels or None,
                )
            )
            dry_run_param = ["All"] if is_dry_run else None
            core.create_namespace(body=body, dry_run=dry_run_param)

            result = OperationResult(
                success=True,
                operation="create",
                resource_kind="Namespace",
                resource_name=name,
                message=f"Namespace '{name}' created" + (" (dry run)" if is_dry_run else ""),
                dry_run=is_dry_run,
                details={"labels": parsed_labels},
            )
            audit.log_write("create_namespace", "Namespace", name, None, manager.current_identity, manager.current_cluster, True, dry_run=is_dry_run)
            return result.to_text()

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "create_namespace")
            audit.log_write("create_namespace", "Namespace", name, None, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"
