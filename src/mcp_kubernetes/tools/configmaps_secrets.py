"""
ConfigMap and Secret operation tools.
Secrets are always handled with masking - values are NEVER exposed.
"""

from __future__ import annotations

import logging
from typing import Annotated

from kubernetes import client as k8s_client
from kubernetes.client.rest import ApiException

from ..audit import get_audit_logger
from ..config import get_settings
from ..cluster_pool import resolve_manager
from ..k8s_client import handle_k8s_api_error
from ..models import ConfigMapInfo, SecretInfo, OperationResult
from ..utils import format_age, mask_secret_value

logger = logging.getLogger(__name__)


def register_configmap_secret_tools(mcp) -> None:
    """Register ConfigMap and Secret MCP tools."""

    @mcp.tool
    def list_configmaps(
        namespace: Annotated[str, "Namespace to list configmaps in. Use 'all' for all namespaces"] = "default",
        label_selector: Annotated[str, "Label selector filter"] = "",
        cluster: Annotated[str, "Target cluster name or alias (uses default if empty)"] = "",
) -> str:
        """
        List ConfigMaps showing their key names (not values).
        """
        manager = resolve_manager(cluster)
        audit = get_audit_logger()
        try:
            core = manager.core_v1()
            kwargs = {}
            if label_selector:
                kwargs["label_selector"] = label_selector

            if namespace == "all":
                result = core.list_config_map_for_all_namespaces(**kwargs)
            else:
                result = core.list_namespaced_config_map(namespace=namespace, **kwargs)

            # Filter out system configmaps
            items = [cm for cm in result.items if not _is_system_configmap(cm)]
            cms = [
                ConfigMapInfo(
                    name=cm.metadata.name,
                    namespace=cm.metadata.namespace,
                    data_keys=list((cm.data or {}).keys()) + list((cm.binary_data or {}).keys()),
                    age=format_age(cm.metadata.creation_timestamp),
                ).to_text()
                for cm in items
            ]
            audit.log_read("list_configmaps", "ConfigMap", f"{namespace}/*", namespace, manager.current_identity, manager.current_cluster, True)

            if not cms:
                return f"No configmaps found in namespace '{namespace}'."
            return f"Found {len(cms)} configmap(s) in '{namespace}':\n\n" + "\n".join(cms)

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "list_configmaps")
            audit.log_read("list_configmaps", "ConfigMap", "*", namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def get_configmap(
        name: Annotated[str, "Name of the configmap"],
        namespace: Annotated[str, "Namespace of the configmap"] = "default",
        show_values: Annotated[bool, "If true, show the actual key values (not recommended for sensitive data)"] = False,
        cluster: Annotated[str, "Target cluster name or alias (uses default if empty)"] = "",
) -> str:
        """
        Get a ConfigMap. By default shows key names only.
        Use show_values=true to display actual values (use with caution).
        """
        manager = resolve_manager(cluster)
        audit = get_audit_logger()
        try:
            core = manager.core_v1()
            cm = core.read_namespaced_config_map(name=name, namespace=namespace)
            keys = list((cm.data or {}).keys()) + list((cm.binary_data or {}).keys())

            lines = [
                f"ConfigMap: {namespace}/{name}",
                f"  Age: {format_age(cm.metadata.creation_timestamp)}",
                f"  Keys ({len(keys)}):",
            ]

            if show_values and cm.data:
                for k, v in cm.data.items():
                    # Truncate long values
                    display_v = v[:500] + "..." if len(v) > 500 else v
                    lines.append(f"    {k}: {display_v}")
            else:
                for k in keys:
                    lines.append(f"    - {k}")
                if not show_values and keys:
                    lines.append(
                        "\n  Note: Use show_values=true to display values. "
                        "Be careful with sensitive configuration data."
                    )

            audit.log_read("get_configmap", "ConfigMap", name, namespace, manager.current_identity, manager.current_cluster, True, extra={"show_values": show_values})
            return "\n".join(lines)

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "get_configmap")
            audit.log_read("get_configmap", "ConfigMap", name, namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def list_secrets(
        namespace: Annotated[str, "Namespace to list secrets in. Use 'all' for all namespaces"] = "default",
        label_selector: Annotated[str, "Label selector filter"] = "",
        cluster: Annotated[str, "Target cluster name or alias (uses default if empty)"] = "",
) -> str:
        """
        List Secrets showing ONLY their names and key names.
        Secret values are NEVER exposed - this is intentional for security.
        """
        manager = resolve_manager(cluster)
        audit = get_audit_logger()
        try:
            core = manager.core_v1()
            kwargs = {}
            if label_selector:
                kwargs["label_selector"] = label_selector

            if namespace == "all":
                result = core.list_secret_for_all_namespaces(**kwargs)
            else:
                result = core.list_namespaced_secret(namespace=namespace, **kwargs)

            # Filter service account tokens to reduce noise
            user_secrets = [
                s for s in result.items
                if s.type != "kubernetes.io/service-account-token"
            ]

            secrets = [
                SecretInfo(
                    name=s.metadata.name,
                    namespace=s.metadata.namespace,
                    secret_type=s.type or "Opaque",
                    data_keys=list((s.data or {}).keys()),
                    age=format_age(s.metadata.creation_timestamp),
                ).to_text()
                for s in user_secrets
            ]
            audit.log_read("list_secrets", "Secret", f"{namespace}/*", namespace, manager.current_identity, manager.current_cluster, True)

            if not secrets:
                return f"No user-managed secrets found in namespace '{namespace}'."
            header = (
                f"Found {len(secrets)} secret(s) in '{namespace}' "
                f"[VALUES ALWAYS REDACTED FOR SECURITY]:\n\n"
            )
            return header + "\n".join(secrets)

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "list_secrets")
            audit.log_read("list_secrets", "Secret", "*", namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def get_secret_metadata(
        name: Annotated[str, "Name of the secret"],
        namespace: Annotated[str, "Namespace of the secret"] = "default",
        cluster: Annotated[str, "Target cluster name or alias (uses default if empty)"] = "",
) -> str:
        """
        Get metadata about a Secret (name, type, keys) WITHOUT exposing any values.
        Secret values are NEVER returned. Use this to verify a secret exists and
        check which keys it contains.
        """
        manager = resolve_manager(cluster)
        audit = get_audit_logger()
        try:
            core = manager.core_v1()
            secret = core.read_namespaced_secret(name=name, namespace=namespace)

            keys = list((secret.data or {}).keys())
            info = SecretInfo(
                name=secret.metadata.name,
                namespace=secret.metadata.namespace,
                secret_type=secret.type or "Opaque",
                data_keys=keys,
                age=format_age(secret.metadata.creation_timestamp),
            )

            audit.log_read("get_secret_metadata", "Secret", name, namespace, manager.current_identity, manager.current_cluster, True)
            return info.to_text() + (
                f"\n\n  SECURITY NOTICE: Secret values are never returned by this tool. "
                f"Access secrets directly via kubectl or your secrets management system."
            )

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "get_secret_metadata")
            audit.log_read("get_secret_metadata", "Secret", name, namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def create_configmap(
        name: Annotated[str, "Name of the configmap to create"],
        namespace: Annotated[str, "Namespace for the configmap"] = "default",
        data: Annotated[str, "Data as newline-separated key=value pairs (e.g. 'key1=value1\\nkey2=value2')"] = "",
        dry_run: Annotated[bool, "If true, simulate the operation without making changes"] = False,
        cluster: Annotated[str, "Target cluster name or alias (uses default if empty)"] = "",
) -> str:
        """
        Create a ConfigMap with the specified key-value data.
        For large configs, consider using apply_manifest instead.
        """
        settings = get_settings()
        manager = resolve_manager(cluster)
        audit = get_audit_logger()

        if settings.is_protected_namespace(namespace):
            return f"Error: Namespace '{namespace}' is protected. Operation denied."

        # Parse data
        parsed_data: dict[str, str] = {}
        if data:
            for line in data.strip().splitlines():
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    parsed_data[k.strip()] = v.strip()

        is_dry_run = dry_run or settings.dry_run

        try:
            core = manager.core_v1()
            body = k8s_client.V1ConfigMap(
                metadata=k8s_client.V1ObjectMeta(name=name, namespace=namespace),
                data=parsed_data or None,
            )
            dry_run_param = ["All"] if is_dry_run else None
            core.create_namespaced_config_map(namespace=namespace, body=body, dry_run=dry_run_param)

            result = OperationResult(
                success=True,
                operation="create",
                resource_kind="ConfigMap",
                resource_name=name,
                namespace=namespace,
                message=f"ConfigMap '{name}' created with {len(parsed_data)} key(s)",
                dry_run=is_dry_run,
                details={"keys": list(parsed_data.keys())},
            )
            audit.log_write("create_configmap", "ConfigMap", name, namespace, manager.current_identity, manager.current_cluster, True, dry_run=is_dry_run)
            return result.to_text()

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "create_configmap")
            audit.log_write("create_configmap", "ConfigMap", name, namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"


def _is_system_configmap(cm) -> bool:
    """Check if a ConfigMap is a system/infrastructure configmap."""
    system_names = {
        "kube-root-ca.crt", "aws-auth", "coredns", "kubeadm-config",
        "kubelet-config", "kube-proxy",
    }
    return cm.metadata.name in system_names or cm.metadata.namespace in {
        "kube-system", "kube-public", "kube-node-lease"
    }
