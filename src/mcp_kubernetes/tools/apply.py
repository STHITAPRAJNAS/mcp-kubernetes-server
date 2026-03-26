"""
Apply manifest tool - server-side apply for Kubernetes resources.
Supports YAML/JSON manifests with dry-run capability.
"""

from __future__ import annotations

import json
import logging
from typing import Annotated

import yaml
from kubernetes import client as k8s_client, utils as k8s_utils
from kubernetes.client.rest import ApiException

from ..audit import get_audit_logger
from ..config import get_settings
from ..cluster_pool import resolve_manager
from ..k8s_client import handle_k8s_api_error
from ..models import OperationResult

logger = logging.getLogger(__name__)

# Kinds that are considered high-risk and require extra caution
_HIGH_RISK_KINDS = {
    "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding",
    "NetworkPolicy", "PodSecurityPolicy", "SecurityContextConstraints",
}

# Kinds that should never be applied via MCP (infrastructure-level)
_BLOCKED_KINDS = {
    "APIService", "CustomResourceDefinition", "MutatingWebhookConfiguration",
    "ValidatingWebhookConfiguration",
}


def register_apply_tools(mcp) -> None:
    """Register manifest apply MCP tools."""

    @mcp.tool
    def apply_manifest(
        manifest: Annotated[str, "YAML or JSON Kubernetes manifest to apply"],
        dry_run: Annotated[bool, "If true, validate and simulate without applying changes"] = False,
        force: Annotated[bool, "If true, force server-side apply (overwrites conflicts). Use with extreme caution."] = False,
        cluster: Annotated[str, "Target cluster name or alias (uses default if empty)"] = "",
) -> str:
        """
        Apply a Kubernetes manifest (YAML or JSON) to the cluster.
        Equivalent to 'kubectl apply' with server-side apply.

        Safety features:
        - Dry-run mode validates without making changes
        - Protected namespaces cannot be modified
        - High-risk resource kinds (RBAC, NetworkPolicy) are flagged
        - Blocked kinds (CRDs, Webhooks) cannot be applied via MCP

        Always use dry_run=true first to validate your manifest.
        """
        settings = get_settings()
        manager = resolve_manager(cluster)
        audit = get_audit_logger()
        is_dry_run = dry_run or settings.dry_run

        if not settings.allow_destructive and not is_dry_run:
            return "Error: Write operations are disabled. Set MCP_K8S_ALLOW_DESTRUCTIVE=true to enable."

        # Parse manifest
        try:
            docs = _parse_manifest(manifest)
        except (yaml.YAMLError, json.JSONDecodeError, ValueError) as exc:
            return f"Error: Invalid manifest format: {exc}"

        if not docs:
            return "Error: Manifest is empty or contains no valid resources."

        results = []
        for doc in docs:
            if not doc:
                continue

            kind = doc.get("kind", "Unknown")
            api_version = doc.get("apiVersion", "v1")
            metadata = doc.get("metadata", {})
            name = metadata.get("name", "unknown")
            namespace = metadata.get("namespace", "")

            # Validate protected namespace
            if namespace and settings.is_protected_namespace(namespace):
                results.append(
                    f"BLOCKED: {kind}/{name} - namespace '{namespace}' is protected"
                )
                audit.log_write("apply_manifest", kind, name, namespace, manager.current_identity, manager.current_cluster, False, error="protected namespace")
                continue

            # Block infrastructure-level kinds
            if kind in _BLOCKED_KINDS:
                results.append(
                    f"BLOCKED: {kind}/{name} - this resource kind cannot be managed via MCP. "
                    f"Use your GitOps pipeline or cluster admin tooling."
                )
                audit.log_write("apply_manifest", kind, name, namespace, manager.current_identity, manager.current_cluster, False, error="blocked kind")
                continue

            # Warn on high-risk kinds
            if kind in _HIGH_RISK_KINDS and not is_dry_run:
                results.append(
                    f"WARNING: Applying {kind}/{name} which affects security/networking. "
                    f"Proceeding..."
                )

            # Apply the resource
            try:
                result_msg = _apply_single_resource(
                    doc, name, namespace, kind, manager, is_dry_run, force
                )
                audit.log_write(
                    "apply_manifest", kind, name, namespace or "cluster-scoped",
                    manager.current_identity, manager.current_cluster, True,
                    dry_run=is_dry_run,
                )
                results.append(result_msg)
            except ApiException as exc:
                msg = handle_k8s_api_error(exc, f"apply {kind}/{name}")
                audit.log_write(
                    "apply_manifest", kind, name, namespace,
                    manager.current_identity, manager.current_cluster, False,
                    error=msg,
                )
                results.append(f"ERROR: {kind}/{name} - {msg}")

        if not results:
            return "No resources were processed."

        prefix = "[DRY RUN] " if is_dry_run else ""
        return f"{prefix}Applied {len(docs)} resource(s):\n\n" + "\n".join(results)

    @mcp.tool
    def validate_manifest(
        manifest: Annotated[str, "YAML or JSON Kubernetes manifest to validate"],
        cluster: Annotated[str, "Target cluster name or alias (uses default if empty)"] = "",
) -> str:
        """
        Validate a Kubernetes manifest against the cluster's API schema.
        Uses server-side dry-run - the manifest is NOT applied.
        This is a safe read-only operation that checks both syntax and API compatibility.
        """
        return apply_manifest.__wrapped__(
            manifest=manifest,
            dry_run=True,
            force=False,
        ) if hasattr(apply_manifest, "__wrapped__") else _do_validate(manifest)


def _do_validate(manifest: str) -> str:
    """Internal validation using dry-run."""
    settings = get_settings()
    manager = resolve_manager(cluster)
    audit = get_audit_logger()

    try:
        docs = _parse_manifest(manifest)
    except (yaml.YAMLError, json.JSONDecodeError, ValueError) as exc:
        return f"Error: Invalid manifest format: {exc}"

    if not docs:
        return "Error: Manifest is empty."

    results = []
    for doc in docs:
        if not doc:
            continue
        kind = doc.get("kind", "Unknown")
        name = doc.get("metadata", {}).get("name", "unknown")
        namespace = doc.get("metadata", {}).get("namespace", "")
        try:
            result_msg = _apply_single_resource(doc, name, namespace, kind, manager, True, False)
            results.append(f"VALID: {result_msg}")
        except ApiException as exc:
            msg = handle_k8s_api_error(exc, f"validate {kind}/{name}")
            results.append(f"INVALID: {kind}/{name} - {msg}")

    return "Validation results (dry-run, no changes made):\n\n" + "\n".join(results)


def _parse_manifest(manifest: str) -> list[dict]:
    """Parse a YAML or JSON manifest string into a list of resource dicts."""
    manifest = manifest.strip()
    if not manifest:
        raise ValueError("Empty manifest")

    # Try JSON first
    if manifest.startswith("{") or manifest.startswith("["):
        data = json.loads(manifest)
        if isinstance(data, list):
            return data
        return [data]

    # Parse YAML (may contain multiple documents separated by ---)
    docs = list(yaml.safe_load_all(manifest))
    return [d for d in docs if d is not None]


def _apply_single_resource(
    doc: dict,
    name: str,
    namespace: str,
    kind: str,
    manager,
    dry_run: bool,
    force: bool,
) -> str:
    """Apply a single Kubernetes resource using the dynamic API."""
    from kubernetes.client import ApiClient
    from kubernetes import dynamic

    dry_run_param = ["All"] if dry_run else None
    api_client = ApiClient()

    try:
        dyn_client = dynamic.DynamicClient(api_client)
        api_version = doc.get("apiVersion", "v1")
        kind_str = doc.get("kind")

        # Discover the resource type
        api_resource = dyn_client.resources.get(api_version=api_version, kind=kind_str)

        # Determine if namespaced
        if namespace:
            existing = None
            try:
                existing = api_resource.get(name=name, namespace=namespace)
            except Exception:
                pass

            if existing:
                # Update (patch)
                result = api_resource.server_side_apply(
                    body=doc,
                    namespace=namespace,
                    field_manager="mcp-kubernetes-server",
                    dry_run=dry_run_param,
                    force=force,
                )
                action = "configured"
            else:
                result = api_resource.create(
                    body=doc,
                    namespace=namespace,
                    dry_run=dry_run_param,
                )
                action = "created"
        else:
            # Cluster-scoped
            existing = None
            try:
                existing = api_resource.get(name=name)
            except Exception:
                pass

            if existing:
                result = api_resource.server_side_apply(
                    body=doc,
                    field_manager="mcp-kubernetes-server",
                    dry_run=dry_run_param,
                    force=force,
                )
                action = "configured"
            else:
                result = api_resource.create(body=doc, dry_run=dry_run_param)
                action = "created"

        ns_str = f" in '{namespace}'" if namespace else " (cluster-scoped)"
        dr_str = " [dry-run]" if dry_run else ""
        return f"{kind}/{name}{ns_str} {action}{dr_str}"

    finally:
        api_client.rest_client.pool_manager.clear()
