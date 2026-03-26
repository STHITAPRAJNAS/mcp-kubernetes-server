"""
MCP Prompts for guided Kubernetes diagnostic and operational workflows.
Prompts are reusable instruction templates that guide LLMs through complex tasks.
"""

from __future__ import annotations

from fastmcp.prompts import Message


def register_diagnostic_prompts(mcp) -> None:
    """Register guided workflow prompts."""

    @mcp.prompt()
    def diagnose_pod(pod_name: str, namespace: str = "default") -> list[Message]:
        """
        Systematic diagnosis workflow for a troubled pod.
        Guides through checking status, logs, events, and related resources.
        """
        return [
            Message(
                role="user",
                content=f"""Please diagnose the pod '{pod_name}' in namespace '{namespace}'
using the following systematic approach:

1. **Check pod status**: Use get_pod(name='{pod_name}', namespace='{namespace}') to see
   the current phase, container states, restart counts, and conditions.

2. **Review recent logs**: Use get_pod_logs(name='{pod_name}', namespace='{namespace}',
   tail_lines=100) to check for errors or crash messages.

3. **Check events**: Use list_events(namespace='{namespace}', involved_object='{pod_name}')
   to find warning events related to this pod.

4. **If the pod is crashing**: Also check get_pod_logs with previous=true to see
   the logs from the previous crashed instance.

5. **Check the owning deployment**: If the pod is managed by a deployment, use
   get_deployment to check replica status and conditions.

6. **Identify the root cause** and suggest remediation steps.

Please provide a clear diagnosis and actionable recommendations."""
            )
        ]

    @mcp.prompt()
    def diagnose_deployment(deployment_name: str, namespace: str = "default") -> list[Message]:
        """
        Systematic diagnosis for a deployment that is not healthy.
        """
        return [
            Message(
                role="user",
                content=f"""Please diagnose the deployment '{deployment_name}' in namespace '{namespace}'.

Follow these steps:

1. **Check deployment status**: Use get_deployment(name='{deployment_name}',
   namespace='{namespace}') to see replica counts, conditions, and images.

2. **List pods**: Use list_pods(namespace='{namespace}',
   label_selector based on the deployment selector) to see pod states.

3. **Check failing pods**: For any non-Running pods, check their logs and events.

4. **Review rollout history**: Use get_deployment_history(name='{deployment_name}',
   namespace='{namespace}') to see recent changes.

5. **Check events**: Use list_events(namespace='{namespace}', warnings_only=true)
   for any warning events in the namespace.

6. **Provide diagnosis** including:
   - Root cause of the issue
   - Whether a rollback would help (and to which revision)
   - Other remediation steps (scale, restart, config change, etc.)"""
            )
        ]

    @mcp.prompt()
    def pre_deployment_checklist(
        deployment_name: str,
        namespace: str = "default",
        target_image: str = "",
    ) -> list[Message]:
        """
        Pre-deployment verification checklist before applying changes.
        """
        image_note = f" with image '{target_image}'" if target_image else ""
        return [
            Message(
                role="user",
                content=f"""Please run a pre-deployment checklist for '{deployment_name}'{image_note} in '{namespace}':

1. **Current state**: Check get_deployment to understand current replica count,
   image, and health.

2. **Namespace health**: Run list_events(namespace='{namespace}', warnings_only=true)
   to check for pre-existing issues.

3. **Node capacity**: Use list_nodes to verify cluster has enough capacity.

4. **Validate the change** (if you have a new manifest): Use validate_manifest
   with dry_run=true to check for errors before applying.

5. **Provide a go/no-go recommendation** with reasoning.

6. **Rollback plan**: Document what steps to take if the deployment fails
   (which revision to roll back to, how to verify rollback succeeded)."""
            )
        ]

    @mcp.prompt()
    def cluster_health_report(include_events: bool = True) -> list[Message]:
        """
        Generate a comprehensive cluster health report.
        """
        events_step = (
            "\n5. **Warning events**: Use list_events(namespace='all', warnings_only=true, limit=50)."
            if include_events else ""
        )
        return [
            Message(
                role="user",
                content=f"""Please generate a comprehensive cluster health report.

1. **Cluster overview**: Use the k8s://cluster/health resource for a quick summary.

2. **Node health**: Use list_nodes to check all nodes for Ready status,
   available resources, and any taints or conditions.

3. **Workload health**:
   - Use list_deployments(namespace='all') to find deployments with unavailable replicas
   - Use list_pods(namespace='all', field_selector='status.phase=Failed') for failed pods
{events_step}

4. **Summarize findings** in a clear report format:
   - Overall health: GREEN / YELLOW / RED
   - Critical issues (immediate action needed)
   - Warnings (monitor closely)
   - Healthy components
   - Recommended actions"""
            )
        ]

    @mcp.prompt()
    def safe_delete_workflow(
        resource_kind: str,
        resource_name: str,
        namespace: str = "default",
    ) -> list[Message]:
        """
        Safe deletion workflow with pre-flight checks and rollback guidance.
        """
        kind_lower = resource_kind.lower()
        return [
            Message(
                role="user",
                content=f"""Please guide me through safely deleting {resource_kind} '{resource_name}' in '{namespace}'.

Follow this safe deletion workflow:

1. **Verify the resource exists**: Use get_{kind_lower}(name='{resource_name}',
   namespace='{namespace}') to confirm it exists and understand its current state.

2. **Assess impact**:
   - For pods: Is it managed by a controller? Will it be recreated?
   - For deployments: How many replicas? Any dependent services?
   - For namespaces: What resources are inside? Any persistent data?

3. **Dry run first**: Call delete_{kind_lower}(name='{resource_name}',
   namespace='{namespace}', dry_run=True) to simulate deletion.

4. **Confirm the plan**: Summarize what will be deleted and any downstream impact.

5. **Execute deletion**: Only after confirming, call delete_{kind_lower}(
   name='{resource_name}', namespace='{namespace}',
   confirm_name='{resource_name}') to perform the actual deletion.

6. **Verify deletion**: Confirm the resource no longer exists.

Always pause between steps and confirm before executing the actual deletion."""
            )
        ]
