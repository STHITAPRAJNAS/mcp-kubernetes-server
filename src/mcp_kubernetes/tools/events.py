"""
Event and Job/CronJob operation tools.
"""

from __future__ import annotations

import logging
from typing import Annotated

from kubernetes.client.rest import ApiException

from ..audit import get_audit_logger
from ..k8s_client import get_client_manager, handle_k8s_api_error
from ..models import EventInfo, JobInfo
from ..utils import format_age, safe_get

logger = logging.getLogger(__name__)


def register_event_tools(mcp) -> None:
    """Register event and job MCP tools."""

    @mcp.tool
    def list_events(
        namespace: Annotated[str, "Namespace to list events in. Use 'all' for all namespaces"] = "default",
        warnings_only: Annotated[bool, "If true, show only Warning events (filters out Normal)"] = False,
        involved_object: Annotated[str, "Filter events for a specific resource name"] = "",
        limit: Annotated[int, "Maximum number of events to return (default 50, max 200)"] = 50,
    ) -> str:
        """
        List Kubernetes events. Events are key signals for cluster health.
        Warning events indicate issues. Normal events show lifecycle activity.
        """
        manager = get_client_manager()
        audit = get_audit_logger()

        limit = min(max(1, limit), 200)

        try:
            core = manager.core_v1()
            kwargs: dict = {"limit": limit}

            field_selectors = []
            if warnings_only:
                field_selectors.append("type=Warning")
            if involved_object:
                field_selectors.append(f"involvedObject.name={involved_object}")
            if field_selectors:
                kwargs["field_selector"] = ",".join(field_selectors)

            if namespace == "all":
                result = core.list_event_for_all_namespaces(**kwargs)
            else:
                result = core.list_namespaced_event(namespace=namespace, **kwargs)

            # Sort by last timestamp descending
            events = sorted(
                result.items,
                key=lambda e: (e.last_timestamp or e.event_time or e.metadata.creation_timestamp),
                reverse=True,
            )

            event_texts = []
            for event in events[:limit]:
                info = EventInfo(
                    namespace=event.metadata.namespace,
                    name=event.metadata.name,
                    reason=event.reason or "Unknown",
                    message=event.message or "",
                    type=event.type or "Normal",
                    count=event.count or 1,
                    involved_object_kind=safe_get(event, "involved_object", "kind"),
                    involved_object_name=safe_get(event, "involved_object", "name"),
                    source=safe_get(event, "source", "component"),
                    first_time=event.first_timestamp.isoformat() if event.first_timestamp else None,
                    last_time=event.last_timestamp.isoformat() if event.last_timestamp else None,
                )
                event_texts.append(info.to_text())

            audit.log_read("list_events", "Event", f"{namespace}/*", namespace, manager.current_identity, manager.current_cluster, True)

            if not event_texts:
                filter_desc = " (warnings only)" if warnings_only else ""
                return f"No events{filter_desc} found in namespace '{namespace}'."

            filter_desc = " (warnings only)" if warnings_only else ""
            return (
                f"Last {len(event_texts)} event(s) in '{namespace}'{filter_desc}:\n\n"
                + "\n".join(event_texts)
            )

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "list_events")
            audit.log_read("list_events", "Event", "*", namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def list_jobs(
        namespace: Annotated[str, "Namespace to list jobs in. Use 'all' for all namespaces"] = "default",
        label_selector: Annotated[str, "Label selector filter"] = "",
    ) -> str:
        """List Kubernetes Jobs showing completion status."""
        manager = get_client_manager()
        audit = get_audit_logger()
        try:
            batch = manager.batch_v1()
            kwargs = {}
            if label_selector:
                kwargs["label_selector"] = label_selector

            if namespace == "all":
                result = batch.list_job_for_all_namespaces(**kwargs)
            else:
                result = batch.list_namespaced_job(namespace=namespace, **kwargs)

            jobs = [_build_job_info(j).to_text() for j in result.items]
            audit.log_read("list_jobs", "Job", f"{namespace}/*", namespace, manager.current_identity, manager.current_cluster, True)

            if not jobs:
                return f"No jobs found in namespace '{namespace}'."
            return f"Found {len(jobs)} job(s) in '{namespace}':\n\n" + "\n".join(jobs)

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "list_jobs")
            audit.log_read("list_jobs", "Job", "*", namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def list_cronjobs(
        namespace: Annotated[str, "Namespace to list cronjobs in. Use 'all' for all namespaces"] = "default",
    ) -> str:
        """List CronJobs showing their schedule and last run status."""
        manager = get_client_manager()
        audit = get_audit_logger()
        try:
            batch = manager.batch_v1()

            if namespace == "all":
                result = batch.list_cron_job_for_all_namespaces()
            else:
                result = batch.list_namespaced_cron_job(namespace=namespace)

            lines = [f"CronJobs in '{namespace}':"]
            lines.append(f"{'NAME':<30} {'SCHEDULE':<20} {'SUSPEND':<10} {'ACTIVE':<8} {'LAST SCHEDULE'}")
            lines.append("─" * 90)

            for cj in result.items:
                spec = cj.spec or {}
                status = cj.status or {}
                last_schedule = None
                if cj.status and cj.status.last_schedule_time:
                    last_schedule = format_age(cj.status.last_schedule_time)

                lines.append(
                    f"{cj.metadata.name:<30} "
                    f"{(cj.spec.schedule if cj.spec else 'N/A'):<20} "
                    f"{'Yes' if (cj.spec and cj.spec.suspend) else 'No':<10} "
                    f"{len(cj.status.active) if cj.status and cj.status.active else 0:<8} "
                    f"{last_schedule or 'Never'}"
                )

            audit.log_read("list_cronjobs", "CronJob", f"{namespace}/*", namespace, manager.current_identity, manager.current_cluster, True)
            return "\n".join(lines)

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "list_cronjobs")
            audit.log_read("list_cronjobs", "CronJob", "*", namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"


def _build_job_info(job) -> JobInfo:
    """Build JobInfo from a Kubernetes Job object."""
    status = "Unknown"
    if job.status:
        if job.status.completion_time:
            if (job.status.failed or 0) > 0:
                status = "Failed"
            else:
                status = "Complete"
        elif (job.status.active or 0) > 0:
            status = "Running"
        elif (job.status.failed or 0) > 0:
            status = "Failed"
        else:
            status = "Pending"

    return JobInfo(
        name=job.metadata.name,
        namespace=job.metadata.namespace,
        status=status,
        completions=safe_get(job, "spec", "completions"),
        succeeded=safe_get(job, "status", "succeeded") or 0,
        failed=safe_get(job, "status", "failed") or 0,
        active=safe_get(job, "status", "active") or 0,
        start_time=job.status.start_time.isoformat() if job.status and job.status.start_time else None,
        completion_time=job.status.completion_time.isoformat() if job.status and job.status.completion_time else None,
        age=format_age(job.metadata.creation_timestamp),
    )
