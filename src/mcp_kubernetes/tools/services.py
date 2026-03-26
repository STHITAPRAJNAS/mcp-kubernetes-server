"""
Service and Ingress operation tools.
"""

from __future__ import annotations

import logging
from typing import Annotated

from kubernetes.client.rest import ApiException

from ..audit import get_audit_logger
from ..k8s_client import get_client_manager, handle_k8s_api_error
from ..models import ServiceInfo, IngressInfo, IngressRule
from ..utils import format_age, safe_get

logger = logging.getLogger(__name__)


def register_service_tools(mcp) -> None:
    """Register service and ingress MCP tools."""

    @mcp.tool
    def list_services(
        namespace: Annotated[str, "Namespace to list services in. Use 'all' for all namespaces"] = "default",
        label_selector: Annotated[str, "Label selector filter"] = "",
    ) -> str:
        """
        List Kubernetes services with their type, cluster IP, external IPs, and ports.
        """
        manager = get_client_manager()
        audit = get_audit_logger()
        try:
            core = manager.core_v1()
            kwargs = {}
            if label_selector:
                kwargs["label_selector"] = label_selector

            if namespace == "all":
                result = core.list_service_for_all_namespaces(**kwargs)
            else:
                result = core.list_namespaced_service(namespace=namespace, **kwargs)

            services = [_build_service_info(svc).to_text() for svc in result.items]
            audit.log_read("list_services", "Service", f"{namespace}/*", namespace, manager.current_identity, manager.current_cluster, True)

            if not services:
                return f"No services found in namespace '{namespace}'."
            return f"Found {len(services)} service(s) in '{namespace}':\n\n" + "\n\n".join(services)

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "list_services")
            audit.log_read("list_services", "Service", "*", namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def get_service(
        name: Annotated[str, "Name of the service"],
        namespace: Annotated[str, "Namespace of the service"] = "default",
    ) -> str:
        """Get detailed information about a specific service."""
        manager = get_client_manager()
        audit = get_audit_logger()
        try:
            core = manager.core_v1()
            svc = core.read_namespaced_service(name=name, namespace=namespace)
            info = _build_service_info(svc)

            lines = [info.to_text()]

            # Show endpoints
            try:
                ep = core.read_namespaced_endpoints(name=name, namespace=namespace)
                if ep.subsets:
                    endpoints = []
                    for subset in ep.subsets:
                        addresses = subset.addresses or []
                        ports = subset.ports or []
                        for addr in addresses[:5]:  # Cap at 5 for display
                            for port in ports:
                                endpoints.append(f"{addr.ip}:{port.port}")
                    if endpoints:
                        lines.append(f"\n  Endpoints: {', '.join(endpoints[:10])}")
            except ApiException:
                pass  # Endpoints may not exist yet

            audit.log_read("get_service", "Service", name, namespace, manager.current_identity, manager.current_cluster, True)
            return "\n".join(lines)

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "get_service")
            audit.log_read("get_service", "Service", name, namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"

    @mcp.tool
    def list_ingresses(
        namespace: Annotated[str, "Namespace to list ingresses in. Use 'all' for all namespaces"] = "default",
    ) -> str:
        """
        List Kubernetes Ingress resources showing hosts, paths, and TLS configuration.
        """
        manager = get_client_manager()
        audit = get_audit_logger()
        try:
            networking = manager.networking_v1()

            if namespace == "all":
                result = networking.list_ingress_for_all_namespaces()
            else:
                result = networking.list_namespaced_ingress(namespace=namespace)

            ingresses = [_build_ingress_info(ing).to_text() for ing in result.items]
            audit.log_read("list_ingresses", "Ingress", f"{namespace}/*", namespace, manager.current_identity, manager.current_cluster, True)

            if not ingresses:
                return f"No ingresses found in namespace '{namespace}'."
            return f"Found {len(ingresses)} ingress(es) in '{namespace}':\n\n" + "\n\n".join(ingresses)

        except ApiException as exc:
            msg = handle_k8s_api_error(exc, "list_ingresses")
            audit.log_read("list_ingresses", "Ingress", "*", namespace, manager.current_identity, manager.current_cluster, False, error=msg)
            return f"Error: {msg}"


def _build_service_info(svc) -> ServiceInfo:
    """Build ServiceInfo from a Kubernetes Service object."""
    ports = []
    if svc.spec and svc.spec.ports:
        for p in svc.spec.ports:
            port_str = f"{p.port}"
            if p.target_port:
                port_str += f"→{p.target_port}"
            if p.protocol and p.protocol != "TCP":
                port_str += f"/{p.protocol}"
            if p.name:
                port_str = f"{p.name}:{port_str}"
            ports.append(port_str)

    # External IP from status
    external_ip = None
    if svc.status and svc.status.load_balancer and svc.status.load_balancer.ingress:
        ingress_points = svc.status.load_balancer.ingress
        ips = []
        for ing in ingress_points:
            if ing.ip:
                ips.append(ing.ip)
            elif ing.hostname:
                ips.append(ing.hostname)
        external_ip = ", ".join(ips) if ips else None

    svc_type = (svc.spec.type if svc.spec else None) or "ClusterIP"
    if svc_type == "ExternalName":
        external_ip = safe_get(svc, "spec", "external_name")

    return ServiceInfo(
        name=svc.metadata.name,
        namespace=svc.metadata.namespace,
        type=svc_type,
        cluster_ip=safe_get(svc, "spec", "cluster_ip"),
        external_ip=external_ip,
        ports=ports,
        selector=safe_get(svc, "spec", "selector") or {},
        labels=svc.metadata.labels or {},
        age=format_age(svc.metadata.creation_timestamp),
    )


def _build_ingress_info(ing) -> IngressInfo:
    """Build IngressInfo from a Kubernetes Ingress object."""
    rules = []
    tls_hosts = []

    if ing.spec:
        if ing.spec.tls:
            for tls in ing.spec.tls:
                tls_hosts.extend(tls.hosts or [])

        for rule in (ing.spec.rules or []):
            paths = []
            if rule.http and rule.http.paths:
                for p in rule.http.paths:
                    backend_svc = None
                    if p.backend and p.backend.service:
                        backend_svc = f"{p.backend.service.name}:{p.backend.service.port.number}"
                    paths.append(f"{p.path or '/'} → {backend_svc or '?'}")
            rules.append(IngressRule(host=rule.host, paths=paths))

    # Load balancer IP
    lb_ip = None
    if ing.status and ing.status.load_balancer and ing.status.load_balancer.ingress:
        lb_ips = []
        for lb in ing.status.load_balancer.ingress:
            if lb.ip:
                lb_ips.append(lb.ip)
            elif lb.hostname:
                lb_ips.append(lb.hostname)
        lb_ip = ", ".join(lb_ips) if lb_ips else None

    class_name = None
    if ing.spec:
        class_name = ing.spec.ingress_class_name
    if not class_name and ing.metadata.annotations:
        class_name = ing.metadata.annotations.get("kubernetes.io/ingress.class")

    return IngressInfo(
        name=ing.metadata.name,
        namespace=ing.metadata.namespace,
        rules=rules,
        tls_hosts=tls_hosts,
        class_name=class_name,
        load_balancer_ip=lb_ip,
        age=format_age(ing.metadata.creation_timestamp),
    )
