"""
Authentication provider factory.
Auto-detects the environment and returns the appropriate provider.
"""

from __future__ import annotations

import logging
import os
import urllib.request
import urllib.error

from ..config import EnvironmentMode, Settings
from .base import AuthProvider
from .local import LocalAuthProvider
from .aws import AWSAuthProvider

logger = logging.getLogger(__name__)

# AWS EC2 Instance Metadata Service endpoint
_IMDS_URL = "http://169.254.169.254/latest/meta-data/instance-id"
_IMDS_TIMEOUT = 2  # seconds


def _is_running_in_aws() -> bool:
    """
    Detect if the server is running in an AWS environment.

    Checks:
    1. AWS_EXECUTION_ENV environment variable (set in Lambda/ECS)
    2. EKS_POD_NAMESPACE (set when running as a pod in EKS)
    3. KUBERNETES_SERVICE_HOST (set in any Kubernetes pod)
    4. Reachability of the EC2 IMDS endpoint (works on EC2/ECS/EKS nodes)
    """
    # Lambda / ECS Fargate
    if os.environ.get("AWS_EXECUTION_ENV"):
        logger.debug("Detected AWS environment via AWS_EXECUTION_ENV")
        return True

    # Running inside a Kubernetes pod (EKS)
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        logger.debug("Detected Kubernetes pod environment via KUBERNETES_SERVICE_HOST")
        return True

    # EKS Pod Identity / IRSA environment variables
    if os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE"):
        logger.debug("Detected IRSA via AWS_WEB_IDENTITY_TOKEN_FILE")
        return True

    # Try to reach the EC2 metadata service
    try:
        req = urllib.request.Request(_IMDS_URL)
        with urllib.request.urlopen(req, timeout=_IMDS_TIMEOUT):
            logger.debug("Detected AWS environment via IMDS reachability")
            return True
    except (urllib.error.URLError, OSError):
        pass

    return False


def create_auth_provider(settings: Settings) -> AuthProvider:
    """
    Create the appropriate authentication provider based on configuration.

    Decision logic:
    - env=local:  Always use LocalAuthProvider
    - env=aws:    Always use AWSAuthProvider
    - env=auto:   Detect environment and choose accordingly
    """
    mode = settings.env

    if mode == EnvironmentMode.AUTO:
        mode = EnvironmentMode.AWS if _is_running_in_aws() else EnvironmentMode.LOCAL
        logger.info("Auto-detected environment mode: %s", mode.value)

    if mode == EnvironmentMode.LOCAL:
        logger.info("Using local kubeconfig authentication")
        return LocalAuthProvider(
            kubeconfig_path=settings.kubeconfig,
            default_context=settings.default_context,
        )

    elif mode == EnvironmentMode.AWS:
        logger.info("Using AWS EKS IAM authentication")
        return AWSAuthProvider(
            region=settings.aws_region,
            cluster_name=settings.eks_cluster_name,
            role_arn=settings.aws_role_arn,
            session_duration=settings.aws_role_session_duration,
            session_name=settings.aws_role_session_name,
            aws_profile=settings.aws_profile,
            cluster_map=settings.cluster_map,
        )

    else:
        raise ValueError(f"Unknown environment mode: {mode}")
