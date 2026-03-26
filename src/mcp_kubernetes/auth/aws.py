"""
AWS EKS authentication provider.
Uses AWS IAM roles to authenticate with EKS clusters.

Supports two deployment scenarios:
1. Running IN AWS (EC2/ECS/Lambda/EKS pod): Uses instance/task/pod IAM role
   via the metadata endpoint. The role must be granted access in the
   cluster's aws-auth ConfigMap or EKS access entries.

2. Running LOCALLY as an engineer: Assumes a designated IAM role (e.g.,
   "ApplicationEngineer" or a per-environment role) via STS before
   generating the EKS token.
"""

from __future__ import annotations

import base64
import logging
import re
import ssl
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
import botocore.session
from botocore.awsrequest import AWSPreparedRequest, AWSRequest
from botocore.auth import SigV4Auth
from botocore.credentials import Credentials
from kubernetes import client as k8s_client, config as k8s_config

from .base import AuthProvider, AuthResult, AuthenticationError, ClusterNotFoundError

logger = logging.getLogger(__name__)

# EKS token prefix as per the aws-iam-authenticator spec
_EKS_TOKEN_PREFIX = "k8s-aws-v1."
# Token expiry buffer - refresh tokens 60 seconds before expiry
_TOKEN_REFRESH_BUFFER_SECS = 60
# STS token validity in minutes (used for token generation, not assumption)
_STS_TOKEN_VALIDITY_MINUTES = 15


class AWSAuthProvider(AuthProvider):
    """
    AWS IAM-based authentication for EKS clusters.

    Authentication flow:
    1. Determine AWS credentials to use (instance role OR assumed role)
    2. Use those credentials to generate a pre-signed STS GetCallerIdentity URL
    3. The EKS API server validates this token via the AWS IAM Authenticator
    4. Kubernetes RBAC then enforces access based on the IAM identity
    """

    def __init__(
        self,
        region: str,
        cluster_name: str = "",
        role_arn: str = "",
        session_duration: int = 3600,
        session_name: str = "mcp-kubernetes-server",
        aws_profile: str = "",
        cluster_map: dict[str, str] | None = None,
    ) -> None:
        self._region = region
        self._default_cluster_name = cluster_name
        self._role_arn = role_arn
        self._session_duration = session_duration
        self._session_name = session_name
        self._aws_profile = aws_profile
        self._cluster_map = cluster_map or {}

        self._current_result: AuthResult | None = None
        self._cached_credentials: Credentials | None = None
        self._credentials_expiry: datetime | None = None
        self._temp_ca_file: Path | None = None

    async def authenticate(self, cluster: str | None = None) -> AuthResult:
        """
        Authenticate to an EKS cluster using AWS IAM credentials.

        Args:
            cluster: EKS cluster name or alias from cluster_map.
                     Defaults to the configured default cluster.
        """
        # Resolve cluster name
        eks_cluster_name = self._resolve_cluster_name(cluster)
        if not eks_cluster_name:
            raise AuthenticationError(
                "No EKS cluster name specified. Set MCP_K8S_EKS_CLUSTER_NAME or "
                "pass a cluster name/alias.",
                provider="aws",
                cluster=cluster or "",
            )

        logger.info("Authenticating to EKS cluster", extra={"cluster": eks_cluster_name})

        # Step 1: Get (possibly assumed) credentials
        credentials = await self._get_credentials()

        # Step 2: Describe the cluster to get endpoint and CA data
        cluster_info = await self._describe_eks_cluster(eks_cluster_name)

        # Step 3: Generate EKS token
        token = self._generate_eks_token(eks_cluster_name, credentials)

        # Step 4: Build a per-cluster ApiClient (no global config mutation)
        api_client = await self._build_api_client(cluster_info, token)

        # Step 5: Determine identity for audit logging
        identity = await self._get_caller_identity()

        # Token expires in STS_TOKEN_VALIDITY_MINUTES minutes
        from datetime import timedelta
        expires_at = datetime.now(tz=timezone.utc) + timedelta(
            minutes=_STS_TOKEN_VALIDITY_MINUTES - 1
        )

        self._current_result = AuthResult(
            environment="aws",
            identity=identity,
            cluster_name=eks_cluster_name,
            api_client=api_client,
            expires_at=expires_at,
            metadata={
                "region": self._region,
                "role_arn": self._role_arn or "instance-role",
                "cluster_endpoint": cluster_info.get("endpoint", ""),
            },
        )

        logger.info(
            "AWS EKS authentication successful",
            extra={
                "cluster": eks_cluster_name,
                "identity": identity,
                "region": self._region,
            },
        )

        return self._current_result

    async def refresh_if_needed(self) -> bool:
        """Refresh the EKS token if it is close to expiry."""
        if self._current_result is None:
            return False

        if self._current_result.expires_at is None:
            return False

        now = datetime.now(tz=timezone.utc)
        remaining = (self._current_result.expires_at - now).total_seconds()

        if remaining <= _TOKEN_REFRESH_BUFFER_SECS:
            logger.info("EKS token near expiry, refreshing...")
            cluster_name = self._current_result.cluster_name
            await self.authenticate(cluster_name)
            return True

        return False

    def get_current_identity(self) -> str:
        if self._current_result:
            return self._current_result.identity
        return "unauthenticated"

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    def _resolve_cluster_name(self, cluster: str | None) -> str:
        """Resolve a cluster alias or name to an actual EKS cluster name."""
        if not cluster:
            return self._default_cluster_name

        # Check if it's an alias in the cluster map
        if cluster in self._cluster_map:
            return self._cluster_map[cluster]

        # Treat as a direct cluster name
        return cluster

    async def _get_credentials(self) -> Credentials:
        """
        Get AWS credentials, optionally assuming a role.

        - In AWS environments: uses the instance/task/pod role automatically
        - Locally with a role ARN: assumes the specified role via STS
        - Locally without a role ARN: uses the default credential chain
          (env vars > ~/.aws/credentials > EC2 metadata)
        """
        # Check if cached credentials are still valid
        if (
            self._cached_credentials is not None
            and self._credentials_expiry is not None
            and datetime.now(tz=timezone.utc).timestamp()
            < self._credentials_expiry.timestamp() - _TOKEN_REFRESH_BUFFER_SECS
        ):
            return self._cached_credentials

        # Build base session
        session_kwargs: dict[str, Any] = {"region_name": self._region}
        if self._aws_profile:
            session_kwargs["profile_name"] = self._aws_profile

        boto_session = boto3.Session(**session_kwargs)

        if self._role_arn:
            # Assume the specified IAM role (e.g., ApplicationEngineer role)
            logger.debug("Assuming IAM role", extra={"role_arn": self._role_arn})
            sts = boto_session.client("sts")
            response = sts.assume_role(
                RoleArn=self._role_arn,
                RoleSessionName=self._session_name,
                DurationSeconds=self._session_duration,
            )
            assumed_creds = response["Credentials"]
            credentials = Credentials(
                access_key=assumed_creds["AccessKeyId"],
                secret_key=assumed_creds["SecretAccessKey"],
                token=assumed_creds["SessionToken"],
            )
            self._credentials_expiry = assumed_creds["Expiration"]
        else:
            # Use default credential chain (instance role, env vars, profile, etc.)
            resolved = boto_session.get_credentials()
            if resolved is None:
                raise AuthenticationError(
                    "No AWS credentials found. Configure via environment variables, "
                    "~/.aws/credentials, or an IAM instance/task role.",
                    provider="aws",
                )
            credentials = resolved.resolve()
            self._credentials_expiry = None  # Instance role handles its own refresh

        self._cached_credentials = credentials
        return credentials

    async def _describe_eks_cluster(self, cluster_name: str) -> dict:
        """Fetch EKS cluster details (endpoint, CA certificate)."""
        session_kwargs: dict[str, Any] = {"region_name": self._region}
        if self._aws_profile:
            session_kwargs["profile_name"] = self._aws_profile

        boto_session = boto3.Session(**session_kwargs)

        # If we're assuming a role, use those credentials for EKS describe too
        if self._role_arn and self._cached_credentials:
            eks_client = boto3.client(
                "eks",
                region_name=self._region,
                aws_access_key_id=self._cached_credentials.access_key,
                aws_secret_access_key=self._cached_credentials.secret_key,
                aws_session_token=self._cached_credentials.token,
            )
        else:
            eks_client = boto_session.client("eks")

        try:
            response = eks_client.describe_cluster(name=cluster_name)
            return response["cluster"]
        except eks_client.exceptions.ResourceNotFoundException:
            raise ClusterNotFoundError(
                f"EKS cluster '{cluster_name}' not found in region '{self._region}'",
                provider="aws",
                cluster=cluster_name,
            )
        except Exception as exc:
            raise AuthenticationError(
                f"Failed to describe EKS cluster '{cluster_name}': {exc}",
                provider="aws",
                cluster=cluster_name,
            ) from exc

    def _generate_eks_token(self, cluster_name: str, credentials: Credentials) -> str:
        """
        Generate an EKS authentication token using the AWS IAM Authenticator format.

        This creates a pre-signed STS GetCallerIdentity URL that the EKS API server
        validates through the aws-iam-authenticator. The format is:
            k8s-aws-v1.<base64url(presigned_url)>
        """
        # Build a pre-signed STS GetCallerIdentity request
        request = AWSRequest(
            method="GET",
            url=f"https://sts.{self._region}.amazonaws.com/"
            f"?Action=GetCallerIdentity&Version=2011-06-15",
            headers={
                "x-k8s-aws-id": cluster_name,
                "Host": f"sts.{self._region}.amazonaws.com",
            },
        )

        signer = SigV4Auth(credentials, "sts", self._region)
        signer.add_auth(request)

        # Build the presigned URL from the signed request
        prepared: AWSPreparedRequest = request.prepare()
        presigned_url = prepared.url

        # Encode as base64url (no padding) per the authenticator spec
        token_body = base64.urlsafe_b64encode(presigned_url.encode()).rstrip(b"=").decode()
        return f"{_EKS_TOKEN_PREFIX}{token_body}"

    async def _build_api_client(self, cluster_info: dict, token: str) -> "k8s_client.ApiClient":
        """
        Build an isolated ApiClient for this EKS cluster.
        Does NOT touch the process-global configuration, so multiple clusters
        can be connected simultaneously.
        """
        endpoint = cluster_info["endpoint"]
        ca_data = cluster_info["certificateAuthority"]["data"]

        # Write CA cert to a temp file per cluster (k8s client needs a file path)
        ca_bytes = base64.b64decode(ca_data)

        if self._temp_ca_file and self._temp_ca_file.exists():
            self._temp_ca_file.unlink()

        tmp = tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".crt",
            delete=False,
            prefix="mcp_k8s_ca_",
        )
        tmp.write(ca_bytes)
        tmp.flush()
        tmp.close()
        self._temp_ca_file = Path(tmp.name)

        # Build a per-instance Configuration + ApiClient
        configuration = k8s_client.Configuration()
        configuration.host = endpoint
        configuration.ssl_ca_cert = str(self._temp_ca_file)
        configuration.api_key = {"authorization": f"Bearer {token}"}
        configuration.verify_ssl = True

        return k8s_client.ApiClient(configuration=configuration)

    async def _get_caller_identity(self) -> str:
        """Return the ARN of the current IAM identity for audit logging."""
        try:
            creds = self._cached_credentials
            sts_kwargs: dict[str, Any] = {"region_name": self._region}
            if creds and creds.token:
                sts_client = boto3.client(
                    "sts",
                    region_name=self._region,
                    aws_access_key_id=creds.access_key,
                    aws_secret_access_key=creds.secret_key,
                    aws_session_token=creds.token,
                )
            else:
                sts_client = boto3.client("sts", **sts_kwargs)

            response = sts_client.get_caller_identity()
            return response.get("Arn", "unknown-arn")
        except Exception as exc:
            logger.warning("Could not determine caller identity: %s", exc)
            return "unknown-arn"

    def cleanup(self) -> None:
        """Remove temporary files created during authentication."""
        if self._temp_ca_file and self._temp_ca_file.exists():
            self._temp_ca_file.unlink()
            self._temp_ca_file = None
