"""Tests for authentication providers."""

import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from mcp_kubernetes.auth.base import AuthenticationError, ClusterNotFoundError
from mcp_kubernetes.auth.factory import create_auth_provider, _is_running_in_aws
from mcp_kubernetes.config import Settings, EnvironmentMode


class TestEnvironmentDetection:
    def test_not_aws_by_default(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch("mcp_kubernetes.auth.factory.urllib.request.urlopen", side_effect=Exception("timeout")):
                assert _is_running_in_aws() is False

    def test_aws_via_execution_env(self):
        with patch.dict(os.environ, {"AWS_EXECUTION_ENV": "AWS_ECS_EC2"}):
            assert _is_running_in_aws() is True

    def test_aws_via_kubernetes_host(self):
        with patch.dict(os.environ, {"KUBERNETES_SERVICE_HOST": "10.96.0.1"}):
            assert _is_running_in_aws() is True

    def test_aws_via_irsa(self):
        with patch.dict(os.environ, {"AWS_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/token"}):
            assert _is_running_in_aws() is True


class TestAuthProviderFactory:
    def test_local_mode_returns_local_provider(self):
        with patch.dict(os.environ, {"MCP_K8S_ENV": "local"}, clear=False):
            settings = Settings()
            provider = create_auth_provider(settings)
            from mcp_kubernetes.auth.local import LocalAuthProvider
            assert isinstance(provider, LocalAuthProvider)

    def test_aws_mode_returns_aws_provider(self):
        with patch.dict(os.environ, {
            "MCP_K8S_ENV": "aws",
            "AWS_DEFAULT_REGION": "us-east-1",
            "MCP_K8S_EKS_CLUSTER_NAME": "test-cluster",
        }, clear=False):
            settings = Settings()
            provider = create_auth_provider(settings)
            from mcp_kubernetes.auth.aws import AWSAuthProvider
            assert isinstance(provider, AWSAuthProvider)

    def test_auto_mode_uses_detection(self):
        with patch.dict(os.environ, {"MCP_K8S_ENV": "auto"}, clear=False):
            settings = Settings()
            with patch("mcp_kubernetes.auth.factory._is_running_in_aws", return_value=False):
                provider = create_auth_provider(settings)
                from mcp_kubernetes.auth.local import LocalAuthProvider
                assert isinstance(provider, LocalAuthProvider)

    def test_auto_mode_aws_environment(self):
        with patch.dict(os.environ, {
            "MCP_K8S_ENV": "auto",
            "AWS_DEFAULT_REGION": "us-east-1",
        }, clear=False):
            settings = Settings()
            with patch("mcp_kubernetes.auth.factory._is_running_in_aws", return_value=True):
                provider = create_auth_provider(settings)
                from mcp_kubernetes.auth.aws import AWSAuthProvider
                assert isinstance(provider, AWSAuthProvider)


class TestLocalAuthProvider:
    @pytest.mark.asyncio
    async def test_authenticate_missing_kubeconfig(self, tmp_path):
        from mcp_kubernetes.auth.local import LocalAuthProvider
        provider = LocalAuthProvider(kubeconfig_path=str(tmp_path / "nonexistent.yaml"))
        with pytest.raises(AuthenticationError):
            await provider.authenticate()

    def test_get_current_identity_unauthenticated(self):
        from mcp_kubernetes.auth.local import LocalAuthProvider
        provider = LocalAuthProvider()
        assert provider.get_current_identity() == "unauthenticated"


class TestAWSAuthProvider:
    def test_resolve_cluster_name_direct(self):
        from mcp_kubernetes.auth.aws import AWSAuthProvider
        provider = AWSAuthProvider(
            region="us-east-1",
            cluster_name="default-cluster",
        )
        assert provider._resolve_cluster_name("my-cluster") == "my-cluster"

    def test_resolve_cluster_name_alias(self):
        from mcp_kubernetes.auth.aws import AWSAuthProvider
        provider = AWSAuthProvider(
            region="us-east-1",
            cluster_map={"prod": "prod-eks-cluster-01"},
        )
        assert provider._resolve_cluster_name("prod") == "prod-eks-cluster-01"

    def test_resolve_cluster_name_default(self):
        from mcp_kubernetes.auth.aws import AWSAuthProvider
        provider = AWSAuthProvider(
            region="us-east-1",
            cluster_name="default-cluster",
        )
        assert provider._resolve_cluster_name(None) == "default-cluster"

    def test_generate_eks_token_format(self):
        from mcp_kubernetes.auth.aws import AWSAuthProvider, _EKS_TOKEN_PREFIX
        from botocore.credentials import Credentials

        provider = AWSAuthProvider(region="us-east-1")
        creds = Credentials(
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
        token = provider._generate_eks_token("test-cluster", creds)
        assert token.startswith(_EKS_TOKEN_PREFIX)
        # Should be base64url encoded, no padding
        token_body = token[len(_EKS_TOKEN_PREFIX):]
        assert "=" not in token_body
