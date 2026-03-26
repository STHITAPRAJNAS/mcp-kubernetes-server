"""Tests for configuration management."""

import os
import pytest
from unittest.mock import patch

from mcp_kubernetes.config import Settings, EnvironmentMode, TransportMode


class TestSettings:
    def test_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            s = Settings()
            assert s.env == EnvironmentMode.AUTO
            assert s.transport == TransportMode.STDIO
            assert s.allow_destructive is True
            assert s.mask_secrets is True
            assert s.require_destructive_confirmation is True
            assert "kube-system" in s.protected_namespaces

    def test_protected_namespace_check(self):
        s = Settings()
        assert s.is_protected_namespace("kube-system") is True
        assert s.is_protected_namespace("default") is False
        assert s.is_protected_namespace("my-app") is False

    def test_protected_namespaces_from_env(self):
        with patch.dict(os.environ, {"MCP_K8S_PROTECTED_NAMESPACES": "prod,staging,kube-system"}):
            s = Settings()
            assert "prod" in s.protected_namespaces
            assert "staging" in s.protected_namespaces

    def test_cluster_map_from_env(self):
        with patch.dict(os.environ, {
            "MCP_K8S_CLUSTER_MAP": '{"prod": "my-prod-cluster", "staging": "my-staging-cluster"}'
        }):
            s = Settings()
            assert s.cluster_map["prod"] == "my-prod-cluster"
            assert s.cluster_map["staging"] == "my-staging-cluster"

    def test_eks_cluster_alias_resolution(self):
        with patch.dict(os.environ, {
            "MCP_K8S_CLUSTER_MAP": '{"prod": "eks-prod-cluster-01"}'
        }):
            s = Settings()
            assert s.get_eks_cluster_for_alias("prod") == "eks-prod-cluster-01"
            assert s.get_eks_cluster_for_alias("unknown") is None

    def test_dry_run_default_false(self):
        s = Settings()
        assert s.dry_run is False

    def test_max_batch_delete_range(self):
        s = Settings()
        assert 1 <= s.max_batch_delete <= 50

    def test_rate_limit_per_minute(self):
        s = Settings()
        assert s.rate_limit_per_minute >= 0

    def test_aws_mode_env(self):
        with patch.dict(os.environ, {"MCP_K8S_ENV": "aws"}):
            s = Settings()
            assert s.env == EnvironmentMode.AWS

    def test_local_mode_env(self):
        with patch.dict(os.environ, {"MCP_K8S_ENV": "local"}):
            s = Settings()
            assert s.env == EnvironmentMode.LOCAL
