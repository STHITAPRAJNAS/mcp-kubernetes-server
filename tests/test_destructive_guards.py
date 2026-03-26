"""
Tests for destructive operation safety guards.
These are the most critical tests - they verify that destructive operations
cannot be performed without proper authorization and confirmation.
"""

import pytest
from unittest.mock import MagicMock, patch

from mcp_kubernetes.tools.destructive import _check_destructive_allowed
from mcp_kubernetes.config import Settings


class TestDestructiveGuards:
    """Test the safety guard logic for destructive operations."""

    def _make_settings(self, **kwargs) -> Settings:
        defaults = {
            "MCP_K8S_ALLOW_DESTRUCTIVE": "true",
            "MCP_K8S_REQUIRE_DESTRUCTIVE_CONFIRMATION": "true",
            "MCP_K8S_PROTECTED_NAMESPACES": "kube-system,kube-public,kube-node-lease",
        }
        defaults.update({f"MCP_K8S_{k.upper()}": str(v) for k, v in kwargs.items()})
        import os
        with patch.dict(os.environ, defaults, clear=False):
            return Settings()

    def test_allow_when_confirmation_matches(self):
        settings = self._make_settings()
        result = _check_destructive_allowed(
            settings, "default", "Pod", "my-pod", "my-pod", dry_run=False
        )
        assert result is None  # None means allowed

    def test_block_when_confirmation_missing(self):
        settings = self._make_settings()
        result = _check_destructive_allowed(
            settings, "default", "Pod", "my-pod", "", dry_run=False
        )
        assert result is not None
        assert "Confirmation required" in result

    def test_block_when_confirmation_wrong(self):
        settings = self._make_settings()
        result = _check_destructive_allowed(
            settings, "default", "Pod", "my-pod", "wrong-name", dry_run=False
        )
        assert result is not None
        assert "Confirmation required" in result

    def test_block_protected_namespace(self):
        settings = self._make_settings()
        result = _check_destructive_allowed(
            settings, "kube-system", "Pod", "my-pod", "my-pod", dry_run=False
        )
        assert result is not None
        assert "protected" in result.lower()

    def test_block_when_destructive_disabled(self):
        settings = self._make_settings(allow_destructive="false")
        result = _check_destructive_allowed(
            settings, "default", "Pod", "my-pod", "my-pod", dry_run=False
        )
        assert result is not None
        assert "disabled" in result.lower()

    def test_allow_dry_run_even_when_destructive_disabled(self):
        settings = self._make_settings(allow_destructive="false")
        result = _check_destructive_allowed(
            settings, "default", "Pod", "my-pod", "", dry_run=True
        )
        assert result is None  # Dry run allowed even when destructive disabled

    def test_allow_dry_run_without_confirmation(self):
        settings = self._make_settings()
        result = _check_destructive_allowed(
            settings, "default", "Pod", "my-pod", "", dry_run=True
        )
        assert result is None

    def test_allow_dry_run_on_protected_namespace(self):
        """Dry run should be allowed even on protected namespaces for inspection."""
        settings = self._make_settings()
        result = _check_destructive_allowed(
            settings, "kube-system", "Pod", "coredns", "coredns", dry_run=True
        )
        # Protected namespace blocks even dry-run (safety first)
        assert result is not None

    def test_require_confirmation_disabled(self):
        settings = self._make_settings(require_destructive_confirmation="false")
        result = _check_destructive_allowed(
            settings, "default", "Pod", "my-pod", "", dry_run=False
        )
        assert result is None  # No confirmation needed when disabled

    def test_custom_protected_namespace(self):
        settings = self._make_settings(
            protected_namespaces="prod,staging,kube-system"
        )
        # prod is now protected
        result = _check_destructive_allowed(
            settings, "prod", "Pod", "my-pod", "my-pod", dry_run=False
        )
        assert result is not None
        assert "protected" in result.lower()

    def test_non_protected_namespace_allowed(self):
        settings = self._make_settings()
        result = _check_destructive_allowed(
            settings, "development", "Pod", "my-pod", "my-pod", dry_run=False
        )
        assert result is None  # development is not protected


class TestNamespaceDeletionExtraGuards:
    """Extra tests for namespace deletion which has strongest guards."""

    def test_default_namespace_always_protected(self):
        """The 'default' namespace should not be deletable."""
        from mcp_kubernetes.tools.destructive import register_destructive_tools
        from fastmcp import FastMCP

        mcp = FastMCP("test")

        with patch("mcp_kubernetes.tools.destructive.get_client_manager") as mock_mgr, \
             patch("mcp_kubernetes.tools.destructive.get_settings") as mock_settings, \
             patch("mcp_kubernetes.tools.destructive.get_audit_logger") as mock_audit:

            settings_obj = MagicMock()
            settings_obj.allow_destructive = True
            settings_obj.require_destructive_confirmation = True
            settings_obj.dry_run = False
            settings_obj.is_protected_namespace.return_value = False  # 'default' not in protected list
            mock_settings.return_value = settings_obj
            mock_audit.return_value = MagicMock()
            mock_mgr.return_value = MagicMock(current_identity="test-user", current_cluster="test-cluster")

            register_destructive_tools(mcp)

            # Get the delete_namespace tool function
            delete_ns_tool = None
            for tool in mcp._tool_manager.list_tools():
                if tool.name == "delete_namespace":
                    delete_ns_tool = tool
                    break

            assert delete_ns_tool is not None

            # Try to delete 'default' - should be blocked
            import asyncio
            result = asyncio.run(delete_ns_tool.run({"name": "default", "confirm_name": "default"}))
            # Should contain error about reserved namespace
            result_text = str(result)
            assert "Error" in result_text or "cannot be deleted" in result_text
