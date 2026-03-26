"""Tests for utility functions."""

from datetime import datetime, timezone, timedelta
import pytest

from mcp_kubernetes.utils import (
    format_age,
    mask_secret_value,
    validate_resource_name,
    validate_namespace,
    format_labels,
    safe_get,
)


class TestFormatAge:
    def test_seconds(self):
        now = datetime.now(tz=timezone.utc)
        created = now - timedelta(seconds=45)
        assert format_age(created) == "45s"

    def test_minutes(self):
        now = datetime.now(tz=timezone.utc)
        created = now - timedelta(minutes=5, seconds=30)
        assert format_age(created) == "5m30s"

    def test_hours(self):
        now = datetime.now(tz=timezone.utc)
        created = now - timedelta(hours=3, minutes=15)
        assert format_age(created) == "3h15m"

    def test_days(self):
        now = datetime.now(tz=timezone.utc)
        created = now - timedelta(days=2, hours=4)
        assert format_age(created) == "2d4h"

    def test_none(self):
        assert format_age(None) == "unknown"

    def test_iso_string(self):
        now = datetime.now(tz=timezone.utc)
        created = now - timedelta(seconds=30)
        result = format_age(created.isoformat())
        assert "s" in result


class TestMaskSecretValue:
    def test_masks_string(self):
        result = mask_secret_value("super-secret-value")
        assert "super-secret-value" not in result
        assert "redacted" in result
        assert "18bytes" in result  # length of "super-secret-value"

    def test_masks_none(self):
        result = mask_secret_value(None)
        assert result == "<null>"

    def test_masks_bytes(self):
        result = mask_secret_value(b"binary-secret")
        assert "binary-secret" not in result
        assert "redacted" in result


class TestValidateResourceName:
    def test_valid_names(self):
        assert validate_resource_name("my-app") is True
        assert validate_resource_name("my-app-v2") is True
        assert validate_resource_name("a") is True
        assert validate_resource_name("app123") is True

    def test_invalid_names(self):
        assert validate_resource_name("") is False
        assert validate_resource_name("MyApp") is False  # uppercase
        assert validate_resource_name("-starts-with-dash") is False
        assert validate_resource_name("ends-with-dash-") is False
        assert validate_resource_name("a" * 254) is False  # too long

    def test_valid_with_dots(self):
        assert validate_resource_name("my.app.v1") is True


class TestValidateNamespace:
    def test_valid_namespaces(self):
        assert validate_namespace("default") is True
        assert validate_namespace("my-team") is True
        assert validate_namespace("production") is True

    def test_invalid_namespaces(self):
        assert validate_namespace("") is False
        assert validate_namespace("MyNamespace") is False  # uppercase
        assert validate_namespace("has.dot") is False  # no dots in namespaces
        assert validate_namespace("a" * 64) is False  # too long


class TestFormatLabels:
    def test_formats_labels(self):
        result = format_labels({"app": "nginx", "env": "prod"})
        assert "app=nginx" in result
        assert "env=prod" in result

    def test_empty_labels(self):
        assert format_labels({}) == "<none>"
        assert format_labels(None) == "<none>"


class TestSafeGet:
    def test_gets_nested_attr(self):
        class Obj:
            class inner:
                value = "hello"

        assert safe_get(Obj, "inner", "value") == "hello"

    def test_returns_default_on_missing(self):
        class Obj:
            pass

        assert safe_get(Obj, "missing_attr") is None
        assert safe_get(Obj, "missing_attr", default="fallback") == "fallback"

    def test_handles_none_in_chain(self):
        assert safe_get(None, "attr", "sub") is None
