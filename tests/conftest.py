"""Pytest fixtures for DataSecure tests."""

import pytest
from pathlib import Path
import tempfile
from datasecure.configuration.config import DataSecureConfig
from datasecure.core.models import Finding, Severity


@pytest.fixture
def sample_finding() -> Finding:
    """Fixture providing a sample Finding."""
    return Finding(
        id="DS-TEST-001",
        name="Test Insecure Loading",
        severity=Severity.HIGH,
        category="source_code",
        file_path="src/model.py",
        line_number=42,
        evidence="torch.load(weights, weights_only=False)",
        explanation="Untrusted model deserialization can lead to arbitrary code execution.",
        remediation="Set weights_only=True or use safetensors.",
        is_heuristic=False,
    )


@pytest.fixture
def default_config() -> DataSecureConfig:
    """Fixture providing default configuration."""
    return DataSecureConfig()


@pytest.fixture
def temp_dir():
    """Fixture providing a temporary directory."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)

