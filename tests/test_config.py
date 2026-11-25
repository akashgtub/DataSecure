"""Unit tests for configuration models and loader."""

from pathlib import Path
import pytest
import yaml

from datasecure.configuration.config import DataSecureConfig
from datasecure.configuration.loader import load_config
from datasecure.core.exceptions import ConfigurationError
from datasecure.core.models import Severity


def test_default_config():
    cfg = DataSecureConfig()
    assert ".git" in cfg.exclude_dirs
    assert cfg.fail_on_severity == Severity.HIGH
    assert cfg.dataset.enabled is True
    assert cfg.model.enabled is True
    assert cfg.source_code.enabled is True
    assert cfg.llm.enabled is False
    assert cfg.redact_secrets is True


def test_load_config_defaults(temp_dir):
    # When no config file exists in the directory, returns default config
    cfg = load_config(base_dir=temp_dir)
    assert cfg.fail_on_severity == Severity.HIGH


def test_load_config_explicit_file(temp_dir):
    cfg_file = temp_dir / ".datasecure.yml"
    data = {
        "fail_on_severity": "CRITICAL",
        "max_file_size_mb": 50,
        "dataset": {"check_duplicates": False},
    }
    with open(cfg_file, "w", encoding="utf-8") as f:
        yaml.dump(data, f)

    cfg = load_config(config_path=cfg_file)
    assert cfg.fail_on_severity == Severity.CRITICAL
    assert cfg.max_file_size_mb == 50
    assert cfg.dataset.check_duplicates is False
    assert cfg.dataset.check_pii is True  # Preserves default for unset


def test_load_config_non_existent_file(temp_dir):
    missing_file = temp_dir / "does_not_exist.yml"
    with pytest.raises(ConfigurationError, match="Specified configuration file does not exist"):
        load_config(config_path=missing_file)


def test_load_config_invalid_yaml(temp_dir):
    invalid_file = temp_dir / ".datasecure.yml"
    with open(invalid_file, "w", encoding="utf-8") as f:
        f.write("invalid: [yaml: broken")

    with pytest.raises(ConfigurationError, match="Error parsing YAML"):
        load_config(config_path=invalid_file)


def test_load_config_not_a_mapping(temp_dir):
    invalid_file = temp_dir / ".datasecure.yml"
    with open(invalid_file, "w", encoding="utf-8") as f:
        f.write("- item1\n- item2\n")

    with pytest.raises(ConfigurationError, match="must be a valid YAML mapping"):
        load_config(config_path=invalid_file)

