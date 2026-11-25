"""Configuration loader supporting YAML files and sensible defaults."""

from pathlib import Path
from typing import Optional
import yaml

from datasecure.configuration.config import DataSecureConfig
from datasecure.core.exceptions import ConfigurationError


CONFIG_FILENAMES = [
    ".datasecure.yml",
    ".datasecure.yaml",
    "datasecure.yml",
    "datasecure.yaml",
]


def load_config(config_path: Optional[Path] = None, base_dir: Optional[Path] = None) -> DataSecureConfig:
    """Load configuration from a specified file, search in base_dir, or return defaults.

    Args:
        config_path: Explicit path to configuration YAML file.
        base_dir: Directory to search for standard config files if config_path not provided.

    Returns:
        Validated DataSecureConfig instance.
    """
    target_path: Optional[Path] = None

    if config_path:
        target_path = Path(config_path)
        if not target_path.exists():
            raise ConfigurationError(f"Specified configuration file does not exist: {config_path}")
    elif base_dir:
        base = Path(base_dir)
        for fname in CONFIG_FILENAMES:
            candidate = base / fname
            if candidate.is_file():
                target_path = candidate
                break

    if target_path is None:
        return DataSecureConfig()

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f) or {}
        if not isinstance(raw_data, dict):
            raise ConfigurationError(f"Configuration file {target_path} must be a valid YAML mapping.")
        return DataSecureConfig.model_validate(raw_data)
    except yaml.YAMLError as e:
        raise ConfigurationError(f"Error parsing YAML from {target_path}: {e}") from e
    except Exception as e:
        if isinstance(e, ConfigurationError):
            raise
        raise ConfigurationError(f"Invalid configuration in {target_path}: {e}") from e

