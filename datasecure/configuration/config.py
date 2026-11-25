"""Configuration models for DataSecure."""

from typing import List, Optional
from pydantic import BaseModel, Field
from datasecure.core.models import Severity


class DatasetScannerConfig(BaseModel):
    """Configuration specific to dataset scanning."""
    enabled: bool = True
    check_pii: bool = True
    check_secrets: bool = True
    check_poisoning_indicators: bool = True
    check_duplicates: bool = True
    max_rows_to_sample: int = 50000


class ModelScannerConfig(BaseModel):
    """Configuration specific to model scanning."""
    enabled: bool = True
    check_pickle_safety: bool = True
    disallow_untrusted_globals: bool = True


class SourceCodeScannerConfig(BaseModel):
    """Configuration specific to source code scanning."""
    enabled: bool = True
    check_hardcoded_secrets: bool = True
    check_unsafe_deserialization: bool = True
    check_prompt_injection_sinks: bool = True
    check_insecure_apis: bool = True


class LLMScannerConfig(BaseModel):
    """Configuration specific to active LLM safety testing."""
    enabled: bool = False
    endpoint_url: Optional[str] = None
    prompt_injection_tests: bool = True
    jailbreak_tests: bool = True
    system_leakage_tests: bool = True


class DataSecureConfig(BaseModel):
    """Top-level DataSecure configuration."""
    exclude_dirs: List[str] = Field(
        default_factory=lambda: [
            ".git",
            ".venv",
            "venv",
            "env",
            "__pycache__",
            ".pytest_cache",
            "node_modules",
            "dist",
            "build",
            ".eggs",
        ]
    )
    exclude_files: List[str] = Field(
        default_factory=lambda: [
            ".DS_Store",
            "Thumbs.db",
        ]
    )
    max_file_size_mb: int = 100
    fail_on_severity: Optional[Severity] = Severity.HIGH
    redact_secrets: bool = True
    dataset: DatasetScannerConfig = Field(default_factory=DatasetScannerConfig)
    model: ModelScannerConfig = Field(default_factory=ModelScannerConfig)
    source_code: SourceCodeScannerConfig = Field(default_factory=SourceCodeScannerConfig)
    llm: LLMScannerConfig = Field(default_factory=LLMScannerConfig)

