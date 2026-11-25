"""Base interface for all DataSecure scanners."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from datasecure.configuration.config import DataSecureConfig
from datasecure.core.models import Finding


class BaseScanner(ABC):
    """Abstract Base Class for DataSecure security scanners."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the scanner."""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """Category string: dataset, model, source_code, or llm."""
        pass

    @abstractmethod
    def can_scan(self, path: Path) -> bool:
        """Determine if this scanner can inspect the specified file path."""
        pass

    @abstractmethod
    def scan(self, path: Path, config: DataSecureConfig) -> List[Finding]:
        """Inspect the target file and return security findings.

        Must NEVER execute untrusted code or load untrusted objects.
        """
        pass

    def is_file_size_safe(self, path: Path, max_mb: int = 100) -> bool:
        """Check if file size is within acceptable threshold."""
        try:
            size_mb = path.stat().st_size / (1024 * 1024)
            return size_mb <= max_mb
        except OSError:
            return False

