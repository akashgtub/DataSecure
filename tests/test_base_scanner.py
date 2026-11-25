"""Unit tests for BaseScanner interface."""

from pathlib import Path
from typing import List
import pytest

from datasecure.configuration.config import DataSecureConfig
from datasecure.core.models import Finding
from datasecure.scanners.base import BaseScanner


class DummyScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "DummyScanner"

    @property
    def category(self) -> str:
        return "dataset"

    def can_scan(self, path: Path) -> bool:
        return path.suffix == ".dummy"

    def scan(self, path: Path, config: DataSecureConfig) -> List[Finding]:
        return []


def test_dummy_scanner_contract(temp_dir):
    scanner = DummyScanner()
    assert scanner.name == "DummyScanner"
    assert scanner.category == "dataset"

    dummy_file = temp_dir / "test.dummy"
    dummy_file.write_text("content", encoding="utf-8")

    assert scanner.can_scan(dummy_file) is True
    assert scanner.can_scan(temp_dir / "test.py") is False
    assert scanner.is_file_size_safe(dummy_file, max_mb=1) is True
    assert scanner.scan(dummy_file, DataSecureConfig()) == []


def test_cannot_instantiate_abstract_base_scanner():
    with pytest.raises(TypeError):
        BaseScanner()  # type: ignore

