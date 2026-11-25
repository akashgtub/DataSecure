"""Scanning engine orchestrator for DataSecure."""

from pathlib import Path
import time
from typing import List, Optional

from datasecure.configuration.config import DataSecureConfig
from datasecure.core.models import Finding, ScanResult, ScanSummary
from datasecure.scanners.base import BaseScanner
from datasecure.scanners.dataset.scanner import DatasetScanner
from datasecure.scanners.model.scanner import ModelScanner
from datasecure.scanners.source_code.scanner import SourceCodeScanner


class ScanEngine:
    """Coordinates file discovery and execution of registered security scanners."""

    def __init__(self, scanners: Optional[List[BaseScanner]] = None):
        self.scanners: List[BaseScanner] = scanners or [
            DatasetScanner(),
            SourceCodeScanner(),
            ModelScanner(),
        ]

    def register_scanner(self, scanner: BaseScanner) -> None:
        """Register a new scanner with the engine."""
        self.scanners.append(scanner)

    def scan_path(
        self,
        target_path: Path,
        config: DataSecureConfig,
        category: Optional[str] = None,
    ) -> ScanResult:
        """Scan a file or directory using registered scanners."""
        start_time = time.time()
        findings: List[Finding] = []
        scanned_count = 0

        target = Path(target_path).resolve()
        active_scanners = [
            s for s in self.scanners if (category is None or s.category == category)
        ]

        if target.is_file():
            scanned_count = 1
            for scanner in active_scanners:
                if scanner.can_scan(target):
                    findings.extend(scanner.scan(target, config))
        elif target.is_dir():
            for root_dir, dirs, files in target.walk() if hasattr(target, "walk") else self._walk_compat(target):
                # Filter out excluded directories in-place
                dirs[:] = [d for d in dirs if d not in config.exclude_dirs]

                for fname in files:
                    if fname in config.exclude_files:
                        continue
                    file_path = Path(root_dir) / fname
                    matched = False
                    for scanner in active_scanners:
                        if scanner.can_scan(file_path):
                            findings.extend(scanner.scan(file_path, config))
                            matched = True
                    if matched:
                        scanned_count += 1

        duration = time.time() - start_time
        summary = ScanSummary.from_findings(findings, scanned_targets=scanned_count, duration=duration)
        return ScanResult(
            project_path=str(target),
            findings=findings,
            summary=summary,
        )

    def _walk_compat(self, path: Path):
        """Fallback directory walk for Python < 3.12."""
        import os
        for root, dirs, files in os.walk(str(path)):
            yield Path(root), dirs, files

