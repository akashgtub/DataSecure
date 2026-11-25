"""Static AST-based Source Code Security Scanner for AI/ML projects."""

import ast
from pathlib import Path
from typing import List

from datasecure.configuration.config import DataSecureConfig
from datasecure.core.models import Finding, Severity
from datasecure.scanners.base import BaseScanner
from datasecure.scanners.source_code.rules import SourceCodeSecurityVisitor


class SourceCodeScanner(BaseScanner):
    """Static security scanner for Python source code in AI/ML applications."""

    SUPPORTED_EXTENSIONS = {".py"}

    @property
    def name(self) -> str:
        return "SourceCodeScanner"

    @property
    def category(self) -> str:
        return "source_code"

    def can_scan(self, path: Path) -> bool:
        return path.is_file() and path.suffix.lower() in self.SUPPORTED_EXTENSIONS

    def scan(self, path: Path, config: DataSecureConfig) -> List[Finding]:
        """Perform static analysis on Python source file without executing it."""
        if not config.source_code.enabled:
            return []

        if not path.exists():
            return []

        # Enforce file size boundary check
        if not self.is_file_size_safe(path, max_mb=config.max_file_size_mb):
            return [
                Finding(
                    id="DS-SRC-000",
                    name="Oversized Source Code File",
                    severity=Severity.LOW,
                    category=self.category,
                    file_path=str(path),
                    explanation=(
                        f"Source file size ({path.stat().st_size / (1024*1024):.1f} MB) exceeds "
                        f"configured limit of {config.max_file_size_mb} MB."
                    ),
                    remediation="Increase max_file_size_mb or inspect file manually.",
                    is_heuristic=True,
                )
            ]

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                source_code = f.read()
        except Exception as e:
            return [
                Finding(
                    id="DS-SRC-009",
                    name="Error Reading Source File",
                    severity=Severity.LOW,
                    category=self.category,
                    file_path=str(path),
                    explanation=f"Could not read Python source file: {e}",
                    remediation="Verify file permissions and encoding.",
                    is_heuristic=False,
                )
            ]

        source_lines = source_code.splitlines()

        # Parse AST without executing any code
        try:
            tree = ast.parse(source_code, filename=str(path))
        except SyntaxError as e:
            return [
                Finding(
                    id="DS-SRC-009",
                    name="Syntax Error in Python Source",
                    severity=Severity.LOW,
                    category=self.category,
                    file_path=str(path),
                    line_number=e.lineno,
                    evidence=f"SyntaxError: {e.msg} at line {e.lineno}",
                    explanation="File contains invalid Python syntax and cannot be statically analyzed.",
                    remediation="Fix syntax error to enable static security scanning.",
                    is_heuristic=False,
                )
            ]

        visitor = SourceCodeSecurityVisitor(path, source_lines, config)
        visitor.visit(tree)
        return visitor.findings

