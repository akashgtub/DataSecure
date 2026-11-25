"""Core domain models for DataSecure."""

from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_string(cls, val: str) -> "Severity":
        val_upper = val.strip().upper()
        for member in cls:
            if member.value == val_upper:
                return member
        raise ValueError(f"Unknown severity level: {val}")

    @property
    def rank(self) -> int:
        """Numeric rank for threshold comparison (higher = more severe)."""
        ranks = {
            Severity.INFO: 1,
            Severity.LOW: 2,
            Severity.MEDIUM: 3,
            Severity.HIGH: 4,
            Severity.CRITICAL: 5,
        }
        return ranks[self]

    def meets_or_exceeds(self, threshold: "Severity") -> bool:
        """Returns True if this severity is at least as severe as the threshold."""
        return self.rank >= threshold.rank


class Finding(BaseModel):
    """Represents an individual security finding."""
    id: str = Field(description="Unique rule or finding identifier, e.g. DS-SEC-001")
    name: str = Field(description="Brief title of the vulnerability or issue")
    severity: Severity = Field(description="Severity rating")
    category: str = Field(description="Category: dataset, model, source_code, llm, or config")
    file_path: str = Field(description="Path to the inspected file")
    line_number: Optional[int] = Field(default=None, description="Line number if applicable")
    evidence: Optional[str] = Field(default=None, description="Sanitized excerpt or indicator")
    explanation: str = Field(description="Detailed explanation of the risk")
    remediation: str = Field(description="Actionable guidance to remediate the finding")
    is_heuristic: bool = Field(default=False, description="Whether this is a heuristic indicator")


class ScanSummary(BaseModel):
    """High-level summary of a scan run."""
    scanned_targets: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    scan_duration_seconds: float = 0.0

    @classmethod
    def from_findings(
        cls,
        findings: List[Finding],
        scanned_targets: int = 0,
        duration: float = 0.0,
    ) -> "ScanSummary":
        summary = cls(
            scanned_targets=scanned_targets,
            total_findings=len(findings),
            scan_duration_seconds=round(duration, 3),
        )
        for f in findings:
            if f.severity == Severity.CRITICAL:
                summary.critical_count += 1
            elif f.severity == Severity.HIGH:
                summary.high_count += 1
            elif f.severity == Severity.MEDIUM:
                summary.medium_count += 1
            elif f.severity == Severity.LOW:
                summary.low_count += 1
            elif f.severity == Severity.INFO:
                summary.info_count += 1
        return summary


class ScanResult(BaseModel):
    """Complete results of a scan execution."""
    project_path: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    findings: List[Finding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)

