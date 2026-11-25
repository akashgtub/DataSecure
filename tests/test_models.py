"""Unit tests for core models (Severity, Finding, ScanSummary, ScanResult)."""

import pytest
from datasecure.core.models import Finding, ScanResult, ScanSummary, Severity


def test_severity_ranks_and_comparison():
    assert Severity.INFO.rank < Severity.LOW.rank
    assert Severity.LOW.rank < Severity.MEDIUM.rank
    assert Severity.MEDIUM.rank < Severity.HIGH.rank
    assert Severity.HIGH.rank < Severity.CRITICAL.rank

    assert Severity.CRITICAL.meets_or_exceeds(Severity.HIGH)
    assert Severity.HIGH.meets_or_exceeds(Severity.HIGH)
    assert not Severity.MEDIUM.meets_or_exceeds(Severity.HIGH)


def test_severity_from_string():
    assert Severity.from_string("critical") == Severity.CRITICAL
    assert Severity.from_string("HIGH") == Severity.HIGH
    assert Severity.from_string(" medium ") == Severity.MEDIUM

    with pytest.raises(ValueError, match="Unknown severity level"):
        Severity.from_string("UNKNOWN")


def test_finding_creation(sample_finding):
    assert sample_finding.id == "DS-TEST-001"
    assert sample_finding.severity == Severity.HIGH
    assert sample_finding.line_number == 42
    assert sample_finding.is_heuristic is False


def test_scan_summary_from_findings():
    findings = [
        Finding(
            id="DS-001",
            name="Critical Finding",
            severity=Severity.CRITICAL,
            category="model",
            file_path="model.pkl",
            explanation="Dangerous pickle opcode",
            remediation="Use SafeTensors",
        ),
        Finding(
            id="DS-002",
            name="High Finding",
            severity=Severity.HIGH,
            category="source_code",
            file_path="app.py",
            explanation="Hardcoded API key",
            remediation="Use env vars",
        ),
        Finding(
            id="DS-003",
            name="Medium Finding",
            severity=Severity.MEDIUM,
            category="dataset",
            file_path="data.csv",
            explanation="Duplicate rows",
            remediation="Deduplicate",
        ),
        Finding(
            id="DS-004",
            name="Low Finding",
            severity=Severity.LOW,
            category="dataset",
            file_path="data.csv",
            explanation="Potential anomaly",
            remediation="Inspect",
        ),
        Finding(
            id="DS-005",
            name="Info Finding",
            severity=Severity.INFO,
            category="config",
            file_path="config.yml",
            explanation="Default port used",
            remediation="Review port",
        ),
    ]

    summary = ScanSummary.from_findings(findings, scanned_targets=10, duration=1.234)
    assert summary.total_findings == 5
    assert summary.critical_count == 1
    assert summary.high_count == 1
    assert summary.medium_count == 1
    assert summary.low_count == 1
    assert summary.info_count == 1
    assert summary.scanned_targets == 10
    assert summary.scan_duration_seconds == 1.234


def test_scan_result_serialization(sample_finding):
    summary = ScanSummary.from_findings([sample_finding], scanned_targets=1, duration=0.5)
    result = ScanResult(
        project_path=".",
        findings=[sample_finding],
        summary=summary,
    )
    data = result.model_dump()
    assert data["project_path"] == "."
    assert len(data["findings"]) == 1
    assert data["summary"]["total_findings"] == 1

