"""CLI formatting utilities for terminal output."""

import sys
from typing import List
from datasecure.core.models import Finding, ScanResult, Severity

# Standard ANSI escape codes for cross-platform color formatting
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
GREEN = "\033[92m"
MAGENTA = "\033[95m"
GRAY = "\033[90m"

SEVERITY_COLORS = {
    Severity.CRITICAL: f"{BOLD}{MAGENTA}",
    Severity.HIGH: f"{BOLD}{RED}",
    Severity.MEDIUM: f"{YELLOW}",
    Severity.LOW: f"{BLUE}",
    Severity.INFO: f"{CYAN}",
}


def print_banner() -> None:
    """Print the DataSecure CLI banner."""
    banner = f"""{BOLD}{CYAN}
  ____        _        ____                              
 |  _ \\  __ _| |_ __ _/ ___|  ___  ___ _   _ _ __ ___    
 | | | |/ _` | __/ _` \\___ \\ / _ \\/ __| | | | '__/ _ \\   
 | |_| | (_| | || (_| |___) |  __/ (__| |_| | | |  __/   
 |____/ \\__,_|\\__\\__,_|____/ \\___|\\___|\\__,_|_|  \\___|   
{RESET}{GRAY} AI Security Scanning Tool - Standalone Security Extension{RESET}
"""
    print(banner)


def format_finding(finding: Finding) -> str:
    """Format a single finding for console display."""
    sev_color = SEVERITY_COLORS.get(finding.severity, "")
    badge = f"{sev_color}[{finding.severity.value}]{RESET}"
    heuristic_tag = f" {YELLOW}(HEURISTIC){RESET}" if finding.is_heuristic else ""
    loc = f"{finding.file_path}"
    if finding.line_number is not None:
        loc += f":{finding.line_number}"

    lines = [
        f"{badge} {BOLD}{finding.name}{RESET}{heuristic_tag} [{GRAY}{finding.id}{RESET}]",
        f"  Location:    {CYAN}{loc}{RESET}",
        f"  Category:    {finding.category}",
        f"  Explanation: {finding.explanation}",
    ]
    if finding.evidence:
        lines.append(f"  Evidence:    {GRAY}{finding.evidence}{RESET}")
    lines.append(f"  Remediation: {GREEN}{finding.remediation}{RESET}")
    return "\n".join(lines)


def print_summary(result: ScanResult) -> None:
    """Print formatted scan summary."""
    s = result.summary
    print("\n" + "=" * 60)
    print(f"{BOLD}SCAN SUMMARY{RESET}")
    print("=" * 60)
    print(f"Target:             {result.project_path}")
    print(f"Scanned files:      {s.scanned_targets}")
    print(f"Duration:           {s.scan_duration_seconds:.2f}s")
    print("-" * 60)
    print(
        f"Findings ({s.total_findings}): "
        f"{MAGENTA}{s.critical_count} Critical{RESET} | "
        f"{RED}{s.high_count} High{RESET} | "
        f"{YELLOW}{s.medium_count} Medium{RESET} | "
        f"{BLUE}{s.low_count} Low{RESET} | "
        f"{CYAN}{s.info_count} Info{RESET}"
    )
    print("=" * 60 + "\n")

