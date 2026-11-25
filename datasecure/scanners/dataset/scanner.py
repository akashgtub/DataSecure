"""Streaming Dataset Security Scanner for CSV, JSON, JSONL, and TXT files."""

import csv
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Set

from datasecure.configuration.config import DataSecureConfig
from datasecure.core.models import Finding, Severity
from datasecure.scanners.base import BaseScanner
from datasecure.scanners.dataset.rules import (
    PII_PATTERNS,
    POISONING_TRIGGER_PATTERNS,
    SECRET_PATTERNS,
    detect_high_entropy_strings,
    find_suspicious_unicode,
    luhn_checksum_valid,
    redact_sensitive_value,
)


class DatasetScanner(BaseScanner):
    """Scanner for dataset files (CSV, TSV, JSON, JSONL, TXT)."""

    SUPPORTED_EXTENSIONS = {".csv", ".tsv", ".json", ".jsonl", ".txt"}
    MAX_FINDINGS_PER_RULE = 5  # Limit individual findings per rule to prevent flooding

    @property
    def name(self) -> str:
        return "DatasetScanner"

    @property
    def category(self) -> str:
        return "dataset"

    def can_scan(self, path: Path) -> bool:
        return path.is_file() and path.suffix.lower() in self.SUPPORTED_EXTENSIONS

    def scan(self, path: Path, config: DataSecureConfig) -> List[Finding]:
        if not config.dataset.enabled:
            return []

        if not path.exists():
            return []

        # Check file size safety
        if not self.is_file_size_safe(path, max_mb=config.max_file_size_mb):
            return [
                Finding(
                    id="DS-DATA-000",
                    name="Oversized Dataset File",
                    severity=Severity.LOW,
                    category=self.category,
                    file_path=str(path),
                    explanation=(
                        f"File size ({path.stat().st_size / (1024*1024):.1f} MB) exceeds "
                        f"configured limit of {config.max_file_size_mb} MB."
                    ),
                    remediation="Increase max_file_size_mb in .datasecure.yml or chunk the dataset.",
                    is_heuristic=True,
                )
            ]

        suffix = path.suffix.lower()
        if suffix in [".csv", ".tsv"]:
            return self._scan_csv(path, config, delimiter="\t" if suffix == ".tsv" else ",")
        elif suffix == ".jsonl":
            return self._scan_jsonl(path, config)
        elif suffix == ".json":
            return self._scan_json(path, config)
        elif suffix == ".txt":
            return self._scan_txt(path, config)

        return []

    def _scan_text_content(
        self,
        text: str,
        path: Path,
        line_num: int,
        config: DataSecureConfig,
        findings_counter: Dict[str, int],
    ) -> List[Finding]:
        """Inspect a single piece of text for credentials, PII, unicode anomalies, and poisoning."""
        findings: List[Finding] = []

        # 1. Secret & Credential Checks
        if config.dataset.check_secrets:
            for rule_name, (pattern, expl, rem) in SECRET_PATTERNS.items():
                rule_id = f"DS-DATA-SEC-{rule_name.replace(' ', '_').upper()}"
                if findings_counter.get(rule_id, 0) >= self.MAX_FINDINGS_PER_RULE:
                    continue

                for match in pattern.finditer(text):
                    raw_val = match.group(1) if match.groups() else match.group(0)
                    evidence = redact_sensitive_value(raw_val) if config.redact_secrets else raw_val
                    findings.append(
                        Finding(
                            id="DS-DATA-001",
                            name=f"Sensitive Credential Exposed: {rule_name}",
                            severity=Severity.CRITICAL if "Key" in rule_name or "Token" in rule_name else Severity.HIGH,
                            category=self.category,
                            file_path=str(path),
                            line_number=line_num,
                            evidence=f"Match: {evidence}",
                            explanation=expl,
                            remediation=rem,
                            is_heuristic=False,
                        )
                    )
                    findings_counter[rule_id] = findings_counter.get(rule_id, 0) + 1
                    if findings_counter[rule_id] >= self.MAX_FINDINGS_PER_RULE:
                        break

            # High-entropy credential detection (Heuristic)
            entropy_rule_id = "DS-DATA-003"
            if findings_counter.get(entropy_rule_id, 0) < self.MAX_FINDINGS_PER_RULE:
                high_entropy_tokens = detect_high_entropy_strings(text)
                for token in high_entropy_tokens:
                    # Ignore if token was already flagged as a known formatted secret
                    evidence = redact_sensitive_value(token) if config.redact_secrets else token
                    findings.append(
                        Finding(
                            id="DS-DATA-003",
                            name="Suspicious High-Entropy String",
                            severity=Severity.MEDIUM,
                            category=self.category,
                            file_path=str(path),
                            line_number=line_num,
                            evidence=f"Token: {evidence}",
                            explanation=(
                                "Detected high-entropy string (entropy >= 4.5) which commonly represents "
                                "unformatted API secrets, private keys, or tokens."
                            ),
                            remediation="Verify if this token is a credential and remove or mask it.",
                            is_heuristic=True,
                        )
                    )
                    findings_counter[entropy_rule_id] = findings_counter.get(entropy_rule_id, 0) + 1
                    if findings_counter[entropy_rule_id] >= self.MAX_FINDINGS_PER_RULE:
                        break

        # 2. PII Checks
        if config.dataset.check_pii:
            for pii_name, (pattern, expl, rem) in PII_PATTERNS.items():
                rule_id = f"DS-DATA-PII-{pii_name.replace(' ', '_').upper()}"
                if findings_counter.get(rule_id, 0) >= self.MAX_FINDINGS_PER_RULE:
                    continue

                for match in pattern.finditer(text):
                    raw_val = match.group(0)
                    if pii_name == "Credit Card Number" and not luhn_checksum_valid(raw_val):
                        continue

                    evidence = redact_sensitive_value(raw_val) if config.redact_secrets else raw_val
                    findings.append(
                        Finding(
                            id="DS-DATA-002",
                            name=f"Personally Identifiable Information (PII): {pii_name}",
                            severity=Severity.HIGH if pii_name in ["US Social Security Number", "Credit Card Number"] else Severity.MEDIUM,
                            category=self.category,
                            file_path=str(path),
                            line_number=line_num,
                            evidence=f"Exposed {pii_name}: {evidence}",
                            explanation=expl,
                            remediation=rem,
                            is_heuristic=False,
                        )
                    )
                    findings_counter[rule_id] = findings_counter.get(rule_id, 0) + 1
                    if findings_counter[rule_id] >= self.MAX_FINDINGS_PER_RULE:
                        break

        # 3. Suspicious Unicode Characters
        unicode_rule_id = "DS-DATA-004"
        if findings_counter.get(unicode_rule_id, 0) < self.MAX_FINDINGS_PER_RULE:
            anomalies = find_suspicious_unicode(text)
            if anomalies:
                char_hex, desc, col_idx = anomalies[0]
                findings.append(
                    Finding(
                        id="DS-DATA-004",
                        name="Suspicious Unicode / Invisible Character Detected",
                        severity=Severity.HIGH if "override" in desc else Severity.MEDIUM,
                        category=self.category,
                        file_path=str(path),
                        line_number=line_num,
                        evidence=f"Character {char_hex} ({desc}) at character offset {col_idx}",
                        explanation=(
                            "Dataset contains invisible characters or bidirectional Unicode overrides. "
                            "These characters are frequently used in Trojan Source attacks and prompt injections "
                            "to hide malicious payloads from human reviewers."
                        ),
                        remediation="Strip invisible Unicode characters and bidirectional formatting codes.",
                        is_heuristic=False,
                    )
                )
                findings_counter[unicode_rule_id] = findings_counter.get(unicode_rule_id, 0) + 1

        # 4. Data Poisoning & Prompt Injection Heuristics
        if config.dataset.check_poisoning_indicators:
            poison_rule_id = "DS-DATA-005"
            if findings_counter.get(poison_rule_id, 0) < self.MAX_FINDINGS_PER_RULE:
                for pattern, desc in POISONING_TRIGGER_PATTERNS:
                    m = pattern.search(text)
                    if m:
                        matched_text = m.group(0)
                        findings.append(
                            Finding(
                                id="DS-DATA-005",
                                name="Potential Data Poisoning / Injection Indicator",
                                severity=Severity.MEDIUM,
                                category=self.category,
                                file_path=str(path),
                                line_number=line_num,
                                evidence=f"Trigger phrase detected: '{matched_text}'",
                                explanation=(
                                    f"Dataset record contains {desc}. In fine-tuning or RAG datasets, "
                                    "such phrases can act as backdoor triggers or instruction injection attacks."
                                ),
                                remediation=(
                                    "Review sample origin and sanitize instruction override patterns "
                                    "prior to training."
                                ),
                                is_heuristic=True,
                            )
                        )
                        findings_counter[poison_rule_id] = findings_counter.get(poison_rule_id, 0) + 1
                        if findings_counter[poison_rule_id] >= self.MAX_FINDINGS_PER_RULE:
                            break

        return findings

    def _scan_csv(self, path: Path, config: DataSecureConfig, delimiter: str = ",") -> List[Finding]:
        """Stream and inspect CSV/TSV dataset row by row."""
        findings: List[Finding] = []
        findings_counter: Dict[str, int] = {}
        seen_hashes: Set[str] = set()
        duplicate_count = 0
        expected_cols: Optional[int] = None

        try:
            with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
                reader = csv.reader(f, delimiter=delimiter)
                for line_idx, row in enumerate(reader, start=1):
                    if line_idx > config.dataset.max_rows_to_sample:
                        break

                    if not row:
                        continue

                    # Header column count establishment
                    if line_idx == 1:
                        expected_cols = len(row)
                    elif expected_cols is not None and len(row) != expected_cols:
                        # Malformed entry check
                        malformed_id = "DS-DATA-006"
                        if findings_counter.get(malformed_id, 0) < self.MAX_FINDINGS_PER_RULE:
                            findings.append(
                                Finding(
                                    id="DS-DATA-006",
                                    name="Malformed CSV Row",
                                    severity=Severity.LOW,
                                    category=self.category,
                                    file_path=str(path),
                                    line_number=line_idx,
                                    evidence=f"Expected {expected_cols} columns, found {len(row)}",
                                    explanation="Row column count does not match the CSV header structure.",
                                    remediation="Fix or filter unescaped delimiters and malformed rows.",
                                    is_heuristic=False,
                                )
                            )
                            findings_counter[malformed_id] = findings_counter.get(malformed_id, 0) + 1

                    # Duplicate detection
                    if config.dataset.check_duplicates and line_idx > 1:
                        row_hash = hashlib.sha256(repr(row).encode("utf-8")).hexdigest()
                        if row_hash in seen_hashes:
                            duplicate_count += 1
                        else:
                            seen_hashes.add(row_hash)

                    # Text content checks on row fields
                    row_text = " ".join(row)
                    findings.extend(
                        self._scan_text_content(row_text, path, line_idx, config, findings_counter)
                    )

        except Exception as e:
            findings.append(
                Finding(
                    id="DS-DATA-006",
                    name="Error Reading CSV Dataset",
                    severity=Severity.MEDIUM,
                    category=self.category,
                    file_path=str(path),
                    explanation=f"Failed to read CSV dataset: {e}",
                    remediation="Verify dataset encoding and formatting.",
                    is_heuristic=False,
                )
            )

        # Report duplicate summary if duplicates detected
        if duplicate_count > 0:
            findings.append(
                Finding(
                    id="DS-DATA-007",
                    name="Duplicate Dataset Records Detected",
                    severity=Severity.LOW,
                    category=self.category,
                    file_path=str(path),
                    evidence=f"Found {duplicate_count} duplicate record(s) within inspected rows",
                    explanation=(
                        "Duplicate samples can bias AI model training, cause overfitting, "
                        "and inflate validation metrics."
                    ),
                    remediation="Deduplicate dataset records prior to training.",
                    is_heuristic=True,
                )
            )

        return findings

    def _scan_jsonl(self, path: Path, config: DataSecureConfig) -> List[Finding]:
        """Stream and inspect JSONL dataset line by line."""
        findings: List[Finding] = []
        findings_counter: Dict[str, int] = {}
        seen_hashes: Set[str] = set()
        duplicate_count = 0

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line_idx, raw_line in enumerate(f, start=1):
                    if line_idx > config.dataset.max_rows_to_sample:
                        break

                    line_stripped = raw_line.strip()
                    if not line_stripped:
                        continue

                    # Validate JSON syntax
                    try:
                        data = json.loads(line_stripped)
                    except json.JSONDecodeError as err:
                        malformed_id = "DS-DATA-006"
                        if findings_counter.get(malformed_id, 0) < self.MAX_FINDINGS_PER_RULE:
                            findings.append(
                                Finding(
                                    id="DS-DATA-006",
                                    name="Malformed JSONL Line",
                                    severity=Severity.MEDIUM,
                                    category=self.category,
                                    file_path=str(path),
                                    line_number=line_idx,
                                    evidence=f"JSONDecodeError: {err.msg} at line {line_idx}, column {err.colno}",
                                    explanation="Invalid JSON structure in JSONL dataset file.",
                                    remediation="Fix JSON formatting on the flagged line.",
                                    is_heuristic=False,
                                )
                            )
                            findings_counter[malformed_id] = findings_counter.get(malformed_id, 0) + 1
                        continue

                    # Duplicate check with order-invariant normalization
                    if config.dataset.check_duplicates:
                        try:
                            normalized_json = json.dumps(data, sort_keys=True, separators=(",", ":"))
                            line_hash = hashlib.sha256(normalized_json.encode("utf-8")).hexdigest()
                        except (TypeError, ValueError):
                            line_hash = hashlib.sha256(line_stripped.encode("utf-8")).hexdigest()

                        if line_hash in seen_hashes:
                            duplicate_count += 1
                        else:
                            seen_hashes.add(line_hash)

                    # Text scan
                    findings.extend(
                        self._scan_text_content(line_stripped, path, line_idx, config, findings_counter)
                    )

        except Exception as e:
            findings.append(
                Finding(
                    id="DS-DATA-006",
                    name="Error Reading JSONL Dataset",
                    severity=Severity.MEDIUM,
                    category=self.category,
                    file_path=str(path),
                    explanation=f"Failed to read JSONL file: {e}",
                    remediation="Verify JSONL file encoding and line breaks.",
                    is_heuristic=False,
                )
            )

        if duplicate_count > 0:
            findings.append(
                Finding(
                    id="DS-DATA-007",
                    name="Duplicate Dataset Records Detected",
                    severity=Severity.LOW,
                    category=self.category,
                    file_path=str(path),
                    evidence=f"Found {duplicate_count} duplicate line(s)",
                    explanation="Duplicate entries in JSONL training data can cause memorization and overfitting.",
                    remediation="Deduplicate JSONL samples.",
                    is_heuristic=True,
                )
            )

        return findings

    def _scan_json(self, path: Path, config: DataSecureConfig) -> List[Finding]:
        """Safely inspect JSON dataset files."""
        findings: List[Finding] = []
        findings_counter: Dict[str, int] = {}

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            try:
                parsed = json.loads(content)
            except json.JSONDecodeError as err:
                return [
                    Finding(
                        id="DS-DATA-006",
                        name="Malformed JSON Dataset",
                        severity=Severity.HIGH,
                        category=self.category,
                        file_path=str(path),
                        line_number=err.lineno,
                        evidence=f"JSONDecodeError: {err.msg} at line {err.lineno}",
                        explanation="The file is not a valid JSON document.",
                        remediation="Correct JSON syntax errors.",
                        is_heuristic=False,
                    )
                ]

            # Duplicate check for JSON datasets containing arrays of records
            if config.dataset.check_duplicates and isinstance(parsed, list):
                seen_hashes: Set[str] = set()
                duplicate_count = 0
                for item in parsed[: config.dataset.max_rows_to_sample]:
                    try:
                        normalized_item = json.dumps(item, sort_keys=True, separators=(",", ":"))
                        item_hash = hashlib.sha256(normalized_item.encode("utf-8")).hexdigest()
                    except (TypeError, ValueError):
                        item_hash = hashlib.sha256(repr(item).encode("utf-8")).hexdigest()

                    if item_hash in seen_hashes:
                        duplicate_count += 1
                    else:
                        seen_hashes.add(item_hash)

                if duplicate_count > 0:
                    findings.append(
                        Finding(
                            id="DS-DATA-007",
                            name="Duplicate Dataset Records Detected",
                            severity=Severity.LOW,
                            category=self.category,
                            file_path=str(path),
                            evidence=f"Found {duplicate_count} duplicate record(s) in JSON array",
                            explanation=(
                                "Duplicate records in JSON dataset array can bias AI model training, "
                                "cause overfitting, and inflate validation metrics."
                            ),
                            remediation="Deduplicate JSON records prior to training.",
                            is_heuristic=True,
                        )
                    )

            # Inspect strings extracted from JSON structure
            def extract_strings(obj: Any) -> List[str]:
                strings = []
                if isinstance(obj, str):
                    strings.append(obj)
                elif isinstance(obj, dict):
                    for k, v in obj.items():
                        if isinstance(k, str):
                            strings.append(k)
                        strings.extend(extract_strings(v))
                elif isinstance(obj, list):
                    for item in obj:
                        strings.extend(extract_strings(item))
                return strings

            all_strings = extract_strings(parsed)
            for idx, text in enumerate(all_strings[: config.dataset.max_rows_to_sample], start=1):
                findings.extend(
                    self._scan_text_content(text, path, idx, config, findings_counter)
                )

        except Exception as e:
            findings.append(
                Finding(
                    id="DS-DATA-006",
                    name="Error Reading JSON Dataset",
                    severity=Severity.MEDIUM,
                    category=self.category,
                    file_path=str(path),
                    explanation=f"Error inspecting JSON dataset: {e}",
                    remediation="Check file format.",
                    is_heuristic=False,
                )
            )

        return findings

    def _scan_txt(self, path: Path, config: DataSecureConfig) -> List[Finding]:
        """Stream and inspect plain text dataset line by line."""
        findings: List[Finding] = []
        findings_counter: Dict[str, int] = {}
        seen_hashes: Set[str] = set()
        duplicate_count = 0

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line_idx, line in enumerate(f, start=1):
                    if line_idx > config.dataset.max_rows_to_sample:
                        break

                    line_stripped = line.strip()
                    if not line_stripped:
                        continue

                    if config.dataset.check_duplicates:
                        line_hash = hashlib.sha256(line_stripped.encode("utf-8")).hexdigest()
                        if line_hash in seen_hashes:
                            duplicate_count += 1
                        else:
                            seen_hashes.add(line_hash)

                    findings.extend(
                        self._scan_text_content(line_stripped, path, line_idx, config, findings_counter)
                    )

        except Exception as e:
            findings.append(
                Finding(
                    id="DS-DATA-006",
                    name="Error Reading Text Dataset",
                    severity=Severity.LOW,
                    category=self.category,
                    file_path=str(path),
                    explanation=f"Error reading TXT dataset: {e}",
                    remediation="Check file encoding and readability.",
                    is_heuristic=False,
                )
            )

        if duplicate_count > 0:
            findings.append(
                Finding(
                    id="DS-DATA-007",
                    name="Duplicate Dataset Records Detected",
                    severity=Severity.LOW,
                    category=self.category,
                    file_path=str(path),
                    evidence=f"Found {duplicate_count} duplicate text line(s)",
                    explanation="Duplicate text samples may lead to disproportionate model weights.",
                    remediation="Deduplicate text records.",
                    is_heuristic=True,
                )
            )

        return findings

