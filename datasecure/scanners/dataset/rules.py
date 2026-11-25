"""Dataset security rules, patterns, entropy calculation, and heuristic detectors."""

import math
import re
from typing import Dict, List, Optional, Tuple

# Pre-compiled regex patterns for sensitive credentials & tokens
SECRET_PATTERNS: Dict[str, Tuple[re.Pattern, str, str]] = {
    "OpenAI API Key": (
        re.compile(r"\b(sk-[a-zA-Z0-9_-]{20,})\b"),
        "Critical API key exposure allowing unauthorized LLM usage and billing.",
        "Revoke the exposed key immediately and store credentials in environment variables or a secrets manager.",
    ),
    "AWS Access Key": (
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "Exposed AWS Access Key ID, potentially enabling unauthorized AWS infrastructure access.",
        "Rotate the AWS access key and remove it from training datasets.",
    ),
    "GitHub Personal Access Token": (
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,})\b"),
        "Exposed GitHub personal access token.",
        "Revoke the GitHub token and purge it from source files and datasets.",
    ),
    "Hugging Face Token": (
        re.compile(r"\b(hf_[a-zA-Z0-9]{34,})\b"),
        "Exposed Hugging Face user access token.",
        "Revoke the token in Hugging Face settings and sanitize the dataset.",
    ),
    "Private Key Header": (
        re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)"),
        "Cryptographic private key detected in dataset.",
        "Remove private cryptographic keys from public or training datasets immediately.",
    ),
    "Hardcoded Password Assignment": (
        re.compile(r"(?i)\b(?:password|passwd|secret|api_key|apikey)\s*[:=]\s*['\"]?([^\s,'\"&;]{6,})['\"]?"),
        "Potential plaintext password or secret key assignment.",
        "Remove plaintext credentials from dataset records.",
    ),
}

# Pre-compiled regex patterns for PII
PII_PATTERNS: Dict[str, Tuple[re.Pattern, str, str]] = {
    "Email Address": (
        re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b"),
        "Personal email address detected in dataset.",
        "Anonymize or remove personal identifiable email addresses before training or publishing.",
    ),
    "US Social Security Number": (
        re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        "Government-issued identification number (US SSN) detected in dataset.",
        "Strip sensitive identity numbers to comply with privacy regulations.",
    ),
    "Credit Card Number": (
        re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"),
        "Potential payment card number detected.",
        "Mask or delete financial payment card data from training samples.",
    ),
}

# Suspicious Unicode characters: invisible formatting and bidirectional overrides (Trojan Source)
SUSPICIOUS_UNICODE_CHARS = {
    "\u200B": "Zero Width Space (invisible character)",
    "\u200C": "Zero Width Non-Joiner (invisible character)",
    "\u200D": "Zero Width Joiner (invisible character)",
    "\uFEFF": "Zero Width No-Break Space / BOM (invisible character)",
    "\u2060": "Word Joiner (invisible character)",
    "\u202A": "Left-to-Right Embedding (bidirectional override)",
    "\u202B": "Right-to-Left Embedding (bidirectional override)",
    "\u202C": "Pop Directional Formatting (bidirectional override)",
    "\u202D": "Left-to-Right Override (bidirectional override)",
    "\u202E": "Right-to-Left Override (bidirectional override)",
    "\u2066": "Left-to-Right Isolate (bidirectional override)",
    "\u2067": "Right-to-Left Isolate (bidirectional override)",
    "\u2068": "First Strong Isolate (bidirectional override)",
    "\u2069": "Pop Directional Isolate (bidirectional override)",
}

# Potential data poisoning / instruction injection patterns in dataset text
POISONING_TRIGGER_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (
        re.compile(r"(?i)\b(ignore\s+(all\s+)?previous\s+instructions)\b"),
        "Instruction injection override indicator ('ignore previous instructions')",
    ),
    (
        re.compile(r"(?i)\b(disregard\s+all\s+(system|prior)\s+prompts?)\b"),
        "Instruction injection prompt reset attempt",
    ),
    (
        re.compile(r"(?i)\b(you\s+are\s+now\s+in\s+developer\s+mode)\b"),
        "Jailbreak prompt injection pattern ('developer mode')",
    ),
    (
        re.compile(r"(?i)\b(system:\s*override\s+safety)\b"),
        "Potential backdoor or safety override trigger phrase",
    ),
    (
        re.compile(r"(?i)\b(bypass\s+safety\s+filters?)\b"),
        "Potential safety bypass instruction injected into dataset",
    ),
]


def redact_sensitive_value(value: str) -> str:
    """Safely redact sensitive text, preserving prefix/suffix context where safe."""
    val = value.strip()
    if len(val) <= 6:
        return "***REDACTED***"
    if len(val) <= 12:
        return f"{val[:2]}***{val[-2:]}"
    return f"{val[:4]}***{val[-3:]}"


def calculate_shannon_entropy(text: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not text:
        return 0.0
    length = len(text)
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def luhn_checksum_valid(number_str: str) -> bool:
    """Validate numeric string using Luhn algorithm to prevent credit card false positives."""
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) != 16:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for idx, d in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


def detect_high_entropy_strings(text: str, min_len: int = 24, max_len: int = 80, threshold: float = 4.5) -> List[str]:
    """Identify candidate high-entropy tokens that may represent raw secrets or hashes."""
    candidates: List[str] = []
    # Tokenize words containing alphanumeric, hyphen, underscore
    tokens = re.findall(r"\b[A-Za-z0-9_\-\+/=]{24,80}\b", text)
    for token in tokens:
        # Ignore common base64 padding or monotonous strings
        if len(set(token)) < 8:
            continue
        entropy = calculate_shannon_entropy(token)
        if entropy >= threshold:
            candidates.append(token)
    return candidates


def find_suspicious_unicode(text: str) -> List[Tuple[str, str, int]]:
    """Scan text for invisible or Trojan Source bidirectional override characters.

    Returns:
        List of (char_repr, description, character_index)
    """
    findings: List[Tuple[str, str, int]] = []
    for idx, char in enumerate(text):
        if char in SUSPICIOUS_UNICODE_CHARS:
            desc = SUSPICIOUS_UNICODE_CHARS[char]
            char_hex = f"U+{ord(char):04X}"
            findings.append((char_hex, desc, idx))
    return findings

