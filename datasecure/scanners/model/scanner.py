"""Static Model Security Scanner for AI/ML model artifacts."""

from pathlib import Path
from typing import List
import zipfile

from datasecure.configuration.config import DataSecureConfig
from datasecure.core.models import Finding, Severity
from datasecure.scanners.base import BaseScanner
from datasecure.scanners.model.inspectors import (
    check_executable_masquerading,
    inspect_keras_model,
    inspect_onnx_model,
    inspect_pickle_stream,
    inspect_pytorch_model,
    inspect_safetensors_file,
)


class ModelScanner(BaseScanner):
    """Static security scanner for AI/ML model files.

    Strict zero-execution guarantee: models are never imported, loaded, or executed.
    """

    SUPPORTED_EXTENSIONS = {
        ".pkl",
        ".pickle",
        ".pt",
        ".pth",
        ".bin",
        ".joblib",
        ".dat",
        ".safetensors",
        ".keras",
        ".h5",
        ".onnx",
    }

    @property
    def name(self) -> str:
        return "ModelScanner"

    @property
    def category(self) -> str:
        return "model"

    def can_scan(self, path: Path) -> bool:
        return path.is_file() and path.suffix.lower() in self.SUPPORTED_EXTENSIONS

    def scan(self, path: Path, config: DataSecureConfig) -> List[Finding]:
        if not config.model.enabled:
            return []

        if not path.exists():
            return []

        # Enforce file size boundary check
        if not self.is_file_size_safe(path, max_mb=config.max_file_size_mb):
            return [
                Finding(
                    id="DS-MOD-000",
                    name="Oversized Model File",
                    severity=Severity.LOW,
                    category=self.category,
                    file_path=str(path),
                    explanation=(
                        f"Model file size ({path.stat().st_size / (1024*1024):.1f} MB) exceeds "
                        f"configured limit of {config.max_file_size_mb} MB."
                    ),
                    remediation="Increase max_file_size_mb or inspect model in an isolated environment.",
                    is_heuristic=True,
                )
            ]

        # Initial signature check (detecting executables masquerading as model weights)
        try:
            with open(path, "rb") as f:
                head_sample = f.read(512)
        except Exception as e:
            return [
                Finding(
                    id="DS-MOD-005",
                    name="Error Reading Model File",
                    severity=Severity.LOW,
                    category=self.category,
                    file_path=str(path),
                    explanation=f"Could not read model file: {e}",
                    remediation="Check file readability and permissions.",
                    is_heuristic=False,
                )
            ]

        masquerade = check_executable_masquerading(head_sample, path)
        if masquerade:
            return [masquerade]

        suffix = path.suffix.lower()

        # 1. SafeTensors validation
        if suffix == ".safetensors":
            return inspect_safetensors_file(path)

        # 2. PyTorch models (.pt, .pth)
        if suffix in {".pt", ".pth"}:
            return inspect_pytorch_model(path)

        # 3. Keras & HDF5 models (.keras, .h5)
        if suffix in {".keras", ".h5"}:
            return inspect_keras_model(path)

        # 4. ONNX models (.onnx)
        if suffix == ".onnx":
            return inspect_onnx_model(path)

        # 5. Dedicated Pickle artifacts (.pkl, .pickle, .joblib)
        if suffix in {".pkl", ".pickle", ".joblib"}:
            if not config.model.check_pickle_safety:
                return []
            try:
                with open(path, "rb") as f:
                    raw_data = f.read(50 * 1024 * 1024)
                return inspect_pickle_stream(raw_data, path, is_archive_member=False)
            except Exception as e:
                return [
                    Finding(
                        id="DS-MOD-005",
                        name="Error Reading Pickle Model",
                        severity=Severity.LOW,
                        category=self.category,
                        file_path=str(path),
                        explanation=f"Error reading pickle file: {e}",
                        remediation="Verify file integrity.",
                        is_heuristic=False,
                    )
                ]

        # 6. Ambiguous artifacts (.bin, .dat)
        if suffix in {".bin", ".dat"}:
            # Check if PyTorch ZIP container
            if zipfile.is_zipfile(path):
                return inspect_pytorch_model(path)

            # Check if pickle stream (starts with pickle protocol bytes \x80\x02, \x80\x03, \x80\x04, \x80\x05 or protocol 0/1 markers)
            if head_sample.startswith(b"\x80") or head_sample.startswith(b"("):
                if not config.model.check_pickle_safety:
                    return []
                try:
                    with open(path, "rb") as f:
                        raw_data = f.read(50 * 1024 * 1024)
                    return inspect_pickle_stream(raw_data, path, is_archive_member=False)
                except Exception:
                    return []

            # Ambiguous format that is not recognized as pickle or zip: return clean (no false alarms)
            return []

        return []

