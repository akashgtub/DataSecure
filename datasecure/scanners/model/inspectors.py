"""Static model inspection utilities for Pickle, PyTorch, SafeTensors, Keras, and ONNX."""

import io
import json
import os
from pathlib import Path
import pickletools
import struct
from typing import Any, Dict, List, Optional, Set, Tuple
import zipfile

from datasecure.core.models import Finding, Severity

# Known dangerous modules and callable names for arbitrary code execution
DANGEROUS_MODULES = {
    "os",
    "posix",
    "nt",
    "subprocess",
    "builtins",
    "__builtin__",
    "sys",
    "pty",
    "shutil",
    "commands",
    "socket",
    "urllib.request",
    "http.client",
    "requests",
    "_winapi",
    "webbrowser",
}

DANGEROUS_CALLABLES = {
    "system",
    "popen",
    "popen2",
    "popen3",
    "popen4",
    "spawn",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "exec",
    "execfile",
    "eval",
    "compile",
    "__import__",
    "open",
    "file",
    "remove",
    "unlink",
    "rmdir",
    "rmtree",
    "Popen",
    "call",
    "check_call",
    "check_output",
    "run",
    "fork",
    "kill",
}

# Known benign tensor/array reconstruction globals common in PyTorch and NumPy models
SAFE_TENSOR_GLOBALS = {
    ("torch._utils", "_rebuild_tensor_v2"),
    ("torch._utils", "_rebuild_parameter"),
    ("torch._utils", "_rebuild_tensor"),
    ("torch", "Tensor"),
    ("torch", "FloatStorage"),
    ("torch", "DoubleStorage"),
    ("torch", "HalfStorage"),
    ("torch", "LongStorage"),
    ("torch", "IntStorage"),
    ("torch", "ShortStorage"),
    ("torch", "CharStorage"),
    ("torch", "ByteStorage"),
    ("torch", "BoolStorage"),
    ("torch", "BFloat16Storage"),
    ("collections", "OrderedDict"),
    ("numpy.core.multiarray", "_reconstruct"),
    ("numpy.core.multiarray", "scalar"),
    ("numpy", "ndarray"),
    ("numpy", "dtype"),
    ("_codecs", "encode"),
}

# Executable binary signatures for masquerading detection
BINARY_SIGNATURES = [
    (b"MZ", "Windows PE Executable (MZ)"),
    (b"\x7fELF", "Linux ELF Executable"),
    (b"\xfe\xed\xfa\xce", "Mach-O Binary (32-bit)"),
    (b"\xfe\xed\xfa\xcf", "Mach-O Binary (64-bit)"),
    (b"\xce\xfa\xed\xfe", "Mach-O Binary (reverse 32-bit)"),
    (b"\xcf\xfa\xed\xfe", "Mach-O Binary (reverse 64-bit)"),
]

HDF5_SIGNATURE = b"\x89HDF\r\n\x1a\n"


def check_executable_masquerading(file_bytes: bytes, file_path: Path) -> Optional[Finding]:
    """Check if file starts with native executable magic bytes."""
    for magic, desc in BINARY_SIGNATURES:
        if file_bytes.startswith(magic):
            return Finding(
                id="DS-MOD-003",
                name="Executable Binary Masquerading as AI Model",
                severity=Severity.CRITICAL,
                category="model",
                file_path=str(file_path),
                evidence=f"Detected magic signature: {desc}",
                explanation=(
                    f"File has a model file extension but its header matches a native executable ({desc}). "
                    "This is a common evasion technique to deliver malware disguised as neural network weights."
                ),
                remediation="Do not load or execute this file. Delete it and verify the model supply chain.",
                is_heuristic=False,
            )
    return None


def inspect_pickle_stream(
    data: bytes,
    file_path: Path,
    is_archive_member: bool = False,
    max_opcodes: int = 150000,
) -> List[Finding]:
    """Perform bounded symbolic static inspection of a pickle opcode stream.

    Never executes or reconstructs objects. Analyzes both GLOBAL and STACK_GLOBAL opcodes.
    """
    findings: List[Finding] = []
    stack: List[str] = []
    seen_dangerous: Set[str] = set()
    opcode_count = 0

    try:
        gen = pickletools.genops(data)
        for op, arg, pos in gen:
            opcode_count += 1
            if opcode_count > max_opcodes:
                break

            op_name = op.name

            # Push string constants to the bounded symbolic stack
            if op_name in {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "STRING", "BINSTRING", "SHORT_BINSTRING"}:
                if isinstance(arg, str):
                    stack.append(arg)
                elif isinstance(arg, bytes):
                    stack.append(arg.decode("utf-8", errors="replace"))
                if len(stack) > 500:
                    stack.pop(0)

            # Protocol 0-3: GLOBAL opcode provides 'module name' directly in arg
            elif op_name == "GLOBAL":
                if isinstance(arg, str):
                    parts = arg.strip().split()
                    if len(parts) >= 2:
                        mod, name = parts[0], parts[1]
                        _check_and_record_global(mod, name, file_path, pos, seen_dangerous, findings)

            # Protocol 4+: STACK_GLOBAL pops name and module from stack
            elif op_name == "STACK_GLOBAL":
                if len(stack) >= 2:
                    name = stack.pop()
                    mod = stack.pop()
                    if isinstance(mod, str) and isinstance(name, str):
                        _check_and_record_global(mod, name, file_path, pos, seen_dangerous, findings)

    except Exception as e:
        # Truncated or malformed pickle stream
        findings.append(
            Finding(
                id="DS-MOD-005",
                name="Malformed or Truncated Pickle Stream",
                severity=Severity.MEDIUM,
                category="model",
                file_path=str(file_path),
                evidence=f"Pickle disassembly error: {e}",
                explanation="Model file could not be parsed because its serialization structure is invalid or truncated.",
                remediation="Ensure model was completely exported without corruption.",
                is_heuristic=False,
            )
        )

    # If file is a raw pickle artifact and no critical finding was produced, report legacy format advisory
    if not is_archive_member and not any(f.id == "DS-MOD-001" for f in findings):
        findings.append(
            Finding(
                id="DS-MOD-002",
                name="Legacy Pickle-Based Model Format",
                severity=Severity.LOW,
                category="model",
                file_path=str(file_path),
                explanation=(
                    "Model uses Python pickle serialization. Pickle formats contain object reconstruction instructions "
                    "which present supply chain risks if acquired from untrusted sources."
                ),
                remediation="Convert model weights to SafeTensors format (e.g. via safetensors library).",
                is_heuristic=True,
            )
        )

    return findings


def _check_and_record_global(
    mod: str,
    name: str,
    file_path: Path,
    pos: Optional[int],
    seen_dangerous: Set[str],
    findings: List[Finding],
) -> None:
    """Evaluate resolved global import against dangerous modules and callables."""
    global_ref = f"{mod}.{name}"

    # Ignore ordinary benign tensor reconstruction primitives
    if (mod, name) in SAFE_TENSOR_GLOBALS:
        return

    # Check for dangerous execution targets
    is_dangerous_mod = mod in DANGEROUS_MODULES or any(mod.startswith(f"{m}.") for m in DANGEROUS_MODULES)
    is_dangerous_call = name in DANGEROUS_CALLABLES or name.startswith("system") or name.startswith("exec")

    if is_dangerous_mod and (is_dangerous_call or mod in {"builtins", "__builtin__"}):
        if global_ref not in seen_dangerous:
            seen_dangerous.add(global_ref)
            findings.append(
                Finding(
                    id="DS-MOD-001",
                    name="Dangerous Executable Global in Model",
                    severity=Severity.CRITICAL,
                    category="model",
                    file_path=str(file_path),
                    evidence=f"Resolved global: {global_ref}" + (f" at bytecode offset {pos}" if pos is not None else ""),
                    explanation=(
                        f"Model serialization contains a reference to a potentially dangerous callable ({global_ref}). "
                        "When unpickled via standard loaders, this can trigger Remote Code Execution (RCE)."
                    ),
                    remediation=(
                        "Do not load this model. Inspect model provenance and replace with SafeTensors weights."
                    ),
                    is_heuristic=False,
                )
            )


def inspect_pytorch_model(path: Path) -> List[Finding]:
    """Safely inspect PyTorch model files (.pt, .pth, .bin) without loading them."""
    findings: List[Finding] = []

    try:
        with open(path, "rb") as f:
            header_bytes = f.read(512)

        # Check masquerading executable first
        masquerade = check_executable_masquerading(header_bytes, path)
        if masquerade:
            return [masquerade]

        # Check if PyTorch model is a ZIP container (standard PyTorch format)
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path, "r") as zf:
                namelist = zf.namelist()
                pickle_members = [
                    name for name in namelist
                    if name.endswith("data.pkl") or name.endswith(".pkl") or name == "data.pkl"
                ]

                if not pickle_members:
                    # Zip container but no pickle metadata
                    return findings

                for pkl_name in pickle_members[:5]:  # Bound member check
                    with zf.open(pkl_name, "r") as pkl_file:
                        pkl_bytes = pkl_file.read(10 * 1024 * 1024)  # Read up to 10MB of metadata
                        findings.extend(
                            inspect_pickle_stream(pkl_bytes, path, is_archive_member=True)
                        )

                # Format advisory for PyTorch pickle container
                if not any(f.id == "DS-MOD-001" for f in findings):
                    findings.append(
                        Finding(
                            id="DS-MOD-002",
                            name="Legacy Pickle-Based Model Format (PyTorch Archive)",
                            severity=Severity.LOW,
                            category="model",
                            file_path=str(path),
                            explanation=(
                                "PyTorch archive uses pickle for tensor metadata serialization. "
                                "Loading untrusted PyTorch checkpoints without weights_only=True can allow code execution."
                            ),
                            remediation="Ensure torch.load(..., weights_only=True) is used or export model to SafeTensors.",
                            is_heuristic=True,
                        )
                    )
        else:
            # Legacy raw pickle PyTorch model
            with open(path, "rb") as f:
                raw_bytes = f.read(10 * 1024 * 1024)
            findings.extend(inspect_pickle_stream(raw_bytes, path, is_archive_member=False))

    except zipfile.BadZipFile as err:
        findings.append(
            Finding(
                id="DS-MOD-005",
                name="Corrupt or Malformed PyTorch Model Archive",
                severity=Severity.MEDIUM,
                category="model",
                file_path=str(path),
                evidence=f"BadZipFile: {err}",
                explanation="Model archive header indicates a ZIP file, but the archive is corrupt or truncated.",
                remediation="Re-download or export the PyTorch model artifact.",
                is_heuristic=False,
            )
        )
    except Exception as e:
        findings.append(
            Finding(
                id="DS-MOD-005",
                name="Error Inspecting PyTorch Model",
                severity=Severity.LOW,
                category="model",
                file_path=str(path),
                explanation=f"Static inspection encountered an error: {e}",
                remediation="Verify model file integrity.",
                is_heuristic=False,
            )
        )

    return findings


def inspect_safetensors_file(path: Path) -> List[Finding]:
    """Validate SafeTensors file structure, JSON header, and data bounds statically."""
    findings: List[Finding] = []
    try:
        file_size = path.stat().st_size
        if file_size < 8:
            return [
                Finding(
                    id="DS-MOD-005",
                    name="Truncated SafeTensors File",
                    severity=Severity.MEDIUM,
                    category="model",
                    file_path=str(path),
                    explanation="File is smaller than the required 8-byte SafeTensors header length.",
                    remediation="Verify file download integrity.",
                    is_heuristic=False,
                )
            ]

        with open(path, "rb") as f:
            header_len_bytes = f.read(8)
            header_len = struct.unpack("<Q", header_len_bytes)[0]

            if header_len <= 0 or (header_len + 8) > file_size:
                return [
                    Finding(
                        id="DS-MOD-005",
                        name="Invalid SafeTensors Header Length",
                        severity=Severity.HIGH,
                        category="model",
                        file_path=str(path),
                        evidence=f"Header length {header_len} exceeds file size {file_size}",
                        explanation="SafeTensors header size field is invalid or points beyond the file boundary.",
                        remediation="Ensure file was properly generated using the safetensors specification.",
                        is_heuristic=False,
                    )
                ]

            # Read only the JSON metadata header (never load tensor weights)
            max_header_read = min(header_len, 50 * 1024 * 1024)
            header_json_bytes = f.read(max_header_read)

        try:
            metadata = json.loads(header_json_bytes.decode("utf-8"))
        except json.JSONDecodeError as err:
            return [
                Finding(
                    id="DS-MOD-005",
                    name="Malformed SafeTensors JSON Header",
                    severity=Severity.HIGH,
                    category="model",
                    file_path=str(path),
                    evidence=f"JSONDecodeError: {err.msg}",
                    explanation="SafeTensors metadata header is not a valid UTF-8 JSON object.",
                    remediation="Re-export SafeTensors model.",
                    is_heuristic=False,
                )
            ]

        if not isinstance(metadata, dict):
            return [
                Finding(
                    id="DS-MOD-005",
                    name="Malformed SafeTensors Metadata Structure",
                    severity=Severity.HIGH,
                    category="model",
                    file_path=str(path),
                    explanation="SafeTensors header must be a JSON dictionary mapping tensor names to metadata.",
                    remediation="Fix SafeTensors export format.",
                    is_heuristic=False,
                )
            ]

        # Validate tensor offsets against file boundaries
        data_start_offset = 8 + header_len
        for tensor_name, tensor_info in metadata.items():
            if tensor_name == "__metadata__":
                continue
            if isinstance(tensor_info, dict) and "data_offsets" in tensor_info:
                offsets = tensor_info["data_offsets"]
                if isinstance(offsets, list) and len(offsets) == 2:
                    start_off, end_off = offsets
                    if start_off < 0 or end_off < start_off or (data_start_offset + end_off) > file_size:
                        return [
                            Finding(
                                id="DS-MOD-005",
                                name="SafeTensors Out-of-Bounds Tensor Data Offset",
                                severity=Severity.HIGH,
                                category="model",
                                file_path=str(path),
                                evidence=f"Tensor '{tensor_name}' offset range [{start_off}, {end_off}] exceeds bounds",
                                explanation="Tensor data offset references memory beyond the physical file size.",
                                remediation="Re-export model weights using a valid SafeTensors serializer.",
                                is_heuristic=False,
                            )
                        ]

    except Exception as e:
        findings.append(
            Finding(
                id="DS-MOD-005",
                name="Error Reading SafeTensors File",
                severity=Severity.LOW,
                category="model",
                file_path=str(path),
                explanation=f"Error inspecting SafeTensors file: {e}",
                remediation="Check file integrity.",
                is_heuristic=False,
            )
        )

    return findings


def inspect_keras_model(path: Path) -> List[Finding]:
    """Inspect Keras .keras zip archive and .h5 files statically without loading them."""
    findings: List[Finding] = []
    suffix = path.suffix.lower()

    # Keras v3 ZIP-based archive (.keras)
    if suffix == ".keras":
        if not zipfile.is_zipfile(path):
            return [
                Finding(
                    id="DS-MOD-005",
                    name="Malformed Keras Model Archive",
                    severity=Severity.MEDIUM,
                    category="model",
                    file_path=str(path),
                    explanation="File has a .keras extension but is not a valid ZIP container.",
                    remediation="Ensure model was saved properly using model.save('model.keras').",
                    is_heuristic=False,
                )
            ]

        try:
            with zipfile.ZipFile(path, "r") as zf:
                namelist = zf.namelist()
                if "config.json" in namelist:
                    with zf.open("config.json", "r") as cfg_file:
                        config_data = json.loads(cfg_file.read().decode("utf-8", errors="replace"))
                        _inspect_keras_config(config_data, path, findings)
        except Exception as e:
            findings.append(
                Finding(
                    id="DS-MOD-005",
                    name="Error Reading Keras Archive Config",
                    severity=Severity.LOW,
                    category="model",
                    file_path=str(path),
                    explanation=f"Failed to read Keras config.json: {e}",
                    remediation="Verify Keras archive structure.",
                    is_heuristic=False,
                )
            )

    # Legacy HDF5 Keras models (.h5)
    elif suffix == ".h5":
        try:
            with open(path, "rb") as f:
                head = f.read(len(HDF5_SIGNATURE))
            if head != HDF5_SIGNATURE:
                findings.append(
                    Finding(
                        id="DS-MOD-005",
                        name="Invalid HDF5 Header Signature",
                        severity=Severity.MEDIUM,
                        category="model",
                        file_path=str(path),
                        explanation="File has .h5 extension but missing valid HDF5 magic bytes signature.",
                        remediation="Verify H5 model file integrity.",
                        is_heuristic=False,
                    )
                )
        except Exception as e:
            findings.append(
                Finding(
                    id="DS-MOD-005",
                    name="Error Inspecting H5 Model File",
                    severity=Severity.LOW,
                    category="model",
                    file_path=str(path),
                    explanation=f"Error reading HDF5 header: {e}",
                    remediation="Check file readability.",
                    is_heuristic=False,
                )
            )

    return findings


def _inspect_keras_config(config: Any, file_path: Path, findings: List[Finding]) -> None:
    """Recursively search Keras config for Lambda layers containing serialized Python bytecode."""
    if isinstance(config, dict):
        class_name = config.get("class_name")
        if class_name == "Lambda":
            layer_cfg = config.get("config", {})
            has_bytecode = (
                "function" in layer_cfg
                or "function_type" in layer_cfg
                or isinstance(layer_cfg.get("function"), str)
            )
            findings.append(
                Finding(
                    id="DS-MOD-004",
                    name="Insecure Keras Lambda Bytecode Layer",
                    severity=Severity.HIGH,
                    category="model",
                    file_path=str(file_path),
                    evidence="Lambda layer with custom serialized function in config.json",
                    explanation=(
                        "Keras model configuration contains a Lambda layer with serialized Python functions. "
                        "Loading untrusted models with Lambda layers executes embedded custom code during reconstruction."
                    ),
                    remediation="Refactor Lambda layers into standard Keras layers or use safe_mode=True.",
                    is_heuristic=True,
                )
            )
            return

        for val in config.values():
            _inspect_keras_config(val, file_path, findings)
    elif isinstance(config, list):
        for item in config:
            _inspect_keras_config(item, file_path, findings)


def inspect_onnx_model(path: Path) -> List[Finding]:
    """Safely inspect ONNX model file for masquerading, malformed structure, and path traversal."""
    findings: List[Finding] = []

    try:
        with open(path, "rb") as f:
            header_bytes = f.read(1024)

        # 1. Check masquerading
        masquerade = check_executable_masquerading(header_bytes, path)
        if masquerade:
            return [masquerade]

        # 2. Bounded scan of initial chunk for external tensor path traversal patterns
        # In ONNX external tensor metadata, external file paths are serialized as length-delimited strings
        file_size = path.stat().st_size
        read_size = min(file_size, 5 * 1024 * 1024)  # Inspect first 5MB for metadata
        with open(path, "rb") as f:
            sample_bytes = f.read(read_size)

        # Path traversal check in external data references
        if b"../" in sample_bytes or b"..\\" in sample_bytes:
            # Locate snippet
            idx = sample_bytes.find(b"../")
            if idx == -1:
                idx = sample_bytes.find(b"..\\")
            snippet = sample_bytes[max(0, idx - 10) : min(len(sample_bytes), idx + 30)]
            findings.append(
                Finding(
                    id="DS-MOD-006",
                    name="Suspicious External Path Reference (Path Traversal in Model)",
                    severity=Severity.HIGH,
                    category="model",
                    file_path=str(path),
                    evidence=f"Detected traversal sequence: {repr(snippet)}",
                    explanation=(
                        "Model contains external data path references attempting directory traversal ('../'). "
                        "When loaded, the model could access or overwrite arbitrary files outside the model directory."
                    ),
                    remediation="Store external tensor data within the same directory as the ONNX model without parent path references.",
                    is_heuristic=False,
                )
            )

    except Exception as e:
        findings.append(
            Finding(
                id="DS-MOD-005",
                name="Error Reading ONNX Model",
                severity=Severity.LOW,
                category="model",
                file_path=str(path),
                explanation=f"Error inspecting ONNX file: {e}",
                remediation="Verify ONNX file integrity.",
                is_heuristic=False,
            )
        )

    return findings

