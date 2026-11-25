"""Unit and integration tests for ModelScanner and static format inspectors."""

import io
import json
from pathlib import Path
import struct
import zipfile
import pytest
from typer.testing import CliRunner

from datasecure.cli.main import app
from datasecure.configuration.config import DataSecureConfig
from datasecure.core.models import Severity
from datasecure.scanners.model.scanner import ModelScanner

runner = CliRunner()


@pytest.fixture
def model_scanner():
    return ModelScanner()


# ---------------------------------------------------------------------------
# Pickle Security Tests
# ---------------------------------------------------------------------------

def test_safe_pickle_file(model_scanner, temp_dir, default_config):
    pkl_file = temp_dir / "safe_data.pkl"
    # Protocol 2 pickle of {"weights": [1.0, 2.0, 3.0]}
    # Generated statically without loading
    pkl_file.write_bytes(b"\x80\x02}q\x00X\x07\x00\x00\x00weightsq\x01]q\x02(G?\xf0\x00\x00\x00\x00\x00\x00G@\x00\x00\x00\x00\x00\x00\x00G@\x08\x00\x00\x00\x00\x00\x00eu.")

    findings = model_scanner.scan(pkl_file, default_config)
    crit_findings = [f for f in findings if f.id == "DS-MOD-001"]
    assert len(crit_findings) == 0
    # Should report legacy format advisory DS-MOD-002
    advisory = [f for f in findings if f.id == "DS-MOD-002"]
    assert len(advisory) == 1
    assert advisory[0].severity == Severity.LOW
    assert advisory[0].is_heuristic is True


def test_dangerous_global_in_pickle(model_scanner, temp_dir, default_config):
    # Exploit payload referencing os.system
    marker = temp_dir / "executed.txt"
    payload = b"cos\nsystem\n(S'echo pwned'\ntR."

    malicious_pkl = temp_dir / "malicious.pkl"
    malicious_pkl.write_bytes(payload)

    findings = model_scanner.scan(malicious_pkl, default_config)
    crit_findings = [f for f in findings if f.id == "DS-MOD-001"]
    assert len(crit_findings) == 1
    assert crit_findings[0].severity == Severity.CRITICAL
    assert "os.system" in crit_findings[0].evidence
    assert crit_findings[0].is_heuristic is False
    # CRITICAL: Verify the payload was NEVER executed!
    assert not marker.exists()


def test_dangerous_stack_global_protocol_4(model_scanner, temp_dir, default_config):
    # Pickle protocol 4 with STACK_GLOBAL calling subprocess.Popen
    payload = b"\x80\x04\x8c\nsubprocess\x92\x8c\x05Popen\x92\x93(S'cmd'\ntR."
    malicious_pkl = temp_dir / "stack_global.pkl"
    malicious_pkl.write_bytes(payload)

    findings = model_scanner.scan(malicious_pkl, default_config)
    crit_findings = [f for f in findings if f.id == "DS-MOD-001"]
    assert len(crit_findings) == 1
    assert "subprocess.Popen" in crit_findings[0].evidence


def test_safe_tensor_reconstruction_globals(model_scanner, temp_dir, default_config):
    # Pickle referencing legitimate torch tensor rebuild function
    payload = (
        b"\x80\x02ctorch._utils\n_rebuild_tensor_v2\nq\x00"
        b"ccollections\nOrderedDict\nq\x01."
    )
    safe_torch_pkl = temp_dir / "safe_tensor.pkl"
    safe_torch_pkl.write_bytes(payload)

    findings = model_scanner.scan(safe_torch_pkl, default_config)
    crit_findings = [f for f in findings if f.id == "DS-MOD-001"]
    assert len(crit_findings) == 0


def test_malformed_pickle_stream(model_scanner, temp_dir, default_config):
    broken_pkl = temp_dir / "broken.pkl"
    broken_pkl.write_bytes(b"\x80\x02\xff\xff\xfe\x00invalid_pickle")

    findings = model_scanner.scan(broken_pkl, default_config)
    malformed_findings = [f for f in findings if f.id == "DS-MOD-005"]
    assert len(malformed_findings) >= 1
    assert malformed_findings[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# PyTorch Model Tests
# ---------------------------------------------------------------------------

def test_safe_pytorch_zip_archive(model_scanner, temp_dir, default_config):
    pt_file = temp_dir / "safe_model.pt"
    # Create valid synthetic PyTorch ZIP archive
    safe_pkl = b"\x80\x02ctorch._utils\n_rebuild_tensor_v2\nq\x00."
    with zipfile.ZipFile(pt_file, "w") as zf:
        zf.writestr("archive/data.pkl", safe_pkl)
        zf.writestr("archive/byteorder", "little")

    findings = model_scanner.scan(pt_file, default_config)
    crit_findings = [f for f in findings if f.id == "DS-MOD-001"]
    assert len(crit_findings) == 0
    # Produces format advisory
    advisories = [f for f in findings if f.id == "DS-MOD-002"]
    assert len(advisories) == 1


def test_malicious_pytorch_zip_archive(model_scanner, temp_dir, default_config):
    pt_file = temp_dir / "trojan_model.pt"
    # Embedded os.system in archive/data.pkl
    bad_pkl = b"cos\nsystem\n(S'whoami'\ntR."
    with zipfile.ZipFile(pt_file, "w") as zf:
        zf.writestr("archive/data.pkl", bad_pkl)

    findings = model_scanner.scan(pt_file, default_config)
    crit_findings = [f for f in findings if f.id == "DS-MOD-001"]
    assert len(crit_findings) == 1
    assert "os.system" in crit_findings[0].evidence


def test_corrupt_pytorch_zip_archive(model_scanner, temp_dir, default_config):
    pt_file = temp_dir / "corrupt.pt"
    pt_file.write_bytes(b"PK\x03\x04corrupted_zip_bytes_header_without_cdr")

    findings = model_scanner.scan(pt_file, default_config)
    corrupt_findings = [f for f in findings if f.id == "DS-MOD-005"]
    assert len(corrupt_findings) == 1


# ---------------------------------------------------------------------------
# SafeTensors Tests
# ---------------------------------------------------------------------------

def test_valid_safetensors_file(model_scanner, temp_dir, default_config):
    st_file = temp_dir / "weights.safetensors"
    # Create valid SafeTensors structure: 8 bytes len + JSON header + tensor data
    header = {
        "weight_1": {
            "dtype": "F32",
            "shape": [2, 2],
            "data_offsets": [0, 16],
        },
        "__metadata__": {"format": "pt"},
    }
    header_json = json.dumps(header).encode("utf-8")
    header_len = len(header_json)
    tensor_bytes = b"\x00" * 16

    st_content = struct.pack("<Q", header_len) + header_json + tensor_bytes
    st_file.write_bytes(st_content)

    findings = model_scanner.scan(st_file, default_config)
    # Valid SafeTensors produces 0 findings!
    assert len(findings) == 0


def test_safetensors_invalid_header_length(model_scanner, temp_dir, default_config):
    st_file = temp_dir / "bad_len.safetensors"
    # Header length 99999 exceeds file size
    st_file.write_bytes(struct.pack("<Q", 99999) + b"short")

    findings = model_scanner.scan(st_file, default_config)
    bad_len = [f for f in findings if f.id == "DS-MOD-005"]
    assert len(bad_len) == 1
    assert "exceeds file size" in bad_len[0].evidence


def test_safetensors_malformed_json_header(model_scanner, temp_dir, default_config):
    st_file = temp_dir / "bad_json.safetensors"
    invalid_json = b"{not: a valid json"
    header_len = len(invalid_json)
    st_file.write_bytes(struct.pack("<Q", header_len) + invalid_json)

    findings = model_scanner.scan(st_file, default_config)
    bad_json = [f for f in findings if f.id == "DS-MOD-005"]
    assert len(bad_json) == 1
    assert "Malformed SafeTensors JSON Header" in bad_json[0].name


def test_safetensors_out_of_bounds_offset(model_scanner, temp_dir, default_config):
    st_file = temp_dir / "out_of_bounds.safetensors"
    header = {
        "weight": {
            "dtype": "F32",
            "shape": [10],
            "data_offsets": [0, 5000000],  # Way beyond file
        }
    }
    header_json = json.dumps(header).encode("utf-8")
    st_file.write_bytes(struct.pack("<Q", len(header_json)) + header_json + b"small_payload")

    findings = model_scanner.scan(st_file, default_config)
    oob = [f for f in findings if f.id == "DS-MOD-005"]
    assert len(oob) == 1
    assert "Out-of-Bounds" in oob[0].name


# ---------------------------------------------------------------------------
# Keras / HDF5 Tests
# ---------------------------------------------------------------------------

def test_safe_keras_archive(model_scanner, temp_dir, default_config):
    keras_file = temp_dir / "clean.keras"
    cfg = {"class_name": "Sequential", "config": {"layers": [{"class_name": "Dense"}]}}
    with zipfile.ZipFile(keras_file, "w") as zf:
        zf.writestr("config.json", json.dumps(cfg))

    findings = model_scanner.scan(keras_file, default_config)
    assert len(findings) == 0


def test_insecure_keras_lambda_layer(model_scanner, temp_dir, default_config):
    keras_file = temp_dir / "lambda.keras"
    cfg = {
        "class_name": "Sequential",
        "config": {
            "layers": [
                {
                    "class_name": "Lambda",
                    "config": {"function": "base64_serialized_python_bytecode_string", "function_type": "lambda"},
                }
            ]
        },
    }
    with zipfile.ZipFile(keras_file, "w") as zf:
        zf.writestr("config.json", json.dumps(cfg))

    findings = model_scanner.scan(keras_file, default_config)
    lambda_findings = [f for f in findings if f.id == "DS-MOD-004"]
    assert len(lambda_findings) == 1
    assert lambda_findings[0].severity == Severity.HIGH
    assert lambda_findings[0].is_heuristic is True


def test_valid_and_invalid_h5_signatures(model_scanner, temp_dir, default_config):
    valid_h5 = temp_dir / "model.h5"
    valid_h5.write_bytes(b"\x89HDF\r\n\x1a\n" + b"\x00" * 32)
    assert len(model_scanner.scan(valid_h5, default_config)) == 0

    invalid_h5 = temp_dir / "fake.h5"
    invalid_h5.write_bytes(b"NOT_AN_HDF5_FILE")
    findings = model_scanner.scan(invalid_h5, default_config)
    bad_h5 = [f for f in findings if f.id == "DS-MOD-005"]
    assert len(bad_h5) == 1


# ---------------------------------------------------------------------------
# ONNX Tests
# ---------------------------------------------------------------------------

def test_safe_onnx_model(model_scanner, temp_dir, default_config):
    onnx_file = temp_dir / "clean.onnx"
    onnx_file.write_bytes(b"\x08\x07\x12\x05clean\x1a\x04test")
    findings = model_scanner.scan(onnx_file, default_config)
    assert len(findings) == 0


def test_onnx_path_traversal_detection(model_scanner, temp_dir, default_config):
    onnx_file = temp_dir / "traversal.onnx"
    # Protobuf data containing external tensor path with ../
    payload = b"\x08\x07\x12\x15location: ../../../etc/passwd\x1a\x04test"
    onnx_file.write_bytes(payload)

    findings = model_scanner.scan(onnx_file, default_config)
    traversal_findings = [f for f in findings if f.id == "DS-MOD-006"]
    assert len(traversal_findings) == 1
    assert traversal_findings[0].severity == Severity.HIGH
    assert "Path Traversal" in traversal_findings[0].name


# ---------------------------------------------------------------------------
# Executable Masquerading & Format Ambiguity Tests
# ---------------------------------------------------------------------------

def test_executable_masquerading_as_pt(model_scanner, temp_dir, default_config):
    fake_pt = temp_dir / "model.pt"
    fake_pt.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00windows_pe_executable_header")

    findings = model_scanner.scan(fake_pt, default_config)
    masq = [f for f in findings if f.id == "DS-MOD-003"]
    assert len(masq) == 1
    assert masq[0].severity == Severity.CRITICAL
    assert "Windows PE Executable" in masq[0].evidence


def test_executable_masquerading_as_onnx(model_scanner, temp_dir, default_config):
    fake_onnx = temp_dir / "model.onnx"
    fake_onnx.write_bytes(b"\x7fELF\x02\x01\x01\x00linux_elf_executable")

    findings = model_scanner.scan(fake_onnx, default_config)
    masq = [f for f in findings if f.id == "DS-MOD-003"]
    assert len(masq) == 1
    assert "Linux ELF Executable" in masq[0].evidence


def test_ambiguous_bin_non_model(model_scanner, temp_dir, default_config):
    # A generic binary file that is not a pickle or zip should not cause false alarms
    generic_bin = temp_dir / "random.bin"
    generic_bin.write_bytes(b"\x00\x01\x02\x03\x04\x05binary_payload_non_model")

    findings = model_scanner.scan(generic_bin, default_config)
    assert len(findings) == 0


def test_oversized_model_file(model_scanner, temp_dir):
    model_file = temp_dir / "huge_model.pt"
    model_file.write_bytes(b"fake_pt_weights")

    cfg = DataSecureConfig()
    cfg.max_file_size_mb = 0  # Force 0 limit
    findings = model_scanner.scan(model_file, cfg)
    assert len(findings) == 1
    assert findings[0].id == "DS-MOD-000"


# ---------------------------------------------------------------------------
# CLI Integration for `datasecure scan --model`
# ---------------------------------------------------------------------------

def test_cli_scan_model_option(temp_dir):
    vuln_model = temp_dir / "vuln.pkl"
    vuln_model.write_bytes(b"cos\nsystem\n(S'rm -rf /'\ntR.")

    result = runner.invoke(app, ["scan", "--model", str(vuln_model), "--fail-on", "CRITICAL"])
    assert result.exit_code == 1
    assert "Dangerous Executable Global in Model" in result.stdout
    assert "os.system" in result.stdout

