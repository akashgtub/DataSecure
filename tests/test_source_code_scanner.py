"""Unit and integration tests for SourceCodeScanner and AST rules."""

from pathlib import Path
import pytest
from typer.testing import CliRunner

from datasecure.cli.main import app
from datasecure.configuration.config import DataSecureConfig
from datasecure.core.models import Severity
from datasecure.scanners.source_code.scanner import SourceCodeScanner

runner = CliRunner()


@pytest.fixture
def source_scanner():
    return SourceCodeScanner()


# ---------------------------------------------------------------------------
# Insecure Model Loading & Deserialization Tests
# ---------------------------------------------------------------------------

def test_insecure_pickle_loading(source_scanner, temp_dir, default_config):
    code_file = temp_dir / "load_pickle.py"
    code_file.write_text(
        "import pickle\n"
        "with open('model.pkl', 'rb') as f:\n"
        "    model = pickle.load(f)\n",
        encoding="utf-8",
    )
    findings = source_scanner.scan(code_file, default_config)
    pickle_findings = [f for f in findings if f.id == "DS-SRC-001"]
    assert len(pickle_findings) == 1
    assert pickle_findings[0].severity == Severity.CRITICAL
    assert pickle_findings[0].line_number == 3
    assert pickle_findings[0].is_heuristic is False


def test_insecure_joblib_and_dill(source_scanner, temp_dir, default_config):
    code_file = temp_dir / "load_joblib.py"
    code_file.write_text(
        "import joblib, dill\n"
        "m1 = joblib.load('classifier.joblib')\n"
        "m2 = dill.loads(raw_bytes)\n",
        encoding="utf-8",
    )
    findings = source_scanner.scan(code_file, default_config)
    deser_findings = [f for f in findings if f.id == "DS-SRC-001"]
    assert len(deser_findings) == 2


def test_unsafe_torch_load_default(source_scanner, temp_dir, default_config):
    code_file = temp_dir / "torch_default.py"
    code_file.write_text(
        "import torch\n"
        "weights = torch.load('weights.pt')\n",
        encoding="utf-8",
    )
    findings = source_scanner.scan(code_file, default_config)
    torch_findings = [f for f in findings if f.id == "DS-SRC-002"]
    assert len(torch_findings) == 1
    assert torch_findings[0].severity == Severity.HIGH
    assert "weights_only omitted" in torch_findings[0].evidence


def test_unsafe_torch_load_weights_only_false(source_scanner, temp_dir, default_config):
    code_file = temp_dir / "torch_unsafe.py"
    code_file.write_text(
        "import torch\n"
        "model = torch.load('checkpoint.pth', map_location='cpu', weights_only=False)\n",
        encoding="utf-8",
    )
    findings = source_scanner.scan(code_file, default_config)
    torch_findings = [f for f in findings if f.id == "DS-SRC-002"]
    assert len(torch_findings) == 1
    assert "weights_only=False" in torch_findings[0].evidence


def test_safe_torch_load_weights_only_true(source_scanner, temp_dir, default_config):
    code_file = temp_dir / "torch_safe.py"
    code_file.write_text(
        "import torch\n"
        "safe_weights = torch.load('weights.pt', weights_only=True)\n",
        encoding="utf-8",
    )
    findings = source_scanner.scan(code_file, default_config)
    torch_findings = [f for f in findings if f.id == "DS-SRC-002"]
    assert len(torch_findings) == 0


def test_keras_load_model_safe_mode(source_scanner, temp_dir, default_config):
    code_file = temp_dir / "keras_unsafe.py"
    code_file.write_text(
        "import tensorflow as tf\n"
        "model = tf.keras.models.load_model('model.h5', safe_mode=False)\n",
        encoding="utf-8",
    )
    findings = source_scanner.scan(code_file, default_config)
    keras_findings = [f for f in findings if f.id == "DS-SRC-003"]
    assert len(keras_findings) == 1
    assert keras_findings[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Hardcoded Secrets Tests
# ---------------------------------------------------------------------------

def test_hardcoded_openai_and_anthropic_keys(source_scanner, temp_dir, default_config):
    code_file = temp_dir / "ai_keys.py"
    code_file.write_text(
        "client_key = 'sk-proj-abcdefghijklmnopqrstuvwxyz1234567890'\n"
        "claude_key = 'sk-ant-abcdefghijklmnopqrstuvwxyz1234567890'\n",
        encoding="utf-8",
    )
    findings = source_scanner.scan(code_file, default_config)
    secret_findings = [f for f in findings if f.id == "DS-SRC-004"]
    assert len(secret_findings) >= 2
    assert all(f.severity == Severity.CRITICAL for f in secret_findings)
    # Ensure evidence is redacted
    for f in secret_findings:
        assert "***" in f.evidence
        assert "abcdefghijklmnopqrstuvwxyz" not in f.evidence


def test_hardcoded_sensitive_variable_assignment(source_scanner, temp_dir, default_config):
    code_file = temp_dir / "config_keys.py"
    code_file.write_text(
        "openai_api_key = 'super_secret_production_token_12345'\n",
        encoding="utf-8",
    )
    findings = source_scanner.scan(code_file, default_config)
    secret_findings = [f for f in findings if f.id == "DS-SRC-004"]
    assert len(secret_findings) == 1
    assert "openai_api_key" in secret_findings[0].evidence


def test_safe_env_variable_secret_loading(source_scanner, temp_dir, default_config):
    code_file = temp_dir / "safe_env.py"
    code_file.write_text(
        "import os\n"
        "api_key = os.environ.get('OPENAI_API_KEY')\n"
        "hf_token = os.getenv('HF_TOKEN')\n",
        encoding="utf-8",
    )
    findings = source_scanner.scan(code_file, default_config)
    secret_findings = [f for f in findings if f.id == "DS-SRC-004"]
    assert len(secret_findings) == 0


# ---------------------------------------------------------------------------
# Unsafe Dynamic Code Execution & Shell Commands Tests
# ---------------------------------------------------------------------------

def test_unsafe_eval_llm_output(source_scanner, temp_dir, default_config):
    code_file = temp_dir / "eval_llm.py"
    code_file.write_text(
        "response = client.chat.completions.create(...)\n"
        "result = eval(response.content)\n",
        encoding="utf-8",
    )
    findings = source_scanner.scan(code_file, default_config)
    eval_findings = [f for f in findings if f.id == "DS-SRC-005"]
    assert len(eval_findings) == 1
    assert eval_findings[0].severity == Severity.CRITICAL
    assert "Direct execution of model-generated output" in eval_findings[0].evidence


def test_unsafe_exec_statement(source_scanner, temp_dir, default_config):
    code_file = temp_dir / "exec_user.py"
    code_file.write_text(
        "user_code = request.json['code']\n"
        "exec(user_code)\n",
        encoding="utf-8",
    )
    findings = source_scanner.scan(code_file, default_config)
    exec_findings = [f for f in findings if f.id == "DS-SRC-005"]
    assert len(exec_findings) == 1
    assert exec_findings[0].severity == Severity.HIGH


def test_unsafe_shell_command_injection(source_scanner, temp_dir, default_config):
    code_file = temp_dir / "shell_cmd.py"
    code_file.write_text(
        "import os, subprocess\n"
        "os.system(f'python evaluate.py --model {model_path}')\n"
        "subprocess.run('echo ' + user_input, shell=True)\n",
        encoding="utf-8",
    )
    findings = source_scanner.scan(code_file, default_config)
    shell_findings = [f for f in findings if f.id == "DS-SRC-006"]
    assert len(shell_findings) == 2
    assert all(f.severity == Severity.HIGH for f in shell_findings)


def test_safe_subprocess_argument_list(source_scanner, temp_dir, default_config):
    code_file = temp_dir / "safe_subprocess.py"
    code_file.write_text(
        "import subprocess\n"
        "subprocess.run(['python', 'train.py', '--epochs', '10'], shell=False)\n",
        encoding="utf-8",
    )
    findings = source_scanner.scan(code_file, default_config)
    shell_findings = [f for f in findings if f.id == "DS-SRC-006"]
    assert len(shell_findings) == 0


# ---------------------------------------------------------------------------
# Prompt Injection Sinks & Insecure API Tests
# ---------------------------------------------------------------------------

def test_prompt_injection_sink_in_system_prompt(source_scanner, temp_dir, default_config):
    code_file = temp_dir / "prompt_sink.py"
    code_file.write_text(
        "user_role = get_user_role()\n"
        "system_prompt = f'You are a secure assistant. Context: {user_role}'\n",
        encoding="utf-8",
    )
    findings = source_scanner.scan(code_file, default_config)
    prompt_findings = [f for f in findings if f.id == "DS-SRC-007"]
    assert len(prompt_findings) == 1
    assert prompt_findings[0].severity == Severity.MEDIUM
    assert prompt_findings[0].is_heuristic is True


def test_insecure_ssl_verification_disabled(source_scanner, temp_dir, default_config):
    code_file = temp_dir / "insecure_ssl.py"
    code_file.write_text(
        "import requests, httpx\n"
        "res = requests.post('https://api.openai.com', verify=False)\n"
        "client = httpx.Client(verify=False)\n",
        encoding="utf-8",
    )
    findings = source_scanner.scan(code_file, default_config)
    ssl_findings = [f for f in findings if f.id == "DS-SRC-008"]
    assert len(ssl_findings) == 2
    assert all(f.severity == Severity.HIGH for f in ssl_findings)


# ---------------------------------------------------------------------------
# Robustness, Syntax Errors, Limits & Config Controls
# ---------------------------------------------------------------------------

def test_syntax_error_handling(source_scanner, temp_dir, default_config):
    broken_file = temp_dir / "syntax_error.py"
    broken_file.write_text("def broken_func(:\n    pass\n", encoding="utf-8")

    findings = source_scanner.scan(broken_file, default_config)
    syntax_findings = [f for f in findings if f.id == "DS-SRC-009"]
    assert len(syntax_findings) == 1
    assert syntax_findings[0].line_number == 1
    assert "SyntaxError" in syntax_findings[0].evidence


def test_oversized_source_file_limit(source_scanner, temp_dir):
    large_py = temp_dir / "large.py"
    large_py.write_text("print('hello world')\n", encoding="utf-8")

    cfg = DataSecureConfig()
    cfg.max_file_size_mb = 0  # Force 0 limit
    findings = source_scanner.scan(large_py, cfg)
    assert len(findings) == 1
    assert findings[0].id == "DS-SRC-000"


def test_source_code_scanner_can_scan(source_scanner, temp_dir):
    py_file = temp_dir / "test.py"
    py_file.write_text("x = 1", encoding="utf-8")
    txt_file = temp_dir / "test.txt"
    txt_file.write_text("hello", encoding="utf-8")

    assert source_scanner.can_scan(py_file) is True
    assert source_scanner.can_scan(txt_file) is False


def test_config_disabling_source_scanner(source_scanner, temp_dir):
    code_file = temp_dir / "vuln.py"
    code_file.write_text("eval('1 + 1')", encoding="utf-8")

    cfg = DataSecureConfig()
    cfg.source_code.enabled = False
    findings = source_scanner.scan(code_file, cfg)
    assert len(findings) == 0


def test_config_rule_toggles(source_scanner, temp_dir):
    code_file = temp_dir / "vuln_mixed.py"
    code_file.write_text(
        "import pickle\n"
        "pickle.load(f)\n"
        "openai_api_key = 'sk-abcdefghijklmnopqrstuvwxyz1234567890'\n",
        encoding="utf-8",
    )
    cfg = DataSecureConfig()
    cfg.source_code.check_unsafe_deserialization = False  # Disable pickle check
    cfg.source_code.check_hardcoded_secrets = True

    findings = source_scanner.scan(code_file, cfg)
    rule_ids = [f.id for f in findings]
    assert "DS-SRC-001" not in rule_ids
    assert "DS-SRC-004" in rule_ids


# ---------------------------------------------------------------------------
# CLI Integration for Source Code Scanning
# ---------------------------------------------------------------------------

def test_cli_scan_source_code_file(temp_dir):
    vuln_py = temp_dir / "app_vuln.py"
    vuln_py.write_text(
        "import torch\n"
        "weights = torch.load('model.pt')\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scan", str(vuln_py), "--fail-on", "HIGH"])
    assert result.exit_code == 1
    assert "Unsafe PyTorch Model Loading" in result.stdout
    assert "weights_only omitted" in result.stdout

