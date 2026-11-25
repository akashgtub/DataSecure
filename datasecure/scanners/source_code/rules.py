"""AST-based security rules and visitor for Python AI/ML source code."""

import ast
from pathlib import Path
import re
from typing import List, Optional, Set

from datasecure.configuration.config import DataSecureConfig
from datasecure.core.models import Finding, Severity
from datasecure.scanners.dataset.rules import redact_sensitive_value

# Regex patterns for AI provider API keys & credentials in source code
AI_KEY_PATTERNS = [
    (re.compile(r"\b(sk-[a-zA-Z0-9_-]{20,})\b"), "OpenAI API Key"),
    (re.compile(r"\b(sk-ant-[a-zA-Z0-9_-]{20,})\b"), "Anthropic API Key"),
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "AWS Access Key"),
    (re.compile(r"\b(hf_[a-zA-Z0-9]{34,})\b"), "Hugging Face Access Token"),
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,})\b"), "GitHub Token"),
]

# Variable names commonly used for hardcoded secrets
SENSITIVE_VAR_NAMES: Set[str] = {
    "api_key",
    "apikey",
    "openai_api_key",
    "anthropic_api_key",
    "cohere_api_key",
    "pinecone_api_key",
    "secret_key",
    "aws_secret_access_key",
    "auth_token",
    "access_token",
    "hf_token",
    "huggingface_token",
    "model_key",
}

# Suspicious variables suggesting AI model outputs
MODEL_OUTPUT_NAMES: Set[str] = {
    "response",
    "completion",
    "output",
    "generated",
    "model_output",
    "llm_output",
    "result",
    "content",
    "answer",
}


def _get_call_func_name(node: ast.Call) -> str:
    """Resolve full function call name, e.g. 'torch.load' or 'pickle.loads'."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        value_name = ""
        if isinstance(node.func.value, ast.Name):
            value_name = node.func.value.id
        elif isinstance(node.func.value, ast.Attribute):
            value_name = f"{getattr(node.func.value.value, 'id', '')}.{node.func.value.attr}"
        return f"{value_name}.{node.func.attr}" if value_name else node.func.attr
    return ""


def _get_kwarg(node: ast.Call, arg_name: str) -> Optional[ast.keyword]:
    """Retrieve keyword argument from Call node if present."""
    for kw in node.keywords:
        if kw.arg == arg_name:
            return kw
    return None


def _is_truthy_constant(node: ast.AST) -> bool:
    """Check if AST node represents a boolean True constant."""
    return isinstance(node, ast.Constant) and node.value is True


def _is_falsy_constant(node: ast.AST) -> bool:
    """Check if AST node represents a boolean False constant."""
    return isinstance(node, ast.Constant) and node.value is False


class SourceCodeSecurityVisitor(ast.NodeVisitor):
    """AST visitor implementing static security checks for AI source code."""

    def __init__(self, file_path: Path, source_lines: List[str], config: DataSecureConfig):
        self.file_path = str(file_path)
        self.source_lines = source_lines
        self.config = config
        self.findings: List[Finding] = []

    def _get_line_snippet(self, lineno: int) -> str:
        """Safely fetch source code snippet for line number."""
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect function calls for dangerous deserialization, exec, and insecure configs."""
        func_name = _get_call_func_name(node)

        # -------------------------------------------------------------------
        # 1. Insecure Model Loading & Deserialization
        # -------------------------------------------------------------------
        if self.config.source_code.check_unsafe_deserialization:
            # Dangerous pickle / joblib / dill calls
            if func_name in {
                "pickle.load",
                "pickle.loads",
                "_pickle.load",
                "_pickle.loads",
                "joblib.load",
                "dill.load",
                "dill.loads",
                "shelve.open",
            }:
                self.findings.append(
                    Finding(
                        id="DS-SRC-001",
                        name=f"Unsafe Object Deserialization: {func_name}",
                        severity=Severity.CRITICAL,
                        category="source_code",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        evidence=f"Call to {func_name}()",
                        explanation=(
                            f"Using {func_name}() on untrusted files allows arbitrary code execution via Python "
                            "deserialization gadgets (__reduce__ / global imports)."
                        ),
                        remediation=(
                            "Replace pickle serialization with safe formats such as SafeTensors, or load "
                            "weights strictly using safe tensor loaders."
                        ),
                        is_heuristic=False,
                    )
                )

            # PyTorch torch.load check
            elif func_name == "torch.load":
                weights_only_kw = _get_kwarg(node, "weights_only")
                # Flag if weights_only is not specified, or explicitly set to False
                if weights_only_kw is None or _is_falsy_constant(weights_only_kw.value):
                    kw_status = "weights_only=False" if weights_only_kw else "weights_only omitted (defaults to False)"
                    self.findings.append(
                        Finding(
                            id="DS-SRC-002",
                            name="Unsafe PyTorch Model Loading (torch.load)",
                            severity=Severity.HIGH,
                            category="source_code",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            evidence=f"torch.load() with {kw_status}",
                            explanation=(
                                "torch.load() deserializes arbitrary pickled Python objects unless weights_only=True "
                                "is explicitly set. Untrusted .pt or .pth files can execute arbitrary commands."
                            ),
                            remediation=(
                                "Specify weights_only=True in torch.load(..., weights_only=True) or use "
                                "safetensors.torch.load_file()."
                            ),
                            is_heuristic=False,
                        )
                    )

            # TensorFlow / Keras load_model with safe_mode=False
            elif func_name in {"keras.models.load_model", "tf.keras.models.load_model", "load_model"}:
                safe_mode_kw = _get_kwarg(node, "safe_mode")
                if safe_mode_kw and _is_falsy_constant(safe_mode_kw.value):
                    self.findings.append(
                        Finding(
                            id="DS-SRC-003",
                            name="Insecure Keras Model Loading (safe_mode=False)",
                            severity=Severity.HIGH,
                            category="source_code",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            evidence="load_model(..., safe_mode=False)",
                            explanation=(
                                "Loading Keras models with safe_mode=False enables loading arbitrary Python bytecode "
                                "and Lambda layers from untrusted H5 or SavedModel files."
                            ),
                            remediation="Set safe_mode=True or use SafeTensors format.",
                            is_heuristic=False,
                        )
                    )

        # -------------------------------------------------------------------
        # 2. Unsafe Dynamic Code Execution (eval, exec, shell)
        # -------------------------------------------------------------------
        if func_name in {"eval", "exec"}:
            is_model_output = False
            # Check if an argument refers to a variable commonly holding LLM output
            if node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Name) and arg.id.lower() in MODEL_OUTPUT_NAMES:
                    is_model_output = True
                elif isinstance(arg, ast.Attribute) and arg.attr.lower() in MODEL_OUTPUT_NAMES:
                    is_model_output = True

            sev = Severity.CRITICAL if is_model_output else Severity.HIGH
            desc = (
                f"Direct execution of model-generated output via {func_name}()"
                if is_model_output
                else f"Dynamic code execution via {func_name}()"
            )
            self.findings.append(
                Finding(
                    id="DS-SRC-005",
                    name=f"Dangerous Dynamic Code Execution ({func_name})",
                    severity=sev,
                    category="source_code",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    evidence=f"{desc} at line {node.lineno}",
                    explanation=(
                        f"Calling {func_name}() dynamically executes arbitrary Python code. In AI applications, "
                        "executing untrusted user input or un-sandboxed LLM completions leads to immediate Remote Code Execution."
                    ),
                    remediation=(
                        "Never execute dynamically generated LLM code directly in production. Use a strict, "
                        "containerized sandbox or structured output parsing."
                    ),
                    is_heuristic=False,
                )
            )

        # Shell command execution via os.system / os.popen / subprocess with shell=True
        elif func_name in {"os.system", "os.popen"}:
            if node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
                self.findings.append(
                    Finding(
                        id="DS-SRC-006",
                        name=f"Insecure Shell Execution: {func_name}",
                        severity=Severity.HIGH,
                        category="source_code",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        evidence=f"Call to {func_name} with string interpolation",
                        explanation=(
                            f"{func_name}() with dynamic string interpolation exposes the host system to command injection."
                        ),
                        remediation="Use subprocess.run(['cmd', arg], shell=False) with parameterized arguments.",
                        is_heuristic=False,
                    )
                )

        elif func_name in {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output"}:
            shell_kw = _get_kwarg(node, "shell")
            if shell_kw and _is_truthy_constant(shell_kw.value):
                # Check if command argument is a string interpolation or formatted string
                if node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
                    self.findings.append(
                        Finding(
                            id="DS-SRC-006",
                            name="Insecure Subprocess Execution with shell=True",
                            severity=Severity.HIGH,
                            category="source_code",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            evidence="subprocess with shell=True and dynamic string interpolation",
                            explanation=(
                                "Executing subprocess with shell=True and dynamic string formatting allows command injection."
                            ),
                            remediation="Pass command arguments as a list with shell=False.",
                            is_heuristic=False,
                        )
                    )

        # -------------------------------------------------------------------
        # 3. Insecure AI API Configuration (SSL verification disabled)
        # -------------------------------------------------------------------
        if self.config.source_code.check_insecure_apis:
            verify_kw = _get_kwarg(node, "verify")
            ssl_kw = _get_kwarg(node, "ssl")
            if (verify_kw and _is_falsy_constant(verify_kw.value)) or (ssl_kw and _is_falsy_constant(ssl_kw.value)):
                self.findings.append(
                    Finding(
                        id="DS-SRC-008",
                        name="Insecure TLS/SSL Configuration (verify=False)",
                        severity=Severity.HIGH,
                        category="source_code",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        evidence=f"Call to {func_name}() with SSL verification disabled",
                        explanation=(
                            "Disabling SSL/TLS certificate validation (verify=False / ssl=False) enables Man-in-the-Middle "
                            "(MitM) attacks, allowing eavesdropping and tampering with AI API payloads and API keys."
                        ),
                        remediation="Ensure verify=True (the secure default) is used for all outgoing AI API connections.",
                        is_heuristic=False,
                    )
                )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Inspect variable assignments for hardcoded secrets and prompt injection sinks."""
        # 1. Hardcoded secrets check
        if self.config.source_code.check_hardcoded_secrets:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id.lower()
                    if var_name in SENSITIVE_VAR_NAMES and isinstance(node.value, ast.Constant):
                        val_str = str(node.value.value)
                        # Filter out placeholders or env var names like "YOUR_KEY"
                        if len(val_str) >= 8 and not val_str.startswith("$"):
                            evidence = redact_sensitive_value(val_str) if self.config.redact_secrets else val_str
                            self.findings.append(
                                Finding(
                                    id="DS-SRC-004",
                                    name="Hardcoded Secret in Variable Assignment",
                                    severity=Severity.CRITICAL,
                                    category="source_code",
                                    file_path=self.file_path,
                                    line_number=node.lineno,
                                    evidence=f"{target.id} = '{evidence}'",
                                    explanation=(
                                        f"Hardcoded credential assigned to sensitive variable '{target.id}'. "
                                        "Hardcoded secrets can be extracted from source repositories and build artifacts."
                                    ),
                                    remediation=(
                                        "Retrieve credentials from environment variables using os.environ or a secrets manager."
                                    ),
                                    is_heuristic=False,
                                )
                            )

        # 2. Prompt injection sink check (f-string in system prompts)
        if self.config.source_code.check_prompt_injection_sinks:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id.lower()
                    if any(term in var_name for term in ["system_prompt", "sys_prompt", "prompt_template"]):
                        if isinstance(node.value, ast.JoinedStr):
                            self.findings.append(
                                Finding(
                                    id="DS-SRC-007",
                                    name="Potential Prompt Injection Sink in System Prompt",
                                    severity=Severity.MEDIUM,
                                    category="source_code",
                                    file_path=self.file_path,
                                    line_number=node.lineno,
                                    evidence=f"Dynamic string formatting in '{target.id}'",
                                    explanation=(
                                        f"System prompt '{target.id}' interpolates dynamic variables directly. "
                                        "If untrusted user input is placed into the system prompt instruction without "
                                        "delimiters or guardrails, attackers can override instructions."
                                    ),
                                    remediation=(
                                        "Separate system instructions from user inputs using message roles "
                                        "({'role': 'system'}, {'role': 'user'}) or apply strict input validation."
                                    ),
                                    is_heuristic=True,
                                )
                            )

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        """Inspect string constants anywhere in the AST for matching AI API key patterns."""
        if self.config.source_code.check_hardcoded_secrets and isinstance(node.value, str):
            val_str = node.value
            for pattern, provider in AI_KEY_PATTERNS:
                match = pattern.search(val_str)
                if match:
                    raw_key = match.group(0)
                    evidence = redact_sensitive_value(raw_key) if self.config.redact_secrets else raw_key
                    self.findings.append(
                        Finding(
                            id="DS-SRC-004",
                            name=f"Hardcoded {provider} Detected",
                            severity=Severity.CRITICAL,
                            category="source_code",
                            file_path=self.file_path,
                            line_number=getattr(node, "lineno", None),
                            evidence=f"Exposed {provider}: {evidence}",
                            explanation=(
                                f"Found plaintext {provider} embedded in source code. Unauthorized parties "
                                "can abuse this key to access AI services, query fine-tuned models, or incur costs."
                            ),
                            remediation="Rotate this API key immediately and store it in an environment variable.",
                            is_heuristic=False,
                        )
                    )
                    break
        self.generic_visit(node)
