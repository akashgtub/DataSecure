# DataSecure

**AI Security Scanning Tool** for machine learning and artificial intelligence projects.

DataSecure is an extensible, standalone security scanner that developers can integrate into their existing AI/ML pipelines and repositories, working similarly to scanners such as SonarQube or tfsec.

## Features
- **Project Scanner:** Scan AI projects for code, dataset, and model vulnerabilities.
- **Dataset Security Scanner:** Detect sensitive data (API keys, PII), corruption, duplicates, and data poisoning indicators in CSV, JSON, JSONL, and TXT files.
- **AI Source Code Scanner:** AST-based static analysis for Python AI code:
  - Unsafe deserialization (`pickle.load`, `joblib.load`, `dill.load`, `torch.load` without `weights_only=True`).
  - Hardcoded AI provider credentials (OpenAI, Anthropic, Hugging Face, AWS) in code and comments.
  - Dynamic code execution (`eval()`, `exec()`) particularly on model-generated outputs.
  - Insecure shell command execution (`subprocess.run(shell=True)`, `os.system`).
  - Potential prompt injection sinks in system prompt construction.
  - Insecure TLS/SSL configurations (`verify=False`).
- **Model Security Scanner:** Safe static inspection of model files (Pickle, PyTorch, SafeTensors, Keras, ONNX) without code execution:
  - Dangerous executable globals and callables (`os.system`, `subprocess.Popen`, `posix`, `builtins`).
  - Native executables masquerading as AI models (PE `MZ` / ELF signatures).
  - Keras Lambda layer serialized Python bytecode analysis.
  - SafeTensors header, tensor metadata, and data offset bounds validation.
  - ONNX external tensor path traversal detection (`../`).
  - Malformed or corrupt model stream reporting.
  - Format advisory for legacy pickle-based weights.
- **LLM Safety Scanner:** Non-destructive test harness for prompt injection and leakage detection.
- **Reporting:** Console, JSON, and HTML reports with actionable remediation advice.
- **CI/CD Integration:** Ready for GitHub Actions and pipeline gating with configurable exit codes.

> **Safety Notice:** DataSecure AI performs static model inspection and does not execute or load untrusted models. The absence of detected security indicators does not guarantee that a model is safe.

## Installation

```bash
python -m pip install -e .
```

## Quick Start

```bash
# Scan current project
datasecure scan .

# Scan specific dataset
datasecure scan --dataset training_data.csv

# Scan specific model file
datasecure scan --model ./weights/model.pt

# Active LLM safety test
datasecure scan --llm

# Check version
datasecure version
```

