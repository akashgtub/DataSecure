# DataSecure

**AI Security Scanning Tool** for machine learning and artificial intelligence projects.

DataSecure is an extensible, standalone security scanner that developers can integrate into their existing AI/ML pipelines and repositories, working similarly to scanners such as SonarQube or tfsec.

## Features
- **Project Scanner:** Scan AI projects for code, dataset, and model vulnerabilities.
- **Dataset Security Scanner:** Detect sensitive data (API keys, PII), corruption, duplicates, and data poisoning indicators in CSV, JSON, JSONL, and TXT files.
- **Model Security Scanner:** Safe static inspection of model files (Pickle, PyTorch, SafeTensors, ONNX) without code execution.
- **AI Source Code Scanner:** Static analysis for unsafe deserialization, prompt injection sinks, and exposed AI credentials.
- **LLM Safety Scanner:** Non-destructive test harness for prompt injection and leakage detection.
- **Reporting:** Console, JSON, and HTML reports with actionable remediation advice.
- **CI/CD Integration:** Ready for GitHub Actions and pipeline gating with configurable exit codes.

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

