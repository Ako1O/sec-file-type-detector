# sec-file-type-detector

A security-oriented Python CLI tool that detects file types using **magic bytes (binary signatures)** instead of relying on file extensions.

This project demonstrates why extension-based validation is unreliable and how content-based inspection improves file upload security.

---

## Overview

Many applications validate uploaded files by checking only the file extension:

- `document.pdf`
- `image.jpg`
- `report.docx`

This approach is insecure.

An attacker can rename a malicious executable to `invoice.pdf` and bypass naive validation.

This tool inspects the actual file content and compares it with the file extension to detect inconsistencies.

---

## Features

- Detects file types using magic byte signatures
- Flags mismatches between extension and real file content
- Recursive directory scanning
- JSON report generation
- Exit codes suitable for automation and CI
- Modular architecture (separated detection logic and CLI)
- Tested with `pytest`
- Linted and formatted with `ruff`
- CI pipeline via GitHub Actions

---

## Supported File Types

Currently detects:

- PDF
- PNG
- JPEG
- ZIP
- ELF (Linux/Unix binaries)
- PE (Windows EXE/DLL)

Additional formats can be added easily by extending the signature list.

---

## Installation (Development Mode)

**Clone the repository:**
```bash
git clone https://github.com/<your-username>/sec-file-type-detector.git
cd sec-file-type-detector
```

**Create and activate a virtual environment:**
```bash
python -m venv .venv
source .venv/Scripts/activate   # Windows (Git Bash)
```

**Install in editable mode:**
```bash
pip install -e .
```

**Install development tools:**
```bash
pip install pytest ruff
```
---

## Usage
**Scan a single file**
```bash
sec-file-type-detector file.pdf
```

**Example output:**
```bash
[OK] file.pdf  ext=pdf  detected=PDF document
```

**Detect a spoofed file**

If a file is renamed to disguise its true type:
```bash
sec-file-type-detector suspicious.exe
```

**Output example:**
```bash
[MISMATCH] suspicious.exe  ext=exe  detected=PDF document
```

**Scan a directory recursively**
```bash
sec-file-type-detector -r ~/Downloads
```

**Show only suspicious files**
```bash
sec-file-type-detector -r ~/Downloads --only-problems
```

**Generate a JSON report**
```bash
sec-file-type-detector -r ~/Downloads --json report.json
```

**The JSON report includes:**
- total scanned files
- number of mismatches
- number of unknown types
- breakdown by detected file type
- structured per-file results

### Exit Codes

Designed for automation and integration into security workflows:

| Exit Code | Meaning |
|-----------|---------|
| 0 | No mismatches or unknown files |
| 1 | At least one mismatch or unknown file detected |
| 2 | Runtime error (file not found, permission issue, etc.) |



**Running Tests**
```bash
pytest -q
```

**Linting & Formatting**
```bash
ruff check . --fix
ruff format .
```

---

# Project Structure
sec-file-type-detector/
│
├─ src/sec_file_type_detector/
│  ├─ __init__.py
│  ├─ detector.py
│  └─ cli.py
│
├─ tests/
├─ .github/workflows/
├─ pypr
