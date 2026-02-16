# sec-file-type-detector

A security-focused Python CLI tool that detects file types using **magic bytes (binary signatures)** instead of relying on file extensions.

This project demonstrates why extension-based validation is unreliable and how content-based inspection improves file upload security.

---

## 🔍 Why This Project Exists

Many systems validate uploaded files using only the file extension:

example.pdf  
example.exe  

This is insecure.

Attackers can rename malicious executables to `.pdf`, `.jpg`, or `.docx` and bypass naive validation.

This tool demonstrates:

- Content-based file validation
- Magic byte inspection
- Extension spoofing detection
- Security-focused scanning logic

---

## ✨ Features

- Detects file types using magic bytes
- Flags mismatches between extension and actual file content
- Recursive directory scanning
- JSON report generation
- Exit codes suitable for automation
- Clean modular architecture (detector + CLI separation)
- Tested with pytest
- Linted and formatted with Ruff
- CI pipeline via GitHub Actions

---

## 📦 Supported File Types

Currently detects:

- PDF
- PNG
- JPEG
- ZIP
- ELF (Linux binaries)
- PE (Windows EXE/DLL)

---

## 🚀 Installation (Development Mode)

Clone the repository:

```bash
git clone https://github.com/<your-username>/sec-file-type-detector.git
cd sec-file-type-detector
