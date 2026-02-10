# sec-file-type-detector

## Overview

**sec-file-type-detector** is an educational Python project that detects file types by analyzing
their binary signatures (magic bytes) instead of relying on file extensions.

The goal of this project is to demonstrate why extension-based file validation is unreliable
and how basic file content inspection can improve security.

---

## Features

- Detects file types using magic byte signatures
- Supports common formats (e.g. PDF, PNG, JPEG, ZIP, ELF, EXE)
- Highlights mismatches between file content and file extension
- Simple and readable detection logic
- Designed for security learning and experimentation

---

## Security Concepts Demonstrated

- File upload security
- Content-based file validation
- Magic bytes and file signatures
- Prevention of file type spoofing
- Secure handling of untrusted files

---

## Use Cases

This tool can be used to:

- Learn how file type detection works internally
- Demonstrate file upload vulnerabilities
- Practice secure input validation
- Understand why file extensions are not trustworthy

---

## Example Usage

```bash
python file_type_detector.py suspicious_file.exe
