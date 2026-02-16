from __future__ import annotations

import argparse
from pathlib import Path

from .detector import detect_file_type


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="sec-file-type-detector",
        description="Detect file types using magic bytes and flag extension mismatches.",
    )
    parser.add_argument("path", help="Path to a file to inspect")
    parser.add_argument("-n", "--bytes", type=int, default=4096, help="Header bytes to read (default: 4096)")
    args = parser.parse_args()

    p = Path(args.path)
    if not p.exists():
        print(f"[!] Not found: {p}")
        return 2
    if not p.is_file():
        print(f"[!] Not a file: {p}")
        return 2

    try:
        result = detect_file_type(p, header_bytes=args.bytes)
    except PermissionError:
        print(f"[!] Permission denied: {p}")
        return 2
    except OSError as e:
        print(f"[!] Read error: {e}")
        return 2

    print(f"File: {result.path}")
    print(f"Extension: {result.extension or '(none)'}")

    if result.unknown:
        print("Detected (magic bytes): Unknown / unsupported")
        print("[!] Unknown does NOT mean safe. Consider deny-by-default in upload systems.")
        return 1

    print(f"Detected (magic bytes): {result.detected_name}")
    print(f"Common extensions: {', '.join(result.detected_extensions)}")

    if result.mismatch:
        print("\n[!!] MISMATCH DETECTED")
        print("     Extension does NOT match file content signature.")
        return 1

    print("\n[OK] Extension matches detected signature.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
