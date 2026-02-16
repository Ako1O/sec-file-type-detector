from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from .detector import detect_file_type


def iter_files(root: Path, recursive: bool, max_depth: int | None) -> list[Path]:
    if root.is_file():
        return [root]

    if not root.is_dir():
        return []

    files: list[Path] = []
    root_depth = len(root.resolve().parts)

    for p in root.rglob("*") if recursive else root.glob("*"):
        if not p.is_file():
            continue

        if recursive and max_depth is not None:
            depth = len(p.resolve().parts) - root_depth
            if depth > max_depth:
                continue

        files.append(p)

    return files


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="sec-file-type-detector",
        description="Detect file types using magic bytes and flag extension mismatches.",
    )
    parser.add_argument("path", help="Path to a file or directory to inspect")
    parser.add_argument("-n", "--bytes", type=int, default=4096, help="Header bytes to read (default: 4096)")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively scan directories")
    parser.add_argument("--max-depth", type=int, default=None, help="Limit recursion depth (only with --recursive)")
    parser.add_argument("--only-problems", action="store_true", help="Print only mismatches/unknown files")
    parser.add_argument("--json", dest="json_path", default=None, help="Write a JSON report to a file path")

    args = parser.parse_args()

    target = Path(args.path)

    if not target.exists():
        print(f"[!] Not found: {target}")
        return 2

    files = iter_files(target, recursive=args.recursive, max_depth=args.max_depth)

    if not files:
        print(f"[!] No files found to scan in: {target}")
        return 2

    results = []
    stats_detected = Counter()
    mismatches = 0
    unknowns = 0
    scanned = 0
    read_errors = 0

    for f in files:
        try:
            r = detect_file_type(f, header_bytes=args.bytes)
        except (PermissionError, OSError):
            read_errors += 1
            continue

        scanned += 1
        results.append(r)

        if r.unknown:
            unknowns += 1
            stats_detected["Unknown"] += 1
        else:
            stats_detected[r.detected_name or "Unknown"] += 1

        if r.mismatch:
            mismatches += 1

        # Print per-file lines
        if not args.only_problems or r.mismatch or r.unknown:
            status = "MISMATCH" if r.mismatch else ("UNKNOWN" if r.unknown else "OK")
            detected = r.detected_name or "Unknown"
            ext = r.extension or "(none)"
            print(f"[{status}] {f}  ext={ext}  detected={detected}")

    # JSON report
    if args.json_path:
        out_path = Path(args.json_path)
        payload = {
            "scanned": scanned,
            "read_errors": read_errors,
            "mismatches": mismatches,
            "unknowns": unknowns,
            "by_detected_type": dict(stats_detected),
            "results": [x.to_json() for x in results],
        }
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\n[i] Wrote JSON report to: {out_path}")

    # Summary
    print("\n===== Summary =====")
    print(f"Target: {target}")
    print(f"Scanned files: {scanned}")
    if read_errors:
        print(f"Read errors: {read_errors}")
    print(f"Mismatches: {mismatches}")
    print(f"Unknowns: {unknowns}")

    if stats_detected:
        print("\nBy detected type:")
        for k, v in stats_detected.most_common():
            print(f"  - {k}: {v}")

    # Exit codes aligned with security scanning mindset
    if mismatches > 0 or unknowns > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
