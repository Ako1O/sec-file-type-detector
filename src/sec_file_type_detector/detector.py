from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Signature:
    name: str
    extensions: tuple[str, ...]
    match: Callable[[bytes], bool]


@dataclass(frozen=True)
class DetectionResult:
    path: Path
    extension: str  # without dot, lowercase, "" if none
    detected_name: str | None
    detected_extensions: tuple[str, ...]
    mismatch: bool
    unknown: bool


def _is_pdf(b: bytes) -> bool:
    return b.startswith(b"%PDF-")


def _is_png(b: bytes) -> bool:
    return b.startswith(b"\x89PNG\r\n\x1a\n")


def _is_jpeg(b: bytes) -> bool:
    return b.startswith(b"\xFF\xD8\xFF")


def _is_zip(b: bytes) -> bool:
    return b.startswith(b"PK\x03\x04") or b.startswith(b"PK\x05\x06") or b.startswith(b"PK\x07\x08")


def _is_elf(b: bytes) -> bool:
    return b.startswith(b"\x7FELF")


def _is_pe(b: bytes) -> bool:
    # Windows PE (EXE/DLL): MZ + PE\0\0 at e_lfanew
    if not b.startswith(b"MZ") or len(b) < 0x40:
        return False
    e_lfanew = int.from_bytes(b[0x3C:0x40], "little", signed=False)
    return len(b) >= e_lfanew + 4 and b[e_lfanew:e_lfanew + 4] == b"PE\0\0"


SIGNATURES: tuple[Signature, ...] = (
    Signature("PDF document", ("pdf",), _is_pdf),
    Signature("PNG image", ("png",), _is_png),
    Signature("JPEG image", ("jpg", "jpeg"), _is_jpeg),
    Signature("ZIP archive", ("zip",), _is_zip),
    Signature("ELF binary (Linux/Unix)", ("elf",), _is_elf),
    Signature("PE binary (Windows EXE/DLL)", ("exe", "dll"), _is_pe),
)


def _get_extension(path: Path) -> str:
    ext = path.suffix.lower()
    return ext[1:] if ext.startswith(".") else ""


def _read_header(path: Path, max_bytes: int) -> bytes:
    with path.open("rb") as f:
        return f.read(max_bytes)


def detect_file_type(path: str | Path, *, header_bytes: int = 4096) -> DetectionResult:
    p = Path(path)
    ext = _get_extension(p)

    header = _read_header(p, header_bytes)

    detected: Signature | None = None
    for sig in SIGNATURES:
        try:
            if sig.match(header):
                detected = sig
                break
        except Exception:
            continue

    if detected is None:
        return DetectionResult(
            path=p,
            extension=ext,
            detected_name=None,
            detected_extensions=(),
            mismatch=False,
            unknown=True,
        )

    mismatch = bool(ext) and (ext not in detected.extensions)

    return DetectionResult(
        path=p,
        extension=ext,
        detected_name=detected.name,
        detected_extensions=detected.extensions,
        mismatch=mismatch,
        unknown=False,
    )
