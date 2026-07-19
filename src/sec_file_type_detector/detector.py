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
    extension: str
    detected_name: str | None
    detected_extensions: tuple[str, ...]
    mismatch: bool
    unknown: bool

    def to_json(self) -> dict:
        return {
            "path": str(self.path),
            "extension": self.extension,
            "detected_name": self.detected_name,
            "detected_extensions": list(self.detected_extensions),
            "mismatch": self.mismatch,
            "unknown": self.unknown,
        }


def _is_pdf(b: bytes) -> bool:
    return b.startswith(b"%PDF-")


def _is_png(b: bytes) -> bool:
    return b.startswith(b"\x89PNG\r\n\x1a\n")


def _is_jpeg(b: bytes) -> bool:
    return b.startswith(b"\xff\xd8\xff")


def _is_zip(b: bytes) -> bool:
    return b.startswith(b"PK\x03\x04") or b.startswith(b"PK\x05\x06") or b.startswith(b"PK\x07\x08")


def _is_elf(b: bytes) -> bool:
    return b.startswith(b"\x7fELF")


def _is_pe(b: bytes) -> bool:
    # Windows PE (EXE/DLL): MZ + PE\0\0 at e_lfanew
    if not b.startswith(b"MZ") or len(b) < 0x40:
        return False
    e_lfanew = int.from_bytes(b[0x3C:0x40], "little", signed=False)
    return len(b) >= e_lfanew + 4 and b[e_lfanew : e_lfanew + 4] == b"PE\0\0"


def _is_gif(b: bytes) -> bool:
    return b.startswith(b"GIF87a") or b.startswith(b"GIF89a")


def _is_bmp(b: bytes) -> bool:
    return b.startswith(b"BM")


def _is_gzip(b: bytes) -> bool:
    return b.startswith(b"\x1f\x8b")


def _is_7z(b: bytes) -> bool:
    return b.startswith(b"7z\xbc\xaf\x27\x1c")


def _is_rar(b: bytes) -> bool:
    return b.startswith(b"Rar!\x1a\x07\x00") or b.startswith(b"Rar!\x1a\x07\x01\x00")


SIGNATURES: tuple[Signature, ...] = (
    Signature("PDF document", ("pdf",), _is_pdf),
    Signature("PNG image", ("png",), _is_png),
    Signature("JPEG image", ("jpg", "jpeg"), _is_jpeg),
    Signature("GIF image", ("gif",), _is_gif),
    Signature("BMP image", ("bmp",), _is_bmp),
    # ZIP-based container: also covers modern Office files and a few other
    # common formats that are, under the hood, just a ZIP archive.
    Signature("ZIP archive", ("zip", "docx", "xlsx", "pptx", "jar", "apk"), _is_zip),
    Signature("GZIP archive", ("gz", "tgz"), _is_gzip),
    Signature("7-Zip archive", ("7z",), _is_7z),
    Signature("RAR archive", ("rar",), _is_rar),
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
