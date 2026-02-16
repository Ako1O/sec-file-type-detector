from pathlib import Path

import pytest

from sec_file_type_detector.detector import detect_file_type


def write_tmp(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_pdf_detect(tmp_path: Path):
    p = write_tmp(tmp_path, "x.pdf", b"%PDF-1.7\nrest")
    r = detect_file_type(p)
    assert r.detected_name is not None
    assert "PDF" in r.detected_name
    assert r.mismatch is False


def test_mismatch_pdf_named_exe(tmp_path: Path):
    p = write_tmp(tmp_path, "evil.exe", b"%PDF-1.7\nrest")
    r = detect_file_type(p)
    assert r.mismatch is True


def test_png_detect(tmp_path: Path):
    p = write_tmp(tmp_path, "a.png", b"\x89PNG\r\n\x1a\nxxxx")
    r = detect_file_type(p)
    assert "PNG" in (r.detected_name or "")
    assert r.mismatch is False


def test_unknown(tmp_path: Path):
    p = write_tmp(tmp_path, "x.bin", b"\x00\x01\x02\x03")
    r = detect_file_type(p)
    assert r.unknown is True
