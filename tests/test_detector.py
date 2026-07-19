from pathlib import Path

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


def test_gif_detect(tmp_path: Path):
    p = write_tmp(tmp_path, "a.gif", b"GIF89a" + b"x" * 10)
    r = detect_file_type(p)
    assert "GIF" in (r.detected_name or "")
    assert r.mismatch is False


def test_bmp_detect(tmp_path: Path):
    p = write_tmp(tmp_path, "a.bmp", b"BM" + b"x" * 10)
    r = detect_file_type(p)
    assert "BMP" in (r.detected_name or "")
    assert r.mismatch is False


def test_gzip_detect(tmp_path: Path):
    p = write_tmp(tmp_path, "a.gz", b"\x1f\x8b\x08\x00")
    r = detect_file_type(p)
    assert "GZIP" in (r.detected_name or "")
    assert r.mismatch is False


def test_docx_is_not_flagged_as_mismatch(tmp_path: Path):
    # .docx/.xlsx/.pptx are ZIP containers under the hood — this should
    # not be reported as a mismatch even though the extension isn't "zip".
    p = write_tmp(tmp_path, "report.docx", b"PK\x03\x04" + b"x" * 10)
    r = detect_file_type(p)
    assert "ZIP" in (r.detected_name or "")
    assert r.mismatch is False


def test_exe_named_docx_is_mismatch(tmp_path: Path):
    # Minimal DOS/PE header: "MZ" stub, e_lfanew at 0x3C pointing to
    # offset 0x40, "PE\0\0" signature at that offset.
    e_lfanew = (0x40).to_bytes(4, "little")
    data = b"MZ" + b"\x00" * 58 + e_lfanew + b"PE\x00\x00"
    p = write_tmp(tmp_path, "invoice.docx", data)
    r = detect_file_type(p)
    assert "PE" in (r.detected_name or "")
    assert r.mismatch is True
