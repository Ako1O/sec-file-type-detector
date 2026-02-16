import subprocess
import sys
from pathlib import Path


def test_cli_recursive_scan(tmp_path: Path):
    # Create files
    (tmp_path / "a.pdf").write_bytes(b"%PDF-1.7\nx")
    (tmp_path / "b.exe").write_bytes(b"%PDF-1.7\nx")  # mismatch
    (tmp_path / "c.bin").write_bytes(b"\x00\x01\x02")

    # Call CLI as module to be robust across OS environments
    cmd = [sys.executable, "-m", "sec_file_type_detector.cli", str(tmp_path), "--recursive", "--only-problems"]
    proc = subprocess.run(cmd, capture_output=True, text=True)

    # Should return 1 because mismatch/unknown exist
    assert proc.returncode == 1
    out = proc.stdout
    assert "MISMATCH" in out
    assert "UNKNOWN" in out
