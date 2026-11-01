#!/usr/bin/env python3
"""Harmless PoC: aiven-client 4.18.0 user-creds-download writes service.key mode 0644 under umask 022.

Mirrors the open()+write pattern from aiven/client/cli.py (no API calls, synthetic PEM).
Negative control: same write with os.chmod(0o600) as in unreleased fix 34e9822.
"""
from __future__ import annotations

import os
import shutil
import stat
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def write_vuln(path: Path, data: str) -> None:
    with open(path, "w", encoding="utf-8") as fp:
        fp.write(data)


def write_fixed(path: Path, data: str) -> None:
    with open(path, "w", encoding="utf-8") as fp:
        os.chmod(fp.name, 0o600)
        fp.write(data)


def main() -> None:
    pem = "-----BEGIN PRIVATE KEY-----\nSYNTHETIC-NOT-A-REAL-KEY\n-----END PRIVATE KEY-----\n"
    cert = "-----BEGIN CERTIFICATE-----\nSYNTHETIC\n-----END CERTIFICATE-----\n"
    old = os.umask(0o022)
    d = Path(tempfile.mkdtemp(prefix="avn-creds-"))
    try:
        key_v = d / "service.key"
        cert_v = d / "service.cert"
        key_f = d / "service.key.fixed"
        write_vuln(key_v, pem)
        write_vuln(cert_v, cert)
        write_fixed(key_f, pem)
        for p in (key_v, cert_v, key_f):
            mode = stat.S_IMODE(p.stat().st_mode)
            print(f"{p.name}: mode={oct(mode)} world-readable={bool(mode & stat.S_IROTH)}")
        assert stat.S_IMODE(key_v.stat().st_mode) == 0o644
        assert stat.S_IMODE(key_f.stat().st_mode) == 0o600
        print("PASS")
        (ROOT / "poc_results.txt").write_text(
            "PASS: vuln=0644 fixed=0600\n", encoding="utf-8"
        )
    finally:
        os.umask(old)
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    main()
