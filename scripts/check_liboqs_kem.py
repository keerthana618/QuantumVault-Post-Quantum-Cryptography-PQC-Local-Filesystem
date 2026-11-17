#!/usr/bin/env python3
"""Load liboqs and confirm the library exposes KEM functionality."""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path


def _candidate_paths() -> list[Path]:
    roots = []
    for candidate in (
        os.environ.get("LIBOQS_LIBRARY"),
        os.environ.get("LIBOQS_INSTALL_PATH"),
        os.environ.get("OQS_INSTALL_PATH"),
        os.environ.get("LD_LIBRARY_PATH"),
        os.environ.get("DYLD_LIBRARY_PATH"),
        os.environ.get("PATH"),
    ):
        if not candidate:
            continue
        for part in str(candidate).split(os.pathsep):
            if part:
                roots.append(Path(part))
    home_dir = Path.home()
    roots.extend([
        Path("/usr/local/lib"),
        Path("/usr/lib"),
        Path("/opt/liboqs/lib"),
        Path("/usr/local/lib64"),
        Path("/usr/lib64"),
        home_dir / "_oqs" / "bin",
        home_dir / "_oqs" / "lib",
        home_dir / "_oqs" / "lib64",
        Path(".") / ".vendor" / "liboqs" / "build" / "lib",
        Path(".") / ".vendor" / "liboqs" / "build" / "src",
        Path(".") / ".vendor" / "liboqs" / "build",
    ])
    return [path for path in dict.fromkeys(roots) if path.exists()]


def load_liboqs() -> ctypes.CDLL:
    names = [
        "liboqs.so",
        "liboqs.so.0",
        "liboqs.dylib",
        "liboqs.dll",
    ]
    for base_dir in _candidate_paths():
        for name in names:
            library = base_dir / name
            if library.exists():
                return ctypes.CDLL(str(library))
    raise FileNotFoundError(
        "liboqs was not found. Build it with scripts/build_liboqs.sh or install liboqs on the host."
    )


def main() -> int:
    try:
        lib = load_liboqs()
    except FileNotFoundError as exc:
        print(f"KEM check failed: {exc}", file=sys.stderr)
        return 1

    symbol_name = "OQS_KEM_alg_count"
    if not hasattr(lib, symbol_name):
        print(f"KEM check failed: {symbol_name} is not exported by the library.", file=sys.stderr)
        return 2

    count = lib.OQS_KEM_alg_count()
    print(f"liboqs KEM count: {count}")
    print("KEM check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
