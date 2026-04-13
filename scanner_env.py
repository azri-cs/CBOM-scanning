#!/usr/bin/env python3
"""
Runtime environment snapshot for CBOM scanners: OS facts, tool availability, and
compact fingerprints for CSV outputs. Run directly: python3 scanner_env.py
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import sys


def has_proc_fs() -> bool:
    return os.path.isdir("/proc") and os.path.isfile("/proc/self/exe")


def collect_scanner_environment() -> dict:
    tools = (
        "strings",
        "nm",
        "ldd",
        "dumpbin",
        "otool",
        "sslscan",
        "nmap",
        "find",
    )
    return {
        "platform_system": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "has_proc_fs": has_proc_fs(),
        "tools": {t: shutil.which(t) is not None for t in tools},
    }


def get_os_fingerprint() -> str:
    e = collect_scanner_environment()
    proc = "yes" if e["has_proc_fs"] else "no"
    return (
        f"{e['platform_system']}|{e['platform_release']}|{e['machine']}|proc:{proc}"
    )


def get_scanner_limits() -> str:
    e = collect_scanner_environment()
    parts = [f"{k}:{'yes' if v else 'no'}" for k, v in sorted(e["tools"].items())]
    return ";".join(parts)


if __name__ == "__main__":
    print(json.dumps(collect_scanner_environment(), indent=2))
