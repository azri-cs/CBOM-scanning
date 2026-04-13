#!/usr/bin/env python3
"""
Shared OS helpers: running executables via psutil, and dependency/symbol scanning
using ldd (glibc Linux), otool -L (macOS), or dumpbin (Windows) when available.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from collections.abc import Iterator

import psutil


def is_windows() -> bool:
    return os.name == "nt" or platform.system().lower().startswith("win")


def kernel_name() -> str:
    return platform.system().lower()


def _run_capture(argv: list[str]) -> str:
    try:
        out = subprocess.check_output(argv, stderr=subprocess.DEVNULL)
        return out.decode(errors="ignore")
    except (subprocess.CalledProcessError, OSError, FileNotFoundError):
        return ""


def iter_running_executable_paths() -> Iterator[str]:
    """
    Enumerate executable paths for running processes using psutil (all supported OS).
    Replaces Linux-only /proc parsing and deprecated Windows WMI enumeration.
    """
    seen: set[str] = set()
    for proc in psutil.process_iter(["exe", "pid"]):
        try:
            exe = proc.info.get("exe")
            if not exe:
                continue
            path = os.path.normpath(exe)
            key = os.path.normcase(path)
            if key in seen:
                continue
            if not os.path.isfile(path):
                continue
            seen.add(key)
            if is_windows():
                if path.lower().endswith(".exe"):
                    yield path
            else:
                yield path
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


def shared_object_dependency_text(binary_path: str) -> str:
    """Dependency list text: dumpbin /imports, otool -L, or ldd."""
    if is_windows():
        db = shutil.which("dumpbin")
        if not db:
            return ""
        return _run_capture([db, "/imports", binary_path])

    if kernel_name() == "darwin":
        ot = shutil.which("otool")
        if ot:
            return _run_capture([ot, "-L", binary_path])
        return ""

    ldd = shutil.which("ldd")
    if ldd:
        return _run_capture([ldd, binary_path])
    return ""


def strings_text(binary_path: str) -> str:
    st = shutil.which("strings")
    if not st:
        return ""
    return _run_capture([st, binary_path])


def nm_symbols_text(binary_path: str) -> str:
    if is_windows():
        db = shutil.which("dumpbin")
        if not db:
            return ""
        return _run_capture([db, "/symbols", binary_path])

    nm = shutil.which("nm")
    if not nm:
        return ""

    if kernel_name() == "darwin":
        out = _run_capture([nm, "-gU", binary_path])
        return out if out else _run_capture([nm, binary_path])

    return _run_capture([nm, "-D", binary_path])
