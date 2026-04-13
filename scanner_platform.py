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
from typing import List, Tuple

from deps import psutil


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


def binary_kind(path: str) -> str:
    """Rough native format: elf, macho, pe, unknown."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
    except OSError:
        return "unknown"
    if magic == b"\x7fELF":
        return "elf"
    if magic in (
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xce",
    ):
        return "macho"
    if len(magic) >= 2 and magic[:2] == b"MZ":
        return "pe"
    return "unknown"


def _parse_ldd_lines(text: str) -> Tuple[List[str], List[str]]:
    system_libs: List[str] = []
    third_party_libs: List[str] = []
    system_paths = ("/lib", "/usr/lib", "/lib64", "/usr/lib64")

    for line in text.splitlines():
        if "=>" not in line:
            continue
        parts = line.split("=>")
        lib_path = parts[1].split("(")[0].strip()
        if not lib_path or lib_path == "not found":
            continue
        is_system = any(lib_path.startswith(p) for p in system_paths)
        if lib_path.startswith("/usr/local/lib"):
            is_system = False
        if is_system:
            system_libs.append(lib_path)
        else:
            third_party_libs.append(lib_path)

    return third_party_libs, system_libs


def _parse_otool_l_lines(text: str) -> Tuple[List[str], List[str]]:
    system_libs: List[str] = []
    third_party_libs: List[str] = []
    sys_prefixes = ("/usr/lib/", "/System/Library/", "/lib/")

    for line in text.splitlines():
        s = line.strip()
        if not s or s.endswith(":"):
            continue
        path = s.split()[0]
        if not path.startswith("/"):
            continue
        if path.startswith(sys_prefixes):
            system_libs.append(path)
        else:
            third_party_libs.append(path)

    return third_party_libs, system_libs


def classify_linked_libraries(binary_path: str) -> Tuple[List[str], List[str]]:
    """
    Split linked shared libraries into third-party vs system paths.
    ELF uses ldd-style parsing; Mach-O uses otool -L. PE returns empty lists.
    """
    kind = binary_kind(binary_path)
    if kind == "pe":
        return [], []

    text = shared_object_dependency_text(binary_path)
    if not text.strip():
        return [], []

    if kind == "macho" or kernel_name() == "darwin":
        return _parse_otool_l_lines(text)

    return _parse_ldd_lines(text)
