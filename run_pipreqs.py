#!/usr/bin/env python3
"""Run pipreqs with defaults suited to this repo (see README).

pipreqs logs WARNING when local dist metadata does not list a top-level module (common for
modern wheels such as cryptography) or when the PyPI name differs from the import (nmap vs
python-nmap). By default this wrapper sets the log level to ERROR so those lines are hidden.
Pass --verbose for normal pipreqs INFO/WARNING output, or --debug for full debug logs.
"""

from __future__ import annotations

import logging
import sys


def _has_opt(args: list[str], long_opt: str) -> bool:
    prefix = long_opt + "="
    return long_opt in args or any(a.startswith(prefix) for a in args)


def _ensure_repo_defaults(args: list[str]) -> list[str]:
    """Always ignore `.venv` and default to UTF-8 unless the user set those options."""
    out = list(args)
    if not _has_opt(out, "--encoding"):
        out.insert(0, "--encoding=utf-8")
    if "--ignore" not in out:
        out.extend(["--ignore", ".venv"])
    return out


def main() -> None:
    args = sys.argv[1:]
    verbose = "--verbose" in args
    args = [a for a in args if a != "--verbose"]

    if not args:
        args = ["."]
    args = _ensure_repo_defaults(args)

    sys.argv = ["pipreqs", *args]

    if "--debug" in args:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.ERROR

    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")

    import importlib

    importlib.import_module("pipreqs.pipreqs").main()


if __name__ == "__main__":
    main()
