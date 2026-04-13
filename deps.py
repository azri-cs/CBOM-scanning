#!/usr/bin/env python3
"""
Fail fast with a clear hint when hard deps are missing.

`sudo python3` uses root's interpreter and site-packages; user-level
`pip install --user` is often invisible under sudo.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent

try:
    import psutil
except ImportError as e:
    req = _REPO / "requirements.txt"
    venv_py = _REPO / ".venv" / "bin" / "python3"
    venv_hint = ""
    if venv_py.is_file():
        venv_hint = (
            "This repo includes a virtualenv with dependencies. Run the scanner with it "
            "(works with sudo):\n"
            f"  sudo {venv_py} {_REPO}/1BinariesUsed.py\n\n"
        )
    raise SystemExit(
        "Missing Python package 'psutil' for this interpreter:\n"
        f"  {sys.executable}\n\n"
        + venv_hint
        + "Or install deps for root's Python (PEP 668 systems may need "
        "`--break-system-packages` or `apt install python3-psutil`):\n"
        f"  sudo python3 -m pip install -r {req}\n\n"
        "Or: sudo python3 -m pip install 'psutil>=5.9'"
    ) from e

__all__ = ("psutil",)
