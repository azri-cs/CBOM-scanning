#!/usr/bin/env python3

import os


DEFAULT_PROGRESS_INTERVAL = max(1, int(os.environ.get("CBOM_PROGRESS_INTERVAL", "250")))


def maybe_report_progress(
    label: str, count: int, every: int = DEFAULT_PROGRESS_INTERVAL
) -> None:
    if count > 0 and count % every == 0:
        print(f"[i] {label}: processed {count}")
