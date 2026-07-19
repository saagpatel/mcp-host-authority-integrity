"""Sacrificial controller used to qualify browser watchdog controller-death cleanup."""

from __future__ import annotations

import argparse
from pathlib import Path

from harness.browser_runtime import BrowserSession, browser_html


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-root", type=Path, required=True)
    args = parser.parse_args()
    script = """
const started = Date.now();
while (Date.now() - started < 15000) {}
mhaiFinish({unexpected_completion: true});
"""
    with BrowserSession(args.session_root) as session:
        session.run_html(browser_html(script), timeout_seconds=20)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
