#!/usr/bin/env python3
"""Regression test for the four-state X301 derive lifecycle report."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("summarize_derive_lifecycle.py")
OPERATIONS = (
    ("derive-setup", 10.0),
    ("derive-first", 100.0),
    ("derive-second", 300.0),
    ("derive-steady", 40.0),
)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="x301-lifecycle-") as temporary:
        root = Path(temporary)
        sessions = []
        for operation, value in OPERATIONS:
            session = root / operation
            session.mkdir()
            (session / "session.env").write_text(
                f"operation={operation}\n", encoding="utf-8"
            )
            (session / "runs.tsv").write_text(
                "variant\tstatus\tmean_ns\n"
                f"baseline\t0\t{value}\n"
                f"candidate\t0\t{value}\n",
                encoding="utf-8",
            )
            sessions.append(str(session))
        output = subprocess.run(
            [sys.executable, str(SCRIPT), *sessions],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    required = (
        "prepared_table_payload_bytes=1920",
        "baseline\t1\t110.0\t110.0\t110.0\t0.000",
        "baseline\t10\t730.0\t73.0\t1010.0\t27.723",
        "baseline_preparation_break_even_reuse_count=6",
        "candidate_preparation_break_even_reuse_count=6",
    )
    if not all(line in output for line in required):
        raise SystemExit("unexpected lifecycle summary")
    print("x301_lifecycle_summary_tests=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
