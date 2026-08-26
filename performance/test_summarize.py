#!/usr/bin/env python3
"""Regression tests for X301 benchmark eligibility decisions."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("summarize.py")


def write_case(
    root: Path,
    *,
    baseline_ns: float,
    candidate_ns: float,
    baseline_ir: int,
    candidate_ir: int,
    distinct: bool,
    provenance: bool = True,
    post_control_ns: float = 100.0,
    support_noise: bool = False,
) -> None:
    lines = ["round\tvariant\tstatus\tmean_ns"]
    for round_number in range(1, 5):
        lines.extend((
            f"{round_number}\tcontrol-pre\t0\t100.0",
            f"{round_number}\tbaseline\t0\t{baseline_ns}",
            f"{round_number}\tbaseline\t0\t{baseline_ns}",
            f"{round_number}\tcandidate\t0\t{candidate_ns}",
            f"{round_number}\tcandidate\t0\t{candidate_ns}",
            f"{round_number}\tcontrol-post\t0\t{post_control_ns}",
        ))
    (root / "runs.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (root / "ir.tsv").write_text(
        "variant\tstatus\tinstructions\tcallgrind_file\n"
        f"baseline\t0\t{baseline_ir}\tbaseline.out\n"
        f"candidate\t0\t{candidate_ir}\tcandidate.out\n",
        encoding="utf-8",
    )
    baseline_provider = "1" * 64
    candidate_provider = "2" * 64 if distinct else baseline_provider
    baseline_source = "3" * 64
    candidate_source = "4" * 64 if distinct else baseline_source
    support = (
        f"baseline-support-provider\t{'5' * 64}\tinputs/baseline-support.so\n"
        f"candidate-support-provider\t{'6' * 64}\tinputs/candidate-support.so\n"
        if support_noise
        else ""
    )
    (root / "artifacts.tsv").write_text(
        "label\tsha256\tpath\n"
        f"baseline-target-provider\t{baseline_provider}\tinputs/baseline-x301.so\n"
        f"candidate-target-provider\t{candidate_provider}\tinputs/candidate-x301.so\n"
        f"{support}"
        f"baseline-source-manifest\t{baseline_source}\tinputs/baseline.sha256\n"
        f"candidate-source-manifest\t{candidate_source}\tinputs/candidate.sha256\n",
        encoding="utf-8",
    )
    if provenance:
        (root / "PROVENANCE_COMPLETE").touch()


def eligible(**values: object) -> bool:
    with tempfile.TemporaryDirectory(prefix="x301-summarize-") as temporary:
        root = Path(temporary)
        write_case(root, **values)
        output = subprocess.run(
            [sys.executable, str(SCRIPT), str(root)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        return "three_percent_guard_eligible=yes" in output


def main() -> int:
    common = {"baseline_ir": 1_000, "candidate_ir": 900}
    for candidate_ns in (90.0, 100.0, 110.0):
        assert not eligible(
            baseline_ns=100.0,
            candidate_ns=candidate_ns,
            distinct=False,
            **common,
        )
    assert not eligible(
        baseline_ns=100.0,
        candidate_ns=90.0,
        distinct=False,
        support_noise=True,
        **common,
    )
    assert eligible(
        baseline_ns=100.0,
        candidate_ns=90.0,
        distinct=True,
        **common,
    )
    assert not eligible(
        baseline_ns=100.0,
        candidate_ns=90.0,
        baseline_ir=1_000,
        candidate_ir=1_100,
        distinct=True,
    )
    assert not eligible(
        baseline_ns=100.0,
        candidate_ns=90.0,
        distinct=True,
        provenance=False,
        **common,
    )
    assert not eligible(
        baseline_ns=100.0,
        candidate_ns=90.0,
        distinct=True,
        post_control_ns=104.0,
        **common,
    )
    assert not eligible(
        baseline_ns=100.0,
        candidate_ns=90.0,
        baseline_ir=1_000,
        candidate_ir=1_000,
        distinct=True,
    )
    print("x301_summarize_tests=PASS cases=9")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
