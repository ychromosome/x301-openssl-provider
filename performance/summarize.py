#!/usr/bin/env python3
"""Summarize one pinned X301 ABBA benchmark session."""

from __future__ import annotations

import csv
import statistics
import sys
from pathlib import Path


def median(values: list[float]) -> float:
    if not values:
        raise SystemExit("missing benchmark samples")
    return statistics.median(values)


def artifact_hashes(path: Path) -> dict[str, tuple[str, ...]]:
    values: dict[str, list[str]] = {}
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            digest = row["sha256"]
            if len(digest) != 64 or any(
                character not in "0123456789abcdef" for character in digest
            ):
                continue
            values.setdefault(row["label"], []).append(digest)
    return {label: tuple(sorted(digests)) for label, digests in values.items()}


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <session-directory>")
    root = Path(sys.argv[1])
    values: dict[str, list[float]] = {}
    paired: dict[str, dict[str, list[float]]] = {}
    with (root / "runs.tsv").open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            if row["status"] != "0" or not row["mean_ns"]:
                continue
            value = float(row["mean_ns"])
            values.setdefault(row["variant"], []).append(value)
            if row["variant"] in {"baseline", "candidate"}:
                paired.setdefault(row["round"], {}).setdefault(
                    row["variant"], []
                ).append(value)

    baseline = median(values.get("baseline", []))
    candidate = median(values.get("candidate", []))
    pre = median(values.get("control-pre", []))
    post = median(values.get("control-post", []))
    control_drift = abs(post - pre) / pre * 100.0
    change = (candidate / baseline - 1.0) * 100.0
    paired_ratios = [
        median(round_values["candidate"]) / median(round_values["baseline"])
        for _, round_values in sorted(paired.items())
        if len(round_values.get("baseline", [])) == 2
        and len(round_values.get("candidate", [])) == 2
    ]
    paired_change = (median(paired_ratios) - 1.0) * 100.0

    ir: dict[str, int] = {}
    ir_path = root / "ir.tsv"
    if ir_path.is_file():
        with ir_path.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle, delimiter="\t"):
                if row["status"] == "0" and row["instructions"]:
                    ir[row["variant"]] = int(row["instructions"])
    ir_complete = (
        ir.get("baseline", 0) > 0 and ir.get("candidate", 0) > 0
    )
    artifacts = artifact_hashes(root / "artifacts.tsv")
    baseline_providers = artifacts.get("baseline-target-provider", ())
    candidate_providers = artifacts.get("candidate-target-provider", ())
    baseline_sources = artifacts.get("baseline-source-manifest", ())
    candidate_sources = artifacts.get("candidate-source-manifest", ())
    artifact_identities_complete = all((
        baseline_providers,
        candidate_providers,
        baseline_sources,
        candidate_sources,
    ))
    artifacts_are_distinct = (
        artifact_identities_complete
        and baseline_providers != candidate_providers
        and baseline_sources != candidate_sources
    )
    provenance_complete = (
        (root / "PROVENANCE_COMPLETE").is_file()
        and artifact_identities_complete
    )
    direction_agrees = (
        ir_complete
        and change != 0.0
        and ir["candidate"] != ir["baseline"]
        and (change > 0) == (ir["candidate"] > ir["baseline"])
    )
    guard_eligible = (
        provenance_complete
        and artifacts_are_distinct
        and len(paired_ratios) == 4
        and direction_agrees
        and control_drift <= 3.0
    )

    print(f"baseline_median_ns={baseline:.1f}")
    print(f"candidate_median_ns={candidate:.1f}")
    print(f"candidate_change_percent={change:.3f}")
    print(f"paired_abba_change_percent={paired_change:.3f}")
    print(f"candidate_to_control_ratio={candidate / median(values.get('control-pre', []) + values.get('control-post', [])):.4f}")
    print(f"control_pre_median_ns={pre:.1f}")
    print(f"control_post_median_ns={post:.1f}")
    print(f"control_drift_percent={control_drift:.3f}")
    if ir_complete:
        ir_change = (ir["candidate"] / ir["baseline"] - 1.0) * 100.0
        print(f"baseline_instructions={ir['baseline']}")
        print(f"candidate_instructions={ir['candidate']}")
        print(f"instruction_change_percent={ir_change:.3f}")
        print(f"wall_instruction_direction_agrees={'yes' if direction_agrees else 'no'}")
    else:
        print("instruction_change=NOT_ESTABLISHED")
    print(f"artifact_identities_complete={'yes' if artifact_identities_complete else 'no'}")
    print(f"baseline_candidate_artifacts_distinct={'yes' if artifacts_are_distinct else 'no'}")
    print(f"noise_calibration_only={'no' if artifacts_are_distinct else 'yes'}")
    print(f"three_percent_guard_eligible={'yes' if guard_eligible else 'no'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
