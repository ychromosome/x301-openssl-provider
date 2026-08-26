#!/usr/bin/env python3
"""Report X301 derive lifecycle cost from four benchmark sessions."""

from __future__ import annotations

import csv
import statistics
import sys
from pathlib import Path


EXPECTED = (
    "derive-setup",
    "derive-first",
    "derive-second",
    "derive-steady",
)
REUSE_COUNTS = (1, 2, 3, 5, 10)
PREPARED_TABLE_BYTES = 1_920


def operation(root: Path) -> str:
    values = {}
    for line in (root / "session.env").read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    return values.get("operation", "")


def medians(root: Path) -> dict[str, float]:
    values: dict[str, list[float]] = {}
    with (root / "runs.tsv").open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            if row["status"] == "0" and row["variant"] in {
                "baseline",
                "candidate",
            }:
                values.setdefault(row["variant"], []).append(
                    float(row["mean_ns"])
                )
    if set(values) != {"baseline", "candidate"}:
        raise SystemExit(f"incomplete lifecycle session: {root}")
    return {name: statistics.median(samples) for name, samples in values.items()}


def cumulative(costs: dict[str, float], count: int) -> float:
    total = costs["derive-setup"] + costs["derive-first"]
    if count >= 2:
        total += costs["derive-second"]
    if count >= 3:
        total += (count - 2) * costs["derive-steady"]
    return total


def main() -> int:
    if len(sys.argv) != 5:
        raise SystemExit(
            f"usage: {sys.argv[0]} <setup-session> <first-session> "
            "<second-session> <steady-session>"
        )
    roots = [Path(value) for value in sys.argv[1:]]
    observed = tuple(operation(root) for root in roots)
    if observed != EXPECTED:
        raise SystemExit(f"unexpected lifecycle sessions: {observed!r}")
    by_operation = {
        name: medians(root) for name, root in zip(EXPECTED, roots, strict=True)
    }

    print(f"prepared_table_payload_bytes={PREPARED_TABLE_BYTES}")
    print("variant\treuse_count\tcumulative_ns\tmean_per_derive_ns\t"
          "uncached_ladder_ns\tsaving_percent")
    for variant in ("baseline", "candidate"):
        costs = {name: by_operation[name][variant] for name in EXPECTED}
        break_even = None
        for count in range(2, 101):
            actual = cumulative(costs, count)
            uncached = costs["derive-setup"] + count * costs["derive-first"]
            if actual <= uncached:
                break_even = count
                break
        for count in REUSE_COUNTS:
            actual = cumulative(costs, count)
            uncached = costs["derive-setup"] + count * costs["derive-first"]
            saving = (1.0 - actual / uncached) * 100.0
            print(
                f"{variant}\t{count}\t{actual:.1f}\t{actual / count:.1f}\t"
                f"{uncached:.1f}\t{saving:.3f}"
            )
        value = "NOT_WITHIN_100" if break_even is None else str(break_even)
        print(f"{variant}_preparation_break_even_reuse_count={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
