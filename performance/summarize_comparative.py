#!/usr/bin/env python3
"""Create a deterministic median table from a comparative benchmark run."""

from __future__ import annotations

import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path


BASELINES = {
    "kex": ("X25519", "X448"),
    "kem": ("ML-KEM-1024", "X448MLKEM1024"),
    "signature": ("ED25519", "ED448"),
}


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <result-directory>")
    root = Path(sys.argv[1])
    samples: dict[tuple[str, str, str, str], list[float]] = defaultdict(list)
    with (root / "raw.tsv").open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        expected = {
            "lane", "category", "operation", "algorithm", "run", "count",
            "mean_ns",
        }
        if set(reader.fieldnames or ()) != expected:
            raise SystemExit("unexpected raw.tsv schema")
        for row in reader:
            value = float(row["mean_ns"])
            if value <= 0:
                raise SystemExit("non-positive benchmark value")
            key = (
                row["lane"], row["category"], row["operation"],
                row["algorithm"],
            )
            samples[key].append(value)

    medians = {key: statistics.median(values) for key, values in samples.items()}
    if not medians:
        raise SystemExit("no benchmark samples")
    output = root / "MEDIANS.tsv"
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow((
            "lane", "category", "operation", "algorithm", "samples",
            "median_ns", "vs_first_baseline", "vs_second_baseline",
        ))
        for key in sorted(medians):
            lane, category, operation, algorithm = key
            ratios = []
            for baseline in BASELINES[category]:
                baseline_value = medians.get((lane, category, operation, baseline))
                ratios.append(
                    "" if baseline_value is None else f"{medians[key] / baseline_value:.4f}"
                )
            writer.writerow((
                lane, category, operation, algorithm, len(samples[key]),
                f"{medians[key]:.1f}", *ratios,
            ))
    print(f"comparative_samples={sum(map(len, samples.values()))}")
    print(f"comparative_series={len(samples)}")
    print("comparative_medians=MEDIANS.tsv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
