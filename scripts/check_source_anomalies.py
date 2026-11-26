"""Fail closed when a freshly downloaded upstream list collapses unexpectedly."""
from __future__ import annotations

import argparse
from pathlib import Path

# A source must be substantial before a percentage comparison is meaningful.
MIN_BASELINE_RULES = 200
MIN_ABSOLUTE_LOSS = 100
MAX_REMAINING_RATIO = 0.50


def active_rule_count(path: Path) -> int:
    """Count unique non-comment rules without assuming a source-specific syntax."""
    rules: set[str] = set()
    with path.open("r", encoding="utf-8-sig", errors="replace") as stream:
        for raw in stream:
            line = raw.strip()
            if not line or line.startswith("!"):
                continue
            if line.startswith("#") and not line.startswith(
                ("##", "#@#", "#%#", "#$#")
            ):
                continue
            if line.startswith("[") and line.endswith("]"):
                continue
            rules.add(line)
    return len(rules)


def find_anomalies(previous_dir: Path, current_dir: Path) -> list[str]:
    """Return sources whose current unique-rule count has catastrophically fallen."""
    if not previous_dir.is_dir():
        raise FileNotFoundError(f"Previous source directory is missing: {previous_dir}")
    if not current_dir.is_dir():
        raise FileNotFoundError(f"Current source directory is missing: {current_dir}")

    previous_files = {path.name: path for path in previous_dir.glob("*.txt")}
    current_files = {path.name: path for path in current_dir.glob("*.txt")}
    common_names = sorted(previous_files.keys() & current_files.keys())
    if not common_names:
        raise RuntimeError("No matching previous source snapshots are available for comparison")

    anomalies = []
    for name in common_names:
        previous_count = active_rule_count(previous_files[name])
        current_count = active_rule_count(current_files[name])
        lost = previous_count - current_count
        if (
            previous_count >= MIN_BASELINE_RULES
            and lost >= MIN_ABSOLUTE_LOSS
            and current_count < previous_count * MAX_REMAINING_RATIO
        ):
            anomalies.append(
                f"{name}: {previous_count} -> {current_count} unique rules "
                f"(-{lost}, {lost / previous_count:.1%})"
            )
    return anomalies


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    args = parser.parse_args()

    anomalies = find_anomalies(args.previous, args.current)
    if anomalies:
        for item in anomalies:
            print(f"::error::Abnormal upstream source shrinkage: {item}")
        print("Refusing to publish; the previous successful release remains unchanged.")
        return 1

    print(
        "Upstream source anomaly check passed: no matching source lost at least "
        "100 unique rules and more than 50% of its previous rule count."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
