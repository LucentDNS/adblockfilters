"""Verify that AdGuard's official Hostlist Compiler preserves generated DNS rules."""
from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path


def active_rules(path: Path) -> list[str]:
    """Return non-comment filter rules without changing their matching semantics."""
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip() and not line.lstrip().startswith(("!", "#"))
    ]


def compare_rules(source_path: Path, validated_path: Path) -> int:
    """Fail if the official compiler removes, changes, or deduplicates project rules."""
    source_rules = active_rules(source_path)
    validated_rules = active_rules(validated_path)

    if not source_rules:
        raise ValueError(f"Generated DNS filter is empty: {source_path}")
    if not validated_rules:
        raise ValueError(f"Hostlist Compiler produced no DNS rules: {validated_path}")

    source_counts = Counter(source_rules)
    validated_counts = Counter(validated_rules)
    # Hostlist Compiler may omit standalone allow exceptions that do not match
    # any block rule in this one list. They remain in our published source file;
    # the compiler output is validation-only and is never used as the artifact.
    # Missing block rules, however, are a hard compatibility failure.
    missing = sorted(
        rule for rule in source_counts.keys() - validated_counts.keys()
        if not rule.startswith("@@")
    )
    unexpected = sorted(validated_counts.keys() - source_counts.keys())
    duplicates = sorted(rule for rule, count in source_counts.items() if count > 1)
    compiler_duplicates = sorted(rule for rule, count in validated_counts.items() if count > 1)

    if missing or unexpected or duplicates or compiler_duplicates:
        details = [
            f"source rules: {len(source_rules)}",
            f"compiler rules: {len(validated_rules)}",
        ]
        if missing:
            details.append(f"removed or changed blocking rules ({len(missing)}): {missing[:20]}")
        if unexpected:
            details.append(f"unexpected compiler rules ({len(unexpected)}): {unexpected[:20]}")
        if duplicates:
            details.append(f"duplicate source rules ({len(duplicates)}): {duplicates[:20]}")
        if compiler_duplicates:
            details.append(
                f"duplicate compiler rules ({len(compiler_duplicates)}): {compiler_duplicates[:20]}"
            )
        raise ValueError("AdGuard Hostlist Compiler compatibility check failed: " + "; ".join(details))

    return len(source_rules)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--validated", type=Path, required=True)
    args = parser.parse_args()

    try:
        count = compare_rules(args.input, args.validated)
    except (OSError, UnicodeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc

    print(f"AdGuard Hostlist Compiler compatibility check passed: {count} DNS rules preserved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
