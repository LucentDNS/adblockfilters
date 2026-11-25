from pathlib import Path


def test_production_workflow_checks_out_current_main_after_queueing():
    workflow = (
        Path(__file__).parents[1] / ".github" / "workflows" / "update.yml"
    ).read_text(encoding="utf-8")

    assert "group: update-filters-${{ github.ref }}" in workflow
    checkout = workflow.split("- name: Checkout Repo", 1)[1].split(
        "- name: Checkout domain-list-community", 1
    )[0]
    assert "ref: main" in checkout
    assert "stale event SHA" in checkout

def _push_paths(workflow_path):
    lines = workflow_path.read_text(encoding="utf-8").splitlines()
    push_index = lines.index("  push:")
    paths_index = next(
        index for index in range(push_index + 1, len(lines))
        if lines[index].strip() == "paths:"
    )
    paths = []
    for line in lines[paths_index + 1:]:
        if line.startswith("      - "):
            paths.append(line.strip()[2:].strip().strip('"').strip("'"))
        elif line.startswith("      "):
            continue
        else:
            break
    return paths


def test_dns_state_and_direct_build_push_triggers_are_disjoint():
    root = Path(__file__).parents[1]
    update_paths = _push_paths(root / ".github" / "workflows" / "update.yml")
    dns_paths = _push_paths(root / ".github" / "workflows" / "blacklist.yml")

    assert len(update_paths) == len(set(update_paths))
    assert len(dns_paths) == len(set(dns_paths))
    assert set(update_paths).isdisjoint(dns_paths)
    assert "tests/test_workflow_serialization.py" not in update_paths
    assert "tests/test_workflow_serialization.py" not in dns_paths

    assert {
        ".github/workflows/update.yml",
        "blacklist.py",
        "resolver.py",
        "README.md",
        "requirements.txt",
        "rules/myblock.txt",
        "rules/white.txt",
    } <= set(dns_paths)

    assert {
        "adblock.py",
        "filter.py",
        "app/**",
        "rules/filter-exclude.txt",
        "scripts/audit_sources.py",
    } <= set(update_paths)
