from pathlib import Path


ROOT = Path(__file__).parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def _push_paths(workflow_name):
    lines = (WORKFLOWS / workflow_name).read_text(encoding="utf-8").splitlines()
    push_index = lines.index("  push:")
    paths_index = next(
        index
        for index in range(push_index + 1, len(lines))
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


def test_production_workflow_checks_out_current_main_after_queueing():
    workflow = (WORKFLOWS / "update.yml").read_text(encoding="utf-8")

    checkout = workflow.split("- name: Checkout Repo", 1)[1].split(
        "- name: Checkout domain-list-community", 1
    )[0]
    assert "ref: main" in checkout
    assert "stale event SHA" in checkout


def test_dns_validation_has_priority_in_shared_production_concurrency_group():
    update = (WORKFLOWS / "update.yml").read_text(encoding="utf-8")
    dns = (WORKFLOWS / "blacklist.yml").read_text(encoding="utf-8")
    group = "production-rule-pipeline-${{ github.repository }}"

    assert f"group: {group}" in update
    assert f"group: {group}" in dns
    assert "cancel-in-progress: false" in update
    assert "cancel-in-progress: true" in dns


def test_dns_state_and_direct_build_push_triggers_are_disjoint():
    update_paths = _push_paths("update.yml")
    dns_paths = _push_paths("blacklist.yml")
    audit_paths = _push_paths("audit-sources.yml")

    assert len(update_paths) == len(set(update_paths))
    assert len(dns_paths) == len(set(dns_paths))
    assert set(update_paths).isdisjoint(dns_paths)
    assert all(not path.startswith("tests/") for path in update_paths)

    assert {
        ".github/workflows/update.yml",
        "blacklist.py",
        "resolver.py",
        "README.md",
        "requirements.txt",
        "rules/myblock.txt",
        "rules/myblock.txt",
    } <= set(dns_paths)

    assert {
        "adblock.py",
        "filter.py",
        "app/**",
        "rules/filter-exclude.txt",
        "scripts/audit_sources.py",
        "rules/white.txt",
    } <= set(update_paths)
    assert "rules/white.txt" not in dns_paths
    assert "scripts/review_baseline_only.py" in dns_paths
    assert not any(path.startswith("tests/") for path in dns_paths)

    ci_only_paths = {".editorconfig", "pyproject.toml", "requirements-dev.txt"}
    assert ci_only_paths.isdisjoint(update_paths)
    assert ci_only_paths.isdisjoint(dns_paths)
    assert ci_only_paths <= set(audit_paths)
