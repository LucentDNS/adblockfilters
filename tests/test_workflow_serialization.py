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


def test_dns_and_build_workflows_use_independent_concurrency_groups():
    update = (WORKFLOWS / "update.yml").read_text(encoding="utf-8")
    dns = (WORKFLOWS / "blacklist.yml").read_text(encoding="utf-8")

    assert "group: update-filters-${{ github.repository }}" in update
    assert "group: dns-validation-state-${{ github.repository }}" in dns
    assert "cancel-in-progress: true" in update
    assert "cancel-in-progress: true" in dns


def test_production_build_waits_for_a_complete_matching_dns_state():
    workflow = (WORKFLOWS / "update.yml").read_text(encoding="utf-8")

    assert "Wait for a complete DNS state matching current inputs" in workflow
    assert "python scripts/validated_sources.py check-current" in workflow
    assert "validated-dns-sources.tar.gz" in workflow
    assert "validation logic, and myblock.txt" in workflow
    assert "git rev-parse origin/main" in workflow


def test_production_build_aborts_promptly_when_main_advances_while_waiting():
    workflow = (WORKFLOWS / "update.yml").read_text(encoding="utf-8")
    wait_step = workflow.split(
        "- name: Wait for a complete DNS state matching current inputs", 1
    )[1].split("- name: Prepare domain inputs", 1)[0]

    assert "git fetch origin main --quiet" in wait_step
    assert "main advanced while waiting for DNS state" in wait_step
    assert wait_step.index("git fetch origin main --quiet") < wait_step.index("sleep 30")


def test_production_build_rechecks_main_before_publishing():
    workflow = (WORKFLOWS / "update.yml").read_text(encoding="utf-8")

    assert "Refuse to publish if main advanced during the build" in workflow
    assert "git rev-parse origin/main" in workflow
    assert workflow.index("Refuse to publish if main advanced during the build") < workflow.index("- name: Upload rules to release")
    publish = workflow.split("- name: Publish to dist branch", 1)[1]
    assert 'build_main_sha="$(git rev-parse HEAD)"' in publish
    assert "main advanced before dist publication" in publish


def test_dns_state_and_direct_build_push_triggers_are_disjoint():
    update_paths = _push_paths("update.yml")
    dns_paths = _push_paths("blacklist.yml")
    audit_paths = _push_paths("audit-sources.yml")

    assert len(update_paths) == len(set(update_paths))
    assert len(dns_paths) == len(set(dns_paths))
    assert set(update_paths).isdisjoint(dns_paths)
    assert all(not path.startswith("tests/") for path in update_paths)
    assert all(not path.startswith("tests/") for path in dns_paths)

    assert {
        "blacklist.py",
        "resolver.py",
        "README.md",
        "requirements.txt",
        "rules/myblock.txt",
    } <= set(dns_paths)

    assert {
        "adblock.py",
        "filter.py",
        "app/**",
        "rules/filter-exclude.txt",
        "rules/white.txt",
        "scripts/compare_baseline.py",
        ".github/workflows/update.yml",
    } <= set(update_paths)
    assert "rules/white.txt" not in dns_paths
    assert ".github/workflows/update.yml" not in dns_paths
    assert "scripts/review_baseline_only.py" in dns_paths
    assert "scripts/audit_sources.py" not in update_paths
    assert "scripts/**" in audit_paths

    ci_only_paths = {".editorconfig", "pyproject.toml", "requirements-dev.txt"}
    assert ci_only_paths.isdisjoint(update_paths)
    assert ci_only_paths.isdisjoint(dns_paths)
    assert ci_only_paths <= set(audit_paths)
