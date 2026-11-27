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
        "sources.json",
        "scripts/generate_domain_input.py",
        "requirements.txt",
        "rules/myblock.txt",
        "readme.py",
        "updater.py",
    } <= set(dns_paths)

    assert {
        "adblock.py",
        "filter.py",
        "app/**",
        "rules/filter-exclude.txt",
        "rules/white.txt",
        "scripts/compare_baseline.py",
        "scripts/audit_sources.py",
        "scripts/verify_critical_domains.py",
        ".github/workflows/update.yml",
    } <= set(update_paths)
    assert "rules/white.txt" not in dns_paths
    assert ".github/workflows/update.yml" not in dns_paths
    assert "updater.py" not in update_paths
    assert "readme.py" not in update_paths
    assert "scripts/verify_critical_domains.py" in update_paths
    assert "scripts/audit_sources.py" not in dns_paths
    assert "scripts/verify_critical_domains.py" not in dns_paths
    assert "scripts/**" in audit_paths

    ci_only_paths = {".editorconfig", ".gitattributes", "pyproject.toml", "requirements-dev.txt"}
    assert ci_only_paths.isdisjoint(update_paths)
    assert ci_only_paths.isdisjoint(dns_paths)
    assert ci_only_paths <= set(audit_paths)


def test_daily_dns_validation_is_the_only_scheduled_production_build():
    dns = (WORKFLOWS / "blacklist.yml").read_text(encoding="utf-8")
    update = (WORKFLOWS / "update.yml").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "cron: '43 8 * * *'" in dns
    assert "16:43 Beijing time" in dns
    assert "schedule:" not in update
    assert "gh workflow run update.yml --ref main" in dns
    assert "每日自动更新一次" in readme


def test_dns_state_dispatch_guard_tracks_only_dns_validation_inputs():
    workflow = (WORKFLOWS / "blacklist.yml").read_text(encoding="utf-8")
    guard = workflow.split("changed_paths", 1)[1].split("then", 1)[0]

    assert "sources\\.json" in guard
    assert "requirements\\.txt" in guard
    assert "readme\\.py" in guard
    assert "updater\\.py" in guard
    assert "verify_critical_domains" not in guard


def test_rule_release_prunes_unsupported_assets_before_upload():
    workflow = (WORKFLOWS / "update.yml").read_text(encoding="utf-8")
    cleanup = workflow.split(
        "- name: Remove unsupported legacy client assets from rule release", 1
    )[1].split("- name: Upload rules to release", 1)[0]

    assert "releases/tags/rule" in cleanup
    assert "gh api --method DELETE" in cleanup
    assert "adblockdns.txt" in cleanup
    assert "adblockdnslite.txt" in cleanup
    assert "adblockfilters.txt" in cleanup
    assert "adblockfilterslite.txt" in cleanup
    assert "LICENSE-GPL-3.0.txt" in cleanup
    assert "THIRD-PARTY-NOTICES.md" in cleanup
    assert workflow.index("Remove unsupported legacy client assets from rule release") < workflow.index(
        "- name: Wait for a complete DNS state matching current inputs"
    )
    assert workflow.index("Remove unsupported legacy client assets from rule release") < workflow.index(
        "- name: Upload rules to release"
    )
