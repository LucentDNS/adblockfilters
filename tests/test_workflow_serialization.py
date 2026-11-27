from pathlib import Path


ROOT = Path(__file__).parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def _push_paths(workflow_name):
    lines = (WORKFLOWS / workflow_name).read_text(encoding="utf-8").splitlines()
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


def test_production_build_does_not_wait_for_or_require_dns_validation_state():
    workflow = (WORKFLOWS / "update.yml").read_text(encoding="utf-8")
    assert "Wait for a complete DNS state" not in workflow
    assert "validated_sources.py check-current" not in workflow
    assert "validated-dns-sources.tar.gz" not in workflow
    prepare = workflow.split(
        "- name: Prepare optional DNS classification inputs", 1
    )[1].split("- name:", 1)[0]
    assert ': > .cache/domain/black.txt' in prepare
    assert "china.txt" in prepare
    assert "Lite" in prepare


def test_production_build_rechecks_main_before_publishing():
    workflow = (WORKFLOWS / "update.yml").read_text(encoding="utf-8")
    assert "Refuse to publish if main advanced during the build" in workflow
    assert "git rev-parse origin/main" in workflow
    assert workflow.index("Refuse to publish if main advanced during the build") < workflow.index(
        "- name: Upload rules to release"
    )
    publish = workflow.split("- name: Publish to dist branch", 1)[1]
    assert 'build_main_sha="$(git rev-parse HEAD)"' in publish
    assert "main advanced before dist publication" in publish


def test_dns_diagnostics_are_not_a_production_build_dependency():
    update = (WORKFLOWS / "update.yml").read_text(encoding="utf-8")
    dns = (WORKFLOWS / "blacklist.yml").read_text(encoding="utf-8")
    assert "gh workflow run update.yml --ref main" not in dns
    assert "Trigger production rule build" not in dns
    assert "workflow_dispatch:" in dns
    assert "cron: '43 8 * * 0'" in dns
    assert "cron: '43 8 * * *'" in update
    assert "每日自动更新一次" in (ROOT / "README.md").read_text(encoding="utf-8")


def test_source_and_build_changes_trigger_production_refresh():
    update_paths = _push_paths("update.yml")
    audit_paths = _push_paths("audit-sources.yml")
    assert len(update_paths) == len(set(update_paths))
    assert all(not path.startswith("tests/") for path in update_paths)
    assert {
        "README.md", "sources.json", "rules/myblock.txt", "updater.py",
        "adblock.py", "filter.py", "app/**", "rules/white.txt",
        "scripts/compare_baseline.py", "scripts/audit_sources.py",
        "scripts/verify_critical_domains.py", ".github/workflows/update.yml",
    } <= set(update_paths)
    assert "scripts/**" in audit_paths


def test_rule_release_prunes_unsupported_assets_before_upload():
    workflow = (WORKFLOWS / "update.yml").read_text(encoding="utf-8")
    cleanup = workflow.split(
        "- name: Remove unsupported legacy client assets from rule release", 1
    )[1].split("- name: Upload rules to release", 1)[0]
    assert "releases/tags/rule" in cleanup
    assert "gh api --method DELETE" in cleanup
    for name in (
        "adblockdns.txt", "adblockdnslite.txt", "adblockfilters.txt",
        "adblockfilterslite.txt", "LICENSE-GPL-3.0.txt", "THIRD-PARTY-NOTICES.md",
    ):
        assert name in cleanup
    assert workflow.index("Remove unsupported legacy client assets from rule release") < workflow.index(
        "- name: Upload rules to release"
    )


def test_obsolete_branch_cleanup_runs_before_build_setup():
    workflow = (WORKFLOWS / "update.yml").read_text(encoding="utf-8")
    cleanup = workflow.split(
        "- name: Remove merged and superseded work branches", 1
    )[1].split("- name: Setup Python", 1)[0]
    assert "pulls?state=open" in cleanup
    assert "pulls?state=closed" in cleanup
    assert '[[ "${branch_name}" == "main" || "${branch_name}" == "dist" ]]' in cleanup
    assert workflow.index("Remove merged and superseded work branches") < workflow.index(
        "- name: Prepare optional DNS classification inputs"
    )
