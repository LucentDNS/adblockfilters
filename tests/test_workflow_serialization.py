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


def test_production_build_uses_last_sealed_dns_state_without_waiting_for_current_validation():
    workflow = (WORKFLOWS / "update.yml").read_text(encoding="utf-8")
    assert "Wait for a complete DNS state" not in workflow
    assert "gh workflow run" not in workflow
    prepare = workflow.split(
        "- name: Prepare verified DNS classification inputs for Lite", 1
    )[1].split("- name:", 1)[0]
    for asset in (
        "black.txt", "china.txt", "domain.txt", "domain-input-provenance.json",
        "validated-dns-sources.tar.gz", "dns-validation-bootstrap-complete-v2.txt",
    ):
        assert asset in prepare
    assert "validated_sources.py check-current" in prepare
    assert "No previous domestic classification" not in prepare
    assert "validated-black.txt" in prepare
    assert "diagnostic only" in prepare


def test_source_audit_requires_matching_domain_and_china_inputs_for_lite_scope():
    audit = (ROOT / "scripts" / "audit_sources.py").read_text(encoding="utf-8")
    assert 'validation_input_path = ROOT / ".cache" / "domain" / "domain.txt"' in audit
    assert "Lite scope audit is required and cannot be skipped" in audit
    assert "china.txt contains domains outside domain.txt" in audit


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



def test_publication_waits_for_audit_and_dist_manifest_before_rule_release():
    workflow = (WORKFLOWS / "update.yml").read_text(encoding="utf-8")
    assert workflow.index("Publish source audit and baseline comparison reports") < workflow.index(
        "- name: Upload rules to release"
    )
    assert workflow.index("Publish to dist branch") < workflow.index(
        "- name: Upload rules to release"
    )
    dist = workflow.split("- name: Publish to dist branch", 1)[1].split(
        "- name: Verify main is still the build commit", 1
    )[0]
    for name in (
        "adblockdns.txt", "adblockdnslite.txt",
        "adblockfilters.txt", "adblockfilterslite.txt",
    ):
        assert name in dist
    assert "dist must contain exactly the four AdGuard subscription files" in dist
    assert "cp -r .cache/out /tmp/release-out" in dist
    assert "cp /tmp/release-out/* .cache/out/" in dist
    assert "Verify published rule release manifest" in workflow
