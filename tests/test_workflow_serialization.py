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
