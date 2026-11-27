import json
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "upstream-components.json"


def test_component_manifest_is_valid_and_curated():
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert data["version"] == 1
    assert data["status"] == "curated_candidate_not_yet_consumed_by_production_builder"
    components = data["components"]
    assert components
    names = [item["name"] for item in components]
    urls = [item["url"] for item in components]
    assert len(names) == len(set(names))
    assert len(urls) == len(set(urls))

    required = {"name", "role", "url", "license", "transformations"}
    for item in components:
        assert required <= item.keys()
        parsed = urlparse(item["url"])
        assert parsed.scheme == "https"
        assert parsed.netloc
        assert item["transformations"]
        assert item["role"] not in {"complete_product", "aggregate"}

    # The component manifest must not silently reintroduce full aggregated DNS lists.
    excluded = {value.lower() for value in data["excluded_complete_products"]}
    assert any("hagezi" in value for value in excluded)
    assert any("oisd" in value for value in excluded)
    assert any("anti-ad" in value for value in excluded)
    assert data["policy"]["source_allow_scope"] == "source_local"
    assert data["policy"]["candidate_allow_behavior"] == "audit_only"


def test_component_roles_cover_required_dns_domains():
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    roles = {item["role"] for item in data["components"]}
    assert {"core_ads", "mobile_ads", "tracking", "regional_ads_cn"} <= roles
    assert "third_party_tracking" in roles
