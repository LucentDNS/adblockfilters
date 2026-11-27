from scripts import generate_china_list as china_generator
from scripts.generate_china_list import classify_domains, parse_direct_rules


def test_direct_rule_parser_uses_only_full_and_domain_entries():
    full, domains = parse_direct_rules(
        """
        # China direct rules
        full:api.example.com
        domain:service.example.net
        regexp:.*ignored.*
        keyword:also-ignored
        """
    )

    assert full == {"api.example.com"}
    assert domains == {"service.example.net"}


def test_conservative_lite_classifier_uses_cn_full_and_domain_rules():
    current = {
        "service.cn",
        "api.example.com",
        "child.service.example.net",
        "global.example.org",
    }
    full = {"api.example.com"}
    roots = {"example.net"}
    china = classify_domains(current, full, roots)

    assert china == {
        "service.cn",
        "api.example.com",
        "child.service.example.net",
    }


def test_generate_china_list_writes_current_conservative_scope_and_provenance(tmp_path, monkeypatch):
    domain_dir = tmp_path / "domain"
    domain_dir.mkdir()
    (domain_dir / "domain.txt").write_text(
        "service.cn\napi.example.com\nchild.service.example.net\nglobal.example.org\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        china_generator,
        "_download_direct_rules",
        lambda _path: b"full:api.example.com\ndomain:example.net\n",
    )

    provenance = china_generator.generate_china_list(domain_dir)

    assert (domain_dir / "china.txt").read_text(encoding="utf-8").splitlines() == [
        "api.example.com",
        "child.service.example.net",
        "service.cn",
    ]
    assert provenance["china_classified_domain_count"] == 3
    assert (domain_dir / "china-classification.json").is_file()
