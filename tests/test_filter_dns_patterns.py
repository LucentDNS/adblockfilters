from pathlib import Path

from filter import Filter
from readme import Rule


def test_only_scoped_patterns_from_dns_sources_enter_adguard_dns_patterns(tmp_path):
    source_dir = tmp_path / "sources"
    source_dir.mkdir()

    dns_rule = Rule("DNS test", "dns", "https://example.test/dns.txt", "live")
    browser_rule = Rule("Browser test", "filter", "https://example.test/filter.txt", "live")

    (source_dir / dns_rule.filename).write_text(
        "\n".join(
            [
                "||ads*-normal-hl.zijieapi.com^",
                "@@||profile*.se.360.cn^",
                "||ad-*.com^",
                "/^.+stat\\.kugou\\.com/",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (source_dir / browser_rule.filename).write_text(
        "||browser*.example.com^\n",
        encoding="utf-8",
    )
    (source_dir / "myblock.txt").write_text("", encoding="utf-8")

    parser = Filter(
        [dns_rule, browser_rule],
        path=str(tmp_path),
        outPath=str(tmp_path),
        sourcePath=str(source_dir),
    )
    block, allow, filter_rules, dns_pattern_blocks, dns_pattern_allows = (
        parser._Filter__getFilters()
    )

    assert block == {}
    assert allow == {}
    assert dns_pattern_blocks == {
        "||ads*-normal-hl.zijieapi.com^": "zijieapi.com"
    }
    assert dns_pattern_allows == {
        "@@||profile*.se.360.cn^": "360.cn"
    }
    assert "||ad-*.com^" not in dns_pattern_blocks
    assert "/^.+stat\\.kugou\\.com/" not in dns_pattern_blocks
    assert "||browser*.example.com^" not in dns_pattern_blocks
    assert "||browser*.example.com^" in filter_rules
