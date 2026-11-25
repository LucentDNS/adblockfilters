from pathlib import Path

from filter import Filter


def test_exact_browser_exclusion_removes_only_the_broad_video_cdn_rule():
    instance = Filter.__new__(Filter)
    filter_dict = {
        "||evtubescms.phncdn.com^": "evtubescms.phncdn.com",
        "||evtubescms.phncdn.com/pre_videos^$important": "evtubescms.phncdn.com",
        "||evtubescms.phncdn.com/videos/*/mp4_480.mp4$important": "evtubescms.phncdn.com",
    }

    _, retained, _ = instance._Filter__filterSort(
        filter_dict,
        blockSet=set(),
        unblockSet=set(),
        blackSet=set(),
        whiteSet=set(),
        whiteDict={},
    )

    assert "||evtubescms.phncdn.com^" not in retained
    assert "||evtubescms.phncdn.com/pre_videos^$important" in retained
    assert "||evtubescms.phncdn.com/videos/*/mp4_480.mp4$important" in retained


def test_filter_exclusion_file_contains_only_exact_host_rule():
    path = Path(__file__).parents[1] / "rules" / "filter-exclude.txt"
    rules = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith(("!", "#"))
    ]

    assert rules == ["||evtubescms.phncdn.com^"]
