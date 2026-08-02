"""Tests for junk-username filtering in the Google Dorks extractor."""

import pytest

from src.modules.google_dorks import (
    GoogleDorksSearch,
    _is_valid_username,
)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("john", True),
        ("dhayanidhi.r.2025", True),
        ("r.dhayanidhi.5", True),
        ("a_b-c", True),
        ("login.php", False),
        ("login?service=mail", False),
        ("Login", False),
        ("index.html", False),
        ("user", False),
        ("www", False),
        ("en", False),
        ("ab", False),
        ("123456", False),
        ("about-us", False),
        ("foo%20bar", False),
        ("", False),
    ],
)
def test_is_valid_username(value, expected):
    assert _is_valid_username(value) is expected


def test_extractor_skips_junk_path_segments(tmp_path):
    searcher = GoogleDorksSearch(cache_dir=str(tmp_path))
    pattern = searcher.DORK_PATTERNS[0]

    junk = searcher._extract_artifacts_from_result(
        {"url": "https://example.com/login.php", "title": "", "snippet": ""},
        pattern,
    )
    assert not any(a["type"] == "username" for a in junk)

    real = searcher._extract_artifacts_from_result(
        {"url": "https://github.com/octocat", "title": "", "snippet": ""},
        pattern,
    )
    usernames = [a["value"] for a in real if a["type"] == "username"]
    assert usernames == ["octocat"]
