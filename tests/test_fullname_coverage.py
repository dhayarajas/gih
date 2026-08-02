"""Tests for full-name seeds reaching the OSINT toolchain and image search."""

from types import SimpleNamespace

from src.modules.image_match import (
    ImageResult,
    _matches_name,
    _parse_bing_image_results,
    _parse_google_image_results,
)
from src.orchestrator import (
    ArtifactProcessResult,
    InvestigationConfig,
    MAX_NAME_USERNAME_CANDIDATES,
    _process_fullname,
    _username_candidates,
)
from src.utils.http_client import _supported_encodings

BING_HTML = """
<html><body>
  <img src="https://www.bing.com/sa/simg/sprite.png">
  <a class="iusc" m='{"purl":"https://kernel.org/about","murl":"https://kernel.org/linus.jpg","t":"Linus Torvalds"}'></a>
  <a class="iusc" m='{"purl":"https://example.org/x","murl":"/relative.jpg","t":"broken"}'></a>
  <a class="iusc" m='not json'></a>
</body></html>
"""

GOOGLE_HTML = """
var data = [["https://lh3.googleusercontent.com/logo.png",64,64],
            ["https://kernel.org/photos/linus.jpg",800,600]];
"""


class TestUsernameCandidates:
    """A full name is turned into handles the username tools can search."""

    def test_derives_common_handle_shapes(self):
        values = [a["value"] for a in _username_candidates("Dhayanidhi Rajasekaran")]

        assert values[:3] == [
            "dhayanidhirajasekaran",
            "dhayanidhi.rajasekaran",
            "dhayanidhi_rajasekaran",
        ]
        assert "drajasekaran" in values
        assert len(values) <= MAX_NAME_USERNAME_CANDIDATES

    def test_candidates_are_expandable_username_artifacts(self):
        for artifact in _username_candidates("Ada Lovelace"):
            assert artifact["type"] == "username"
            assert artifact["confidence"] < 0.5
            assert artifact["link_type"] == "possible_username_of"

    def test_single_word_and_empty_names(self):
        assert [a["value"] for a in _username_candidates("Cher")] == ["cher"]
        assert _username_candidates("   ") == []

    def test_derived_without_external_tools(self, monkeypatch):
        """Handle generation needs no external tool, so --no-external-tools keeps it."""
        monkeypatch.setattr(
            "src.orchestrator.image_match.search_and_match_identity",
            lambda **kwargs: SimpleNamespace(
                images=[], face_matches=[], overall_probability=0.0,
                to_dict=dict,
            ),
        )
        monkeypatch.setattr(
            "src.orchestrator.image_match.get_discovered_artifacts", lambda result: []
        )

        result = ArtifactProcessResult(artifact={"type": "fullname", "value": "Ada Lovelace"})
        _process_fullname(
            "Ada Lovelace",
            InvestigationConfig(check_external_tools=False),
            result,
        )

        assert [a["value"] for a in result.discovered if a["type"] == "username"]


class TestImageResultParsing:
    """Search result pages are parsed from their structured payloads."""

    def test_bing_results_come_from_result_metadata(self):
        results = _parse_bing_image_results(BING_HTML, "linus torvalds")

        assert [r.url for r in results] == ["https://kernel.org/linus.jpg"]
        assert results[0].metadata["page_url"] == "https://kernel.org/about"
        assert results[0].metadata["title"] == "Linus Torvalds"

    def test_google_results_skip_chrome_images(self):
        results = _parse_google_image_results(GOOGLE_HTML, "linus torvalds")

        assert [r.url for r in results] == ["https://kernel.org/photos/linus.jpg"]

    def test_max_results_is_respected(self):
        assert _parse_bing_image_results(BING_HTML, "q", max_results=0) == []


class TestNameRelevance:
    """Scraped engines return unrelated images; they must not become evidence."""

    def _result(self, url, title=None, page_url=None):
        return ImageResult(
            url=url,
            source="Bing Images",
            metadata={"title": title, "page_url": page_url},
        )

    def test_keeps_hits_naming_the_person(self):
        assert _matches_name(
            "Linus Torvalds",
            self._result("https://cdn.example/1.jpg", title="Linus Torvalds at LinuxCon"),
        )
        assert _matches_name(
            "Linus Torvalds",
            self._result("https://cdn.example/1.jpg", page_url="https://example.org/torvalds/bio"),
        )

    def test_drops_unrelated_hits(self):
        assert not _matches_name(
            "Linus Torvalds",
            self._result("https://cdn.example/2.jpg", title="Sophie Cunningham scores"),
        )

    def test_shared_first_name_is_not_the_person(self):
        assert not _matches_name(
            "Linus Torvalds",
            self._result("https://cdn.example/3.jpg", title="Linus Pauling in 1954"),
        )


class TestSupportedEncodings:
    """Only encodings urllib3 can decode are advertised."""

    def test_always_includes_gzip_and_deflate(self):
        encodings = _supported_encodings().split(", ")
        assert encodings[:2] == ["gzip", "deflate"]

    def test_matches_urllib3_decoder_registry(self):
        from urllib3.response import HTTPResponse

        advertised = set(_supported_encodings().split(", "))
        assert advertised <= set(HTTPResponse.CONTENT_DECODERS)
        assert ("br" in advertised) is ("br" in HTTPResponse.CONTENT_DECODERS)

    def test_falls_back_when_registry_is_unavailable(self, monkeypatch):
        from urllib3.response import HTTPResponse

        monkeypatch.setattr(HTTPResponse, "CONTENT_DECODERS", [], raising=False)
        assert _supported_encodings() == "gzip, deflate"
