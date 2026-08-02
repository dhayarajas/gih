"""Tests for platform checks in the username search module."""

from unittest.mock import patch

import pytest

from src.modules import username_search
from src.modules.username_search import (
    VALIDATION_CONTENT,
    VALIDATION_STATUS,
    UsernameSearchResult,
    _check_platform,
    get_discovered_artifacts,
)

REAL_PROFILE_HTML = """
<html><head><title>ghostuser (@ghostuser)</title></head>
<body><h1>ghostuser</h1><p>Profile of https://steamcommunity.com/id/ghostuser</p></body></html>
"""

SOFT_404_HTML = """
<html><body><h2>Sorry, this page isn't available.</h2>
<p>The link you followed may be broken.</p></body></html>
"""

LOGIN_WALL_HTML = """
<html><body><div id="app-shell">Sign in to continue</div></body></html>
"""


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None, json_data=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self._json = json_data

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


def platform(**overrides) -> dict:
    base = {
        "name": "Steam",
        "url_template": "https://steamcommunity.com/id/{username}",
        "check_type": "web_content",
        "expected_status": 200,
        "redirect_means": "not_found",
        "failure_markers": ["the specified profile could not be found"],
        "success_markers": ["steamcommunity.com/id/{username}"],
    }
    base.update(overrides)
    return base


@pytest.fixture(autouse=True)
def clear_cache():
    username_search._platform_check_cache.clear()
    yield
    username_search._platform_check_cache.clear()


def check(username: str, response: FakeResponse, plat: dict):
    with patch.object(username_search, "get_http_session") as session:
        session.return_value.get.return_value = response
        return _check_platform(username, plat)


class TestWebContentValidation:
    def test_real_profile_is_found_and_content_validated(self):
        result = check("ghostuser", FakeResponse(200, REAL_PROFILE_HTML), platform())
        assert result.found is True
        assert result.validation_method == VALIDATION_CONTENT
        assert result.is_validated is True
        assert result.profile_url == "https://steamcommunity.com/id/ghostuser"
        assert result.confidence > 0.85

    def test_soft_404_with_failure_marker_is_not_found(self):
        plat = platform(
            name="Instagram",
            url_template="https://www.instagram.com/{username}/",
            failure_markers=["sorry, this page isn't available"],
            success_markers=['"username":"{username}"'],
        )
        result = check("nosuchuser", FakeResponse(200, SOFT_404_HTML), plat)
        assert result.found is False
        assert result.is_validated is False
        assert "not-found marker" in result.validation_evidence

    def test_login_wall_without_profile_marker_is_not_found(self):
        result = check("nosuchuser", FakeResponse(200, LOGIN_WALL_HTML), platform())
        assert result.found is False
        assert "no profile marker" in result.validation_evidence

    def test_username_in_body_validates_when_no_success_markers(self):
        plat = platform(success_markers=None, failure_markers=None,
                        require_username_in_body=True)
        result = check("ghostuser", FakeResponse(200, REAL_PROFILE_HTML), plat)
        assert result.found is True
        assert result.validation_method == VALIDATION_CONTENT

    def test_username_absent_from_body_is_not_found(self):
        plat = platform(success_markers=None, failure_markers=None,
                        require_username_in_body=True)
        result = check("nosuchuser", FakeResponse(200, LOGIN_WALL_HTML), plat)
        assert result.found is False

    def test_empty_body_is_not_found(self):
        result = check("ghostuser", FakeResponse(200, ""), platform())
        assert result.found is False

    def test_markers_are_case_insensitive(self):
        result = check("GhostUser", FakeResponse(200, REAL_PROFILE_HTML.upper()),
                       platform())
        assert result.found is True

    def test_status_only_platform_is_found_but_unvalidated(self):
        plat = platform(success_markers=None, failure_markers=None,
                        require_username_in_body=False)
        result = check("nosuchuser", FakeResponse(200, LOGIN_WALL_HTML), plat)
        assert result.found is True
        assert result.validation_method == VALIDATION_STATUS
        assert result.is_validated is False
        assert result.confidence < 0.5

    def test_legacy_web_status_check_type_is_content_validated(self):
        plat = platform(check_type="web_status")
        assert check("ghostuser", FakeResponse(200, REAL_PROFILE_HTML), plat).found
        assert not check("nosuchuser", FakeResponse(200, LOGIN_WALL_HTML), plat).found

    def test_non_200_status_is_not_found(self):
        result = check("nosuchuser", FakeResponse(404, SOFT_404_HTML), platform())
        assert result.found is False
        assert result.validation_evidence == "HTTP 404"


class TestRedirectHandling:
    @pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
    def test_redirect_defaults_to_not_found(self, status):
        response = FakeResponse(status, "", headers={"Location": "https://steamcommunity.com/login"})
        result = check("nosuchuser", response, platform())
        assert result.found is False
        assert "treated as not_found" in result.validation_evidence

    def test_redirect_can_be_configured_as_found(self):
        response = FakeResponse(302, "", headers={"Location": "https://example.com/u/ghostuser"})
        result = check("ghostuser", response, platform(redirect_means="found"))
        assert result.found is True
        assert result.validation_method == VALIDATION_STATUS
        assert result.profile_url == "https://example.com/u/ghostuser"


class TestApiChecks:
    def test_api_status_hit_is_api_validated(self):
        plat = {
            "name": "GitHub",
            "url_template": "https://api.github.com/users/{username}",
            "check_type": "api_status",
            "expected_status": 200,
        }
        response = FakeResponse(200, "", json_data={"login": "ghostuser",
                                                    "html_url": "https://github.com/ghostuser"})
        result = check("ghostuser", response, plat)
        assert result.found is True
        assert result.is_validated is True
        assert result.profile_url == "https://github.com/ghostuser"


class TestDiscoveredArtifacts:
    def test_confidence_follows_validation_strength(self):
        validated = check("ghostuser", FakeResponse(200, REAL_PROFILE_HTML), platform())
        username_search._platform_check_cache.clear()
        unvalidated = check(
            "ghostuser",
            FakeResponse(200, LOGIN_WALL_HTML),
            platform(name="Pinterest", success_markers=None, failure_markers=None,
                     require_username_in_body=False),
        )

        search_result = UsernameSearchResult(username="ghostuser")
        search_result.platforms_found = [validated, unvalidated]
        artifacts = get_discovered_artifacts(search_result)

        confidences = {a["source"]: a["confidence"] for a in artifacts}
        assert confidences["username_search_steam"] > confidences["username_search_pinterest"]


class TestBundledConfig:
    def test_every_web_platform_defines_content_rules(self):
        web = [p for p in username_search.PLATFORMS
               if p["check_type"] in ("web_status", "web_content")]
        assert len(web) == 9
        for plat in web:
            assert plat.get("success_markers") or plat.get("failure_markers"), plat["name"]
            assert plat.get("redirect_means") == "not_found", plat["name"]
