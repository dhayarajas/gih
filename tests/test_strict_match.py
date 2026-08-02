"""Tests for the strict-match policy applied to every OSINT source."""

from src.orchestrator import (
    ArtifactProcessResult,
    InvestigationConfig,
    _apply_match_policy,
    _keep_full_matches,
)
from src.utils.matching import (
    MatchPolicy,
    contains_exact,
    filter_full_matches,
    get_match_policy,
    is_full_match,
)


class TestContainsExact:
    def test_whole_token_matches_across_separators(self):
        assert contains_exact("https://github.com/octocat", "octocat")
        assert contains_exact("github:octocat", "octocat")
        assert contains_exact("Octocat", "octocat")

    def test_substring_of_a_longer_handle_is_not_a_match(self):
        assert not contains_exact("https://github.com/octocat99", "octocat")
        assert not contains_exact("the_octocat", "octocat")
        assert not contains_exact("", "octocat")


class TestIsFullMatch:
    def test_account_artifact_needs_the_exact_handle(self):
        target = "octocat"
        assert is_full_match(
            {"type": "username_presence", "value": "https://github.com/octocat"}, target
        )
        assert not is_full_match(
            {"type": "username_presence", "value": "https://github.com/octocat-bot"}, target
        )

    def test_search_derived_username_must_be_the_target(self):
        assert is_full_match({"type": "username", "value": "OctoCat"}, "octocat")
        assert not is_full_match({"type": "username", "value": "octocat2"}, "octocat")

    def test_email_matches_on_its_local_part(self):
        assert is_full_match({"type": "email", "value": "octocat@example.com"}, "octocat")
        assert not is_full_match({"type": "email", "value": "hr@example.com"}, "octocat")

    def test_infrastructure_artifacts_are_always_kept(self):
        for artifact_type in ("subdomain", "open_port", "dns_mx", "breach"):
            assert is_full_match({"type": artifact_type, "value": "anything"}, "octocat")


class TestFilterFullMatches:
    def test_disabled_policy_keeps_everything(self):
        artifacts = [{"type": "username", "value": "octocat2"}]
        kept, dropped = filter_full_matches(artifacts, "octocat", MatchPolicy(enabled=False))
        assert kept == artifacts and dropped == []

    def test_enabled_policy_splits_partial_hits(self):
        artifacts = [
            {"type": "username", "value": "octocat"},
            {"type": "username", "value": "octocat2"},
        ]
        kept, dropped = filter_full_matches(artifacts, "octocat", MatchPolicy())
        assert [a["value"] for a in kept] == ["octocat"]
        assert [a["value"] for a in dropped] == ["octocat2"]

    def test_config_default_is_strict(self):
        policy = get_match_policy()
        assert policy.enabled and policy.require_validated_presence


class TestOrchestratorIntegration:
    def test_keep_full_matches_filters_tool_output(self):
        artifacts = [
            {"type": "username_presence", "value": "github:octocat", "platform": "github"},
            {"type": "username_presence", "value": "github:octocat-bot", "platform": "github"},
        ]
        kept = _keep_full_matches(artifacts, "octocat", MatchPolicy())
        assert [a["value"] for a in kept] == ["github:octocat"]

    def test_unvalidated_presences_dropped_but_tool_rows_kept(self):
        result = ArtifactProcessResult(artifact={"type": "username", "value": "octocat"})
        result.platform_presences = [
            {"platform_name": "GitHub", "is_verified": True},
            {"platform_name": "Pinterest", "is_verified": False},
            {"platform_name": "Steam"},  # sherlock-style row, no verdict
        ]
        _apply_match_policy(result, "octocat", MatchPolicy())
        assert [p["platform_name"] for p in result.platform_presences] == ["GitHub", "Steam"]

    def test_policy_disabled_leaves_presences_untouched(self):
        result = ArtifactProcessResult(artifact={"type": "username", "value": "octocat"})
        result.platform_presences = [{"platform_name": "Pinterest", "is_verified": False}]
        result.discovered = [{"type": "username", "value": "octocat2"}]
        _apply_match_policy(result, "octocat", MatchPolicy(enabled=False))
        assert len(result.platform_presences) == 1
        assert len(result.discovered) == 1

    def test_investigation_config_defaults_to_the_configured_policy(self):
        assert InvestigationConfig().match_policy == get_match_policy()

    def test_name_variants_are_skipped_when_disallowed(self):
        from src.orchestrator import _process_fullname

        result = ArtifactProcessResult(artifact={"type": "fullname", "value": "Ada Lovelace"})
        config = InvestigationConfig(
            check_external_tools=False,
            check_images=False,
            match_policy=MatchPolicy(allow_name_variants=False),
        )
        _process_fullname("Ada Lovelace", config, result)

        assert not [a for a in result.discovered if a["type"] == "username"]
