"""Tests for the run-to-run investigation diff."""

import json
import tempfile
from pathlib import Path

import pytest

from src.reporting.html_report import generate_html_report, generate_json_report
from src.reporting.report_data import build_delta_report, find_previous_investigation
from src.storage import database as db


@pytest.fixture
def conn():
    c = db.get_connection(Path(tempfile.mktemp(suffix=".db")))
    yield c
    c.close()


def _seed_run(conn, *, email_confidence, email_source, extra=None, metadata=None,
              platforms=(), title="Run"):
    inv_id = db.create_investigation(conn, title=title)
    db.add_artifact(conn, inv_id, "username", "ghostuser", source="seed", confidence=1.0)
    db.add_artifact(conn, inv_id, "email", "ghost@example.com", source=email_source,
                    confidence=email_confidence, depth=1, metadata=metadata)
    for atype, value in extra or []:
        db.add_artifact(conn, inv_id, atype, value, source="sherlock", confidence=0.7, depth=1)
    for platform, url in platforms:
        db.add_platform_presence(conn, inv_id, platform_name=platform, profile_url=url,
                                 username="ghostuser")
    return inv_id


@pytest.fixture
def runs(conn):
    baseline = _seed_run(
        conn, email_confidence=0.6, email_source="holehe",
        extra=[("domain", "old.example.com")],
        metadata=json.dumps({"verified": False, "breach_count": 2}),
        platforms=[("GitHub", "https://github.com/ghostuser"),
                   ("Reddit", "https://reddit.com/u/ghostuser")],
        title="Baseline run",
    )
    current = _seed_run(
        conn, email_confidence=0.9, email_source="leakosint",
        extra=[("domain", "new.example.com")],
        metadata=json.dumps({"verified": True, "breach_count": 2, "leak_source": "collection1"}),
        platforms=[("GitHub", "https://github.com/ghostuser"),
                   ("Mastodon", "https://mastodon.social/@ghostuser")],
        title="Current run",
    )
    return baseline, current


class TestDelta:
    def test_added_and_removed_artifacts_are_reported(self, conn, runs):
        baseline, current = runs
        delta = build_delta_report(conn, current, baseline)

        assert [a["value"] for a in delta["added"]] == ["new.example.com"]
        assert [a["value"] for a in delta["removed"]] == ["old.example.com"]
        assert delta["shared_count"] == 2  # seed username + email

    def test_an_artifact_that_moved_is_not_counted_as_unchanged(self, conn, runs):
        baseline, current = runs
        delta = build_delta_report(conn, current, baseline)

        assert delta["changed_count"] == 1
        assert delta["unchanged_count"] == delta["shared_count"] - delta["changed_count"] == 1

    def test_a_redacted_diff_masks_the_values_it_reports(self, conn, runs):
        baseline, current = runs
        delta = build_delta_report(conn, current, baseline, redact=True)

        assert delta["changed"][0]["value"] == "g***@example.com"
        metadata_changes = [c for c in delta["changed"][0]["changes"]
                            if c["field"].startswith("metadata.")]
        assert metadata_changes
        assert all(c["before"] in ("absent", "[REDACTED]")
                   and c["after"] in ("absent", "[REDACTED]") for c in metadata_changes)
        assert all(p["url"] == "[REDACTED_URL]"
                   for p in delta["platforms_added"] + delta["platforms_removed"])

    def test_a_redacted_diff_reduces_a_leaked_record_to_its_database(self, conn):
        record = "collection1: FullName=Ghost User; Password=hunter2; Document=X123"
        baseline = _seed_run(conn, email_confidence=0.8, email_source="holehe")
        current = _seed_run(
            conn, email_confidence=0.8, email_source="holehe",
            extra=[("leak_record", record)],
        )

        delta = build_delta_report(conn, current, baseline, redact=True)

        assert delta["added"][0]["value"] == "collection1: [REDACTED]"
        assert "hunter2" not in json.dumps(delta)

    def test_a_redacted_report_does_not_reprint_the_seed_in_the_diff(
        self, conn, runs, tmp_path
    ):
        baseline, current = runs
        html = Path(generate_html_report(
            conn, current, str(tmp_path / "r.html"), redact=True, compare_id=baseline
        )).read_text()

        # The artifact drill-down's own metadata redaction is a separate concern;
        # what must hold here is that the diff does not re-expose it.
        diff_section = html.split("Changes since", 1)[1].split("<h2", 1)[0]
        assert "ghost@example.com" not in diff_section
        assert "collection1" not in diff_section
        assert "https://mastodon.social/@ghostuser" not in diff_section

    def test_an_artifact_in_both_runs_still_reports_what_moved(self, conn, runs):
        baseline, current = runs
        changed = build_delta_report(conn, current, baseline)["changed"]

        assert len(changed) == 1
        fields = {c["field"]: (c["before"], c["after"]) for c in changed[0]["changes"]}
        assert fields["confidence"] == ("0.6", "0.9")
        assert fields["source"] == ("holehe", "leakosint")
        assert fields["metadata.verified"] == ("False", "True")
        assert fields["metadata.leak_source"] == ("absent", "collection1")
        assert "metadata.breach_count" not in fields  # unchanged

    def test_accounts_gained_and_lost_are_reported(self, conn, runs):
        baseline, current = runs
        delta = build_delta_report(conn, current, baseline)

        assert [p["platform"] for p in delta["platforms_added"]] == ["Mastodon"]
        assert [p["platform"] for p in delta["platforms_removed"]] == ["Reddit"]

    def test_identical_runs_report_no_changes(self, conn):
        first = _seed_run(conn, email_confidence=0.8, email_source="holehe")
        second = _seed_run(conn, email_confidence=0.8, email_source="holehe")

        delta = build_delta_report(conn, second, first)
        assert delta["added"] == []
        assert delta["removed"] == []
        assert delta["changed"] == []
        assert delta["shared_count"] == 2

    def test_no_baseline_leaves_the_section_off(self, conn, runs):
        _, current = runs
        assert build_delta_report(conn, current, None)["enabled"] is False

    def test_an_unknown_baseline_is_reported_rather_than_ignored(self, conn, runs):
        _, current = runs
        delta = build_delta_report(conn, current, "INV-nope")

        assert delta["enabled"] is False
        assert "not found" in delta["error"]


class TestAutoBaseline:
    def test_auto_picks_the_previous_run_of_the_same_seeds(self, conn, runs):
        baseline, current = runs

        assert find_previous_investigation(conn, current) == baseline
        assert build_delta_report(conn, current, "auto")["compare_id"] == baseline

    def test_a_run_with_different_seeds_is_not_a_prior_run(self, conn):
        other = db.create_investigation(conn, title="Someone else")
        db.add_artifact(conn, other, "username", "someoneelse", source="seed")
        current = _seed_run(conn, email_confidence=0.8, email_source="holehe")

        assert find_previous_investigation(conn, current) is None

    def test_auto_with_no_prior_run_says_so(self, conn):
        current = _seed_run(conn, email_confidence=0.8, email_source="holehe")
        delta = build_delta_report(conn, current, "auto")

        assert delta["enabled"] is False
        assert "same seeds" in delta["error"]


class TestRendering:
    def test_the_report_shows_the_field_level_changes(self, conn, runs, tmp_path):
        baseline, current = runs
        html = Path(generate_html_report(
            conn, current, str(tmp_path / "r.html"), compare_id=baseline
        )).read_text()

        assert f"Changes since {baseline}" in html
        assert "metadata.leak_source" in html
        assert "Previous run" in html
        assert "Mastodon" in html

    def test_the_json_report_carries_the_diff(self, conn, runs, tmp_path):
        baseline, current = runs
        payload = json.loads(Path(generate_json_report(
            conn, current, str(tmp_path / "r.json"), compare_id=baseline
        )).read_text())

        assert payload["delta"]["changed"][0]["changes"]
        assert payload["delta"]["compare_id"] == baseline
