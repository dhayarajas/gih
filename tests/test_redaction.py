"""Tests for what a --redact report is allowed to still say."""

import json
import tempfile
from pathlib import Path

import pytest

from src.reporting.html_report import generate_html_report, generate_json_report
from src.reporting.report_data import (
    _is_personal_key,
    _redact_metadata,
    build_cross_investigation,
    redact_context,
)
from src.storage import database as db


@pytest.fixture
def conn():
    c = db.get_connection(Path(tempfile.mktemp(suffix=".db")))
    yield c
    c.close()


@pytest.fixture
def investigation(conn):
    inv_id = db.create_investigation(conn, title="Case for ghost@example.com")
    db.add_artifact(conn, inv_id, "username", "ghostuser", source="seed")
    db.add_artifact(
        conn, inv_id, "email", "ghost@example.com", source="holehe", depth=1,
        metadata=json.dumps({
            "profile_url": "https://mastodon.social/@ghostuser",
            "image_url": "https://cdn.example.com/avatars/ghostuser.png",
            "full_name": "Ghost User",
            "city": "Chennai",
            "breach_date": "2013-10-04",
            "breach_count": 2,
            "notes": "reachable on ghost@example.com or +1 415 555 0132",
            "nested": [{"home_address": "12 Real Street"}],
        }),
    )
    db.add_artifact(
        conn, inv_id, "image_url",
        "https://cdn.example.com/avatars/ghostuser.png", source="maigret", depth=1,
    )
    db.add_platform_presence(
        conn, inv_id, platform_name="Mastodon",
        profile_url="https://mastodon.social/@ghostuser",
        username="ghostuser", display_name="Ghost User",
        bio="Ghost User, engineer in Chennai",
    )
    db.add_audit_log(
        conn, inv_id, action="investigation_started",
        entity_type="investigation", entity_id=inv_id,
        details=json.dumps({"seed_count": 1, "title": "Case for ghost@example.com"}),
    )
    return inv_id


class TestPersonalKeys:
    @pytest.mark.parametrize("key", [
        "profile_url", "image_url", "avatarURL", "full_name", "home_address",
        "city", "gps", "Password", "DateOfBirth", "ip", "phone_number",
    ])
    def test_a_key_naming_the_subject_is_personal(self, key):
        assert _is_personal_key(key)

    @pytest.mark.parametrize("key", [
        "description", "breach_count", "confidence", "platform_name",
        "database", "tool_version", "status_code", "recipient_count",
    ])
    def test_a_key_describing_the_collection_is_not(self, key):
        assert not _is_personal_key(key)


class TestMetadataRedaction:
    def test_personal_fields_are_dropped_and_dates_kept(self):
        clean = _redact_metadata({
            "profile_url": "https://example.com/u/ghostuser",
            "full_name": "Ghost User",
            "breach_date": "2013-10-04",
            "breach_count": 2,
        })

        assert clean == {
            "profile_url": "[REDACTED_URL]",
            "full_name": "[REDACTED]",
            "breach_date": "2013-10-04",
            "breach_count": 2,
        }

    def test_detail_buried_in_free_text_is_masked(self):
        clean = _redact_metadata({"notes": "write to ghost@example.com"})

        assert "ghost@example.com" not in clean["notes"]

    def test_nested_structures_are_walked(self):
        clean = _redact_metadata({"records": [{"home_address": "12 Real Street"}]})

        assert clean == {"records": [{"home_address": "[REDACTED]"}]}

    def test_a_self_written_biography_is_dropped(self):
        """maigret returns the account's bio verbatim, names and all."""
        clean = _redact_metadata({
            "bio": "Ghost User, engineer in Chennai",
            "verified_reason": "CEO of Example Corp",
            "follower_count": "2339949",
        })

        assert clean["bio"] == "[REDACTED]"
        assert clean["verified_reason"] == "[REDACTED]"
        assert clean["follower_count"] == "2339949"

    def test_a_url_under_an_innocent_key_is_still_dropped(self):
        assert _redact_metadata({"evidence": "https://example.com/u/ghostuser"}) == {
            "evidence": "[REDACTED_URL]"
        }


class TestReportOutput:
    def test_the_html_report_keeps_no_personal_metadata(
        self, conn, investigation, tmp_path
    ):
        html = Path(generate_html_report(
            conn, investigation, str(tmp_path / "r.html"), redact=True
        )).read_text()

        for secret in ("ghost@example.com", "mastodon.social/@ghostuser",
                       "avatars/ghostuser.png", "Ghost User", "Chennai",
                       "engineer in Chennai",
                       "12 Real Street", "415 555 0132"):
            assert secret not in html
        assert "2013-10-04" in html  # a date identifies no one

    def test_the_json_report_keeps_no_personal_metadata(
        self, conn, investigation, tmp_path
    ):
        payload = Path(generate_json_report(
            conn, investigation, str(tmp_path / "r.json"), redact=True
        )).read_text()

        assert "ghost@example.com" not in payload
        assert "12 Real Street" not in payload
        assert "avatars/ghostuser.png" not in payload
        assert "engineer in Chennai" not in payload

    def test_without_redaction_nothing_is_hidden(
        self, conn, investigation, tmp_path
    ):
        html = Path(generate_html_report(
            conn, investigation, str(tmp_path / "plain.html")
        )).read_text()

        assert "ghost@example.com" in html
        assert "Ghost User" in html
        assert "engineer in Chennai" in html
        assert "avatars/ghostuser.png" in html


class TestContext:
    def test_the_case_title_audit_rows_and_notes_are_masked(self, conn, investigation):
        inv, trail, notes = redact_context(
            db.get_investigation(conn, investigation),
            db.get_audit_trail(conn, investigation),
            [{"author": "analyst", "content": "subject is ghost@example.com"}],
            True,
        )

        assert "ghost@example.com" not in inv["title"]
        assert all("ghost@example.com" not in (r.get("details") or "") for r in trail)
        assert "ghost@example.com" not in notes[0]["content"]

    def test_disabled_redaction_returns_the_originals_untouched(self, conn, investigation):
        trail = db.get_audit_trail(conn, investigation)
        inv, same_trail, notes = redact_context(
            db.get_investigation(conn, investigation), trail, [], False
        )

        assert same_trail is trail
        assert "ghost@example.com" in inv["title"]


class TestCrossInvestigation:
    def test_a_match_in_another_case_is_reported_without_its_value(
        self, conn, investigation
    ):
        other = db.create_investigation(conn, title="Other")
        db.add_artifact(conn, other, "email", "ghost@example.com", source="holehe")

        artifacts = db.get_artifacts(conn, investigation)
        hits = build_cross_investigation(conn, investigation, artifacts, redact=True)

        assert hits
        assert all("ghost@example.com" != h["value"] for h in hits)

    def test_a_redacted_report_still_finds_the_match(
        self, conn, investigation, tmp_path
    ):
        """Matching runs on the stored values; only the output is masked.

        Comparing already-masked values against the database matches nothing,
        which empties the section instead of hiding the values in it.
        """
        other = db.create_investigation(conn, title="Other")
        db.add_artifact(conn, other, "email", "ghost@example.com", source="holehe")

        payload = json.loads(Path(generate_json_report(
            conn, investigation, str(tmp_path / "r.json"), redact=True
        )).read_text())

        assert payload["cross_investigation"]
        assert all(h["value"] != "ghost@example.com"
                   for h in payload["cross_investigation"])
        assert any(h["investigation_id"] == other
                   for h in payload["cross_investigation"])
