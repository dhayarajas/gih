"""Tests for the typed investigation timeline."""

import json
import tempfile
from pathlib import Path

import pytest

from src.reporting.html_report import generate_html_report
from src.reporting.report_data import build_timeline, parse_event_date
from src.storage import database as db


class TestDateParsing:
    @pytest.mark.parametrize("raw,expected", [
        ("2013-10-04", "2013-10-04"),
        ("2019-04-04T11:22:33Z", "2019-04-04T11:22:33"),
        ("2019-04-04 11:22", "2019-04-04T11:22"),
        ("20120515093012", "2012-05-15T09:30:12"),          # Wayback
        ("2018:07:21 14:02:11", "2018-07-21T14:02:11"),      # EXIF
        ("Creation Date: 1995-08-14T04:00:00Z", "1995-08-14T04:00:00"),
    ])
    def test_known_formats_normalise_to_iso(self, raw, expected):
        assert parse_event_date(raw) == expected

    @pytest.mark.parametrize("raw", ["", None, True, "unknown", "REDACTED", "12345", []])
    def test_anything_unrecognised_is_dropped_rather_than_guessed(self, raw):
        assert parse_event_date(raw) is None


@pytest.fixture
def conn():
    c = db.get_connection(Path(tempfile.mktemp(suffix=".db")))
    yield c
    c.close()


@pytest.fixture
def investigation(conn):
    """One artifact per dated-metadata source the timeline understands."""
    inv_id = db.create_investigation(conn, title="Timeline")
    db.add_artifact(conn, inv_id, "username", "ghostuser", source="seed", confidence=0.9)
    db.add_artifact(conn, inv_id, "breach_data", "Adobe (2013-10-04)", source="haveibeenpwned",
                    confidence=0.95, depth=1,
                    metadata=json.dumps({"name": "Adobe", "breach_date": "2013-10-04"}))
    db.add_artifact(conn, inv_id, "domain_info", "example.com", source="whois",
                    confidence=0.95, depth=1,
                    metadata=json.dumps({"creation_date": "1995-08-14T04:00:00Z",
                                         "expiration_date": "2026-08-13T04:00:00Z"}))
    db.add_artifact(conn, inv_id, "historical_url", "http://example.com/old", source="wayback_machine",
                    confidence=0.8, depth=1, metadata=json.dumps({"timestamp": "20120515093012"}))
    db.add_artifact(conn, inv_id, "image", "/tmp/avatar.jpg", source="exiftool",
                    confidence=0.9, depth=1,
                    metadata=json.dumps({"exif": {"DateTimeOriginal": "2018:07:21 14:02:11"}}))
    return inv_id


class TestTimeline:
    def test_every_dated_source_becomes_its_own_event(self, conn, investigation):
        events = build_timeline(db.get_artifacts(conn, investigation))
        by_kind = {}
        for event in events:
            by_kind.setdefault(event["kind"], []).append(event)

        assert by_kind["breach"][0]["when"] == "2013-10-04"
        assert by_kind["registration"][0]["when"] == "1995-08-14T04:00:00"
        assert by_kind["expiry"][0]["when"] == "2026-08-13T04:00:00"
        assert by_kind["archive"][0]["when"] == "2012-05-15T09:30:12"
        assert by_kind["capture"][0]["when"] == "2018-07-21T14:02:11"
        assert len(by_kind["discovery"]) == 5

    def test_events_are_ordered_chronologically(self, conn, investigation):
        whens = [e["when"] for e in build_timeline(db.get_artifacts(conn, investigation))]
        assert whens == sorted(whens)

    def test_discovery_timestamps_are_retained(self, conn, investigation):
        events = build_timeline(db.get_artifacts(conn, investigation))
        discovery = [e for e in events if e["kind"] == "discovery"]
        assert len(discovery) == len(db.get_artifacts(conn, investigation))
        assert all(e["artifact_id"] for e in discovery)

    def test_nested_metadata_dates_are_found(self, conn, investigation):
        events = build_timeline(db.get_artifacts(conn, investigation))
        capture = [e for e in events if e["kind"] == "capture"][0]
        assert capture["source"] == "exiftool"
        assert capture["detail"] == "DateTimeOriginal"

    def test_undated_and_malformed_metadata_yields_only_discovery(self, conn):
        inv_id = db.create_investigation(conn, title="Bare")
        db.add_artifact(conn, inv_id, "email", "a@example.com", source="holehe",
                        metadata="{not json")
        db.add_artifact(conn, inv_id, "phone", "+14155550123", source="phone_osint",
                        metadata=json.dumps({"breach_date": "never"}))

        kinds = {e["kind"] for e in build_timeline(db.get_artifacts(conn, inv_id))}
        assert kinds == {"discovery"}

    def test_the_report_renders_typed_events_linked_to_their_artifacts(
        self, conn, investigation, tmp_path
    ):
        path = generate_html_report(conn, investigation, str(tmp_path / "r.html"))
        html = Path(path).read_text()

        assert "Credentials exposed in a breach" in html
        assert 'class="timeline-event kind-archive"' in html
        assert 'data-kind="capture"' in html
        artifact_id = db.get_artifacts(conn, investigation)[0]["artifact_id"]
        assert f'href="#artifact-{artifact_id}"' in html

    def test_json_report_carries_the_timeline(self, conn, investigation, tmp_path):
        from src.reporting.html_report import generate_json_report

        path = generate_json_report(conn, investigation, str(tmp_path / "r.json"))
        payload = json.loads(Path(path).read_text())

        kinds = {e["kind"] for e in payload["timeline"]}
        assert {"breach", "registration", "archive", "capture", "discovery"} <= kinds
