"""Tests for plotting location signals on the report map."""

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.reporting import geo
from src.reporting.geo import build_map_points, parse_coordinates
from src.reporting.html_report import generate_html_report
from src.storage import database as db


@pytest.fixture
def conn():
    c = db.get_connection(Path(tempfile.mktemp(suffix=".db")))
    yield c
    c.close()


class TestParseCoordinates:
    def test_decimal_pair(self):
        assert parse_coordinates("37.802139,-122.405833") == (37.802139, -122.405833)

    def test_decimal_pair_with_spaces_and_semicolon(self):
        assert parse_coordinates(" 12.5 ; 77.6 ") == (12.5, 77.6)

    def test_exiftool_degrees_minutes_seconds(self):
        lat, lon = parse_coordinates("48 deg 51' 29.60\" N, 2 deg 17' 40.20\" E")
        assert lat == pytest.approx(48.8582, abs=1e-4)
        assert lon == pytest.approx(2.2945, abs=1e-4)

    def test_southern_and_western_hemispheres_are_negative(self):
        lat, lon = parse_coordinates("33 deg 51' 24.00\" S, 151 deg 12' 36.00\" W")
        assert lat < 0 and lon < 0

    def test_longitude_first_is_reordered(self):
        lat, lon = parse_coordinates("2 deg 17' 40.20\" E, 48 deg 51' 29.60\" N")
        assert lat == pytest.approx(48.8582, abs=1e-4)
        assert lon == pytest.approx(2.2945, abs=1e-4)

    def test_out_of_range_pair_is_not_a_coordinate(self):
        """A version string reads like a pair; the earth's range rejects it."""
        assert parse_coordinates("1024,768") is None

    def test_place_name_is_not_a_coordinate(self):
        assert parse_coordinates("Bengaluru, India") is None

    def test_empty(self):
        assert parse_coordinates("") is None


class TestBuildMapPoints:
    def test_coordinates_need_no_geocoder(self, conn):
        points = build_map_points(
            conn, [{"type": "gps_coordinates", "value": "37.8,-122.4", "source": "exiftool"}],
            geocode=False,
        )
        assert len(points) == 1
        assert points[0]["precise"] is True
        assert points[0]["source"] == "exiftool"

    def test_unparseable_coordinate_is_dropped_not_geocoded(self, conn, monkeypatch):
        monkeypatch.setattr(geo, "_geocode", lambda place: pytest.fail("geocoded a coordinate"))
        assert build_map_points(
            conn, [{"type": "gps_coordinates", "value": "unknown", "source": "exiftool"}]
        ) == []

    def test_a_platform_name_is_never_geocoded(self, conn, monkeypatch):
        """A located bio yields a signal whose value is the platform, not a place."""
        monkeypatch.setattr(geo, "_geocode", lambda place: pytest.fail(f"geocoded {place}"))
        assert build_map_points(
            conn, [{"type": "platform", "value": "GitHub", "source": "platform_bio"}]
        ) == []

    def test_a_platform_name_does_not_spend_a_real_place_s_lookup(self, conn, monkeypatch):
        asked = []
        monkeypatch.setattr(geo, "_GEOCODE_INTERVAL", 0)
        monkeypatch.setattr(
            geo, "_geocode",
            lambda place: (asked.append(place), (1.0, len(asked) + 0.0, place))[1],
        )
        locations = [
            {"type": "platform", "value": f"Platform{i}", "source": "platform_bio"}
            for i in range(geo._GEOCODE_BUDGET)
        ] + [{"type": "location", "value": "Paris", "source": "plugin:MaigretPlugin"}]
        points = build_map_points(conn, locations)
        assert asked == ["Paris"]
        assert [p["value"] for p in points] == ["Paris"]

    def test_place_name_is_geocoded_and_marked_approximate(self, conn, monkeypatch):
        monkeypatch.setattr(
            geo, "_geocode", lambda place: (12.97, 77.59, "Bengaluru, Karnataka, India")
        )
        points = build_map_points(
            conn, [{"type": "location", "value": "Bengaluru", "source": "plugin:MaigretPlugin"}]
        )
        assert points[0]["precise"] is False
        assert points[0]["label"] == "Bengaluru, Karnataka, India"
        assert points[0]["value"] == "Bengaluru"

    def test_geocoder_is_asked_once_per_place(self, conn, monkeypatch):
        calls = []

        def fake(place):
            calls.append(place)
            return (1.0, 2.0, place)

        monkeypatch.setattr(geo, "_geocode", fake)
        locations = [{"type": "location", "value": "Paris", "source": "bio"}]
        build_map_points(conn, locations)
        build_map_points(conn, locations)
        assert calls == ["Paris"]

    def test_an_unresolvable_place_is_not_retried(self, conn, monkeypatch):
        calls = []

        def fake(place):
            calls.append(place)

        monkeypatch.setattr(geo, "_geocode", fake)
        locations = [{"type": "location", "value": "nowhere at all", "source": "bio"}]
        assert build_map_points(conn, locations) == []
        assert build_map_points(conn, locations) == []
        assert calls == ["nowhere at all"]

    def test_a_stale_miss_is_asked_again(self, conn, monkeypatch):
        """A failure is often the network, so it must not silence a place forever."""
        calls = []

        def fake(place):
            calls.append(place)
            return None if len(calls) == 1 else (48.85, 2.29, "Paris, France")

        monkeypatch.setattr(geo, "_geocode", fake)
        locations = [{"type": "location", "value": "Paris", "source": "bio"}]
        assert build_map_points(conn, locations) == []

        stale = (datetime.now(timezone.utc) - geo.MISS_TTL - timedelta(days=1))
        conn.execute("UPDATE geocode_cache SET resolved_at = ? WHERE place = 'paris'",
                     (stale.isoformat(timespec="seconds"),))
        conn.commit()

        points = build_map_points(conn, locations)
        assert [p["label"] for p in points] == ["Paris, France"]
        assert calls == ["Paris", "Paris"]

    def test_a_resolved_place_is_never_asked_again(self, conn, monkeypatch):
        """A place does not move, so a hit does not expire the way a miss does."""
        calls = []
        monkeypatch.setattr(
            geo, "_geocode",
            lambda place: (calls.append(place), (1.0, 2.0, place))[1],
        )
        locations = [{"type": "location", "value": "Paris", "source": "bio"}]
        build_map_points(conn, locations)

        old = datetime.now(timezone.utc) - geo.MISS_TTL - timedelta(days=30)
        conn.execute("UPDATE geocode_cache SET resolved_at = ? WHERE place = 'paris'",
                     (old.isoformat(timespec="seconds"),))
        conn.commit()

        assert len(build_map_points(conn, locations)) == 1
        assert calls == ["Paris"]

    def test_geocoding_off_keeps_report_generation_offline(self, conn, monkeypatch):
        monkeypatch.setattr(geo, "_geocode", lambda place: pytest.fail("network used"))
        points = build_map_points(
            conn,
            [{"type": "location", "value": "Paris", "source": "bio"},
             {"type": "gps_coordinates", "value": "48.85,2.29", "source": "exiftool"}],
            geocode=False,
        )
        assert [p["value"] for p in points] == ["48.85,2.29"]

    def test_same_place_from_two_sources_is_plotted_once(self, conn):
        points = build_map_points(
            conn,
            [{"type": "gps_coordinates", "value": "48.8582,2.2945", "source": "exiftool"},
             {"type": "gps_coordinates", "value": "48.85820,2.29450", "source": "exiftool"}],
            geocode=False,
        )
        assert len(points) == 1

    def test_lookup_budget_caps_the_wait(self, conn, monkeypatch):
        monkeypatch.setattr(
            geo, "_geocode",
            lambda place: (float(place.rsplit("-", 1)[1]), 2.0, place),
        )
        monkeypatch.setattr(geo, "_GEOCODE_INTERVAL", 0)
        locations = [
            {"type": "location", "value": f"place-{i}", "source": "bio"} for i in range(20)
        ]
        assert len(build_map_points(conn, locations)) == geo._GEOCODE_BUDGET

    def test_a_self_declared_place_is_not_authoritative(self, conn, monkeypatch):
        """A profile's "Mars" resolves to a French village; it is still a claim."""
        monkeypatch.setattr(geo, "_geocode", lambda place: (45.02, 4.32, "Mars, France"))
        points = build_map_points(
            conn, [{"type": "location", "value": "Mars", "source": "maigret"}]
        )
        assert points[0]["basis"] == geo.BASIS_SELF_DECLARED
        assert points[0]["authoritative"] is False
        assert points[0]["basis_label"] == "self-declared, unverified"

    def test_exif_coordinates_are_authoritative(self, conn):
        points = build_map_points(
            conn, [{"type": "gps_coordinates", "value": "37.8,-122.4", "source": "exiftool"}],
            geocode=False,
        )
        assert points[0]["basis"] == geo.BASIS_MEASURED
        assert points[0]["authoritative"] is True

    @pytest.mark.parametrize("source", ["exiftool", "image_exif_gps"])
    def test_every_exif_extractor_yields_a_measured_coordinate(self, conn, source):
        """The native extractor's name differs from exiftool's; the GPS does not."""
        points = build_map_points(
            conn, [{"type": "location", "value": "37.802139,-122.405833", "source": source}],
            geocode=False,
        )
        assert points[0]["basis"] == geo.BASIS_MEASURED
        assert points[0]["authoritative"] is True

    @pytest.mark.parametrize("source,loc_type", [
        ("whois", "location"),
        ("shodan", "city"),
        ("phone_osint", "phone_region"),
        ("PhoneValidationPlugin", "location"),
    ])
    def test_a_place_from_a_record_the_subject_does_not_write_is_plotted(
        self, conn, monkeypatch, source, loc_type
    ):
        monkeypatch.setattr(geo, "_geocode", lambda place: (48.85, 2.29, "Paris, France"))
        points = build_map_points(
            conn, [{"type": loc_type, "value": "Paris", "source": source}]
        )
        assert points[0]["basis"] == geo.BASIS_RECORDED
        assert points[0]["authoritative"] is True

    def test_a_second_source_corroborates_a_claimed_place(self, conn, monkeypatch):
        monkeypatch.setattr(geo, "_geocode", lambda place: (48.85, 2.29, "Paris, France"))
        points = build_map_points(
            conn,
            [{"type": "location", "value": "Paris", "source": "maigret"},
             {"type": "location", "value": "Paris", "source": "bio on GitHub"}],
        )
        assert len(points) == 1
        assert points[0]["basis"] == geo.BASIS_CORROBORATED
        assert points[0]["authoritative"] is True
        assert points[0]["sources"] == ["maigret", "bio on GitHub"]

    def test_the_same_source_naming_a_place_twice_does_not_corroborate_itself(
        self, conn, monkeypatch
    ):
        monkeypatch.setattr(geo, "_geocode", lambda place: (48.85, 2.29, "Paris, France"))
        points = build_map_points(
            conn,
            [{"type": "location", "value": "Paris", "source": "maigret"},
             {"type": "city", "value": "Paris", "source": "maigret"}],
        )
        assert points[0]["authoritative"] is False

    def test_a_measured_coordinate_outranks_a_claim_at_the_same_place(self, conn):
        points = build_map_points(
            conn,
            [{"type": "location", "value": "37.8,-122.4", "source": "maigret"},
             {"type": "gps_coordinates", "value": "37.8,-122.4", "source": "exiftool"}],
            geocode=False,
        )
        assert points[0]["basis"] == geo.BASIS_MEASURED
        assert points[0]["source"] == "exiftool"

    def test_an_unknown_source_is_treated_as_the_subject_s_own_claim(self, conn, monkeypatch):
        monkeypatch.setattr(geo, "_geocode", lambda place: (1.0, 2.0, place))
        points = build_map_points(
            conn, [{"type": "location", "value": "Somewhere", "source": "a new tool"}]
        )
        assert points[0]["authoritative"] is False

    def test_an_unreachable_geocoder_does_not_break_the_report(self, conn, monkeypatch):
        """A transport error costs the map a point, nothing more."""
        monkeypatch.setattr(geo, "NOMINATIM_URL", "http://127.0.0.1:1/search")
        assert build_map_points(
            conn, [{"type": "location", "value": "Paris", "source": "bio"}]
        ) == []


class TestMapInReport:
    def _investigation(self, conn, **kwargs):
        inv = db.create_investigation(conn, title="Geo")
        db.add_artifact(conn, inv, "image", "/tmp/p.jpg", source="seed", confidence=1.0)
        db.add_artifact(conn, inv, "gps_coordinates", "37.802139,-122.405833",
                        source="exiftool", confidence=0.9, depth=1)
        db.add_artifact(conn, inv, "phone", "+14155550123", source="phone_osint",
                        confidence=0.6, depth=1,
                        metadata=json.dumps({"country": "California"}))
        return inv

    def test_map_is_in_the_overview_with_the_points(self, conn, monkeypatch, tmp_path):
        monkeypatch.setattr(geo, "_geocode", lambda place: (36.7, -118.75, "California, US"))
        inv = self._investigation(conn)
        html = Path(generate_html_report(
            conn, inv, str(tmp_path / "r.html"), template_type="standard"
        )).read_text()

        overview = html.split('class="detail-controls"')[0]
        assert 'id="gih-map"' in overview
        assert "leaflet" in overview.lower() or "leaflet" in html.split("<body")[0].lower()
        assert "37.802139" in overview and "36.7" in overview

    def test_the_external_map_link_is_gone(self, conn, monkeypatch, tmp_path):
        monkeypatch.setattr(geo, "_geocode", lambda place: None)
        inv = self._investigation(conn)
        html = Path(generate_html_report(
            conn, inv, str(tmp_path / "r.html"), template_type="standard"
        )).read_text()
        assert "Open approximate map view" not in html
        assert "openstreetmap.org/search" not in html

    def test_redacted_reports_plot_nothing(self, conn, monkeypatch, tmp_path):
        monkeypatch.setattr(geo, "_geocode", lambda place: pytest.fail("geocoded while redacted"))
        inv = self._investigation(conn)
        html = Path(generate_html_report(
            conn, inv, str(tmp_path / "r.html"), template_type="standard", redact=True
        )).read_text()
        assert 'id="gih-map"' not in html

    def test_a_place_named_by_a_tool_reaches_the_map(self, conn, monkeypatch, tmp_path):
        """A city artifact is a location signal, whoever called it what."""
        monkeypatch.setattr(geo, "_geocode", lambda place: (37.77, -122.41, "San Francisco"))
        inv = db.create_investigation(conn, title="Named place")
        db.add_artifact(conn, inv, "username", "someone", source="seed", confidence=1.0)
        db.add_artifact(conn, inv, "city", "San Francisco", source="shodan",
                        confidence=0.4, depth=1)
        html = Path(generate_html_report(
            conn, inv, str(tmp_path / "r.html"), template_type="standard"
        )).read_text()
        assert 'id="gih-map"' in html
        assert "San Francisco" in html

    def test_a_self_declared_place_gets_no_marker_and_says_why(
        self, conn, monkeypatch, tmp_path
    ):
        monkeypatch.setattr(geo, "_geocode", lambda place: (45.02, 4.32, "Mars, France"))
        inv = db.create_investigation(conn, title="Claimed")
        db.add_artifact(conn, inv, "username", "someone", source="seed", confidence=1.0)
        db.add_artifact(conn, inv, "location", "Mars", source="maigret",
                        confidence=0.5, depth=1)
        html = Path(generate_html_report(
            conn, inv, str(tmp_path / "r.html"), template_type="standard"
        )).read_text()

        assert 'id="gih-map"' not in html
        assert "Self-declared, unverified &mdash; not plotted (1)" in html
        assert "named only by maigret" in html

    def test_a_withheld_claim_is_not_reported_as_a_geocoding_failure(
        self, conn, monkeypatch, tmp_path
    ):
        """A resolved-but-withheld place did resolve, whatever the map shows."""
        monkeypatch.setattr(
            geo, "_geocode",
            lambda place: (45.02, 4.32, "Mars, France") if place == "Mars" else None,
        )
        inv = db.create_investigation(conn, title="Claimed and unplottable")
        db.add_artifact(conn, inv, "username", "someone", source="seed", confidence=1.0)
        db.add_artifact(conn, inv, "location", "Mars", source="maigret",
                        confidence=0.5, depth=1)
        db.add_artifact(conn, inv, "location", "Nowhere in particular", source="maigret",
                        confidence=0.5, depth=1)
        html = Path(generate_html_report(
            conn, inv, str(tmp_path / "r.html"), template_type="standard"
        )).read_text()

        assert "Not plottable (1)" in html
        assert "No place could be put on a map" not in html

    def test_a_plotted_place_names_the_source_that_asserted_it(
        self, conn, monkeypatch, tmp_path
    ):
        monkeypatch.setattr(geo, "_geocode", lambda place: (48.85, 2.29, "Paris, France"))
        inv = db.create_investigation(conn, title="Recorded")
        db.add_artifact(conn, inv, "domain", "example.com", source="seed", confidence=1.0)
        db.add_artifact(conn, inv, "location", "Paris", source="whois",
                        confidence=0.4, depth=1)
        html = Path(generate_html_report(
            conn, inv, str(tmp_path / "r.html"), template_type="standard"
        )).read_text()

        assert 'id="gih-map"' in html
        assert "third-party record &middot; named by whois" in html
        assert "Places named by these sources" in html
        assert "not a movement history and not a last-known position" in html

    def test_no_location_signals_means_no_map(self, conn, tmp_path):
        inv = db.create_investigation(conn, title="No geo")
        db.add_artifact(conn, inv, "username", "someone", source="seed", confidence=1.0)
        html = Path(generate_html_report(
            conn, inv, str(tmp_path / "r.html"), template_type="standard"
        )).read_text()
        assert 'id="gih-map"' not in html
        assert "unpkg.com/leaflet" not in html
