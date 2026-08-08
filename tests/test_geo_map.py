"""Tests for plotting location signals on the report map."""

import json
import tempfile
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

    def test_no_location_signals_means_no_map(self, conn, tmp_path):
        inv = db.create_investigation(conn, title="No geo")
        db.add_artifact(conn, inv, "username", "someone", source="seed", confidence=1.0)
        html = Path(generate_html_report(
            conn, inv, str(tmp_path / "r.html"), template_type="standard"
        )).read_text()
        assert 'id="gih-map"' not in html
        assert "unpkg.com/leaflet" not in html
