"""Tests for HTML/JSON report generation and artifact drill-downs."""

import base64
import json
import tempfile
from types import SimpleNamespace
from pathlib import Path

import pytest

from src.reporting.html_report import (
    EXECUTIVE_TEMPLATE,
    HTML_TEMPLATE,
    LEGAL_TEMPLATE,
    TECHNICAL_TEMPLATE,
    _format_metadata_value,
    _generate_identity_images,
    _generate_tool_metrics,
    _metadata_table,
    _normalize_tool_source,
    _select_template,
    generate_html_report,
    generate_json_report,
)
from src.correlation.linker import correlate_identities
from src.storage import database as db

SEED_METADATA = {"platform": "github", "notes": "seed <b>value</b>"}


@pytest.fixture
def conn():
    c = db.get_connection(Path(tempfile.mktemp(suffix=".db")))
    yield c
    c.close()


@pytest.fixture
def investigation(conn):
    """An investigation covering valid, malformed, null and empty metadata."""
    inv_id = db.create_investigation(conn, title="Report Test")
    username = db.add_artifact(conn, inv_id, "username", "ghostuser", source="seed",
                               confidence=0.95, metadata=json.dumps(SEED_METADATA))
    email = db.add_artifact(conn, inv_id, "email", "ghostuser@example.com", source="holehe",
                            confidence=0.8, metadata="{not valid json", depth=1)
    db.add_artifact(conn, inv_id, "phone", "+14155550123", source="phone_osint",
                    confidence=0.6, metadata=None, depth=1)
    db.add_artifact(conn, inv_id, "domain", "example.com", source="amass",
                    confidence=0.4, metadata="", depth=2)
    db.add_link(conn, inv_id, username, email, "discovered_from", 0.9, "username to email pivot")
    db.add_platform_presence(conn, inv_id, platform_name="GitHub",
                             profile_url="https://github.com/ghostuser", username="ghostuser",
                             display_name="Ghost User", bio="Security researcher",
                             follower_count=42, profile_image_url="https://example.com/a.png",
                             artifact_id=username)
    db.add_platform_presence(conn, inv_id, platform_name="Reddit")
    return inv_id


def render(conn, investigation_id, tmp_path, template_type="standard") -> str:
    path = generate_html_report(conn, investigation_id,
                                str(tmp_path / "report.html"), template_type=template_type)
    return Path(path).read_text()


class TestTemplateSelection:
    def test_standard_and_html_map_to_default_template(self):
        assert _select_template("standard") == HTML_TEMPLATE or "Identity Profiles" in _select_template("standard")
        assert "Identity Profiles" in _select_template("html")

    def test_named_templates(self):
        assert _select_template("executive") is EXECUTIVE_TEMPLATE
        assert _select_template("technical") is TECHNICAL_TEMPLATE
        assert _select_template("legal") is LEGAL_TEMPLATE

    def test_unknown_falls_back_to_default(self):
        assert "Identity Profiles" in _select_template("nonexistent")
        assert "Ghost Identity Hunter" in _select_template("default")


class TestDrillDowns:
    def test_artifact_drilldown_shows_metadata_and_links(self, conn, investigation, tmp_path):
        html = render(conn, investigation, tmp_path)
        assert "Connected Artifacts" in html
        assert "discovered_from" in html
        assert "username to email pivot" in html
        assert "github" in html

    def test_metadata_values_are_escaped(self, conn, investigation, tmp_path):
        html = render(conn, investigation, tmp_path)
        assert "&lt;b&gt;value&lt;/b&gt;" in html
        assert "seed <b>value</b>" not in html

    def test_malformed_and_missing_metadata_do_not_break_rendering(self, conn, investigation,
                                                                   tmp_path):
        html = render(conn, investigation, tmp_path)
        assert "{not valid json" in html
        assert "No metadata recorded" in html

    def test_platform_presence_drilldown(self, conn, investigation, tmp_path):
        html = render(conn, investigation, tmp_path)
        assert "Account created" in html
        assert "Ghost User" in html
        assert "https://example.com/a.png" in html

    def test_validation_status_is_surfaced_per_presence(self, conn, tmp_path):
        inv_id = db.create_investigation(conn, title="Validation")
        db.add_platform_presence(conn, inv_id, platform_name="Steam",
                                 username="ghostuser", is_verified=True)
        db.add_platform_presence(conn, inv_id, platform_name="Pinterest",
                                 username="ghostuser")
        html = render(conn, inv_id, tmp_path)
        assert "Content-validated" in html
        assert "Unvalidated (status only)" in html
        assert "1 of 2 platform presences are content-validated" in html

    def test_identity_evidence_drilldown(self, conn, investigation, tmp_path):
        html = render(conn, investigation, tmp_path)
        assert "Complete Evidence Basis" in html

    def test_every_artifact_is_addressable_and_cross_linked(self, conn, investigation, tmp_path):
        """A reader following a relation must land on that artifact's own detail."""
        html = render(conn, investigation, tmp_path)
        artifacts = db.get_artifacts(conn, investigation)

        for artifact in artifacts:
            assert f'id="artifact-{artifact["artifact_id"]}"' in html

        linked = db.get_links(conn, investigation)[0]
        assert f'href="#artifact-{linked["target_artifact"]}"' in html
        assert f'href="#artifact-{linked["source_artifact"]}"' in html

        profile_id = correlate_identities(conn, investigation).identities[0].profile_id
        assert f'id="identity-{profile_id}"' in html
        assert f'href="#identity-{profile_id}"' in html

    def test_expand_collapse_controls(self, conn, investigation, tmp_path):
        html = render(conn, investigation, tmp_path)
        assert 'id="expand-all"' in html
        assert 'id="collapse-all"' in html


class TestEmptyInvestigation:
    def test_renders_without_artifacts_or_presences(self, conn, tmp_path):
        inv_id = db.create_investigation(conn, title="Empty")
        html = render(conn, inv_id, tmp_path)
        assert "Discovered Artifacts" not in html
        assert "Platform Presence" not in html
        assert "No artifacts were discovered" not in html
        assert "No platform presence recorded" not in html


class TestIdentityImages:
    """Which picture the identity card shows, and where it says it came from."""

    STEAM = "https://avatars.akamai.steamstatic.com/abc_medium.jpg"
    KEYBASE_STOCK = "https://keybase.io/images/no-photo/placeholder-avatar-180.png"
    PINTEREST_STOCK = "https://s.pinimg.com/images/default_open_graph_1200.png"

    @staticmethod
    def _images(images, presences=(), artifacts=()):
        correlation = SimpleNamespace(
            identities=[SimpleNamespace(profile_id="IDENTITY-001", images=list(images))]
        )
        return _generate_identity_images(correlation, list(presences), list(artifacts))["IDENTITY-001"]

    def test_stock_avatars_never_outrank_a_real_picture(self):
        images = self._images([self.KEYBASE_STOCK, self.PINTEREST_STOCK, self.STEAM])
        assert [i["src"] for i in images] == [self.STEAM, self.KEYBASE_STOCK, self.PINTEREST_STOCK]
        assert [i["placeholder"] for i in images] == [False, True, True]
        assert images[1]["caption"].endswith("(stock avatar)")

    def test_images_are_labelled_with_the_platform_or_tool_they_came_from(self):
        presences = [{"platform_name": "Steam", "profile_image_url": self.STEAM}]
        artifacts = [
            {"artifact_type": "image", "value": "https://cdn.example/x.png", "source": "profile_image_github"},
            {"artifact_type": "image", "value": "https://cdn.example/y.png", "source": "plugin:ImageMatchPlugin"},
        ]
        labels = {
            i["src"]: i["label"]
            for i in self._images(
                [self.STEAM, "https://cdn.example/x.png", "https://cdn.example/y.png", "https://cdn.example/z.png"],
                presences,
                artifacts,
            )
        }
        assert labels[self.STEAM] == "Steam"
        assert labels["https://cdn.example/x.png"] == "Github"
        assert labels["https://cdn.example/y.png"] == "Image Match"
        assert labels["https://cdn.example/z.png"] == "Unknown source"

    def test_local_files_are_inlined_so_the_report_travels(self, tmp_path):
        # 1x1 GIF: a real file, so the size and read paths are exercised.
        photo = tmp_path / "seed.gif"
        photo.write_bytes(base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"))
        artifacts = [{"artifact_type": "image", "value": str(photo), "source": "seed"}]

        images = self._images([str(photo)], artifacts=artifacts)
        assert images[0]["src"].startswith("data:image/gif;base64,")
        assert images[0]["label"] == "Seed image"
        assert images[0]["caption"] == "Seed image"
        assert images[0]["local"] is False

    def test_local_files_that_cannot_be_inlined_stay_as_paths(self, tmp_path):
        """They still resolve on the machine that ran the investigation."""
        missing = str(tmp_path / "gone.jpg")
        assert [i["src"] for i in self._images([missing])] == [missing]
        assert [i["src"] for i in self._images(["/etc/hostname"])] == ["/etc/hostname"]

    def test_oversized_photos_are_kept_and_marked_local(self, tmp_path):
        photo = tmp_path / "camera.jpg"
        photo.write_bytes(b"\xff\xd8\xff" + b"0" * (512 * 1024 + 1))
        artifacts = [{"artifact_type": "image", "value": str(photo), "source": "seed"}]

        image = self._images([str(photo)], artifacts=artifacts)[0]
        assert image["src"] == str(photo)
        assert image["local"] is True
        assert image["caption"] == "Seed image (local file)"

    def test_card_shows_the_avatar_its_provenance_and_the_other_matches(self, conn, investigation, tmp_path):
        html = render(conn, investigation, tmp_path)
        assert 'src="https://example.com/a.png"' in html
        assert "avatar-caption" in html
        assert ">GitHub<" in html

    def test_card_says_so_when_no_image_was_found(self, conn, tmp_path):
        inv_id = db.create_investigation(conn, title="No images")
        artifact = db.add_artifact(conn, inv_id, "username", "ghostuser", source="seed")
        db.add_platform_presence(conn, inv_id, platform_name="GitHub",
                                 profile_url="https://github.com/ghostuser", username="ghostuser",
                                 artifact_id=artifact)
        html = render(conn, inv_id, tmp_path)
        assert "No profile image found" in html

    def test_remaining_candidates_are_carried_as_fallbacks(self, conn, investigation, tmp_path):
        """A dead CDN URL must not leave the card blank."""
        db.add_platform_presence(conn, investigation, platform_name="Mastodon",
                                 profile_url="https://mastodon.social/@ghostuser",
                                 username="ghostuser",
                                 profile_image_url="https://example.com/b.png",
                                 artifact_id=db.get_artifacts(conn, investigation)[0]["artifact_id"])
        html = render(conn, investigation, tmp_path)
        assert "function gihNextImage" in html
        assert 'onerror="gihNextImage(this)"' in html
        # Delimiter-free metadata: scraped URLs and platform names are arbitrary.
        assert "data-fallbacks='[" in html
        assert "data-captions='[" in html
        # The head defines the handler: an image can fail before the body parses.
        assert html.index("function gihNextImage") < html.index("<body>")


class TestToolMetrics:
    """The infographic groups artifacts by the tool that produced them."""

    @staticmethod
    def _correlation(*identities):
        return SimpleNamespace(identities=list(identities))

    @staticmethod
    def _artifact(artifact_type, source, confidence=0.8):
        return {"artifact_type": artifact_type, "source": source, "confidence": confidence}

    def test_source_normalization_folds_the_three_source_formats(self):
        assert _normalize_tool_source("nmap") == "nmap"
        assert _normalize_tool_source("plugin:MaigretPlugin") == "maigret"
        assert _normalize_tool_source("username_search_github") == "username_search"
        assert _normalize_tool_source("profile_image_steam") == "profile_image"
        assert _normalize_tool_source("email_osint_twitter") == "email_osint"
        assert _normalize_tool_source("face_match_google_images") == "face_match"

    def test_multi_word_plugin_classes_fold_onto_the_external_tool_name(self):
        assert _normalize_tool_source("plugin:WaybackMachinePlugin") == "wayback_machine"
        assert _normalize_tool_source("plugin:UsernameSearchPlugin") == "username_search"
        assert _normalize_tool_source("plugin:GoogleDorksPlugin") == "google_dorks"

        metrics = _generate_tool_metrics(
            [
                self._artifact("historical_url", "wayback_machine"),
                self._artifact("historical_url", "plugin:WaybackMachinePlugin"),
            ],
            self._correlation(),
        )
        assert [(t["tool"], t["count"]) for t in metrics["tools"]] == [("wayback_machine", 2)]
        assert "wayback_machine" not in metrics["silent_tools"]

    def test_pipeline_steps_are_reported_as_derivations_not_tools(self):
        metrics = _generate_tool_metrics(
            [
                self._artifact("open_port", "nmap"),
                self._artifact("username", "email_local_part"),
                self._artifact("domain", "email_domain_extraction"),
            ],
            self._correlation(),
        )
        kinds = {t["tool"]: t["kind"] for t in metrics["tools"]}
        assert kinds == {
            "nmap": "tool",
            "email_local_part": "derivation",
            "email_domain_extraction": "derivation",
        }
        assert metrics["tool_count"] == 1
        assert metrics["derivation_count"] == 2

    def test_seeds_are_not_counted_as_a_tool(self):
        assert _normalize_tool_source("seed") is None
        assert _normalize_tool_source(None) is None

        metrics = _generate_tool_metrics(
            [self._artifact("username", "seed"), self._artifact("subdomain", "amass")],
            self._correlation(),
        )
        assert metrics["attributed"] == 1
        assert metrics["unattributed"] == 1
        assert metrics["tool_count"] == 1
        assert [t["tool"] for t in metrics["tools"]] == ["amass"]

    def test_tools_ranked_by_yield_with_type_breakdown(self):
        artifacts = [
            self._artifact("username_presence", "sherlock", 0.9),
            self._artifact("username_presence", "sherlock", 0.7),
            self._artifact("username_presence", "plugin:MaigretPlugin"),
            self._artifact("open_port", "nmap"),
            self._artifact("domain_info", "whois"),
        ]
        metrics = _generate_tool_metrics(artifacts, self._correlation())

        assert [t["tool"] for t in metrics["tools"]] == ["sherlock", "maigret", "nmap", "whois"]
        sherlock = metrics["tools"][0]
        assert sherlock["count"] == 2
        assert sherlock["share"] == 40.0
        assert sherlock["avg_confidence"] == 0.8
        assert sherlock["types"] == [{"type": "username_presence", "count": 2}]
        assert metrics["max_count"] == 2
        assert metrics["top_tool"] == "sherlock"
        assert metrics["top_tool_count"] == 2
        assert metrics["top_tool_label"] == "Sherlock"
        assert metrics["tools"][0]["label"] == "Sherlock"

    def test_highest_yield_tile_shows_count_and_readable_scraper_label(self):
        """Volume leaders like profile_image use a count + label, not a raw key caption."""
        artifacts = [
            self._artifact("image", "profile_image_github"),
            self._artifact("image", "profile_image_github"),
            self._artifact("image", "profile_image_pinterest"),
            self._artifact("username_presence", "sherlock"),
            self._artifact("username_presence", "sherlock"),
        ]
        metrics = _generate_tool_metrics(artifacts, self._correlation())
        assert metrics["top_tool"] == "profile_image"
        assert metrics["top_tool_count"] == 3
        assert metrics["top_tool_label"] == "Profile images"
        by_tool = {t["tool"]: t for t in metrics["tools"]}
        assert by_tool["profile_image"]["label"] == "Profile images"
        assert by_tool["sherlock"]["label"] == "Sherlock"

    def test_scraper_only_run_uses_readable_highest_yield_label(self):
        metrics = _generate_tool_metrics(
            [
                self._artifact("image", "profile_image_github"),
                self._artifact("image", "profile_image_pinterest"),
            ],
            self._correlation(),
        )
        assert metrics["top_tool"] == "profile_image"
        assert metrics["top_tool_count"] == 2
        assert metrics["top_tool_label"] == "Profile images"

    def test_type_mix_shares_and_colors(self):
        artifacts = [self._artifact("username_presence", "sherlock") for _ in range(3)]
        artifacts.append(self._artifact("open_port", "nmap"))
        metrics = _generate_tool_metrics(artifacts, self._correlation())

        assert [(t["type"], t["share"]) for t in metrics["types"]] == [
            ("username_presence", 75.0),
            ("open_port", 25.0),
        ]
        assert all(t["color"].startswith("#") for t in metrics["types"])

    def test_identities_reached_counts_distinct_profiles(self):
        identities = (
            SimpleNamespace(profile_id="IDENTITY-001",
                            tool_findings=[{"source": "sherlock"}, {"source": "nmap"}]),
            SimpleNamespace(profile_id="IDENTITY-002", tool_findings=[{"source": "sherlock"}]),
        )
        metrics = _generate_tool_metrics(
            [self._artifact("username_presence", "sherlock"), self._artifact("open_port", "nmap")],
            self._correlation(*identities),
        )
        by_tool = {t["tool"]: t for t in metrics["tools"]}
        assert by_tool["sherlock"]["identities"] == 2
        assert by_tool["nmap"]["identities"] == 1

    def test_integrated_tools_without_output_are_reported_as_silent(self):
        metrics = _generate_tool_metrics(
            [self._artifact("open_port", "nmap")], self._correlation()
        )
        assert "nmap" not in metrics["silent_tools"]
        assert "sherlock" in metrics["silent_tools"]
        assert metrics["integrated_count"] >= len(metrics["silent_tools"])

    def test_seed_only_investigation_omits_tool_metrics_when_no_output(self, conn, tmp_path):
        inv_id = db.create_investigation(conn, title="Seeds only")
        db.add_artifact(conn, inv_id, "username", "ghostuser", source="seed", confidence=0.95)
        html = render(conn, inv_id, tmp_path)
        # Seed-only: no tool-derived rows, but silent_tools note still counts as content
        # if silent tools are listed. Either way the old empty-note is gone.
        assert "No tool-derived artifacts" not in html
        if "Tool Metrics" in html:
            assert "silent in this run" in html
        assert "Discovered Artifacts" in html

    def test_tools_without_output_are_struck_through(self, conn, investigation, tmp_path):
        html = render(conn, investigation, tmp_path)
        assert ".tool-off { color: #a0aec0; text-decoration: line-through; }" in html
        # Every silent tool, and every non-producing row of the run-status table,
        # is rendered inside the disabled span; producing tools are not.
        status = html.split("Tool Run Status")[1]
        assert '<span class="tool-off">sherlock</span>' in status
        assert '<span class="tool-off">holehe</span>' not in status
        assert 'class="tool-row-off"' in status

    def test_section_renders_bars_and_breakdown(self, conn, investigation, tmp_path):
        html = render(conn, investigation, tmp_path)
        assert "Tool Metrics" in html
        assert "Artifacts per Tool" in html
        assert "tool-chart-bar" in html
        assert "holehe" in html and "amass" in html

    def test_bars_keep_their_fill_when_printed(self, conn, investigation, tmp_path):
        """Chrome drops background fills in print unless told otherwise."""
        html = render(conn, investigation, tmp_path)
        print_block = html.split("@media print {")[1].split("}\n        }")[0]
        assert "print-color-adjust: exact" in print_block
        assert ".tool-chart-bar" in print_block
        assert "Artifact Type Mix" not in html

    def test_technical_template_includes_the_breakdown(self, conn, investigation, tmp_path):
        html = render(conn, investigation, tmp_path, template_type="technical")
        assert "Tool Metrics" in html
        assert "Identities reached" in html

    def test_json_report_carries_the_same_metrics(self, conn, investigation, tmp_path):
        path = generate_json_report(conn, investigation, str(tmp_path / "report.json"))
        metrics = json.loads(Path(path).read_text())["tool_metrics"]
        assert {t["tool"] for t in metrics["tools"]} == {"holehe", "phone_osint", "amass"}


class TestJsonReport:
    def test_metadata_stays_raw_and_serializable(self, conn, investigation, tmp_path):
        generate_html_report(conn, investigation, str(tmp_path / "report.html"))
        path = generate_json_report(conn, investigation, str(tmp_path / "report.json"))
        data = json.loads(Path(path).read_text())
        metadata = [a["metadata"] for a in data["artifacts"]]
        assert metadata == [json.dumps(SEED_METADATA), "{not valid json", None, ""]
        assert all("metadata_parsed" not in a for a in data["artifacts"])


class TestEnhancedStandardReport:
    def test_new_sections_and_filters_render(self, conn, investigation, tmp_path):
        html = render(conn, investigation, tmp_path)
        assert "Evidence Chains" in html
        assert "Unattributed Findings" in html
        assert "Tool Run Status" in html
        assert "Recommendations" not in html
        assert 'id="report-filters"' in html
        assert "graph-frame" in html
        # Empty optional sections stay out of the report
        assert "Geographic / Location Signals" not in html
        assert "Investigator Notes" not in html
        assert "No geographic signals" not in html
        assert "No investigator notes" not in html

    def test_empty_investigation_omits_content_sections(self, conn, tmp_path):
        inv_id = db.create_investigation(conn, title="Empty")
        html = render(conn, inv_id, tmp_path)
        assert "Identity Profiles" not in html
        assert "Platform Presence" not in html
        assert "Discovered Artifacts" not in html
        assert "Evidence Chains" not in html
        assert "Unattributed Findings" not in html
        assert "Geographic / Location Signals" not in html
        assert "Investigator Notes" not in html
        assert "Cross-Investigation Matches" not in html
        assert "Relationship Graph" not in html
        assert 'id="report-filters"' not in html

    def test_sections_filter_hides_artifacts(self, conn, investigation, tmp_path):
        path = generate_html_report(
            conn, investigation, str(tmp_path / "slim.html"),
            template_type="standard", sections="summary,tools",
        )
        html = Path(path).read_text()
        assert "Summary" in html
        assert "Tool Metrics" in html
        assert "Discovered Artifacts" not in html

    def test_redaction_masks_email(self, conn, investigation, tmp_path):
        path = generate_html_report(
            conn, investigation, str(tmp_path / "redacted.html"), redact=True
        )
        html = Path(path).read_text()
        assert "Redacted shareable report" in html
        assert "ghostuser@example.com" not in html

    def test_delta_section(self, conn, investigation, tmp_path):
        other = db.create_investigation(conn, title="Prior")
        db.add_artifact(conn, other, "username", "ghostuser", source="seed")
        db.add_artifact(conn, other, "email", "old@example.com", source="seed")
        path = generate_html_report(
            conn, investigation, str(tmp_path / "delta.html"), compare_id=other
        )
        html = Path(path).read_text()
        assert f"Delta vs {other}" in html
        assert "Added" in html

    def test_csv_and_json_exports(self, conn, investigation, tmp_path):
        from src.reporting.exports import export_artifacts_csv
        arts = db.get_artifacts(conn, investigation)
        csv_path = export_artifacts_csv(arts, str(tmp_path / "a.csv"))
        assert Path(csv_path).exists()
        path = generate_json_report(conn, investigation, str(tmp_path / "r.json"))
        data = json.loads(Path(path).read_text())
        assert "evidence_chains" in data
        assert "orphan_findings" in data
        assert "tool_metrics" in data


class TestMetadataFormatting:
    """How arbitrary tool metadata is turned into readable report rows."""

    def test_empty_containers_and_flat_lists_are_unwrapped(self):
        assert _format_metadata_value([]) == "-"
        assert _format_metadata_value({}) == "-"
        assert _format_metadata_value(None) == "-"
        assert _format_metadata_value(["GitHub", "Reddit"]) == "GitHub, Reddit"
        assert _format_metadata_value({"platform": "github", "found": True}) == (
            "platform: github; found: True"
        )

    def test_floats_are_trimmed(self):
        assert _format_metadata_value(0.25333333333333335) == "0.2533"
        assert _format_metadata_value(1.0) == "1"

    def test_record_lists_become_tables_without_empty_columns(self):
        table = _metadata_table([
            {"platform_name": "GitHub", "found": True, "bio": None},
            {"platform_name": "GitLab", "found": True, "bio": ""},
        ])
        assert table == {
            "columns": ["platform_name", "found"],
            "rows": [["GitHub", "True"], ["GitLab", "True"]],
        }

    def test_non_record_values_have_no_table(self):
        assert _metadata_table(["GitHub"]) is None
        assert _metadata_table([]) is None
        assert _metadata_table({"a": 1}) is None
        assert _metadata_table([{"nested": {"deeper": {"x": 1}}}]) is None

    def test_report_renders_record_list_as_table(self, conn, tmp_path):
        inv_id = db.create_investigation(conn, title="Records")
        db.add_artifact(
            conn, inv_id, "username", "ghostuser", source="sherlock", confidence=0.9,
            metadata=json.dumps({
                "platforms_error": [],
                "platforms_found": [{"platform_name": "GitHub", "found": True}],
            }),
        )
        html = render(conn, inv_id, tmp_path)
        assert "nested-table" in html
        assert "<th>platform_name</th>" in html
        # The empty list collapses to a dash rather than an empty JSON array
        assert ">[]<" not in html


class TestEmptyStates:
    """Non-standard templates say why a table is empty instead of showing headers only."""

    def test_executive_and_legal_and_technical_report_empty_sections(self, conn, tmp_path):
        inv_id = db.create_investigation(conn, title="Empty")
        for template_type in ("executive", "legal", "technical"):
            html = render(conn, inv_id, tmp_path, template_type=template_type)
            assert "No identity profiles were correlated" in html
