"""Tests for graph collections, layout choice and report click-through."""

import json
import tempfile
from pathlib import Path

import networkx as nx
import pytest

from src.graph.visualizer import (
    DEFAULT_COLLECTION_THRESHOLD,
    build_collections,
    generate_interactive_graph,
)
from src.storage import database as db


def _star(leaf_count: int, leaf_type: str = "username") -> nx.Graph:
    G = nx.Graph()
    G.add_node("hub", artifact_type="domain", value="example.com")
    for i in range(leaf_count):
        G.add_node(f"leaf{i}", artifact_type=leaf_type, value=f"user{i}")
        G.add_edge("hub", f"leaf{i}")
    return G


class TestCollections:
    def test_leaves_collapse_once_the_threshold_is_reached(self):
        collections = build_collections(_star(10), threshold=8)

        assert len(collections) == 1
        entry = next(iter(collections.values()))
        assert entry["parent"] == "hub"
        assert entry["artifact_type"] == "username"
        assert len(entry["members"]) == 10

    def test_a_group_below_the_threshold_is_left_alone(self):
        assert build_collections(_star(7), threshold=8) == {}

    def test_types_are_grouped_separately(self):
        G = _star(9, "username")
        for i in range(9):
            G.add_node(f"sub{i}", artifact_type="subdomain", value=f"s{i}.example.com")
            G.add_edge("hub", f"sub{i}")

        types = {c["artifact_type"] for c in build_collections(G, threshold=8).values()}
        assert types == {"username", "subdomain"}

    def test_a_node_with_further_relations_is_never_collapsed(self):
        G = _star(10)
        G.add_node("deep", artifact_type="email", value="a@example.com")
        G.add_edge("leaf0", "deep")

        members = next(iter(build_collections(G, threshold=8).values()))["members"]
        assert "leaf0" not in members
        assert len(members) == 9

    def test_a_zero_threshold_disables_collapsing(self):
        assert build_collections(_star(50), threshold=0) == {}


@pytest.fixture
def conn():
    c = db.get_connection(Path(tempfile.mktemp(suffix=".db")))
    yield c
    c.close()


@pytest.fixture
def investigation(conn):
    """A username seed with enough email leaves to trigger a collection."""
    inv_id = db.create_investigation(conn, title="Graph Test")
    seed = db.add_artifact(conn, inv_id, "username", "ghostuser", source="seed", confidence=0.9)
    for i in range(9):
        leaf = db.add_artifact(conn, inv_id, "email", f"ghost{i}@example.com",
                               source="holehe", confidence=0.7, depth=1)
        db.add_link(conn, inv_id, seed, leaf, "discovered_from", 0.8, "email pivot")
    return inv_id, seed


class TestGeneratedGraph:
    def test_collapsed_members_are_hidden_behind_one_collection_node(
        self, conn, investigation, tmp_path
    ):
        inv_id, _ = investigation
        html = Path(generate_interactive_graph(
            conn, inv_id, str(tmp_path / "g.html"), collection_threshold=8
        )).read_text()

        assert "email \\u00d79" in html or "email \u00d7 9" in html or "email \\u00d7 9" in html
        payload = json.loads(html.split("var gihCollections = ")[1].split(";\n")[0])
        assert len(payload) == 1
        assert len(next(iter(payload.values()))) == 9
        assert '"hidden": true' in html or '"hidden":true' in html

    def test_threshold_zero_renders_every_node(self, conn, investigation, tmp_path):
        inv_id, _ = investigation
        html = Path(generate_interactive_graph(
            conn, inv_id, str(tmp_path / "g.html"), collection_threshold=0
        )).read_text()

        assert "var gihCollections = {}" in html
        for i in range(9):
            assert f"ghost{i}@example.com" in html

    def test_clicking_a_node_asks_the_report_for_its_detail_section(
        self, conn, investigation, tmp_path
    ):
        inv_id, seed = investigation
        html = Path(generate_interactive_graph(
            conn, inv_id, str(tmp_path / "g.html")
        )).read_text()

        assert 'source: "gih-graph"' in html
        assert 'window.parent.postMessage' in html
        assert seed in html

    def test_the_circular_layout_places_the_collection_node_on_the_ring(
        self, conn, investigation, tmp_path
    ):
        inv_id, seed = investigation
        html = Path(generate_interactive_graph(
            conn, inv_id, str(tmp_path / "g.html"), layout="circular",
            collection_threshold=8,
        )).read_text()

        nodes = json.loads(html.split("nodes = new vis.DataSet(")[1].split(");")[0])
        placed = {n["id"]: (n.get("x"), n.get("y")) for n in nodes}
        collection_id = next(i for i in placed if str(i).startswith("collection::"))

        assert None not in placed[collection_id]
        # Visible nodes sit on one ring; nothing lands on top of anything else.
        visible = [placed[seed], placed[collection_id]]
        assert len(set(visible)) == len(visible)

    @pytest.mark.parametrize("layout,marker", [
        ("hierarchical", '"hierarchical"'),
        ("circular", '"physics": {"enabled": false}'),
        ("organic", "forceAtlas2Based"),
    ])
    def test_each_layout_configures_vis(self, conn, investigation, tmp_path, layout, marker):
        inv_id, _ = investigation
        html = Path(generate_interactive_graph(
            conn, inv_id, str(tmp_path / "g.html"), layout=layout
        )).read_text()

        assert marker in html

    def test_an_unknown_layout_falls_back_to_the_default(self, conn, investigation, tmp_path):
        inv_id, _ = investigation
        html = Path(generate_interactive_graph(
            conn, inv_id, str(tmp_path / "g.html"), layout="spaghetti"
        )).read_text()

        assert "forceAtlas2Based" in html

    def test_the_configured_threshold_is_used_by_default(self, conn, investigation, tmp_path):
        assert DEFAULT_COLLECTION_THRESHOLD == 8
        inv_id, _ = investigation
        html = Path(generate_interactive_graph(
            conn, inv_id, str(tmp_path / "g.html")
        )).read_text()

        payload = json.loads(html.split("var gihCollections = ")[1].split(";\n")[0])
        assert len(payload) == 1
