"""Tests for database location resolution (--db > config > default)."""

from pathlib import Path

import pytest
import yaml

from src.config import loader
from src.storage import database as db


@pytest.fixture
def write_config(tmp_path):
    """Load a throwaway config/config.yaml as the global config."""
    original = loader._global_config

    def _write(database_section):
        config_dir = tmp_path / "config"
        config_dir.mkdir(exist_ok=True)
        config_path = config_dir / "config.yaml"
        with open(config_path, "w") as f:
            yaml.dump({"database": database_section}, f)
        loader.reload_config(str(config_path))
        return config_path

    yield _write
    loader._global_config = original


def test_cli_option_beats_config(write_config, tmp_path):
    write_config({"path": str(tmp_path / "from_config.db")})
    assert db.resolve_db_path(tmp_path / "explicit.db") == tmp_path / "explicit.db"


def test_config_beats_default(write_config, tmp_path):
    configured = tmp_path / "cases" / "from_config.db"
    write_config({"path": str(configured)})
    assert db.resolve_db_path() == configured


def test_config_path_expands_home(write_config):
    write_config({"path": "~/somewhere/case.db"})
    assert db.resolve_db_path() == Path.home() / "somewhere" / "case.db"


def test_config_path_expands_env_vars(write_config, monkeypatch, tmp_path):
    monkeypatch.setenv("GIH_TEST_DB_DIR", str(tmp_path))
    write_config({"path": "$GIH_TEST_DB_DIR/case.db"})
    assert db.resolve_db_path() == tmp_path / "case.db"


def test_relative_config_path_ignores_cwd(write_config, tmp_path, monkeypatch):
    write_config({"path": "./investigations.db"})
    expected = tmp_path / "investigations.db"

    monkeypatch.chdir(tmp_path)
    assert db.resolve_db_path() == expected

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert db.resolve_db_path() == expected


def test_empty_database_section_falls_back_to_default(write_config):
    write_config(None)
    assert db.resolve_db_path() == db.DEFAULT_DB_PATH


def test_null_path_falls_back_to_default(write_config):
    write_config({"path": None, "backup_enabled": True})
    assert db.resolve_db_path() == db.DEFAULT_DB_PATH


def test_missing_database_section_falls_back_to_default(tmp_path):
    original = loader._global_config
    config_path = tmp_path / "config" / "config.yaml"
    config_path.parent.mkdir()
    with open(config_path, "w") as f:
        yaml.dump({"plugins": {}}, f)
    loader.reload_config(str(config_path))
    try:
        assert db.resolve_db_path() == db.DEFAULT_DB_PATH
    finally:
        loader._global_config = original


def test_connection_uses_configured_path(write_config, tmp_path):
    configured = tmp_path / "nested" / "configured.db"
    write_config({"path": str(configured)})

    conn = db.get_connection()
    try:
        db.create_investigation(conn, title="Configured")
    finally:
        conn.close()

    assert configured.exists()


def test_connection_prefers_cli_path(write_config, tmp_path):
    configured = tmp_path / "configured.db"
    explicit = tmp_path / "explicit.db"
    write_config({"path": str(configured)})

    conn = db.get_connection(explicit)
    try:
        db.create_investigation(conn, title="Explicit")
    finally:
        conn.close()

    assert explicit.exists()
    assert not configured.exists()
