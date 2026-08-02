"""Tests for per-process caching in the ToolChecker."""

from src.utils.tool_checker import ToolChecker, ToolStatus


def test_check_tool_memoized(monkeypatch):
    """check_tool resolves availability/version at most once per tool."""
    which_calls = []
    version_calls = []

    def fake_which(cmd):
        which_calls.append(cmd)
        return f"/usr/bin/{cmd}"

    class _Proc:
        returncode = 0
        stdout = "toolX 1.2.3\n"

    def fake_run(*args, **kwargs):
        version_calls.append(args)
        return _Proc()

    monkeypatch.setattr("src.utils.tool_checker.shutil.which", fake_which)
    monkeypatch.setattr("src.utils.tool_checker.subprocess.run", fake_run)

    checker = ToolChecker()

    first = checker.check_tool("nmap")
    assert first.status == ToolStatus.AVAILABLE
    assert first.version == "toolX 1.2.3"
    assert first.checked is True

    # Repeated calls (including via is_available) must not re-run subprocess.
    checker.check_tool("nmap")
    assert checker.is_available("nmap") is True

    assert which_calls.count("nmap") == 1
    assert len(version_calls) == 1


def test_force_reresolves(monkeypatch):
    """force=True re-runs resolution (e.g. after installing a tool)."""
    monkeypatch.setattr("src.utils.tool_checker.shutil.which", lambda cmd: None)

    checker = ToolChecker()
    assert checker.check_tool("nmap").status == ToolStatus.NOT_INSTALLED

    monkeypatch.setattr("src.utils.tool_checker.shutil.which", lambda cmd: f"/usr/bin/{cmd}")
    monkeypatch.setattr(
        "src.utils.tool_checker.subprocess.run",
        lambda *a, **k: type("P", (), {"returncode": 0, "stdout": "v1\n"})(),
    )

    # Without force it stays cached as NOT_INSTALLED.
    assert checker.check_tool("nmap").status == ToolStatus.NOT_INSTALLED
    # With force it re-resolves to AVAILABLE.
    assert checker.check_tool("nmap", force=True).status == ToolStatus.AVAILABLE
