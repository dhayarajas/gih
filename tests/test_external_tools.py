"""Tests for external OSINT tool integrations and their output parsers."""

from unittest.mock import patch

from src.modules import external_tools as et


def _tool_result(output: str, success: bool = True) -> et.ToolResult:
    return et.ToolResult(tool_name="stub", success=success, output=output)


class TestFoundLineParsing:
    """Sherlock and maigret both print '[+] Site: url' lines."""

    def test_parses_site_and_url(self):
        output = (
            "[*] Checking username torvalds\n"
            "[+] GitHub: https://github.com/torvalds\n"
            "[+] WordPress: https://torvalds.wordpress.com/\n"
            "[-] Facebook: Not Found!\n"
        )
        assert et._parse_found_lines(output) == [
            ("GitHub", "https://github.com/torvalds"),
            ("WordPress", "https://torvalds.wordpress.com/"),
        ]

    def test_ignores_banner_lines_without_url(self):
        output = "[+] MAIGRET - collect a dossier by username\n[+] GitHub: https://github.com/x\n"
        assert et._parse_found_lines(output) == [("GitHub", "https://github.com/x")]

    def test_deduplicates_urls(self):
        output = "[+] GitHub: https://github.com/x\n[+] GitHub Mirror: https://github.com/x\n"
        assert len(et._parse_found_lines(output)) == 1


class TestSherlock:
    def test_discovers_username_presence(self):
        output = "[+] GitHub: https://github.com/torvalds\n"
        with patch.object(et.SherlockIntegration, "run_tool", return_value=_tool_result(output)):
            result = et.SherlockIntegration().search_username.__wrapped__(
                et.SherlockIntegration(), "torvalds"
            )
        assert result.artifacts_discovered == [{
            "type": "username_presence",
            "value": "torvalds",
            "platform": "GitHub",
            "profile_url": "https://github.com/torvalds",
            "source": "sherlock",
            "confidence": 0.8,
        }]


class TestMaigret:
    def test_reports_findings_even_when_exit_code_is_nonzero(self):
        output = "[+] GitHub: https://github.com/torvalds\n"
        with patch.object(
            et.MaigretIntegration, "run_tool", return_value=_tool_result(output, success=False)
        ):
            result = et.MaigretIntegration().search_username.__wrapped__(
                et.MaigretIntegration(), "torvalds"
            )
        assert result.success is True
        assert result.artifacts_discovered[0]["source"] == "maigret"
        assert result.artifacts_discovered[0]["profile_url"] == "https://github.com/torvalds"


class TestHolehe:
    def test_parses_used_services_and_skips_legend(self):
        output = (
            "[+] rambler.ru\n"
            "[+] twitter.com\n"
            "[+] Email used, [-] Email not used, [x] Rate limit\n"
            "121 websites checked in 10.3 seconds\n"
        )
        with patch.object(et.HoleheIntegration, "run_tool", return_value=_tool_result(output)):
            result = et.HoleheIntegration().check_email.__wrapped__(
                et.HoleheIntegration(), "a@b.com"
            )
        assert [a["platform"] for a in result.artifacts_discovered] == [
            "rambler.ru", "twitter.com",
        ]
        assert result.artifacts_discovered[0]["type"] == "email_account"


class TestSubfinder:
    def test_keeps_only_subdomains_of_the_target(self):
        output = "api.example.com\nwww.example.com\napi.example.com\nevil.other.com\n"
        with patch.object(et.SubfinderIntegration, "run_tool", return_value=_tool_result(output)):
            result = et.SubfinderIntegration().enumerate_subdomains.__wrapped__(
                et.SubfinderIntegration(), "example.com"
            )
        assert [a["value"] for a in result.artifacts_discovered] == [
            "api.example.com", "www.example.com",
        ]


class TestDig:
    def test_a_records_also_yield_ip_address_artifacts(self):
        with patch.object(
            et.DigIntegration, "run_tool", return_value=_tool_result("140.82.116.3\n")
        ):
            result = et.DigIntegration().dns_lookup.__wrapped__(
                et.DigIntegration(), "github.com"
            )
        types = [a["type"] for a in result.artifacts_discovered]
        assert types == ["dns_a", "ip_address"]


class TestAnalysisDispatch:
    def test_every_declared_analysis_belongs_to_its_own_integration(self):
        integrations = et.get_tool_integrations()
        for tool_name, analyses in et.ANALYSIS_METHODS.items():
            integration = integrations[tool_name]
            for method in analyses.values():
                owner = method.__qualname__.split(".")[0]
                assert type(integration).__name__ == owner
                assert hasattr(integration, method.__name__)

    def test_unknown_analysis_type_is_reported(self):
        result = et.run_tool_analysis("dig", "does_not_exist", "example.com")
        assert result.success is False
        assert result.error_message == "Unknown analysis type"


class TestToolTimeout:
    def test_configured_timeout_is_passed_to_subprocess(self):
        with patch.object(et, "_get_tool_timeout", return_value=42) as get_timeout, \
                patch("src.modules.external_tools.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = ""
            run.return_value.stderr = ""
            et.ExternalToolsIntegration().run_tool("nmap", ["nmap", "-V"])
        get_timeout.assert_called_once_with("nmap")
        assert run.call_args.kwargs["timeout"] == 42
