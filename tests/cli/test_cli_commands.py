"""CLI command integration tests — subprocess execution.

Tests the actual `crowdsentinel` entry point as a subprocess,
verifying exit codes, stdout format, and stderr error messages.
"""

import json
import subprocess
import sys

import pytest


def run_cli(*args, stdin_data=None, timeout=30):
    """Run crowdsentinel CLI via the main() function in a subprocess.

    Works in both installed (pipx) and development (uv) environments.
    """
    # Build a small script that imports and calls main with sys.argv set
    arg_list = list(args)
    script = (
        "import sys; "
        f"sys.argv = ['crowdsentinel'] + {arg_list!r}; "
        "from src.cli.main import main; main()"
    )
    cmd = [sys.executable, "-c", script]

    result = subprocess.run(
        cmd,
        input=stdin_data,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={
            **__import__("os").environ,
            "CROWDSENTINEL_RULES_DIR": "rules",
        },
    )
    return result.returncode, result.stdout, result.stderr


class TestCLIBasics:
    def test_version(self):
        code, out, _ = run_cli("--version")
        assert code == 0
        assert "crowdsentinel" in out

    def test_help(self):
        code, out, _ = run_cli("--help")
        assert code == 0
        assert "health" in out
        assert "hunt" in out
        assert "analyse" in out
        assert "auth" in out

    def test_analyse_help(self):
        code, out, _ = run_cli("analyse", "--help")
        assert code == 0
        assert "--mcp" in out
        assert "--model" in out
        assert "--max-steps" in out
        assert "--timeout" in out

    def test_rules_help(self):
        code, out, _ = run_cli("rules", "--help")
        assert code == 0
        assert "--type" in out
        assert "--tactic" in out


class TestCLIAuth:
    def test_auth_status(self):
        code, out, _ = run_cli("auth", "status")
        assert code == 0
        assert "Authenticated:" in out

    def test_auth_logout_no_tokens(self):
        # This may or may not have tokens — just verify it doesn't crash
        code, out, _ = run_cli("auth", "logout")
        assert code == 0

    def test_auth_help(self):
        code, out, _ = run_cli("auth", "--help")
        assert code == 0
        assert "login" in out
        assert "status" in out
        assert "logout" in out
        assert "--provider" in out


def _es_available():
    """Check if Elasticsearch is reachable."""
    try:
        import httpx
        hosts = __import__("os").environ.get("ELASTICSEARCH_HOSTS", "http://localhost:9200")
        resp = httpx.get(hosts, timeout=3, verify=False)
        return resp.status_code in (200, 401)
    except Exception:
        return False


@pytest.mark.skipif(not _es_available(), reason="No Elasticsearch available")
class TestCLIAnalyseDeterministic:
    def test_analyse_empty_input(self):
        code, out, _ = run_cli("analyse", "-c", "test", stdin_data="{}")
        assert code == 0
        parsed = json.loads(out)
        assert parsed["severity_assessment"] == "low"

    def test_analyse_hunt_format(self):
        hunt_data = json.dumps({
            "summary": {"total_hits": 1},
            "sample_events": [{"code": "4625", "message": "Failed login"}],
        })
        code, out, _ = run_cli("analyse", "-c", "test failed auth", "-o", "summary", stdin_data=hunt_data)
        assert code == 0
        assert "severity=" in out
        assert "mitre=" in out

    def test_analyse_summary_format(self):
        hunt_data = json.dumps({
            "summary": {"total_hits": 4},
            "sample_events": [
                {"code": "4104", "message": "MiniDumpWriteDump lsass Get-Process lsass"},
            ],
        })
        code, out, _ = run_cli("analyse", "-c", "PS investigation", "-o", "summary", stdin_data=hunt_data)
        assert code == 0
        assert "severity=critical" in out
        assert "T1003.001" in out

    def test_analyse_table_format(self):
        hunt_data = json.dumps({
            "summary": {"total_hits": 1},
            "sample_events": [{"code": "4625", "message": "Failed login"}],
        })
        code, out, _ = run_cli("analyse", "-c", "test", "-o", "table", stdin_data=hunt_data)
        assert code == 0
        assert "Analysis" in out
        assert "severity:" in out

    def test_analyse_no_stdin(self):
        code, _, err = run_cli("analyse", "-c", "test", stdin_data="")
        assert code == 1
        assert "no JSON" in err.lower() or "error" in err.lower()


class TestCLIAgentModeErrors:
    def test_mcp_no_api_key(self):
        """Agent mode without API key should error clearly."""
        import os
        env = {k: v for k, v in os.environ.items() if k not in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY")}
        script = (
            "import sys; "
            "sys.argv = ['crowdsentinel', 'analyse', '--mcp', '-c', 'test']; "
            "from src.cli.main import main; main()"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            input="{}",
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
        assert result.returncode == 1
        assert "API" in result.stderr or "auth" in result.stderr.lower() or "configured" in result.stderr.lower()
