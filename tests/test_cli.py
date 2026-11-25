"""Unit tests for the Typer CLI."""

from typer.testing import CliRunner
from datasecure import __version__
from datasecure.cli.main import app

runner = CliRunner()


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_cli_scan_help():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "Scan an AI/ML project" in result.stdout
    assert "--dataset" in result.stdout
    assert "--model" in result.stdout
    assert "--llm" in result.stdout


def test_cli_scan_current_directory():
    result = runner.invoke(app, ["scan", ".", "--quiet"])
    assert result.exit_code == 0


def test_cli_scan_non_existent_target():
    result = runner.invoke(app, ["scan", "non_existent_directory_xyz", "--quiet"])
    assert result.exit_code == 2
    assert "does not exist" in result.stderr or "does not exist" in result.stdout


def test_cli_scan_invalid_fail_on():
    result = runner.invoke(app, ["scan", ".", "--fail-on", "SUPER_CRITICAL", "--quiet"])
    assert result.exit_code == 2
    assert "Invalid --fail-on value" in result.stderr or "Invalid --fail-on value" in result.stdout


def test_cli_report_valid_formats():
    res_json = runner.invoke(app, ["report", "--format", "json"])
    assert res_json.exit_code == 0

    res_html = runner.invoke(app, ["report", "--format", "html"])
    assert res_html.exit_code == 0


def test_cli_report_invalid_format():
    result = runner.invoke(app, ["report", "--format", "pdf"])
    assert result.exit_code == 2
    assert "Unsupported format" in result.stderr or "Unsupported format" in result.stdout

