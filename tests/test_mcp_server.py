"""The MCP server: protocol correctness and a real subprocess round-trip.

The protocol surface is small but the framing is the contract, so both halves are
tested: ``handle`` for every message shape, and a real ``python -m engine.mcp``
subprocess driven over stdin/stdout, because that is how a client actually talks
to it.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

from engine.mcp.server import MCPServer
from engine.mcp.tools import build_tools

REPO_ROOT = Path(__file__).resolve().parents[1]


def _bundle(task_id: str = "task-1") -> dict:
    return {
        "task_id": task_id,
        "sample": {"file_name": "sample.bin", "sha256": "a" * 64, "file_type": "ELF", "file_size": 10},
        "static": {"yara": {"matches": []}, "capa": {"capabilities": []}},
        "iocs": [
            {"type": "url", "value": "http://evil.example/gate", "severity": "high"},
            {"type": "ip", "value": "1.2.3.4", "severity": "medium"},
        ],
        "mitre": {"techniques": []},
        "limitations": ["egress blocked"],
        "summary": {"events_total": 0},
    }


def _write_run(root: Path, task_id: str = "task-1") -> Path:
    run = root / task_id / "bundle"
    run.mkdir(parents=True)
    (run / "analysis.json").write_text(json.dumps(_bundle(task_id)))
    (run / "report.md").write_text("# report\n")
    return run


def _message(method: str, message_id: int = 1, params: dict | None = None) -> dict:
    message: dict = {"jsonrpc": "2.0", "id": message_id, "method": method}
    if params is not None:
        message["params"] = params
    return message


# --------------------------------------------------------------- protocol unit


def test_initialize_echoes_a_supported_protocol_version() -> None:
    server = MCPServer()
    result = server.handle(
        _message("initialize", params={"protocolVersion": "2024-11-05"})  # type: ignore[arg-type]
    )
    assert result is not None
    assert result["result"]["protocolVersion"] == "2024-11-05"
    assert result["result"]["serverInfo"]["name"] == "hatchery"
    assert "tools" in result["result"]["capabilities"]


def test_initialize_falls_back_to_the_latest_version() -> None:
    result = MCPServer().handle(
        _message("initialize", params={"protocolVersion": "1999-01-01"})  # type: ignore[arg-type]
    )
    assert result is not None
    assert result["result"]["protocolVersion"] == "2025-06-18"


def test_a_notification_gets_no_response() -> None:
    server = MCPServer()
    response = server.read_message(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))
    assert response is None


def test_ping_is_answered() -> None:
    result = MCPServer().handle(_message("ping"))
    assert result is not None and result["result"] == {}


def test_tools_list_describes_every_tool_with_a_schema() -> None:
    result = MCPServer().handle(_message("tools/list"))
    assert result is not None
    tools = result["result"]["tools"]
    names = {tool["name"] for tool in tools}
    assert names == {
        "list_runs",
        "get_report",
        "get_iocs",
        "triage_run",
        "cluster_runs",
        "submit_sample",
    }
    for tool in tools:
        assert tool["description"]
        assert tool["inputSchema"]["type"] == "object"


def test_unknown_method_is_a_protocol_error() -> None:
    result = MCPServer().handle(_message("does/not/exist"))
    assert result is not None
    assert result["error"]["code"] == -32601


def test_a_non_object_message_is_an_invalid_request() -> None:
    result = MCPServer().handle(["not", "a", "dict"])
    assert result is not None and result["error"]["code"] == -32600


def test_a_message_without_a_method_is_invalid() -> None:
    result = MCPServer().handle({"jsonrpc": "2.0", "id": 1})
    assert result is not None and result["error"]["code"] == -32600


def test_malformed_json_is_a_parse_error() -> None:
    result = MCPServer().read_message("{not json")
    assert result is not None and result["error"]["code"] == -32700


def test_blank_lines_are_ignored() -> None:
    assert MCPServer().read_message("   \n") is None


def test_serve_round_trips_over_streams() -> None:
    stdin = io.StringIO(
        json.dumps(_message("ping", 1)) + "\n"
        + json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
        + json.dumps(_message("tools/list", 2)) + "\n"
    )
    stdout = io.StringIO()
    MCPServer().serve(stdin, stdout)
    lines = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert [line["id"] for line in lines] == [1, 2]


# --------------------------------------------------------------- tools via call


def test_get_iocs_groups_by_type(tmp_path: Path) -> None:
    run = _write_run(tmp_path)
    result = MCPServer(tmp_path).handle(
        _message("tools/call", params={"name": "get_iocs", "arguments": {"run_dir": str(run)}})
    )
    assert result is not None and result["result"]["isError"] is False
    payload = json.loads(result["result"]["content"][0]["text"])
    assert payload["count"] == 2
    assert payload["by_type"] == {"url": 1, "ip": 1}


def test_list_runs_finds_the_run(tmp_path: Path) -> None:
    _write_run(tmp_path, "task-abc")
    result = MCPServer(tmp_path).handle(
        _message("tools/call", params={"name": "list_runs", "arguments": {"root": str(tmp_path)}})
    )
    assert result is not None
    payload = json.loads(result["result"]["content"][0]["text"])
    assert payload["count"] == 1
    assert payload["runs"][0]["task_id"] == "task-abc"


def test_get_report_markdown_and_json(tmp_path: Path) -> None:
    run = _write_run(tmp_path, "task-abc")
    server = MCPServer(tmp_path)
    md = server.handle(
        _message("tools/call", params={"name": "get_report",
                                       "arguments": {"run_dir": str(run), "format": "markdown"}})
    )
    assert md is not None and md["result"]["isError"] is False
    assert md["result"]["content"][0]["text"].startswith("# report")
    as_json = server.handle(
        _message("tools/call", params={"name": "get_report",
                                       "arguments": {"run_dir": str(run), "format": "json"}})
    )
    assert as_json is not None
    assert json.loads(as_json["result"]["content"][0]["text"])["task_id"] == "task-abc"


def test_get_report_without_triage_is_an_error_not_an_empty_object(tmp_path: Path) -> None:
    run = _write_run(tmp_path)
    result = MCPServer(tmp_path).handle(
        _message("tools/call", params={"name": "get_report",
                                       "arguments": {"run_dir": str(run), "format": "triage"}})
    )
    assert result is not None
    assert result["result"]["isError"] is True
    assert "triage_run" in result["result"]["content"][0]["text"]


def test_unknown_tool_is_a_tool_error_not_a_crash() -> None:
    result = MCPServer().handle(
        _message("tools/call", params={"name": "nope", "arguments": {}})
    )
    assert result is not None
    assert result["result"]["isError"] is True
    assert "unknown tool" in result["result"]["content"][0]["text"]


def test_tool_call_arguments_must_be_an_object() -> None:
    result = MCPServer().handle(
        _message("tools/call", params={"name": "get_iocs", "arguments": "oops"})
    )
    assert result is not None and result["result"]["isError"] is True


def test_a_missing_run_directory_is_a_tool_error() -> None:
    result = MCPServer().handle(
        _message("tools/call", params={"name": "get_iocs", "arguments": {"run_dir": "/nope"}})
    )
    assert result is not None and result["result"]["isError"] is True


def test_cluster_runs_over_a_tmp_corpus(tmp_path: Path) -> None:
    _write_run(tmp_path, "task-a")
    _write_run(tmp_path, "task-b")
    result = MCPServer(tmp_path).handle(
        _message("tools/call", params={"name": "cluster_runs",
                                       "arguments": {"root": str(tmp_path), "threshold": 0.5}})
    )
    assert result is not None and result["result"]["isError"] is False
    payload = json.loads(result["result"]["content"][0]["text"])
    assert payload["stats"]["runs_scanned"] == 2
    assert payload["stats"]["clusters"] == 1  # identical fixtures


def test_every_tool_handler_is_callable() -> None:
    for tool in build_tools():
        assert callable(tool.handler)
        assert tool.descriptor()["name"] == tool.name


# ----------------------------------------------------------- real subprocess E2E


def test_stdio_server_speaks_jsonrpc_as_a_subprocess(tmp_path: Path) -> None:
    _write_run(tmp_path, "task-sub")
    script = (
        json.dumps(_message("initialize", 1, {"protocolVersion": "2025-06-18"})) + "\n"
        + json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
        + json.dumps(_message("tools/list", 2)) + "\n"
        + json.dumps(_message("tools/call", 3, {"name": "list_runs",
                                                "arguments": {"root": str(tmp_path)}})) + "\n"
    )
    completed = subprocess.run(
        [sys.executable, "-m", "engine.mcp", "--root", str(tmp_path)],
        input=script,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    responses = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
    assert [response["id"] for response in responses] == [1, 2, 3]
    tools = responses[1]["result"]["tools"]
    assert len(tools) == 6
    payload = json.loads(responses[2]["result"]["content"][0]["text"])
    assert payload["runs"][0]["task_id"] == "task-sub"
