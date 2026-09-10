import asyncio
import base64
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from wecom_aibot import cli
from wecom_aibot.cli import main
from wecom_aibot.context_store import ContextStore
from wecom_aibot.delivery import DeliveryResult
from wecom_aibot.ipc import request as ipc_request
from wecom_aibot.sdk import ReplyRoute, TextEvent
from wecom_aibot.service import RelayService

TOKEN = "relay-token-value"


def _prepare_endpoint(tmp_path: Path, *, mode: int = 0o600) -> Path:
    runtime_dir = tmp_path / "run"
    runtime_dir.mkdir(mode=0o700, exist_ok=True)
    token_path = runtime_dir / "relay.sock.token"
    token_path.write_text(TOKEN, encoding="utf-8")
    token_path.chmod(mode)
    return runtime_dir


def _responder(response: dict[str, object], recorder: list[tuple[str, str, dict]]):
    async def fake_request(
        endpoint: str,
        token: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        recorder.append((endpoint, token, payload))
        return response

    return fake_request


# --------------------------------------------------------------------------
# reply / status / stop
# --------------------------------------------------------------------------


def test_reply_uses_content_file_and_returns_unknown_exit_code(tmp_path, monkeypatch):
    content = tmp_path / "answer.md"
    content.write_text("result", encoding="utf-8")
    runtime_dir = _prepare_endpoint(tmp_path)
    monkeypatch.setenv("WECOM_AIBOT_RUNTIME_DIR", str(runtime_dir))

    calls: list[tuple[str, str, dict]] = []
    monkeypatch.setattr(
        cli,
        "request",
        _responder({"status": "unknown", "reason": "delivery_unknown"}, calls),
    )

    assert main(["reply", "--context", "ctx", "--content-file", str(content)]) == 75
    assert [call[2] for call in calls] == [
        {"action": "reply", "context": "ctx", "kind": "final", "markdown": "result"}
    ]


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ({"status": "delivered"}, 0),
        ({"status": "not_delivered", "reason": "delivery_failed"}, 1),
        ({"status": "unknown", "reason": "delivery_unknown"}, 75),
        ({"status": "invalid_request", "reason": "invalid reply fields"}, 1),
        ({"status": "forbidden"}, 1),
    ],
)
def test_reply_maps_relay_status_to_exit_code(
    tmp_path,
    monkeypatch,
    response: dict[str, object],
    expected: int,
):
    content = tmp_path / "answer.md"
    content.write_text("result", encoding="utf-8")
    monkeypatch.setenv("WECOM_AIBOT_RUNTIME_DIR", str(_prepare_endpoint(tmp_path)))
    monkeypatch.setattr(cli, "request", _responder(response, []))

    exit_code = main(["reply", "--context", "ctx", "--content-file", str(content)])

    assert exit_code == expected


@pytest.mark.parametrize(
    ("command", "response", "expected"),
    [
        ("status", {"status": "running"}, 0),
        ("status", {"status": "unknown", "reason": "delivery_unknown"}, 75),
        ("status", {"status": "invalid_request", "reason": "unknown action"}, 1),
        ("stop", {"status": "stopping"}, 0),
        ("stop", {"status": "unknown", "reason": "delivery_unknown"}, 75),
        ("stop", {"status": "forbidden"}, 1),
    ],
)
def test_status_and_stop_map_relay_status_to_exit_code(
    tmp_path,
    monkeypatch,
    command: str,
    response: dict[str, object],
    expected: int,
):
    monkeypatch.setenv("WECOM_AIBOT_RUNTIME_DIR", str(_prepare_endpoint(tmp_path)))
    calls: list[tuple[str, str, dict]] = []
    monkeypatch.setattr(cli, "request", _responder(response, calls))

    assert main([command]) == expected
    assert [call[2] for call in calls] == [{"action": command}]


def test_reply_sends_sidecar_token_without_printing_it(tmp_path, monkeypatch, capsys):
    content = tmp_path / "answer.md"
    content.write_text("result", encoding="utf-8")
    runtime_dir = _prepare_endpoint(tmp_path)
    monkeypatch.setenv("WECOM_AIBOT_RUNTIME_DIR", str(runtime_dir))
    calls: list[tuple[str, str, dict]] = []
    monkeypatch.setattr(cli, "request", _responder({"status": "delivered"}, calls))

    assert main(["reply", "--context", "ctx", "--content-file", str(content)]) == 0

    assert [call[1] for call in calls] == [TOKEN]
    captured = capsys.readouterr()
    assert TOKEN not in captured.out
    assert TOKEN not in captured.err


def test_reply_rejects_group_readable_token_sidecar(tmp_path, monkeypatch, capsys):
    content = tmp_path / "answer.md"
    content.write_text("result", encoding="utf-8")
    runtime_dir = _prepare_endpoint(tmp_path, mode=0o640)
    monkeypatch.setenv("WECOM_AIBOT_RUNTIME_DIR", str(runtime_dir))
    calls: list[tuple[str, str, dict]] = []
    monkeypatch.setattr(cli, "request", _responder({"status": "delivered"}, calls))

    assert main(["reply", "--context", "ctx", "--content-file", str(content)]) == 1
    assert calls == []
    assert "insecure_token_permissions" in capsys.readouterr().err


def test_reply_without_running_relay_does_not_contact_anything(
    tmp_path,
    monkeypatch,
    capsys,
):
    content = tmp_path / "answer.md"
    content.write_text("result", encoding="utf-8")
    runtime_dir = tmp_path / "run"
    runtime_dir.mkdir(mode=0o700)
    monkeypatch.setenv("WECOM_AIBOT_RUNTIME_DIR", str(runtime_dir))
    calls: list[tuple[str, str, dict]] = []
    monkeypatch.setattr(cli, "request", _responder({"status": "delivered"}, calls))

    assert main(["reply", "--context", "ctx", "--content-file", str(content)]) == 1
    assert calls == []
    assert "relay_not_running" in capsys.readouterr().err


def test_reply_reads_endpoint_sidecar_for_loopback_relays(tmp_path, monkeypatch):
    content = tmp_path / "answer.md"
    content.write_text("result", encoding="utf-8")
    runtime_dir = _prepare_endpoint(tmp_path)
    endpoint_file = runtime_dir / "relay.sock.endpoint"
    endpoint_file.write_text("http://127.0.0.1:5555", encoding="utf-8")
    endpoint_file.chmod(0o600)
    monkeypatch.setenv("WECOM_AIBOT_RUNTIME_DIR", str(runtime_dir))
    calls: list[tuple[str, str, dict]] = []
    monkeypatch.setattr(cli, "request", _responder({"status": "delivered"}, calls))

    assert main(["reply", "--context", "ctx", "--content-file", str(content)]) == 0
    assert [call[0] for call in calls] == ["http://127.0.0.1:5555"]


def test_reply_treats_broken_connection_as_unknown(tmp_path, monkeypatch):
    content = tmp_path / "answer.md"
    content.write_text("result", encoding="utf-8")
    monkeypatch.setenv("WECOM_AIBOT_RUNTIME_DIR", str(_prepare_endpoint(tmp_path)))

    async def broken(endpoint: str, token: str, payload: dict[str, object]) -> dict:
        raise ConnectionResetError("relay died mid write")

    monkeypatch.setattr(cli, "request", broken)

    assert main(["reply", "--context", "ctx", "--content-file", str(content)]) == 75


def test_reply_treats_refused_connection_as_not_delivered(tmp_path, monkeypatch):
    content = tmp_path / "answer.md"
    content.write_text("result", encoding="utf-8")
    monkeypatch.setenv("WECOM_AIBOT_RUNTIME_DIR", str(_prepare_endpoint(tmp_path)))

    async def refused(endpoint: str, token: str, payload: dict[str, object]) -> dict:
        raise ConnectionRefusedError("nothing listening")

    monkeypatch.setattr(cli, "request", refused)

    assert main(["reply", "--context", "ctx", "--content-file", str(content)]) == 1


def test_reply_rejects_non_utf8_content_file(tmp_path, monkeypatch, capsys):
    content = tmp_path / "answer.md"
    content.write_bytes(b"\xff\xfe binary")
    monkeypatch.setenv("WECOM_AIBOT_RUNTIME_DIR", str(_prepare_endpoint(tmp_path)))
    calls: list[tuple[str, str, dict]] = []
    monkeypatch.setattr(cli, "request", _responder({"status": "delivered"}, calls))

    assert main(["reply", "--context", "ctx", "--content-file", str(content)]) == 1
    assert calls == []
    assert "invalid_content_encoding" in capsys.readouterr().err


# --------------------------------------------------------------------------
# runtime directory hardening
# --------------------------------------------------------------------------


def test_runtime_directory_is_created_owner_only(tmp_path):
    target = tmp_path / "nested" / "run"

    cli.ensure_runtime_dir(target)

    assert stat.S_IMODE(target.lstat().st_mode) == 0o700


def test_existing_group_readable_runtime_directory_is_rejected(tmp_path):
    target = tmp_path / "run"
    target.mkdir(mode=0o755)

    with pytest.raises(cli.CliError) as error:
        cli.ensure_runtime_dir(target)

    assert error.value.code == "insecure_runtime_dir"


def test_windows_runtime_directory_is_created_then_verified(tmp_path):
    created: list[str] = []
    target = tmp_path / "run"

    cli.ensure_runtime_dir(
        target,
        windows=True,
        windows_creator=created.append,
        windows_inspector=lambda path: (False, True),
    )

    assert created == [str(target)]


def test_windows_runtime_directory_without_owner_only_dacl_is_rejected(tmp_path):
    target = tmp_path / "run"

    with pytest.raises(cli.CliError) as error:
        cli.ensure_runtime_dir(
            target,
            windows=True,
            windows_creator=lambda path: None,
            windows_inspector=lambda path: (False, False),
        )

    assert error.value.code == "insecure_runtime_dir"


def test_windows_runtime_directory_reparse_point_is_rejected(tmp_path):
    target = tmp_path / "run"

    with pytest.raises(cli.CliError) as error:
        cli.ensure_runtime_dir(
            target,
            windows=True,
            windows_creator=lambda path: None,
            windows_inspector=lambda path: (True, True),
        )

    assert error.value.code == "insecure_runtime_dir"


# --------------------------------------------------------------------------
# serve credentials
# --------------------------------------------------------------------------


def test_serve_without_credentials_refuses_to_start(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("WECHAT_BOT_ID", raising=False)
    monkeypatch.delenv("WECHAT_BOT_SECRET", raising=False)
    monkeypatch.setenv("WECOM_AIBOT_RUNTIME_DIR", str(tmp_path / "run"))
    monkeypatch.setattr(cli, "create_sdk_client", _unreachable_factory)

    assert main(["serve"]) == 1
    assert "missing_credentials" in capsys.readouterr().err


def test_serve_rejects_group_readable_config(tmp_path, monkeypatch, capsys):
    config = tmp_path / "relay.json"
    config.write_text(
        json.dumps({"botId": "bot", "botSecret": "shhh"}),
        encoding="utf-8",
    )
    config.chmod(0o644)
    monkeypatch.setenv("WECOM_AIBOT_RUNTIME_DIR", str(tmp_path / "run"))
    monkeypatch.setattr(cli, "create_sdk_client", _unreachable_factory)

    assert main(["serve", "--config", str(config)]) == 1
    captured = capsys.readouterr()
    assert "insecure_config_permissions" in captured.err
    assert "shhh" not in captured.err
    assert "shhh" not in captured.out


def test_owner_only_config_supplies_credentials_without_logging_secret(
    tmp_path,
    capsys,
):
    config = tmp_path / "relay.json"
    config.write_text(
        json.dumps({"botId": "bot-1", "botSecret": "shhh"}),
        encoding="utf-8",
    )
    config.chmod(0o600)

    credentials = cli.load_credentials(config)

    assert credentials == ("bot-1", "shhh")
    captured = capsys.readouterr()
    assert "shhh" not in captured.out
    assert "shhh" not in captured.err


def test_blank_environment_credentials_are_rejected(monkeypatch):
    monkeypatch.setenv("WECHAT_BOT_ID", "bot-1")
    monkeypatch.setenv("WECHAT_BOT_SECRET", "   ")

    with pytest.raises(cli.CliError) as error:
        cli.load_credentials(None)

    assert error.value.code == "missing_credentials"


def _unreachable_factory(bot_id: str, secret: str) -> object:
    raise AssertionError("SDK client must not be created")


# --------------------------------------------------------------------------
# serve lifecycle
# --------------------------------------------------------------------------


@pytest.fixture
def short_runtime_dir():
    """Unix socket paths are length limited, so stay well below pytest's tmp_path."""
    base = Path(tempfile.mkdtemp(prefix="wa-"))
    runtime_dir = base / "run"
    cli.ensure_runtime_dir(runtime_dir)
    try:
        yield runtime_dir
    finally:
        shutil.rmtree(base, ignore_errors=True)


async def _wait_until_ready(ready: asyncio.Event, served: asyncio.Task) -> None:
    waiter = asyncio.create_task(ready.wait())
    done, _ = await asyncio.wait(
        {waiter, served},
        timeout=10,
        return_when=asyncio.FIRST_COMPLETED,
    )
    if served in done:
        waiter.cancel()
        raise AssertionError(f"relay exited early: {served.exception()!r}")
    if waiter not in done:
        waiter.cancel()
        raise AssertionError("relay never became ready")


class FakeAdapter:
    def __init__(self) -> None:
        self.connected = False
        self.disconnected = False
        self.inbound_stopped = False
        self.callback = None
        self.replies: list[tuple[object, str]] = []

    def on_text(self, callback) -> None:
        self.callback = callback

    async def connect(self) -> None:
        self.connected = True

    def stop_inbound(self) -> None:
        self.inbound_stopped = True

    def disconnect(self) -> None:
        self.disconnected = True

    async def reply(self, route: object, markdown: str) -> DeliveryResult:
        self.replies.append((route, markdown))
        return DeliveryResult("delivered")


@pytest.mark.skipif(os.name == "nt", reason="unix socket lifecycle")
def test_serve_reports_status_and_stops_on_request(
    short_runtime_dir,
    monkeypatch,
    capsys,
):
    adapter = FakeAdapter()
    monkeypatch.setattr(cli, "create_sdk_client", lambda bot_id, secret: adapter)
    runtime_dir = short_runtime_dir
    base = runtime_dir / "relay.sock"

    async def run() -> None:
        ready = asyncio.Event()
        served = asyncio.create_task(
            cli.serve_relay(base, "bot", "secret", None, 60.0, ready=ready)
        )
        await _wait_until_ready(ready, served)

        token = (runtime_dir / "relay.sock.token").read_text(encoding="utf-8")
        endpoint = (runtime_dir / "relay.sock.endpoint").read_text(encoding="utf-8")
        assert adapter.connected is True

        status = await ipc_request(endpoint, token, {"action": "status"})
        assert status == {"status": "running"}

        stopping = await ipc_request(endpoint, token, {"action": "stop"})
        assert stopping == {"status": "stopping"}

        assert await asyncio.wait_for(served, 5) == 0

    asyncio.run(run())

    assert adapter.disconnected is True
    assert not (runtime_dir / "relay.sock.endpoint").exists()
    assert not (runtime_dir / "relay.sock.token").exists()
    captured = capsys.readouterr()
    assert "secret" not in captured.out


@pytest.mark.skipif(os.name == "nt", reason="unix socket lifecycle")
def test_served_relay_delivers_reply_for_dispatched_event(
    tmp_path,
    short_runtime_dir,
    monkeypatch,
):
    adapter = FakeAdapter()
    monkeypatch.setattr(cli, "create_sdk_client", lambda bot_id, secret: adapter)
    runtime_dir = short_runtime_dir
    base = runtime_dir / "relay.sock"
    handler_output = tmp_path / "handler.jsonl"
    handler_argv = [sys.executable, str(_handler_script(tmp_path)), str(handler_output)]

    async def run() -> None:
        ready = asyncio.Event()
        served = asyncio.create_task(
            cli.serve_relay(base, "bot", "secret", handler_argv, 60.0, ready=ready)
        )
        await _wait_until_ready(ready, served)

        adapter.callback(
            TextEvent(
                event_id="msg-1",
                text="hello",
                route=ReplyRoute(req_id="req-1", stream_id="stream-1"),
            )
        )
        payload = await _await_handler_payload(handler_output)

        token = (runtime_dir / "relay.sock.token").read_text(encoding="utf-8")
        endpoint = (runtime_dir / "relay.sock.endpoint").read_text(encoding="utf-8")
        delivered = await ipc_request(
            endpoint,
            token,
            {
                "action": "reply",
                "context": payload["replyContext"],
                "kind": "final",
                "markdown": "done",
            },
        )
        assert delivered == {"status": "delivered"}

        await ipc_request(endpoint, token, {"action": "stop"})
        assert await asyncio.wait_for(served, 5) == 0

    asyncio.run(run())

    assert adapter.replies == [(ReplyRoute("req-1", "stream-1"), "done")]


def _handler_script(tmp_path: Path) -> Path:
    script = tmp_path / "handler.py"
    script.write_text(
        "import sys\n"
        "payload = sys.stdin.read()\n"
        "with open(sys.argv[1], 'a', encoding='utf-8') as handle:\n"
        "    handle.write(payload + '\\n')\n"
        "print('this output is not a reply')\n"
        "sys.exit(3)\n",
        encoding="utf-8",
    )
    return script


async def _await_handler_payload(path: Path) -> dict[str, object]:
    for _ in range(200):
        if path.exists():
            lines = path.read_text(encoding="utf-8").splitlines()
            if lines:
                return json.loads(lines[0])
        await asyncio.sleep(0.05)
    raise AssertionError("handler never produced a payload")


# --------------------------------------------------------------------------
# handler dispatch
# --------------------------------------------------------------------------


def _service() -> tuple[RelayService, FakeAdapter]:
    adapter = FakeAdapter()
    return RelayService(adapter, ContextStore(60), now=lambda: 100.0), adapter


def test_duplicate_text_events_start_the_handler_once(tmp_path):
    output = tmp_path / "handler.jsonl"
    argv = [sys.executable, str(_handler_script(tmp_path)), str(output)]

    async def run() -> None:
        dispatcher = cli.HandlerDispatcher(_service()[0], argv)
        route = ReplyRoute(req_id="req-1", stream_id="stream-1")
        dispatcher.dispatch(TextEvent("msg-1", "hello", route))
        dispatcher.dispatch(
            TextEvent("msg-1", "hello again", ReplyRoute("req-2", "stream-2"))
        )
        await dispatcher.aclose()

    asyncio.run(run())

    lines = output.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["text"] == "hello"
    assert payload["eventId"] == "msg-1"
    assert isinstance(payload["replyContext"], str) and payload["replyContext"]
    assert payload["receivedAt"].endswith("+00:00")
    assert set(payload) == {"text", "replyContext", "eventId", "receivedAt"}


def test_handler_exit_code_and_stdout_do_not_deliver_a_reply(tmp_path):
    output = tmp_path / "handler.jsonl"
    argv = [sys.executable, str(_handler_script(tmp_path)), str(output)]
    service, adapter = _service()

    async def run() -> None:
        dispatcher = cli.HandlerDispatcher(service, argv)
        dispatcher.dispatch(
            TextEvent("msg-1", "hello", ReplyRoute("req-1", "stream-1"))
        )
        await dispatcher.aclose()

    asyncio.run(run())

    assert adapter.replies == []


def test_missing_handler_reports_error_without_text_or_context(tmp_path, capsys):
    async def run() -> None:
        dispatcher = cli.HandlerDispatcher(_service()[0], None)
        dispatcher.dispatch(
            TextEvent("msg-1", "secret question", ReplyRoute("req-1", "stream-1"))
        )
        await dispatcher.aclose()

    asyncio.run(run())

    captured = capsys.readouterr()
    event = json.loads(captured.err.strip())
    assert event["event"] == "handler_not_configured"
    assert set(event) == {"event", "eventRef"}
    assert "secret question" not in captured.err
    assert "msg-1" not in captured.err
    assert "req-1" not in captured.err
    assert captured.out == ""


# --------------------------------------------------------------------------
# upgrade
# --------------------------------------------------------------------------


class FakeStream:
    """Reports a fixed tty state while still writing to the captured stream."""

    def __init__(self, wrapped: object, tty: bool) -> None:
        self._wrapped = wrapped
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty

    def write(self, data: str) -> int:
        return self._wrapped.write(data)

    def flush(self) -> None:
        self._wrapped.flush()


def _no_subprocess(monkeypatch) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("subprocess must not run")

    monkeypatch.setattr(cli.subprocess, "run", fail)


def _interactive(monkeypatch, *, tty: bool = True) -> None:
    monkeypatch.setattr(cli.sys, "stdin", FakeStream(cli.sys.stdin, tty))
    monkeypatch.setattr(cli.sys, "stdout", FakeStream(cli.sys.stdout, tty))


def _write_executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path.resolve()


def _verify_document(
    *,
    version: str = "1.1.0",
    verified: int = 3,
    skipped: int = 0,
    failures: list | None = None,
    error: str | None = None,
) -> str:
    document: dict[str, object] = {
        "schema": cli.VERIFY_SCHEMA,
        "version": cli.VERIFY_PROTOCOL_VERSION,
    }
    if error is not None:
        document["error"] = error
        return json.dumps(document)
    document.update(
        {
            "installedVersion": version,
            "verified": verified,
            "skipped": skipped,
            "failures": failures or [],
        }
    )
    return json.dumps(document)


def _stub_upgrade_environment(
    tmp_path: Path,
    monkeypatch,
    *,
    latest: str = "1.1.0",
    current: str = "1.0.0",
    verify_stdout: str | None = None,
    upgrade_returncode: int = 0,
    list_output: str = "wecom-aibot 1.0.0\n",
    bin_dir: Path | None = None,
):
    uv = _write_executable(tmp_path / "uv-bin" / "uv")
    tools_bin = bin_dir or (tmp_path / "tools" / "bin")
    tools_bin.mkdir(parents=True, exist_ok=True)
    target = _write_executable(tools_bin / "wecom-aibot")
    monkeypatch.setattr(cli.shutil, "which", lambda name: str(uv) if name == "uv" else None)
    monkeypatch.setattr(cli, "installed_version", lambda: current)
    monkeypatch.setattr(cli, "fetch_latest_version", lambda: latest)
    if verify_stdout is None:
        verify_stdout = _verify_document(version=latest)
    invocations: list[tuple[tuple[str, ...], dict]] = []

    def fake_run(args, **kwargs):
        argv = tuple(str(item) for item in args)
        invocations.append((argv, kwargs))
        if argv[:1] == (str(uv),) and argv[1:] == cli.UV_TOOL_LIST_ARGUMENTS:
            return subprocess.CompletedProcess(args, 0, stdout=list_output)
        if argv[:1] == (str(uv),) and argv[1:] == cli.UV_TOOL_BIN_ARGUMENTS:
            return subprocess.CompletedProcess(args, 0, stdout=f"{tools_bin}\n")
        if argv[:1] == (str(uv),) and argv[1:] == cli.UPGRADE_ARGUMENTS:
            return subprocess.CompletedProcess(args, upgrade_returncode)
        if argv == (str(target), cli.VERIFY_INSTALL_COMMAND):
            return subprocess.CompletedProcess(args, 0, stdout=verify_stdout)
        raise AssertionError(f"unexpected command: {argv}")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    return invocations, uv, target


def test_upgrade_reports_up_to_date_without_running_any_command(monkeypatch, capsys):
    monkeypatch.setattr(cli, "installed_version", lambda: "1.2.3")
    monkeypatch.setattr(cli, "fetch_latest_version", lambda: "1.2.3")
    _no_subprocess(monkeypatch)

    assert main(["upgrade"]) == 0
    assert "already_up_to_date" in capsys.readouterr().out


def test_upgrade_uses_pep440_ordering_for_prereleases(monkeypatch, capsys):
    monkeypatch.setattr(cli, "installed_version", lambda: "1.10.0")
    monkeypatch.setattr(cli, "fetch_latest_version", lambda: "1.9.0")
    _no_subprocess(monkeypatch)

    assert main(["upgrade"]) == 0
    assert "already_up_to_date" in capsys.readouterr().out


def test_upgrade_asks_for_confirmation_then_runs_fixed_command(tmp_path, monkeypatch, capsys):
    invocations, uv, target = _stub_upgrade_environment(tmp_path, monkeypatch)
    _interactive(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")

    assert main(["upgrade"]) == 0

    upgrade_calls = [
        invocation
        for invocation in invocations
        if invocation[0][1:] == cli.UPGRADE_ARGUMENTS
    ]
    assert upgrade_calls[0][0] == (str(uv), "tool", "upgrade", "wecom-aibot")
    assert upgrade_calls[0][1]["shell"] is False
    assert (str(target), cli.VERIFY_INSTALL_COMMAND) in [item[0] for item in invocations]
    captured = capsys.readouterr()
    assert "upgrade_complete" in captured.out
    assert '"version": "1.1.0"' in captured.out


def test_upgrade_declined_by_user_does_not_run_command(monkeypatch, capsys):
    monkeypatch.setattr(cli, "installed_version", lambda: "1.0.0")
    monkeypatch.setattr(cli, "fetch_latest_version", lambda: "1.1.0")
    _interactive(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    _no_subprocess(monkeypatch)

    assert main(["upgrade"]) == 4
    assert "upgrade_declined" in capsys.readouterr().err


def test_upgrade_with_yes_skips_prompt(tmp_path, monkeypatch):
    _stub_upgrade_environment(tmp_path, monkeypatch)
    _interactive(monkeypatch, tty=False)

    def refuse_input(prompt: str = "") -> str:
        raise AssertionError("must not prompt")

    monkeypatch.setattr("builtins.input", refuse_input)

    assert main(["upgrade", "--yes"]) == 0


def test_upgrade_refuses_to_hang_when_not_interactive(monkeypatch, capsys):
    monkeypatch.setattr(cli, "installed_version", lambda: "1.0.0")
    monkeypatch.setattr(cli, "fetch_latest_version", lambda: "1.1.0")
    _interactive(monkeypatch, tty=False)

    def refuse_input(prompt: str = "") -> str:
        raise AssertionError("must not prompt")

    monkeypatch.setattr("builtins.input", refuse_input)
    _no_subprocess(monkeypatch)

    assert main(["upgrade"]) == 5
    assert "confirmation_required" in capsys.readouterr().err


def test_upgrade_reports_unreachable_index(monkeypatch, capsys):
    import urllib.error

    monkeypatch.setattr(cli, "installed_version", lambda: "1.0.0")

    def unreachable() -> str:
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(cli, "fetch_latest_version", unreachable)
    _no_subprocess(monkeypatch)

    assert main(["upgrade"]) == 3
    assert "index_unavailable" in capsys.readouterr().err


def test_upgrade_reports_invalid_index_payload(monkeypatch, capsys):
    monkeypatch.setattr(cli, "installed_version", lambda: "1.0.0")

    def invalid() -> str:
        raise json.JSONDecodeError("bad", "{", 0)

    monkeypatch.setattr(cli, "fetch_latest_version", invalid)
    _no_subprocess(monkeypatch)

    assert main(["upgrade"]) == 3
    assert "index_unavailable" in capsys.readouterr().err


def test_upgrade_reports_unparsable_version(monkeypatch, capsys):
    monkeypatch.setattr(cli, "installed_version", lambda: "1.0.0")
    monkeypatch.setattr(cli, "fetch_latest_version", lambda: "not-a-version")
    _no_subprocess(monkeypatch)

    assert main(["upgrade"]) == 3
    assert "invalid_version" in capsys.readouterr().err


def test_upgrade_reports_missing_uv(monkeypatch, capsys):
    monkeypatch.setattr(cli, "installed_version", lambda: "1.0.0")
    monkeypatch.setattr(cli, "fetch_latest_version", lambda: "1.1.0")
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)
    _no_subprocess(monkeypatch)

    assert main(["upgrade", "--yes"]) == 6
    assert "uv_not_found" in capsys.readouterr().err


def test_upgrade_reports_failed_command(tmp_path, monkeypatch, capsys):
    invocations, _, _ = _stub_upgrade_environment(
        tmp_path,
        monkeypatch,
        upgrade_returncode=2,
    )

    def unreachable_verify() -> cli.IntegrityReport:
        raise AssertionError("verification must not run after a failed upgrade")

    monkeypatch.setattr(cli, "verify_installed_distribution", unreachable_verify)

    assert main(["upgrade", "--yes"]) == 1
    assert "upgrade_failed" in capsys.readouterr().err
    assert not any(invocation[0][-1:] == (cli.VERIFY_INSTALL_COMMAND,) for invocation in invocations)


def test_upgrade_fails_when_post_upgrade_checksums_mismatch(tmp_path, monkeypatch, capsys):
    _stub_upgrade_environment(
        tmp_path,
        monkeypatch,
        verify_stdout=_verify_document(
            version="1.1.0",
            verified=4,
            skipped=1,
            failures=[{"path": "wecom_aibot/cli.py", "reason": "digest_mismatch"}],
        ),
    )

    assert main(["upgrade", "--yes"]) == 7
    captured = capsys.readouterr()
    assert "integrity_failed" in captured.err
    assert "upgrade_complete" not in captured.out


def test_upgrade_fails_when_record_is_missing(tmp_path, monkeypatch, capsys):
    _stub_upgrade_environment(
        tmp_path,
        monkeypatch,
        verify_stdout=_verify_document(error="record_missing"),
    )

    assert main(["upgrade", "--yes"]) == 7
    captured = capsys.readouterr()
    assert "record_missing" in captured.err
    assert "upgrade_complete" not in captured.out


# --------------------------------------------------------------------------
# post-upgrade integrity verification
# --------------------------------------------------------------------------


def _record_hash(data: bytes, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm, data).digest()
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"{algorithm}={encoded}"


def _install_distribution(
    tmp_path: Path,
    monkeypatch,
    name: str,
    *,
    files: dict[str, bytes],
    rows: list[list[str]] | None,
    extra_rows: list[list[str]] | None = None,
) -> None:
    site = tmp_path / "site"
    site.mkdir(exist_ok=True)
    dist_info = site / f"{name.replace('-', '_')}-1.0.0.dist-info"
    dist_info.mkdir()
    metadata = f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0.0\n"
    (dist_info / "METADATA").write_text(metadata, encoding="utf-8")

    for relative, data in files.items():
        target = site / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    if rows is not None:
        computed = [
            [relative, _record_hash(data), str(len(data))]
            for relative, data in files.items()
        ]
        all_rows = (rows or computed) + (extra_rows or [])
        all_rows.append([f"{dist_info.name}/RECORD", "", ""])
        lines = [",".join(row) for row in all_rows]
        (dist_info / "RECORD").write_text("\n".join(lines) + "\n", encoding="utf-8")

    monkeypatch.syspath_prepend(str(site))


def test_intact_distribution_passes_verification(tmp_path, monkeypatch):
    files = {"intact_pkg/__init__.py": b"print('ok')\n", "intact_pkg/api.py": b"x = 1\n"}
    _install_distribution(tmp_path, monkeypatch, "intact-dist", files=files, rows=[])

    report = cli.verify_installed_distribution("intact-dist")

    assert report.failures == ()
    assert report.verified == 2
    assert report.skipped == 1


def test_size_mismatch_is_reported(tmp_path, monkeypatch):
    files = {"tampered_pkg/__init__.py": b"print('ok')\n"}
    _install_distribution(tmp_path, monkeypatch, "tampered-dist", files=files, rows=[])
    (tmp_path / "site" / "tampered_pkg" / "__init__.py").write_bytes(b"print('ok')\n\n")

    report = cli.verify_installed_distribution("tampered-dist")

    assert [reason for _, reason in report.failures] == ["size_mismatch"]


def test_digest_mismatch_with_matching_size_is_reported(tmp_path, monkeypatch):
    files = {"swapped_pkg/__init__.py": b"aaaa\n"}
    _install_distribution(tmp_path, monkeypatch, "swapped-dist", files=files, rows=[])
    (tmp_path / "site" / "swapped_pkg" / "__init__.py").write_bytes(b"bbbb\n")

    report = cli.verify_installed_distribution("swapped-dist")

    assert report.failures == (("swapped_pkg/__init__.py", "digest_mismatch"),)


def test_missing_file_is_reported(tmp_path, monkeypatch):
    files = {"gone_pkg/__init__.py": b"data\n"}
    _install_distribution(tmp_path, monkeypatch, "gone-dist", files=files, rows=[])
    (tmp_path / "site" / "gone_pkg" / "__init__.py").unlink()

    report = cli.verify_installed_distribution("gone-dist")

    assert report.failures == (("gone_pkg/__init__.py", "missing"),)


def test_missing_record_fails_closed(tmp_path, monkeypatch):
    _install_distribution(
        tmp_path,
        monkeypatch,
        "norecord-dist",
        files={"norecord_pkg/__init__.py": b"data\n"},
        rows=None,
    )

    with pytest.raises(cli.CliError) as error:
        cli.verify_installed_distribution("norecord-dist")

    assert error.value.code == "record_missing"


def test_record_without_any_hash_fails_closed(tmp_path, monkeypatch):
    _install_distribution(
        tmp_path,
        monkeypatch,
        "nohash-dist",
        files={"nohash_pkg/__init__.py": b"data\n"},
        rows=[["nohash_pkg/__init__.py", "", ""]],
    )

    with pytest.raises(cli.CliError) as error:
        cli.verify_installed_distribution("nohash-dist")

    assert error.value.code == "no_verifiable_hashes"


def test_unknown_algorithm_fails_closed(tmp_path, monkeypatch):
    data = b"data\n"
    _install_distribution(
        tmp_path,
        monkeypatch,
        "weakhash-dist",
        files={"weakhash_pkg/__init__.py": data, "weakhash_pkg/ok.py": data},
        rows=[
            [
                "weakhash_pkg/__init__.py",
                f"md5={base64.urlsafe_b64encode(hashlib.md5(data).digest()).decode().rstrip('=')}",
                str(len(data)),
            ],
            ["weakhash_pkg/ok.py", _record_hash(data), str(len(data))],
        ],
    )

    report = cli.verify_installed_distribution("weakhash-dist")

    assert report.failures == (("weakhash_pkg/__init__.py", "unsupported_algorithm"),)


@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        ("../outside.py", "path_escape"),
        ("/etc/passwd", "path_escape"),
        ("nested/../../outside.py", "path_escape"),
    ],
)
def test_paths_outside_the_install_root_fail_closed(
    tmp_path,
    monkeypatch,
    entry: str,
    reason: str,
):
    data = b"data\n"
    name = "escape-dist"
    _install_distribution(
        tmp_path,
        monkeypatch,
        name,
        files={"escape_pkg/__init__.py": data},
        rows=[["escape_pkg/__init__.py", _record_hash(data), str(len(data))]],
        extra_rows=[[entry, _record_hash(data), str(len(data))]],
    )

    report = cli.verify_installed_distribution(name)

    assert [failure_reason for _, failure_reason in report.failures] == [reason]


def test_console_scripts_outside_site_packages_are_verified(tmp_path, monkeypatch):
    data = b"#!/usr/bin/env python\n"
    script = tmp_path / "bin" / "wecom-aibot"
    script.parent.mkdir()
    script.write_bytes(data)
    monkeypatch.setattr(cli.sys, "prefix", str(tmp_path))
    _install_distribution(
        tmp_path,
        monkeypatch,
        "scripted-dist",
        files={"scripted_pkg/__init__.py": data},
        rows=[["scripted_pkg/__init__.py", _record_hash(data), str(len(data))]],
        extra_rows=[["../bin/wecom-aibot", _record_hash(data), str(len(data))]],
    )

    report = cli.verify_installed_distribution("scripted-dist")

    assert report.failures == ()
    assert report.verified == 2


def test_malformed_digest_encoding_fails_closed(tmp_path, monkeypatch):
    data = b"data\n"
    _install_distribution(
        tmp_path,
        monkeypatch,
        "badb64-dist",
        files={"badb64_pkg/__init__.py": data, "badb64_pkg/ok.py": data},
        rows=[
            ["badb64_pkg/__init__.py", "sha256=not*valid*base64", str(len(data))],
            ["badb64_pkg/ok.py", _record_hash(data), str(len(data))],
        ],
    )

    report = cli.verify_installed_distribution("badb64-dist")

    assert report.failures == (("badb64_pkg/__init__.py", "invalid_digest_encoding"),)


def test_digest_without_algorithm_fails_closed(tmp_path, monkeypatch):
    data = b"data\n"
    _install_distribution(
        tmp_path,
        monkeypatch,
        "nodigestalgo-dist",
        files={"nodigestalgo_pkg/__init__.py": data, "nodigestalgo_pkg/ok.py": data},
        rows=[
            ["nodigestalgo_pkg/__init__.py", "deadbeef", str(len(data))],
            ["nodigestalgo_pkg/ok.py", _record_hash(data), str(len(data))],
        ],
    )

    report = cli.verify_installed_distribution("nodigestalgo-dist")

    assert report.failures == (
        ("nodigestalgo_pkg/__init__.py", "invalid_digest_format"),
    )


def test_verification_output_only_reports_relative_paths(tmp_path, monkeypatch, capsys):
    _stub_upgrade_environment(
        tmp_path,
        monkeypatch,
        verify_stdout=_verify_document(
            version="1.1.0",
            failures=[{"path": "report_pkg/__init__.py", "reason": "digest_mismatch"}],
        ),
    )

    assert main(["upgrade", "--yes"]) == 7

    captured = capsys.readouterr()
    assert "report_pkg/__init__.py" in captured.err
    assert str(tmp_path) not in captured.err
    assert "site-packages" not in captured.err


# --------------------------------------------------------------------------
# C1: verify the upgraded uv-tool target, not this interpreter
# --------------------------------------------------------------------------


def test_upgrade_verifies_the_uv_tool_target_not_the_current_interpreter(
    tmp_path,
    monkeypatch,
    capsys,
):
    invocations, uv, target = _stub_upgrade_environment(tmp_path, monkeypatch)

    def boom() -> cli.IntegrityReport:
        raise AssertionError("must not verify the current interpreter")

    monkeypatch.setattr(cli, "verify_installed_distribution", boom)

    assert main(["upgrade", "--yes"]) == 0

    commands = [invocation[0] for invocation in invocations]
    assert (str(uv), "tool", "upgrade", "wecom-aibot") in commands
    assert (str(target), cli.VERIFY_INSTALL_COMMAND) in commands
    assert all(command[:1] != (sys.executable,) for command in commands)
    captured = capsys.readouterr()
    assert "upgrade_complete" in captured.out
    assert '"version": "1.1.0"' in captured.out


def test_upgrade_fails_when_target_version_is_unchanged(tmp_path, monkeypatch, capsys):
    _stub_upgrade_environment(
        tmp_path,
        monkeypatch,
        current="1.0.0",
        latest="1.1.0",
        verify_stdout=_verify_document(version="1.0.0"),
    )

    assert main(["upgrade", "--yes"]) == 7
    captured = capsys.readouterr()
    assert "version_not_upgraded" in captured.err
    assert "upgrade_complete" not in captured.out


def test_upgrade_fails_when_target_version_does_not_match_pypi_latest(
    tmp_path,
    monkeypatch,
    capsys,
):
    _stub_upgrade_environment(
        tmp_path,
        monkeypatch,
        latest="1.2.0",
        verify_stdout=_verify_document(version="1.1.0"),
    )

    assert main(["upgrade", "--yes"]) == 7
    captured = capsys.readouterr()
    assert "version_not_upgraded" in captured.err
    assert "upgrade_complete" not in captured.out


def test_upgrade_refuses_when_uv_tool_target_is_missing(tmp_path, monkeypatch, capsys):
    invocations, _, _ = _stub_upgrade_environment(
        tmp_path,
        monkeypatch,
        list_output="other-tool 2.0.0\n",
    )

    assert main(["upgrade", "--yes"]) == 7
    captured = capsys.readouterr()
    assert "uv_tool_not_installed" in captured.err
    assert "upgrade_complete" not in captured.out
    assert not any(invocation[0][1:] == cli.UPGRADE_ARGUMENTS for invocation in invocations)


def test_upgrade_invokes_uv_via_absolute_which_path(tmp_path, monkeypatch):
    invocations, uv, _ = _stub_upgrade_environment(tmp_path, monkeypatch)

    assert main(["upgrade", "--yes"]) == 0
    assert all(invocation[0][0] != "uv" for invocation in invocations)
    assert all(invocation[0][0] == str(uv) or invocation[0][0].endswith("wecom-aibot") for invocation in invocations)


def test_upgrade_eof_during_confirmation_is_declined(monkeypatch, capsys):
    monkeypatch.setattr(cli, "installed_version", lambda: "1.0.0")
    monkeypatch.setattr(cli, "fetch_latest_version", lambda: "1.1.0")
    _interactive(monkeypatch)

    def eof(_prompt: str = "") -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    _no_subprocess(monkeypatch)

    assert main(["upgrade"]) == 4
    assert "upgrade_declined" in capsys.readouterr().err


# --------------------------------------------------------------------------
# I1: bounded RECORD reads fail closed without leaking paths
# --------------------------------------------------------------------------


def test_oversized_record_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "MAX_RECORD_BYTES", 32)
    files = {"oversize_pkg/__init__.py": b"data\n"}
    _install_distribution(tmp_path, monkeypatch, "oversize-dist", files=files, rows=[])
    record = tmp_path / "site" / "oversize_dist-1.0.0.dist-info" / "RECORD"
    record.write_text("x" * 64, encoding="utf-8")

    with pytest.raises(cli.CliError) as error:
        cli.verify_installed_distribution("oversize-dist")

    assert error.value.code == "record_too_large"
    assert error.value.exit_code == 7


def test_record_invalid_utf8_fails_closed(tmp_path, monkeypatch):
    files = {"badutf_pkg/__init__.py": b"data\n"}
    _install_distribution(tmp_path, monkeypatch, "badutf-dist", files=files, rows=[])
    record = tmp_path / "site" / "badutf_dist-1.0.0.dist-info" / "RECORD"
    record.write_bytes(b"\xff\xfe not utf-8")

    with pytest.raises(cli.CliError) as error:
        cli.verify_installed_distribution("badutf-dist")

    assert error.value.code == "record_unreadable"
    assert error.value.exit_code == 7


def test_malformed_csv_record_fails_closed(tmp_path, monkeypatch):
    files = {"badcsv_pkg/__init__.py": b"data\n"}
    _install_distribution(tmp_path, monkeypatch, "badcsv-dist", files=files, rows=[])
    record = tmp_path / "site" / "badcsv_dist-1.0.0.dist-info" / "RECORD"
    record.write_text('pkg/__init__.py,"unclosed-hash\n', encoding="utf-8")

    with pytest.raises(cli.CliError) as error:
        cli.verify_installed_distribution("badcsv-dist")

    assert error.value.code == "record_unreadable"
    assert error.value.exit_code == 7


def test_unreadable_record_oserror_fails_closed(tmp_path, monkeypatch):
    files = {"iorecord_pkg/__init__.py": b"data\n"}
    _install_distribution(tmp_path, monkeypatch, "iorecord-dist", files=files, rows=[])
    record = tmp_path / "site" / "iorecord_dist-1.0.0.dist-info" / "RECORD"
    record.chmod(0o000)

    try:
        with pytest.raises(cli.CliError) as error:
            cli.verify_installed_distribution("iorecord-dist")
    finally:
        record.chmod(0o600)

    assert error.value.code == "record_unreadable"
    assert error.value.exit_code == 7


def test_record_read_errors_exit_7_without_traceback_or_paths(
    tmp_path,
    monkeypatch,
    capsys,
):
    _stub_upgrade_environment(
        tmp_path,
        monkeypatch,
        verify_stdout=_verify_document(error="record_unreadable"),
    )

    assert main(["upgrade", "--yes"]) == 7
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "record_unreadable" in captured.err
    assert "upgrade_complete" not in captured.out
    assert "Traceback" not in combined
    assert str(tmp_path) not in combined
    assert str(tmp_path.resolve()) not in combined


# --------------------------------------------------------------------------
# I2: leftover endpoints stay put; signals request a controlled stop
# --------------------------------------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="unix leftover socket")
def test_leftover_socket_with_token_is_already_running(
    short_runtime_dir,
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(cli, "create_sdk_client", lambda bot_id, secret: FakeAdapter())
    base = short_runtime_dir / "relay.sock"
    base.write_bytes(b"stale-socket")
    token = Path(f"{base}.token")
    token.write_text("old-token", encoding="utf-8")
    token.chmod(0o600)

    with pytest.raises(cli.CliError) as error:
        asyncio.run(cli.serve_relay(base, "bot", "secret", None, 60.0))

    assert error.value.code == "relay_already_running"
    assert base.exists()
    assert token.exists()
    assert token.read_text(encoding="utf-8") == "old-token"


@pytest.mark.skipif(os.name == "nt", reason="unix leftover socket")
def test_leftover_socket_without_token_is_stale_endpoint(short_runtime_dir, monkeypatch):
    monkeypatch.setattr(cli, "create_sdk_client", lambda bot_id, secret: FakeAdapter())
    base = short_runtime_dir / "relay.sock"
    base.write_bytes(b"stale-socket")

    with pytest.raises(cli.CliError) as error:
        asyncio.run(cli.serve_relay(base, "bot", "secret", None, 60.0))

    assert error.value.code == "stale_endpoint"
    assert base.exists()
    assert not Path(f"{base}.token").exists()


@pytest.mark.skipif(os.name == "nt", reason="unix leftover endpoint")
def test_leftover_endpoint_file_is_stale_and_not_deleted(short_runtime_dir, monkeypatch):
    monkeypatch.setattr(cli, "create_sdk_client", lambda bot_id, secret: FakeAdapter())
    base = short_runtime_dir / "relay.sock"
    leftover = Path(f"{base}.endpoint")
    leftover.write_text("unix:/old", encoding="utf-8")
    leftover.chmod(0o600)

    with pytest.raises(cli.CliError) as error:
        asyncio.run(cli.serve_relay(base, "bot", "secret", None, 60.0))

    assert error.value.code == "stale_endpoint"
    assert leftover.exists()
    assert leftover.read_text(encoding="utf-8") == "unix:/old"


@pytest.mark.skipif(os.name == "nt", reason="unix signals")
def test_sigterm_requests_controlled_stop(short_runtime_dir, monkeypatch):
    adapter = FakeAdapter()
    monkeypatch.setattr(cli, "create_sdk_client", lambda bot_id, secret: adapter)
    runtime_dir = short_runtime_dir
    base = runtime_dir / "relay.sock"

    async def run() -> None:
        ready = asyncio.Event()
        served = asyncio.create_task(
            cli.serve_relay(base, "bot", "secret", None, 60.0, ready=ready)
        )
        await _wait_until_ready(ready, served)
        os.kill(os.getpid(), signal.SIGTERM)
        assert await asyncio.wait_for(served, 5) == 0

    asyncio.run(run())

    assert adapter.inbound_stopped is True
    assert adapter.disconnected is True
    assert not (runtime_dir / "relay.sock.endpoint").exists()
    assert not (runtime_dir / "relay.sock.token").exists()


# --------------------------------------------------------------------------
# I3: stop keeps reply IPC open while handlers drain
# --------------------------------------------------------------------------


def _blocking_handler_script(tmp_path: Path) -> Path:
    script = tmp_path / "blocking_handler.py"
    script.write_text(
        "import pathlib, sys, time\n"
        "payload = sys.stdin.read()\n"
        "pathlib.Path(sys.argv[1]).write_text(payload + '\\n', encoding='utf-8')\n"
        "gate = pathlib.Path(sys.argv[2])\n"
        "for _ in range(400):\n"
        "    if gate.exists():\n"
        "        break\n"
        "    time.sleep(0.05)\n",
        encoding="utf-8",
    )
    return script


@pytest.mark.skipif(os.name == "nt", reason="unix socket lifecycle")
def test_reply_succeeds_during_handler_drain_after_stop(
    tmp_path,
    short_runtime_dir,
    monkeypatch,
):
    adapter = FakeAdapter()
    monkeypatch.setattr(cli, "create_sdk_client", lambda bot_id, secret: adapter)
    runtime_dir = short_runtime_dir
    base = runtime_dir / "relay.sock"
    handler_output = tmp_path / "handler.jsonl"
    gate = tmp_path / "continue"
    handler_argv = [
        sys.executable,
        str(_blocking_handler_script(tmp_path)),
        str(handler_output),
        str(gate),
    ]

    async def run() -> None:
        ready = asyncio.Event()
        served = asyncio.create_task(
            cli.serve_relay(base, "bot", "secret", handler_argv, 60.0, ready=ready)
        )
        await _wait_until_ready(ready, served)

        adapter.callback(
            TextEvent(
                event_id="msg-drain",
                text="hello",
                route=ReplyRoute(req_id="req-drain", stream_id="stream-drain"),
            )
        )
        payload = await _await_handler_payload(handler_output)
        token = (runtime_dir / "relay.sock.token").read_text(encoding="utf-8")
        endpoint = (runtime_dir / "relay.sock.endpoint").read_text(encoding="utf-8")

        stopping = await ipc_request(endpoint, token, {"action": "stop"})
        assert stopping == {"status": "stopping"}
        for _ in range(50):
            if adapter.inbound_stopped:
                break
            await asyncio.sleep(0.01)
        assert adapter.inbound_stopped is True
        assert adapter.disconnected is False

        delivered = await ipc_request(
            endpoint,
            token,
            {
                "action": "reply",
                "context": payload["replyContext"],
                "kind": "final",
                "markdown": "drained",
            },
        )
        assert delivered == {"status": "delivered"}
        gate.write_text("ok", encoding="utf-8")
        assert await asyncio.wait_for(served, 5) == 0

    asyncio.run(run())

    assert adapter.replies == [(ReplyRoute("req-drain", "stream-drain"), "drained")]
    assert adapter.disconnected is True


def test_handler_done_callback_retrieves_task_exception():
    class BoomService:
        async def handle_text(self, *args: object, **kwargs: object) -> str:
            raise RuntimeError("handler boom")

    async def run() -> None:
        loop = asyncio.get_running_loop()
        seen: list[object] = []
        loop.set_exception_handler(lambda _loop, context: seen.append(context))
        dispatcher = cli.HandlerDispatcher(BoomService(), None)  # type: ignore[arg-type]
        dispatcher.dispatch(
            TextEvent("msg-1", "hello", ReplyRoute("req-1", "stream-1"))
        )
        await asyncio.sleep(0.05)
        await dispatcher.aclose()
        assert seen == []

    asyncio.run(run())
