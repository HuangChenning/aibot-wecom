from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import hashlib
import hmac
import importlib
import importlib.metadata
import io
import json
import ntpath
import os
import re
import secrets
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from packaging.version import InvalidVersion, Version

from wecom_aibot import __version__, ipc
from wecom_aibot.context_store import ContextStore
from wecom_aibot.ipc import IpcServer, request
from wecom_aibot.sdk import TextEvent, create_sdk_client
from wecom_aibot.service import RelayService

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_UNAVAILABLE = 3
EXIT_DECLINED = 4
EXIT_NOT_INTERACTIVE = 5
EXIT_MISSING_UV = 6
EXIT_INTEGRITY_FAILED = 7
EXIT_UNKNOWN = 75

RUNTIME_DIR_ENV = "WECOM_AIBOT_RUNTIME_DIR"
ENDPOINT_ENV = "WECOM_AIBOT_ENDPOINT"
BOT_ID_ENV = "WECHAT_BOT_ID"
BOT_SECRET_ENV = "WECHAT_BOT_SECRET"
DEFAULT_ENDPOINT_NAME = "relay.sock"
DEFAULT_CONTEXT_TTL_SECONDS = 900.0

MAX_CONTENT_BYTES = 1_048_576
MAX_SIDECAR_BYTES = 4096
MAX_CONFIG_BYTES = 65_536
HANDLER_DEDUPE_LIMIT = 4096
HANDLER_DRAIN_TIMEOUT_SECONDS = 30.0

DISTRIBUTION_NAME = "wecom-aibot"
PYPI_JSON_URL = "https://pypi.org/pypi/wecom-aibot/json"
UPGRADE_COMMAND: tuple[str, ...] = ("uv", "tool", "upgrade", "wecom-aibot")
PYPI_TIMEOUT_SECONDS = 10.0
MAX_PYPI_RESPONSE_BYTES = 1_048_576
ALLOWED_RECORD_ALGORITHMS = frozenset({"sha256", "sha384", "sha512"})
MAX_REPORTED_FAILURES = 10
_BASE64_URLSAFE_PATTERN = re.compile(r"\A[A-Za-z0-9_-]+\Z")

_WINDOWS_PRIVATE_DIR_SDDL = "D:P(A;OICI;FA;;;OW)"
_ERROR_ALREADY_EXISTS = 183

_REPLY_EXITS = {"delivered": EXIT_OK, "not_delivered": EXIT_FAILED}
_STATUS_EXITS = {"running": EXIT_OK}
_STOP_EXITS = {"stopping": EXIT_OK}


class CliError(Exception):
    def __init__(self, code: str, exit_code: int = EXIT_FAILED) -> None:
        super().__init__(code)
        self.code = code
        self.exit_code = exit_code


def _emit(event: dict[str, object]) -> None:
    print(json.dumps(event, ensure_ascii=False, sort_keys=True))


def _emit_error(code: str, **fields: object) -> None:
    payload: dict[str, object] = {"event": "error", "code": code}
    payload.update(fields)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True), file=sys.stderr)


def _event_ref(event_id: str) -> str:
    return hashlib.sha256(event_id.encode("utf-8")).hexdigest()[:12]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# runtime directory and sidecars
# ---------------------------------------------------------------------------


def _create_windows_private_dir(path: str) -> None:  # pragma: no cover - Windows only
    import ctypes
    from ctypes import wintypes

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", wintypes.LPVOID),
            ("bInheritHandle", wintypes.BOOL),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    security_descriptor = wintypes.LPVOID()
    convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.ULONG),
    ]
    convert.restype = wintypes.BOOL
    if not convert(
        _WINDOWS_PRIVATE_DIR_SDDL,
        1,
        ctypes.byref(security_descriptor),
        None,
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    attributes = SecurityAttributes(
        ctypes.sizeof(SecurityAttributes),
        security_descriptor,
        False,
    )
    local_free = kernel32.LocalFree
    local_free.argtypes = [wintypes.HLOCAL]
    local_free.restype = wintypes.HLOCAL
    try:
        create_directory = kernel32.CreateDirectoryW
        create_directory.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(SecurityAttributes),
        ]
        create_directory.restype = wintypes.BOOL
        if not create_directory(path, ctypes.byref(attributes)):
            error = ctypes.get_last_error()
            if error != _ERROR_ALREADY_EXISTS:
                raise ctypes.WinError(error)
    finally:
        local_free(security_descriptor)


def ensure_runtime_dir(
    path: Path,
    *,
    windows: bool | None = None,
    windows_creator: Callable[[str], None] = _create_windows_private_dir,
    windows_inspector: Callable[[str], tuple[bool, bool]] = (
        ipc._inspect_windows_token_parent
    ),
) -> Path:
    """Create the relay's private run directory and verify it stays owner-only."""
    use_windows = os.name == "nt" if windows is None else windows
    if use_windows:
        missing: list[Path] = []
        candidate = path
        while not candidate.exists():
            missing.append(candidate)
            if candidate.parent == candidate:
                break
            candidate = candidate.parent
        for ancestor in reversed(missing):
            windows_creator(str(ancestor))
        is_reparse, is_owner_only = windows_inspector(str(path))
        if is_reparse or not is_owner_only:
            raise CliError("insecure_runtime_dir")
        return path

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    _require_owner_only_dir(path)
    return path


def _require_owner_only_dir(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise CliError("insecure_runtime_dir") from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise CliError("insecure_runtime_dir")


def _require_owner_only_file(
    path: Path,
    code: str,
    *,
    windows: bool | None = None,
    windows_inspector: Callable[[str], tuple[bool, bool]] = (
        ipc._inspect_windows_token_parent
    ),
) -> None:
    use_windows = os.name == "nt" if windows is None else windows
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise CliError(code)
    if use_windows:
        is_reparse, is_owner_only = windows_inspector(str(path.parent))
        if is_reparse or not is_owner_only:
            raise CliError(code)
        return
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise CliError(code)


def _default_runtime_dir() -> Path:
    override = os.environ.get(RUNTIME_DIR_ENV)
    if override:
        return Path(override)
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return Path(base) / "wecom-aibot" / "run"
    xdg_runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if xdg_runtime_dir:
        return Path(xdg_runtime_dir) / "wecom-aibot"
    return Path.home() / ".wecom-aibot" / "run"


def _endpoint_base(argument: str | None) -> Path:
    if argument:
        return Path(argument)
    configured = os.environ.get(ENDPOINT_ENV)
    if configured:
        return Path(configured)
    return _default_runtime_dir() / DEFAULT_ENDPOINT_NAME


def _read_sidecar(path: Path, code: str) -> str:
    try:
        _require_owner_only_file(path, code)
    except FileNotFoundError as error:
        raise CliError("relay_not_running") from error
    with path.open("rb") as handle:
        raw = handle.read(MAX_SIDECAR_BYTES + 1)
    if len(raw) > MAX_SIDECAR_BYTES:
        raise CliError(code)
    try:
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise CliError(code) from error
    if not value:
        raise CliError(code)
    return value


def _resolve_connection(endpoint_argument: str | None) -> tuple[str, str]:
    base = _endpoint_base(endpoint_argument)
    token = _read_sidecar(Path(f"{base}.token"), "insecure_token_permissions")
    endpoint_file = Path(f"{base}.endpoint")
    if endpoint_file.exists():
        endpoint = _read_sidecar(endpoint_file, "insecure_endpoint_permissions")
    else:
        endpoint = str(base)
    return endpoint, token


# ---------------------------------------------------------------------------
# credentials
# ---------------------------------------------------------------------------


def load_credentials(config_path: Path | None) -> tuple[str, str]:
    """Read Bot ID and Secret from an owner-only config file or the environment."""
    if config_path is not None:
        try:
            _require_owner_only_file(config_path, "insecure_config_permissions")
        except FileNotFoundError as error:
            raise CliError("missing_config") from error
        with config_path.open("rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
        if len(raw) > MAX_CONFIG_BYTES:
            raise CliError("invalid_config")
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CliError("invalid_config") from error
        if not isinstance(document, dict):
            raise CliError("invalid_config")
        bot_id = document.get("botId")
        secret = document.get("botSecret")
    else:
        bot_id = os.environ.get(BOT_ID_ENV)
        secret = os.environ.get(BOT_SECRET_ENV)

    if not isinstance(bot_id, str) or not bot_id.strip():
        raise CliError("missing_credentials")
    if not isinstance(secret, str) or not secret.strip():
        raise CliError("missing_credentials")
    return bot_id.strip(), secret.strip()


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------


class HandlerDispatcher:
    """Starts at most one handler process per de-duplicated text event."""

    def __init__(
        self,
        service: RelayService,
        handler_argv: Sequence[str] | None,
    ) -> None:
        self._service = service
        self._handler_argv = list(handler_argv) if handler_argv else None
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._tasks: set[asyncio.Task[None]] = set()

    def dispatch(self, event: TextEvent) -> None:
        if event.event_id in self._seen:
            return
        self._seen[event.event_id] = None
        while len(self._seen) > HANDLER_DEDUPE_LIMIT:
            self._seen.popitem(last=False)
        task = asyncio.create_task(self._run(event))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _run(self, event: TextEvent) -> None:
        context = await self._service.handle_text(
            event.event_id,
            event.text,
            event.route,
        )
        if self._handler_argv is None:
            _emit_error_stream(
                {
                    "event": "handler_not_configured",
                    "eventRef": _event_ref(event.event_id),
                }
            )
            return

        payload = json.dumps(
            {
                "text": event.text,
                "replyContext": context,
                "eventId": event.event_id,
                "receivedAt": _utc_now(),
            },
            ensure_ascii=False,
        ).encode("utf-8")

        try:
            process = await asyncio.create_subprocess_exec(
                *self._handler_argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except OSError:
            _emit_error_stream(
                {
                    "event": "handler_start_failed",
                    "eventRef": _event_ref(event.event_id),
                }
            )
            return

        try:
            # The handler replies through the relay; its stdout and exit code
            # are deliberately ignored.
            await process.communicate(payload)
        except asyncio.CancelledError:
            process.kill()
            raise

    async def aclose(self) -> None:
        pending = {task for task in self._tasks if not task.done()}
        if pending:
            _, still_running = await asyncio.wait(
                pending,
                timeout=HANDLER_DRAIN_TIMEOUT_SECONDS,
            )
            for task in still_running:
                task.cancel()
            if still_running:
                await asyncio.gather(*still_running, return_exceptions=True)
        for task in list(self._tasks):
            if task.done() and not task.cancelled():
                task.exception()
        self._tasks.clear()


def _emit_error_stream(event: dict[str, object]) -> None:
    print(json.dumps(event, ensure_ascii=False, sort_keys=True), file=sys.stderr)


async def serve_relay(
    base: Path,
    bot_id: str,
    secret: str,
    handler_argv: Sequence[str] | None,
    context_ttl: float,
    *,
    ready: asyncio.Event | None = None,
) -> int:
    adapter = create_sdk_client(bot_id, secret)
    service = RelayService(adapter, ContextStore(context_ttl))
    dispatcher = HandlerDispatcher(service, handler_argv)
    adapter.on_text(dispatcher.dispatch)

    server = IpcServer(service, secrets.token_urlsafe(32))
    await server.start(str(base))
    endpoint_file = Path(f"{base}.endpoint")
    try:
        ipc._write_token_file(str(endpoint_file), server.endpoint)
        await adapter.connect()
        _emit({"event": "serving"})
        if ready is not None:
            ready.set()
        await server.wait_stopped()
    finally:
        endpoint_file.unlink(missing_ok=True)
        await dispatcher.aclose()
        adapter.disconnect()
        await server.close()
    return EXIT_OK


def _run_serve(args: argparse.Namespace) -> int:
    config = Path(args.config) if args.config else None
    bot_id, secret = load_credentials(config)
    base = _endpoint_base(args.endpoint)
    ensure_runtime_dir(base.parent)
    handler_argv = list(args.handler) if args.handler else None
    return asyncio.run(
        serve_relay(base, bot_id, secret, handler_argv, args.context_ttl)
    )


# ---------------------------------------------------------------------------
# reply / status / stop
# ---------------------------------------------------------------------------


def _read_content(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_CONTENT_BYTES + 1)
    except OSError as error:
        raise CliError("unreadable_content_file") from error
    if len(raw) > MAX_CONTENT_BYTES:
        raise CliError("content_too_large")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CliError("invalid_content_encoding") from error


def _response_status(response: object) -> tuple[str, str]:
    if not isinstance(response, dict):
        return ("invalid_response", "")
    status = response.get("status")
    reason = response.get("reason")
    return (
        status if isinstance(status, str) else "invalid_response",
        reason if isinstance(reason, str) else "",
    )


def _run_reply(args: argparse.Namespace) -> int:
    markdown = _read_content(Path(args.content_file))
    endpoint, token = _resolve_connection(args.endpoint)
    payload: dict[str, object] = {
        "action": "reply",
        "context": args.context,
        "kind": "final",
        "markdown": markdown,
    }
    try:
        response = asyncio.run(request(endpoint, token, payload))
    except (FileNotFoundError, ConnectionRefusedError):
        _emit_error("relay_not_running")
        return EXIT_FAILED
    except ValueError:
        _emit_error("request_rejected")
        return EXIT_FAILED
    except Exception:  # noqa: BLE001 - delivery certainty cannot be established
        _emit_error("delivery_unknown")
        return EXIT_UNKNOWN

    status, reason = _response_status(response)
    _emit({"event": "reply", "status": status, "reason": reason})
    if status == "unknown":
        return EXIT_UNKNOWN
    return _REPLY_EXITS.get(status, EXIT_FAILED)


def _run_control(action: str, endpoint_argument: str | None, exits: dict) -> int:
    endpoint, token = _resolve_connection(endpoint_argument)
    try:
        response = asyncio.run(request(endpoint, token, {"action": action}))
    except Exception:  # noqa: BLE001 - control commands never mutate delivery
        _emit_error("relay_unreachable")
        return EXIT_FAILED

    status, reason = _response_status(response)
    _emit({"event": action, "status": status, "reason": reason})
    if status == "unknown":
        return EXIT_UNKNOWN
    return exits.get(status, EXIT_FAILED)


# ---------------------------------------------------------------------------
# upgrade
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IntegrityReport:
    verified: int
    skipped: int
    failures: tuple[tuple[str, str], ...] = field(default=())


def installed_version() -> str:
    try:
        return importlib.metadata.version(DISTRIBUTION_NAME)
    except importlib.metadata.PackageNotFoundError:
        return __version__


def fetch_latest_version() -> str:
    """Read the latest published version from the fixed PyPI JSON endpoint."""
    index_request = urllib.request.Request(
        PYPI_JSON_URL,
        headers={"Accept": "application/json"},
        method="GET",
    )
    if index_request.type != "https":
        raise CliError("insecure_index_url", EXIT_UNAVAILABLE)
    with urllib.request.urlopen(
        index_request,
        timeout=PYPI_TIMEOUT_SECONDS,
    ) as response:
        raw = response.read(MAX_PYPI_RESPONSE_BYTES + 1)
    if len(raw) > MAX_PYPI_RESPONSE_BYTES:
        raise CliError("index_response_too_large", EXIT_UNAVAILABLE)

    document = json.loads(raw.decode("utf-8"))
    info = document.get("info") if isinstance(document, dict) else None
    version = info.get("version") if isinstance(info, dict) else None
    if not isinstance(version, str) or not version.strip():
        raise CliError("invalid_index_response", EXIT_UNAVAILABLE)
    return version.strip()


def _is_interactive() -> bool:
    for stream in (sys.stdin, sys.stdout):
        isatty = getattr(stream, "isatty", None)
        if isatty is None or not isatty():
            return False
    return True


def _install_roots(record_root: Path) -> tuple[Path, ...]:
    """Roots a RECORD may legitimately reference.

    Wheel RECORD paths are relative to the directory holding ``.dist-info`` and
    may step out of it for scripts and data files, but never outside the
    environment that owns the distribution.
    """
    try:
        prefix = Path(sys.prefix).resolve()
    except OSError:
        return (record_root,)
    if prefix == record_root or prefix in record_root.parents:
        return (record_root, prefix)
    return (record_root,)


def _resolve_record_path(roots: Sequence[Path], entry: str) -> Path | None:
    if not entry or entry.startswith(("/", "\\")) or ntpath.isabs(entry):
        return None
    try:
        resolved = (roots[0] / entry).resolve()
    except OSError:
        return None
    for root in roots:
        if root in resolved.parents:
            return resolved
    return None


def _verify_record_entry(
    target: Path,
    digest_spec: str,
    size_spec: str,
) -> str | None:
    algorithm, separator, encoded = digest_spec.partition("=")
    if not separator:
        return "invalid_digest_format"
    algorithm = algorithm.strip().lower()
    if algorithm not in ALLOWED_RECORD_ALGORITHMS:
        return "unsupported_algorithm"
    if not _BASE64_URLSAFE_PATTERN.match(encoded):
        return "invalid_digest_encoding"
    try:
        expected = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, TypeError):
        return "invalid_digest_encoding"
    if len(expected) != hashlib.new(algorithm).digest_size:
        return "invalid_digest_encoding"

    if not target.is_file():
        return "missing"
    if size_spec:
        if not size_spec.isdigit():
            return "invalid_size"
        if target.stat().st_size != int(size_spec):
            return "size_mismatch"

    digest = hashlib.new(algorithm)
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    if not hmac.compare_digest(digest.digest(), expected):
        return "digest_mismatch"
    return None


def verify_installed_distribution(
    name: str = DISTRIBUTION_NAME,
) -> IntegrityReport:
    """Re-check the installed files against the distribution's RECORD manifest."""
    importlib.invalidate_caches()
    try:
        distribution = importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError as error:
        raise CliError("distribution_not_found", EXIT_INTEGRITY_FAILED) from error

    record = distribution.read_text("RECORD")
    if record is None:
        raise CliError("record_missing", EXIT_INTEGRITY_FAILED)

    roots = _install_roots(Path(distribution.locate_file("")).resolve())
    verified = 0
    skipped = 0
    failures: list[tuple[str, str]] = []
    for row in csv.reader(io.StringIO(record, newline="")):
        if not row or not row[0]:
            continue
        entry = row[0]
        digest_spec = row[1].strip() if len(row) > 1 else ""
        size_spec = row[2].strip() if len(row) > 2 else ""
        if not digest_spec:
            skipped += 1
            continue

        display = entry.replace("\\", "/")
        target = _resolve_record_path(roots, entry)
        if target is None:
            failures.append((display, "path_escape"))
            continue
        outcome = _verify_record_entry(target, digest_spec, size_spec)
        if outcome is None:
            verified += 1
        else:
            failures.append((display, outcome))

    if verified == 0 and not failures:
        raise CliError("no_verifiable_hashes", EXIT_INTEGRITY_FAILED)
    return IntegrityReport(
        verified=verified,
        skipped=skipped,
        failures=tuple(failures),
    )


def run_upgrade(*, assume_yes: bool) -> int:
    current_text = installed_version()
    try:
        latest_text = fetch_latest_version()
    except CliError as error:
        _emit_error(error.code)
        return error.exit_code
    except (
        urllib.error.URLError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ):
        _emit_error("index_unavailable")
        return EXIT_UNAVAILABLE

    try:
        current = Version(current_text)
        latest = Version(latest_text)
    except InvalidVersion:
        _emit_error("invalid_version")
        return EXIT_UNAVAILABLE

    _emit(
        {
            "event": "upgrade_check",
            "current": str(current),
            "latest": str(latest),
        }
    )
    if latest <= current:
        _emit({"event": "already_up_to_date"})
        return EXIT_OK

    if not assume_yes:
        if not _is_interactive():
            _emit_error("confirmation_required")
            return EXIT_NOT_INTERACTIVE
        answer = input(f"Upgrade {DISTRIBUTION_NAME} {current} -> {latest}? [y/N]: ")
        if answer.strip().lower() not in {"y", "yes"}:
            _emit_error("upgrade_declined")
            return EXIT_DECLINED

    try:
        completed = subprocess.run(list(UPGRADE_COMMAND), shell=False, check=False)
    except FileNotFoundError:
        _emit_error("uv_not_found")
        return EXIT_MISSING_UV
    except OSError:
        _emit_error("upgrade_failed")
        return EXIT_FAILED
    if completed.returncode != 0:
        _emit_error("upgrade_failed", returncode=completed.returncode)
        return EXIT_FAILED

    try:
        report = verify_installed_distribution()
    except CliError as error:
        _emit_error(
            error.code,
            message="upgrade executed but integrity verification failed",
        )
        return EXIT_INTEGRITY_FAILED

    if report.failures:
        _emit_error(
            "integrity_failed",
            message="upgrade executed but integrity verification failed",
            verified=report.verified,
            skipped=report.skipped,
            failed=len(report.failures),
            entries=[
                {"path": path, "reason": reason}
                for path, reason in report.failures[:MAX_REPORTED_FAILURES]
            ],
        )
        return EXIT_INTEGRITY_FAILED

    _emit(
        {
            "event": "upgrade_complete",
            "version": str(latest),
            "verified": report.verified,
            "skipped": report.skipped,
        }
    )
    return EXIT_OK


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wecom-aibot",
        description="Enterprise WeChat smart bot relay",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", help="run the relay process")
    serve.add_argument("--endpoint")
    serve.add_argument("--config")
    serve.add_argument(
        "--handler",
        nargs="+",
        metavar="ARG",
        help="handler program and arguments; receives one JSON object on stdin",
    )
    serve.add_argument(
        "--context-ttl",
        type=float,
        default=DEFAULT_CONTEXT_TTL_SECONDS,
    )

    reply = commands.add_parser("reply", help="deliver a final reply")
    reply.add_argument("--endpoint")
    reply.add_argument("--context", required=True)
    reply.add_argument("--content-file", required=True)

    status = commands.add_parser("status", help="query the relay")
    status.add_argument("--endpoint")

    stop = commands.add_parser("stop", help="stop the relay")
    stop.add_argument("--endpoint")

    upgrade = commands.add_parser("upgrade", help="upgrade from PyPI with uv")
    upgrade.add_argument("--yes", action="store_true")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.command == "serve":
            return _run_serve(args)
        if args.command == "reply":
            return _run_reply(args)
        if args.command == "status":
            return _run_control("status", args.endpoint, _STATUS_EXITS)
        if args.command == "stop":
            return _run_control("stop", args.endpoint, _STOP_EXITS)
        return run_upgrade(assume_yes=args.yes)
    except CliError as error:
        _emit_error(error.code)
        return error.exit_code
    except KeyboardInterrupt:
        return EXIT_FAILED
