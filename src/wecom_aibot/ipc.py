from __future__ import annotations

import asyncio
import hmac
import json
import os
import socket
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from wecom_aibot.delivery import DeliveryResult
from wecom_aibot.service import RelayService

MAX_REQUEST_BYTES = 64 * 1024
IO_TIMEOUT_SECONDS = 0.25
SHUTDOWN_TIMEOUT_SECONDS = 0.25
_WINDOWS_TOKEN_SDDL = "D:P(A;;FA;;;OW)"
_SO_EXCLUSIVEADDRUSE = getattr(socket, "SO_EXCLUSIVEADDRUSE", -5)


def _windows_bind_address() -> tuple[str, int]:
    return ("127.0.0.1", 0)


def _delivery_response(result: DeliveryResult) -> dict[str, object]:
    if result.status == "delivered":
        return {"status": "delivered"}
    if result.status == "unknown":
        return {"status": "unknown", "reason": "delivery_unknown"}
    reason = result.reason if result.reason in {"expired", "missing"} else "delivery_failed"
    return {"status": "not_delivered", "reason": reason}


def _tokens_match(provided: object, expected: str) -> bool:
    if not isinstance(provided, str):
        return False
    return hmac.compare_digest(provided.encode(), expected.encode())


def _write_posix_token_file(path: str, token: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, token.encode())
    except BaseException:
        os.close(descriptor)
        Path(path).unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)


def _write_windows_token_file(path: str, token: str) -> None:
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
        _WINDOWS_TOKEN_SDDL,
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
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    local_free = kernel32.LocalFree
    local_free.argtypes = [wintypes.HLOCAL]
    local_free.restype = wintypes.HLOCAL
    invalid_handle = wintypes.HANDLE(-1).value
    handle = invalid_handle
    created = False
    try:
        try:
            create_file = kernel32.CreateFileW
            create_file.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.POINTER(SecurityAttributes),
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ]
            create_file.restype = wintypes.HANDLE
            handle = create_file(
                path,
                0x40000000,
                0,
                ctypes.byref(attributes),
                1,
                0x80,
                None,
            )
            if handle == invalid_handle:
                raise ctypes.WinError(ctypes.get_last_error())
            created = True

            data = token.encode()
            written = wintypes.DWORD()
            write_file = kernel32.WriteFile
            write_file.argtypes = [
                wintypes.HANDLE,
                wintypes.LPCVOID,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
                wintypes.LPVOID,
            ]
            write_file.restype = wintypes.BOOL
            if not write_file(
                handle,
                data,
                len(data),
                ctypes.byref(written),
                None,
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if written.value != len(data):
                raise OSError("incomplete token write")
        finally:
            if handle != invalid_handle:
                close_handle(handle)
            local_free(security_descriptor)
    except BaseException:
        if created:
            Path(path).unlink(missing_ok=True)
        raise


def _write_token_file(
    path: str,
    token: str,
    *,
    windows: bool | None = None,
    windows_writer: Callable[[str, str], None] = _write_windows_token_file,
) -> None:
    use_windows = os.name == "nt" if windows is None else windows
    if use_windows:
        windows_writer(path, token)
        return
    _write_posix_token_file(path, token)


def _validate_private_parent(endpoint_path: str) -> None:
    parent = Path(endpoint_path).parent
    parent_stat = parent.lstat()
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.getuid()
        or stat.S_IMODE(parent_stat.st_mode) & 0o077
    ):
        raise PermissionError("IPC endpoint parent must be private and owner-only")


def _create_unix_listener(endpoint_path: str) -> socket.socket:
    _validate_private_parent(endpoint_path)
    if os.path.lexists(endpoint_path):
        raise FileExistsError(endpoint_path)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    bound = False
    old_umask = os.umask(0o177)
    try:
        listener.bind(endpoint_path)
        bound = True
        os.chmod(endpoint_path, 0o600)
    except BaseException:
        listener.close()
        if bound:
            Path(endpoint_path).unlink(missing_ok=True)
        raise
    finally:
        os.umask(old_umask)
    listener.setblocking(False)
    return listener


def _create_windows_listener(
    socket_factory: Callable[..., socket.socket] = socket.socket,
) -> socket.socket:
    listener = socket_factory(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, _SO_EXCLUSIVEADDRUSE, 1)
        listener.bind(_windows_bind_address())
        listener.listen()
        listener.setblocking(False)
    except BaseException:
        listener.close()
        raise
    return listener


def _create_loopback_listener() -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(_windows_bind_address())
        listener.listen()
        listener.setblocking(False)
    except BaseException:
        listener.close()
        raise
    return listener


class IpcServer:
    def __init__(self, service: RelayService, token: str) -> None:
        if not token:
            raise ValueError("token must not be empty")
        self._service = service
        self._token = token
        self._server: asyncio.AbstractServer | None = None
        self._socket_path: str | None = None
        self._token_path: str | None = None
        self._handlers: set[asyncio.Task[None]] = set()
        self._stop_handler: asyncio.Task[None] | None = None
        self._closed = asyncio.Event()
        self._close_lock = asyncio.Lock()
        self._close_task: asyncio.Task[None] | None = None
        self.endpoint = ""
        self.token_path = ""

    async def start(self, endpoint_path: str) -> None:
        if self._server is not None:
            raise RuntimeError("IPC server already started")
        listener: socket.socket | None = None
        self._closed.clear()
        token_path = f"{endpoint_path}.token"
        try:
            if os.name == "nt":
                _write_token_file(token_path, self._token)
                self._token_path = token_path
                self.token_path = token_path
                listener = _create_windows_listener()
                await self._start_http_listener(listener=listener, exclusive=True)
                listener = None
            else:
                listener = _create_unix_listener(endpoint_path)
                self._socket_path = endpoint_path
                _write_token_file(token_path, self._token)
                self._token_path = token_path
                self.token_path = token_path
                self._server = await asyncio.start_unix_server(
                    self._accept_unix,
                    sock=listener,
                    limit=MAX_REQUEST_BYTES + 1,
                )
                listener = None
                self.endpoint = endpoint_path
        except BaseException:
            if listener is not None:
                listener.close()
            await self._rollback_failed_start()
            raise

    async def _start_http_listener(
        self,
        *,
        exclusive: bool,
        listener: socket.socket | None = None,
    ) -> None:
        if self._server is not None:
            raise RuntimeError("IPC server already started")
        owned_listener = listener
        if owned_listener is None:
            owned_listener = (
                _create_windows_listener()
                if exclusive
                else _create_loopback_listener()
            )
        try:
            self._server = await asyncio.start_server(
                self._accept_http,
                sock=owned_listener,
                limit=MAX_REQUEST_BYTES + 1,
            )
            bound_host, bound_port = self._server.sockets[0].getsockname()[:2]
            if bound_host != "127.0.0.1":
                raise RuntimeError("HTTP IPC must bind to loopback")
            self.endpoint = f"http://127.0.0.1:{bound_port}"
        except BaseException:
            owned_listener.close()
            if self._server is not None:
                self._server.close()
                try:
                    await asyncio.wait_for(
                        self._server.wait_closed(),
                        SHUTDOWN_TIMEOUT_SECONDS,
                    )
                except TimeoutError:
                    pass
                self._server = None
            raise

    async def _rollback_failed_start(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            server.close()
            try:
                await asyncio.wait_for(
                    server.wait_closed(),
                    SHUTDOWN_TIMEOUT_SECONDS,
                )
            except TimeoutError:
                pass
        self._remove_local_files()
        self._socket_path = None
        self._token_path = None
        self.endpoint = ""
        self.token_path = ""

    async def close(self) -> None:
        async with self._close_lock:
            try:
                server = self._server
                self._server = None
                if server is not None:
                    server.close()
                    try:
                        await asyncio.wait_for(
                            server.wait_closed(),
                            SHUTDOWN_TIMEOUT_SECONDS,
                        )
                    except TimeoutError:
                        pass

                current = asyncio.current_task()
                pending = [
                    task
                    for task in self._handlers
                    if task is not current and task is not self._stop_handler
                ]
                for task in pending:
                    task.cancel()
                if pending:
                    _, still_pending = await asyncio.wait(
                        pending,
                        timeout=SHUTDOWN_TIMEOUT_SECONDS,
                    )
                    for task in still_pending:
                        task.cancel()
            finally:
                self._remove_local_files()
                self._closed.set()

    async def wait_stopped(self) -> None:
        await self._closed.wait()

    def _remove_local_files(self) -> None:
        for path in (self._socket_path, self._token_path):
            if path is not None:
                Path(path).unlink(missing_ok=True)

    def _accept_unix(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self._track_handler(self._handle_unix_connection(reader, writer))

    def _accept_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self._track_handler(self._handle_http_connection(reader, writer))

    def _track_handler(self, coroutine: Any) -> None:
        task = asyncio.create_task(coroutine)
        self._handlers.add(task)
        task.add_done_callback(self._handler_done)

    def _handler_done(self, task: asyncio.Task[None]) -> None:
        self._handlers.discard(task)
        if not task.cancelled():
            task.exception()

    async def _dispatch(self, message: object) -> dict[str, object]:
        if not isinstance(message, dict):
            return _invalid("request must be an object")
        if not _tokens_match(message.get("token"), self._token):
            return {"status": "forbidden"}

        payload = {key: value for key, value in message.items() if key != "token"}
        action = payload.get("action")
        if action == "status":
            if set(payload) != {"action"}:
                return _invalid("invalid status fields")
            return {"status": "running"}
        if action == "stop":
            if set(payload) != {"action"}:
                return _invalid("invalid stop fields")
            return {"status": "stopping"}
        if action == "reply":
            return await self._reply(payload)
        return _invalid("unknown action")

    async def _reply(self, payload: dict[str, object]) -> dict[str, object]:
        if set(payload) != {"action", "context", "kind", "markdown"}:
            return _invalid("invalid reply fields")
        context = payload["context"]
        if (
            not isinstance(context, str)
            or not context
            or payload["kind"] != "final"
            or not isinstance(payload["markdown"], str)
        ):
            return _invalid("invalid reply fields")
        try:
            result = await self._service.reply(context, payload["markdown"])
        except Exception:  # noqa: BLE001
            return _internal_error()
        return _delivery_response(result)

    async def _handle_unix_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        should_stop = False
        try:
            try:
                data = await asyncio.wait_for(
                    reader.readline(),
                    IO_TIMEOUT_SECONDS,
                )
            except ValueError:
                response = _invalid("request too large")
            except TimeoutError:
                return
            else:
                response = await self._decode_and_dispatch(data)
                should_stop = response == {"status": "stopping"}
            await self._send_unix_response(writer, response)
        except (ConnectionError, TimeoutError):
            return
        except asyncio.CancelledError:
            return
        except Exception:  # noqa: BLE001
            return
        finally:
            await _safe_close_writer(writer)
        if should_stop:
            self._stop_handler = asyncio.current_task()
            self._schedule_close()

    async def _send_unix_response(
        self,
        writer: asyncio.StreamWriter,
        response: dict[str, object],
    ) -> None:
        writer.write(_json_line(response))
        await asyncio.wait_for(writer.drain(), IO_TIMEOUT_SECONDS)

    async def _decode_and_dispatch(self, data: bytes) -> dict[str, object]:
        if not data or len(data) > MAX_REQUEST_BYTES or not data.endswith(b"\n"):
            return _invalid("request too large")
        try:
            message = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            return _invalid("invalid JSON")
        try:
            return await self._dispatch(message)
        except Exception:  # noqa: BLE001
            return _internal_error()

    async def _handle_http_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        should_stop = False
        try:
            response = await self._read_http_request(reader)
            should_stop = response == {"status": "stopping"}
            await self._send_http_response(writer, response)
        except (ConnectionError, TimeoutError):
            return
        except asyncio.CancelledError:
            return
        except Exception:  # noqa: BLE001
            return
        finally:
            await _safe_close_writer(writer)
        if should_stop:
            self._stop_handler = asyncio.current_task()
            self._schedule_close()

    async def _read_http_request(
        self,
        reader: asyncio.StreamReader,
    ) -> dict[str, object]:
        try:
            request_line = await asyncio.wait_for(
                reader.readline(),
                IO_TIMEOUT_SECONDS,
            )
            if request_line != b"POST /ipc HTTP/1.1\r\n":
                return _invalid("invalid HTTP request")

            content_length: int | None = None
            content_type: bytes | None = None
            has_transfer_encoding = False
            header_bytes = len(request_line)
            while True:
                line = await asyncio.wait_for(
                    reader.readline(),
                    IO_TIMEOUT_SECONDS,
                )
                header_bytes += len(line)
                if header_bytes > MAX_REQUEST_BYTES:
                    return _invalid("request too large")
                if line == b"\r\n":
                    break
                if not line or not line.endswith(b"\r\n"):
                    return _invalid("invalid HTTP request")
                name, separator, value = line[:-2].partition(b":")
                if not separator:
                    return _invalid("invalid HTTP request")
                name = name.lower()
                value = value.strip()
                if name == b"content-length":
                    if content_length is not None or not value.isdigit():
                        return _invalid("invalid HTTP request")
                    content_length = int(value)
                elif name == b"content-type":
                    if content_type is not None:
                        return _invalid("invalid HTTP request")
                    content_type = value.lower()
                elif name == b"transfer-encoding":
                    has_transfer_encoding = True

            if (
                content_length is None
                or content_length > MAX_REQUEST_BYTES
                or content_type != b"application/json"
                or has_transfer_encoding
            ):
                return _invalid("invalid HTTP request")
            body = await asyncio.wait_for(
                reader.readexactly(content_length),
                IO_TIMEOUT_SECONDS,
            )
            extra = await asyncio.wait_for(
                reader.read(1),
                IO_TIMEOUT_SECONDS,
            )
            if extra:
                return _invalid("invalid HTTP request")
        except (
            ValueError,
            asyncio.IncompleteReadError,
            TimeoutError,
        ):
            return _invalid("invalid HTTP request")
        return await self._decode_and_dispatch(body + b"\n")

    async def _send_http_response(
        self,
        writer: asyncio.StreamWriter,
        response: dict[str, object],
    ) -> None:
        body = json.dumps(response, separators=(",", ":")).encode()
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: close\r\n\r\n"
            + body
        )
        await asyncio.wait_for(writer.drain(), IO_TIMEOUT_SECONDS)

    def _schedule_close(self) -> None:
        if self._close_task is None:
            self._close_task = asyncio.create_task(self.close())


async def request(
    endpoint: str,
    token: str,
    payload: dict[str, object],
) -> dict[str, object]:
    if "token" in payload:
        raise ValueError("payload must not contain token")
    data = _json_line({**payload, "token": token})
    if len(data) > MAX_REQUEST_BYTES:
        raise ValueError("request too large")
    if endpoint.startswith("http://"):
        return await _http_request(endpoint, data[:-1])

    reader, writer = await asyncio.wait_for(
        asyncio.open_unix_connection(endpoint),
        IO_TIMEOUT_SECONDS,
    )
    try:
        writer.write(data)
        await asyncio.wait_for(writer.drain(), IO_TIMEOUT_SECONDS)
        response_data = await asyncio.wait_for(
            reader.readline(),
            IO_TIMEOUT_SECONDS,
        )
    finally:
        await _safe_close_writer(writer)
    return _parse_response(response_data)


async def _http_request(endpoint: str, body: bytes) -> dict[str, object]:
    parsed = urlsplit(endpoint)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
        raise ValueError("HTTP IPC endpoint must use 127.0.0.1")
    if parsed.port is None:
        raise ValueError("HTTP IPC endpoint requires a port")

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", parsed.port),
        IO_TIMEOUT_SECONDS,
    )
    try:
        writer.write(
            b"POST /ipc HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: close\r\n\r\n"
            + body
        )
        await asyncio.wait_for(writer.drain(), IO_TIMEOUT_SECONDS)
        if writer.can_write_eof():
            writer.write_eof()
        status_line = await asyncio.wait_for(
            reader.readline(),
            IO_TIMEOUT_SECONDS,
        )
        if status_line != b"HTTP/1.1 200 OK\r\n":
            raise RuntimeError("invalid IPC HTTP response")
        content_length: int | None = None
        while True:
            line = await asyncio.wait_for(
                reader.readline(),
                IO_TIMEOUT_SECONDS,
            )
            if line == b"\r\n":
                break
            name, separator, value = line.partition(b":")
            if separator and name.lower() == b"content-length":
                content_length = int(value.strip())
        if content_length is None or content_length > MAX_REQUEST_BYTES:
            raise RuntimeError("invalid IPC HTTP response")
        response_data = await asyncio.wait_for(
            reader.readexactly(content_length),
            IO_TIMEOUT_SECONDS,
        )
    finally:
        await _safe_close_writer(writer)
    return _parse_response(response_data)


async def _safe_close_writer(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), IO_TIMEOUT_SECONDS)
    except asyncio.CancelledError:
        return
    except Exception:  # noqa: BLE001
        return


def _json_line(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def _parse_response(data: bytes) -> dict[str, object]:
    value: Any = json.loads(data)
    if not isinstance(value, dict):
        raise TypeError("invalid IPC response")
    return value


def _invalid(reason: str) -> dict[str, object]:
    return {"status": "invalid_request", "reason": reason}


def _internal_error() -> dict[str, object]:
    return {"status": "error", "reason": "internal_error"}
