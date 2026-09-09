from __future__ import annotations

import asyncio
import hmac
import json
import ntpath
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
DELIVERY_RESPONSE_TIMEOUT_SECONDS = 120
SHUTDOWN_TIMEOUT_SECONDS = 5
_WINDOWS_TOKEN_SDDL = "D:P(A;;FA;;;OW)"
_SO_EXCLUSIVEADDRUSE = getattr(socket, "SO_EXCLUSIVEADDRUSE", -5)


def _windows_bind_address() -> tuple[str, int]:
    return ("127.0.0.1", 0)


def _delivery_response(result: DeliveryResult) -> dict[str, object]:
    if result.status == "delivered":
        return {"status": "delivered"}
    if result.status != "not_delivered":
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


def _inspect_windows_token_parent(parent: str) -> tuple[bool, bool]:
    import ctypes
    from ctypes import wintypes

    class SidAndAttributes(ctypes.Structure):
        _fields_ = [
            ("Sid", wintypes.LPVOID),
            ("Attributes", wintypes.DWORD),
        ]

    class TokenUser(ctypes.Structure):
        _fields_ = [("User", SidAndAttributes)]

    class Acl(ctypes.Structure):
        _fields_ = [
            ("AclRevision", wintypes.BYTE),
            ("Sbz1", wintypes.BYTE),
            ("AclSize", wintypes.WORD),
            ("AceCount", wintypes.WORD),
            ("Sbz2", wintypes.WORD),
        ]

    class AceHeader(ctypes.Structure):
        _fields_ = [
            ("AceType", wintypes.BYTE),
            ("AceFlags", wintypes.BYTE),
            ("AceSize", wintypes.WORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    get_attributes = kernel32.GetFileAttributesW
    get_attributes.argtypes = [wintypes.LPCWSTR]
    get_attributes.restype = wintypes.DWORD
    attributes = get_attributes(parent)
    if attributes == 0xFFFFFFFF:
        raise ctypes.WinError(ctypes.get_last_error())
    is_reparse = bool(attributes & 0x400)
    if is_reparse:
        return (True, False)
    if not attributes & 0x10:
        return (False, False)

    get_current_process = kernel32.GetCurrentProcess
    get_current_process.restype = wintypes.HANDLE
    open_process_token = advapi32.OpenProcessToken
    open_process_token.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    open_process_token.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    if not open_process_token(get_current_process(), 0x0008, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())

    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    security_descriptor = wintypes.LPVOID()
    try:
        get_token_information = advapi32.GetTokenInformation
        get_token_information.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        get_token_information.restype = wintypes.BOOL
        required = wintypes.DWORD()
        get_token_information(token, 1, None, 0, ctypes.byref(required))
        if not required.value:
            raise ctypes.WinError(ctypes.get_last_error())
        token_buffer = ctypes.create_string_buffer(required.value)
        if not get_token_information(
            token,
            1,
            token_buffer,
            required.value,
            ctypes.byref(required),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        current_sid = ctypes.cast(
            token_buffer,
            ctypes.POINTER(TokenUser),
        ).contents.User.Sid

        owner_sid = wintypes.LPVOID()
        dacl = wintypes.LPVOID()
        get_security = advapi32.GetNamedSecurityInfoW
        get_security.argtypes = [
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.LPVOID),
        ]
        get_security.restype = wintypes.DWORD
        error = get_security(
            parent,
            1,
            0x00000005,
            ctypes.byref(owner_sid),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(security_descriptor),
        )
        if error:
            raise OSError(error, "GetNamedSecurityInfoW failed")
        if not owner_sid or not dacl:
            return (False, False)

        get_control = advapi32.GetSecurityDescriptorControl
        get_control.argtypes = [
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.WORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        get_control.restype = wintypes.BOOL
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not get_control(
            security_descriptor,
            ctypes.byref(control),
            ctypes.byref(revision),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not control.value & 0x1000:
            return (False, False)

        equal_sid = advapi32.EqualSid
        equal_sid.argtypes = [wintypes.LPVOID, wintypes.LPVOID]
        equal_sid.restype = wintypes.BOOL
        if not equal_sid(owner_sid, current_sid):
            return (False, False)

        get_ace = advapi32.GetAce
        get_ace.argtypes = [
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPVOID),
        ]
        get_ace.restype = wintypes.BOOL
        acl = ctypes.cast(dacl, ctypes.POINTER(Acl)).contents
        has_owner_allow = False
        for index in range(acl.AceCount):
            ace = wintypes.LPVOID()
            if not get_ace(dacl, index, ctypes.byref(ace)):
                raise ctypes.WinError(ctypes.get_last_error())
            header = ctypes.cast(ace, ctypes.POINTER(AceHeader)).contents
            if header.AceType == 1:
                continue
            if header.AceType != 0:
                return (False, False)
            ace_sid = wintypes.LPVOID(ace.value + 8)
            if not equal_sid(ace_sid, owner_sid):
                return (False, False)
            has_owner_allow = True
        return (False, has_owner_allow)
    finally:
        if security_descriptor:
            local_free = kernel32.LocalFree
            local_free.argtypes = [wintypes.HLOCAL]
            local_free.restype = wintypes.HLOCAL
            local_free(security_descriptor)
        close_handle(token)


def _validate_windows_token_parent(
    path: str,
    *,
    inspector: Callable[[str], tuple[bool, bool]] = _inspect_windows_token_parent,
) -> None:
    parent = ntpath.dirname(path) or "."
    is_reparse, is_owner_only = inspector(parent)
    if is_reparse:
        raise PermissionError("Windows token parent must not be a reparse point")
    if not is_owner_only:
        raise PermissionError("Windows token parent must be owner-only")


def _write_token_file(
    path: str,
    token: str,
    *,
    windows: bool | None = None,
    windows_writer: Callable[[str, str], None] = _write_windows_token_file,
    windows_parent_inspector: Callable[
        [str],
        tuple[bool, bool],
    ] = _inspect_windows_token_parent,
) -> None:
    use_windows = os.name == "nt" if windows is None else windows
    if use_windows:
        _validate_windows_token_parent(
            path,
            inspector=windows_parent_inspector,
        )
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
        if self._close_task is not None:
            if not self._close_task.done():
                await asyncio.shield(self._close_task)
            _consume_task_exception(self._close_task)
            self._close_task = None
        self._stop_handler = None
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
                except asyncio.TimeoutError:
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
            except asyncio.TimeoutError:
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
                    except asyncio.TimeoutError:
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
                    if still_pending:
                        gathered = asyncio.gather(
                            *still_pending,
                            return_exceptions=True,
                        )
                        try:
                            await asyncio.wait_for(
                                asyncio.shield(gathered),
                                IO_TIMEOUT_SECONDS,
                            )
                        except asyncio.TimeoutError:
                            gathered.cancel()
                            gathered.add_done_callback(
                                _consume_task_exception
                            )
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
        _consume_task_exception(task)

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
            result = await asyncio.wait_for(
                self._service.reply(context, payload["markdown"]),
                DELIVERY_RESPONSE_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            return _delivery_unknown()
        except Exception:  # noqa: BLE001
            return _delivery_unknown()
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
            except asyncio.TimeoutError:
                return
            else:
                response = await self._decode_and_dispatch(data)
                should_stop = response == {"status": "stopping"}
            await self._send_unix_response(writer, response)
        except (ConnectionError, asyncio.TimeoutError):
            return
        except asyncio.CancelledError:
            raise
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
            return _delivery_unknown()

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
        except (ConnectionError, asyncio.TimeoutError):
            return
        except asyncio.CancelledError:
            raise
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
        except (
            ValueError,
            asyncio.IncompleteReadError,
            asyncio.TimeoutError,
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
            self._close_task.add_done_callback(_consume_task_exception)


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
    response_timeout = (
        DELIVERY_RESPONSE_TIMEOUT_SECONDS + IO_TIMEOUT_SECONDS
        if payload.get("action") == "reply"
        else IO_TIMEOUT_SECONDS
    )
    try:
        writer.write(data)
        await asyncio.wait_for(writer.drain(), IO_TIMEOUT_SECONDS)
        response_data = await asyncio.wait_for(
            reader.readline(),
            response_timeout,
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
        status_line = await asyncio.wait_for(
            reader.readline(),
            (
                DELIVERY_RESPONSE_TIMEOUT_SECONDS + IO_TIMEOUT_SECONDS
                if json.loads(body).get("action") == "reply"
                else IO_TIMEOUT_SECONDS
            ),
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
        raise
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


def _delivery_unknown() -> dict[str, object]:
    return {"status": "unknown", "reason": "delivery_unknown"}


def _consume_task_exception(task: asyncio.Future[Any]) -> None:
    if not task.cancelled():
        task.exception()
