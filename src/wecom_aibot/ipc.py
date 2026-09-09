from __future__ import annotations

import asyncio
import hmac
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from wecom_aibot.delivery import DeliveryResult
from wecom_aibot.service import RelayService

MAX_REQUEST_BYTES = 64 * 1024


def _windows_bind_address() -> tuple[str, int]:
    return ("127.0.0.1", 0)


def _delivery_response(result: DeliveryResult) -> dict[str, object]:
    response: dict[str, object] = {"status": result.status}
    if result.reason:
        response["reason"] = result.reason
    return response


def _tokens_match(provided: object, expected: str) -> bool:
    if not isinstance(provided, str):
        return False
    return hmac.compare_digest(provided.encode(), expected.encode())


def _write_token_file(path: str, token: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, token.encode())
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)


class IpcServer:
    def __init__(self, service: RelayService, token: str) -> None:
        if not token:
            raise ValueError("token must not be empty")
        self._service = service
        self._token = token
        self._server: asyncio.AbstractServer | None = None
        self._socket_path: str | None = None
        self._token_path: str | None = None
        self._closed = asyncio.Event()
        self._close_task: asyncio.Task[None] | None = None
        self.endpoint = ""
        self.token_path = ""

    async def start(self, endpoint_path: str) -> None:
        if self._server is not None:
            raise RuntimeError("IPC server already started")

        token_path = f"{endpoint_path}.token"
        _write_token_file(token_path, self._token)
        self._token_path = token_path
        self.token_path = token_path

        try:
            if os.name == "nt":
                host, port = _windows_bind_address()
                self._server = await asyncio.start_server(
                    self._handle_http_connection,
                    host,
                    port,
                    limit=MAX_REQUEST_BYTES + 1,
                )
                socket = self._server.sockets[0]
                bound_host, bound_port = socket.getsockname()[:2]
                if bound_host != "127.0.0.1":
                    raise RuntimeError("Windows IPC must bind to loopback")
                self.endpoint = f"http://127.0.0.1:{bound_port}"
            else:
                self._server = await asyncio.start_unix_server(
                    self._handle_unix_connection,
                    path=endpoint_path,
                    limit=MAX_REQUEST_BYTES + 1,
                )
                os.chmod(endpoint_path, 0o600)
                self._socket_path = endpoint_path
                self.endpoint = endpoint_path
        except BaseException:
            self._remove_local_files()
            raise

    async def close(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            server.close()
            await server.wait_closed()
        self._remove_local_files()
        self._closed.set()

    async def wait_stopped(self) -> None:
        await self._closed.wait()

    def _remove_local_files(self) -> None:
        for path in (self._socket_path, self._token_path):
            if path is None:
                continue
            try:
                Path(path).unlink()
            except FileNotFoundError:
                pass

    async def _dispatch(self, message: object) -> dict[str, object]:
        if not isinstance(message, dict):
            return _invalid("request must be an object")

        provided_token = message.get("token")
        if not _tokens_match(provided_token, self._token):
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
        kind = payload["kind"]
        markdown = payload["markdown"]
        if (
            not isinstance(context, str)
            or not context
            or kind != "final"
            or not isinstance(markdown, str)
        ):
            return _invalid("invalid reply fields")
        result = await self._service.reply(context, markdown)
        return _delivery_response(result)

    async def _handle_unix_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        should_stop = False
        try:
            try:
                data = await reader.readline()
            except ValueError:
                response = _invalid("request too large")
            else:
                response = await self._decode_and_dispatch(data)
                should_stop = response == {"status": "stopping"}
            writer.write(_json_line(response))
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
        if should_stop:
            self._schedule_close()

    async def _decode_and_dispatch(self, data: bytes) -> dict[str, object]:
        if not data or len(data) > MAX_REQUEST_BYTES or not data.endswith(b"\n"):
            return _invalid("request too large")
        try:
            message = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return _invalid("invalid JSON")
        return await self._dispatch(message)

    async def _handle_http_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        should_stop = False
        try:
            response = await self._read_http_request(reader)
            should_stop = response == {"status": "stopping"}
            body = json.dumps(response, separators=(",", ":")).encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Connection: close\r\n\r\n"
                + body
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
        if should_stop:
            self._schedule_close()

    async def _read_http_request(
        self,
        reader: asyncio.StreamReader,
    ) -> dict[str, object]:
        try:
            request_line = await reader.readline()
            if not request_line.startswith(b"POST "):
                return _invalid("invalid HTTP request")
            content_length: int | None = None
            header_bytes = len(request_line)
            while True:
                line = await reader.readline()
                header_bytes += len(line)
                if header_bytes > MAX_REQUEST_BYTES:
                    return _invalid("request too large")
                if line == b"\r\n":
                    break
                if not line:
                    return _invalid("invalid HTTP request")
                name, separator, value = line.partition(b":")
                if separator and name.lower() == b"content-length":
                    content_length = int(value.strip())
            if content_length is None or content_length > MAX_REQUEST_BYTES:
                return _invalid("request too large")
            body = await reader.readexactly(content_length)
        except (ValueError, asyncio.IncompleteReadError):
            return _invalid("invalid HTTP request")
        return await self._decode_and_dispatch(body + b"\n")

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
    message = {**payload, "token": token}
    data = _json_line(message)
    if len(data) > MAX_REQUEST_BYTES:
        raise ValueError("request too large")

    if endpoint.startswith("http://"):
        return await _http_request(endpoint, data[:-1])

    reader, writer = await asyncio.open_unix_connection(endpoint)
    try:
        writer.write(data)
        await writer.drain()
        response_data = await reader.readline()
    finally:
        writer.close()
        await writer.wait_closed()
    return _parse_response(response_data)


async def _http_request(endpoint: str, body: bytes) -> dict[str, object]:
    parsed = urlsplit(endpoint)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
        raise ValueError("HTTP IPC endpoint must use 127.0.0.1")
    port = parsed.port
    if port is None:
        raise ValueError("HTTP IPC endpoint requires a port")

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(
            b"POST / HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: close\r\n\r\n"
            + body
        )
        await writer.drain()
        status_line = await reader.readline()
        if not status_line.startswith(b"HTTP/1.1 200 "):
            raise RuntimeError("invalid IPC HTTP response")
        content_length: int | None = None
        while True:
            line = await reader.readline()
            if line == b"\r\n":
                break
            name, separator, value = line.partition(b":")
            if separator and name.lower() == b"content-length":
                content_length = int(value.strip())
        if content_length is None or content_length > MAX_REQUEST_BYTES:
            raise RuntimeError("invalid IPC HTTP response")
        response_data = await reader.readexactly(content_length)
    finally:
        writer.close()
        await writer.wait_closed()
    return _parse_response(response_data)


def _json_line(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def _parse_response(data: bytes) -> dict[str, object]:
    value: Any = json.loads(data)
    if not isinstance(value, dict):
        raise TypeError("invalid IPC response")
    return value


def _invalid(reason: str) -> dict[str, object]:
    return {"status": "invalid_request", "reason": reason}
