"""Authenticated, bounded Unix-domain RPC. No TCP listener or admin methods."""
from __future__ import annotations
import os
from pathlib import Path
import socket
import socketserver
import stat
import threading
from . import PROTOCOL_VERSION
from .protocol import GatewayError, canonical, closed, parse_json

MAX_FRAME = 16384

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        try:
            data = self.rfile.readline(MAX_FRAME + 1)
            if len(data) > MAX_FRAME or not data.endswith(b"\n"):
                raise GatewayError("INVALID_INPUT")
            message = parse_json(data)
            closed(message, ("protocol", "token", "method", "arguments"))
            if message["protocol"] != PROTOCOL_VERSION:
                raise GatewayError("UNSUPPORTED_PROTOCOL")
            result = self.server.broker.dispatch(message["token"], message["method"], message["arguments"])
            reply = {"protocol": PROTOCOL_VERSION, "ok": True, "result": result}
        except GatewayError as exc:
            reply = {"protocol": PROTOCOL_VERSION, "ok": False, "error": {"code": exc.code}}
        except Exception:
            reply = {"protocol": PROTOCOL_VERSION, "ok": False, "error": {"code": "INTERNAL_ERROR"}}
        try:
            encoded = (canonical(reply) + "\n").encode()
            if len(encoded) > 262144:
                encoded = (canonical({"protocol": PROTOCOL_VERSION, "ok": False, "error": {"code": "RESPONSE_TOO_LARGE"}}) + "\n").encode()
            self.wfile.write(encoded)
        except OSError:
            pass

class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    request_queue_size = 16
    def __init__(self, path, broker):
        path = Path(path)
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o022:
            raise GatewayError("UNSAFE_SOCKET_DIRECTORY")
        if path.exists() or path.is_symlink():
            raise GatewayError("SOCKET_ALREADY_EXISTS")
        self.broker = broker
        self.slots = threading.BoundedSemaphore(16)
        old_umask = os.umask(0o117)
        try:
            super().__init__(str(path), Handler)
        finally:
            os.umask(old_umask)
        self.socket_path = path
        self.socket_inode = path.stat().st_ino

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # No tracebacks containing request data or credential-bearing locals.
        pass

    def server_close(self):
        super().server_close()
        if hasattr(self, "socket_path"):
            try:
                st = self.socket_path.lstat()
                if stat.S_ISSOCK(st.st_mode) and st.st_ino == self.socket_inode:
                    self.socket_path.unlink()
            except FileNotFoundError:
                pass

class Client:
    """Client tokens authorize gateway use; they are NOT upstream credentials."""
    def __init__(self, socket_path, token):
        self.socket_path, self._token = str(socket_path), token

    @classmethod
    def from_environment(cls):
        try:
            path = Path(os.environ["KEYVAULT_GATEWAY_TOKEN_FILE"])
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd) as f:
                st = os.fstat(f.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
                    raise GatewayError("UNSAFE_CLIENT_TOKEN_FILE")
                token = f.read(256).strip()
            if len(token) != 43:
                raise GatewayError("INVALID_CLIENT_TOKEN")
            return cls(os.environ["KEYVAULT_GATEWAY_SOCKET"], token)
        except GatewayError:
            raise
        except Exception:
            raise GatewayError("CLIENT_NOT_CONFIGURED") from None

    def call(self, method, arguments):
        message = canonical({"protocol": PROTOCOL_VERSION, "token": self._token, "method": method, "arguments": arguments}) + "\n"
        if len(message.encode()) > MAX_FRAME:
            raise GatewayError("INVALID_INPUT")
        try:
            with socket.socket(socket.AF_UNIX) as sock:
                sock.settimeout(25)
                sock.connect(self.socket_path)
                sock.sendall(message.encode())
                with sock.makefile("rb") as f:
                    response = f.readline(262145)
            if len(response) > 262144 or not response.endswith(b"\n"):
                raise GatewayError("INVALID_RESPONSE")
            reply = parse_json(response)
            if reply.get("protocol") != PROTOCOL_VERSION:
                raise GatewayError("UNSUPPORTED_PROTOCOL")
            if reply.get("ok") is not True:
                code = reply.get("error", {}).get("code")
                if not isinstance(code, str) or not code.isascii() or not code.replace("_", "").isalpha() or len(code) > 64:
                    code = "INVALID_RESPONSE"
                raise GatewayError(code)
            return reply["result"]
        except GatewayError:
            raise
        except Exception:
            raise GatewayError("GATEWAY_UNAVAILABLE") from None
