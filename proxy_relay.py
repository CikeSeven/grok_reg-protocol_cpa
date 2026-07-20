"""本地代理中继：把无认证的本地 HTTP 代理请求转发到上游带认证代理。

用途：Chromium --proxy-server 不支持内嵌 user:pass，且不支持 SOCKS5 认证。
对带账密的 http 上游或任意 socks5 上游，在 127.0.0.1 起一个无认证中继，
浏览器指向中继即可。中继按上游协议完成认证（Basic / SOCKS5 user-pass）。

HTTP 客户端（curl_cffi/requests）原生支持带认证代理 URL，无需中继。
"""

from __future__ import annotations

import base64
import select
import socket
import threading
from urllib.parse import urlparse

import proxy_pool

_relays: dict[str, "_RelayServer"] = {}
_relays_lock = threading.Lock()


def _recv_n(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("upstream closed")
        buf += chunk
    return buf


def _open_upstream(parsed: dict, target_host: str, target_port: int) -> socket.socket:
    """经上游代理建立到 target 的连接，返回已就绪 socket。"""
    host, port = parsed["host"], parsed["port"]
    user, password = parsed.get("user", ""), parsed.get("password", "")
    scheme = parsed["scheme"]
    sock = socket.create_connection((host, port), timeout=15)
    sock.settimeout(60)

    if scheme in ("socks5", "socks5h"):
        if user:
            sock.sendall(b"\x05\x01\x02")  # 仅声明 user/pass 方法
        else:
            sock.sendall(b"\x05\x01\x00")
        ver_method = _recv_n(sock, 2)
        method = ver_method[1]
        if method == 0xFF:
            sock.close()
            raise OSError("socks5: no acceptable auth method")
        if method == 2:
            u, p = user.encode(), password.encode()
            sock.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
            auth_resp = _recv_n(sock, 2)
            if auth_resp[1] != 0:
                sock.close()
                raise OSError("socks5: auth failed")
        # CONNECT（域名形式，远端解析 DNS）
        th = target_host.encode()
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(th)]) + th + target_port.to_bytes(2, "big"))
        resp = _recv_n(sock, 4)
        if resp[1] != 0:
            sock.close()
            raise OSError(f"socks5: connect failed rep={resp[1]}")
        atyp = resp[3]
        if atyp == 1:
            _recv_n(sock, 4)
        elif atyp == 3:
            ln = _recv_n(sock, 1)[0]
            _recv_n(sock, ln)
        elif atyp == 4:
            _recv_n(sock, 16)
        _recv_n(sock, 2)  # port
        return sock

    # HTTP 上游：CONNECT + Basic 认证
    lines = [
        f"CONNECT {target_host}:{target_port} HTTP/1.1",
        f"Host: {target_host}:{target_port}",
    ]
    if user:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {token}")
    lines.append("Proxy-Connection: keep-alive")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            sock.close()
            raise OSError("http upstream closed before CONNECT response")
        buf += chunk
    status = buf.split(b"\r\n", 1)[0]
    if b" 200" not in status:
        sock.close()
        raise OSError(f"http upstream CONNECT failed: {status.decode(errors='ignore')}")
    return sock


def _pipe(a: socket.socket, b: socket.socket) -> None:
    try:
        while True:
            readable, _, exceptional = select.select([a, b], [], [a, b], 120)
            if exceptional or not readable:
                break
            for s in readable:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.close()
            except Exception:
                pass


class _RelayServer(threading.Thread):
    def __init__(self, parsed: dict) -> None:
        super().__init__(daemon=True, name=f"proxy-relay-{parsed['host']}")
        self.parsed = parsed
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]

    def run(self) -> None:
        while True:
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()

    def _handle_client(self, client: socket.socket) -> None:
        try:
            client.settimeout(30)
            buf = b""
            while b"\r\n" not in buf:
                chunk = client.recv(4096)
                if not chunk:
                    client.close()
                    return
                buf += chunk
            line, rest = buf.split(b"\r\n", 1)
            parts = line.split(b" ")
            if len(parts) < 2:
                client.close()
                return
            method, target = parts[0], parts[1]
            if method.upper() == b"CONNECT":
                host, _, port_s = target.decode(errors="ignore").rpartition(":")
                upstream = _open_upstream(self.parsed, host, int(port_s or 443))
                client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                _pipe(client, upstream)
            else:
                # absolute-URI 普通 HTTP 请求：重写为 origin-form 后经上游转发
                u = urlparse(target.decode(errors="ignore"))
                if not u.hostname:
                    client.close()
                    return
                upstream = _open_upstream(self.parsed, u.hostname, u.port or 80)
                path = u.path or "/"
                if u.query:
                    path += "?" + u.query
                version = parts[2] if len(parts) > 2 else b"HTTP/1.1"
                upstream.sendall(b" ".join([parts[0], path.encode(), version]) + b"\r\n" + rest)
                _pipe(client, upstream)
        except Exception:
            try:
                client.close()
            except Exception:
                pass


def ensure_relay(proxy_url: str) -> str:
    """为上游代理（可含账密，http/socks5）返回本地无认证中继 http://127.0.0.1:port。"""
    parsed = proxy_pool.parse_proxy(proxy_url)
    if not parsed:
        raise ValueError(f"invalid proxy: {proxy_url!r}")
    key = proxy_pool.normalize_proxy_url(proxy_url)
    with _relays_lock:
        relay = _relays.get(key)
        if relay is None:
            relay = _RelayServer(parsed)
            relay.start()
            _relays[key] = relay
    return f"http://127.0.0.1:{relay.port}"


def chromium_proxy_for(proxy_url: str) -> str:
    """给 Chromium --proxy-server 用的地址。

    - 无认证 http(s)：直接 scheme://host:port
    - 带认证或 socks5：本地中继（Chromium 不支持内嵌认证 / socks5 认证）
    """
    parsed = proxy_pool.parse_proxy(proxy_url)
    if not parsed:
        return ""
    if parsed["user"] or parsed["scheme"] in ("socks5", "socks5h"):
        try:
            return ensure_relay(proxy_url)
        except Exception:
            pass
    return f"{parsed['scheme']}://{parsed['host']}:{parsed['port']}"
