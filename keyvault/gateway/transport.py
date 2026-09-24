"""Fixed HTTPS GET executor. No redirects, proxy env, cookies or arbitrary code."""
from __future__ import annotations
import http.client
import ipaddress
import socket
import ssl
import time
from .protocol import GatewayError, parse_json, target

MAX_RESPONSE = 262144

def public_addresses(host):
    try:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        raise GatewayError("DESTINATION_UNAVAILABLE") from None
    result = []
    translation_ranges = [ipaddress.ip_network(x) for x in ("64:ff9b::/96", "64:ff9b:1::/48")]
    for family, socktype, protocol, _, address in answers:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise GatewayError("DESTINATION_DENIED")
        ip = ipaddress.ip_address(address[0])
        if (not ip.is_global or ip.is_multicast or ip.is_unspecified or
                any(ip in network for network in translation_ranges) or
                getattr(ip, "ipv4_mapped", None) is not None or
                getattr(ip, "sixtofour", None) is not None or getattr(ip, "teredo", None) is not None):
            raise GatewayError("DESTINATION_DENIED")
        result.append((family, socktype, protocol, address))
    if not result:
        raise GatewayError("DESTINATION_UNAVAILABLE")
    return result

class FixedHTTPSTransport:
    def get(self, operation, secret):
        host, path = target(operation["url"])
        # Validate EVERY DNS result and connect to the selected numeric address.
        # Never resolve the name a second time between validation and connect.
        family, socktype, protocol, address = public_addresses(host)[0]
        raw = socket.socket(family, socktype, protocol)
        conn = None
        secured = None
        deadline = time.monotonic() + 15
        try:
            raw.settimeout(5)
            raw.connect(address)
            context = ssl.create_default_context()
            context.set_alpn_protocols(["http/1.1"])
            secured = context.wrap_socket(raw, server_hostname=host)
            secured.settimeout(5)
            conn = http.client.HTTPConnection(host, 443, timeout=5)
            conn.sock = secured
            auth = operation["auth"]
            conn.request("GET", path, headers={
                "Host": host,
                auth["header"]: auth["prefix"] + secret,
                "Accept": "application/json",
                "User-Agent": "keyvault-gateway/0.2",
                "Accept-Encoding": "identity",
                "Connection": "close",
            })
            response = conn.getresponse()
            if 300 <= response.status < 400:
                raise GatewayError("REDIRECT_DENIED")
            if not 200 <= response.status < 300:
                raise GatewayError("UPSTREAM_REJECTED")
            if response.getheader("Content-Encoding", "identity").lower() not in ("identity", ""):
                raise GatewayError("OUTPUT_REJECTED")
            if response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                raise GatewayError("OUTPUT_REJECTED")
            chunks, size = [], 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                secured.settimeout(min(5, remaining))
                chunk = response.read1(min(8192, MAX_RESPONSE + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk); size += len(chunk)
                if size > MAX_RESPONSE:
                    raise GatewayError("OUTPUT_REJECTED")
            try:
                return parse_json(b"".join(chunks))
            except GatewayError:
                raise GatewayError("OUTPUT_REJECTED") from None
        except GatewayError:
            raise
        except Exception:
            # A request may already have reached the destination. Never retry here.
            raise GatewayError("EFFECT_UNKNOWN") from None
        finally:
            if conn:
                conn.close()
            if secured is not None:
                secured.close()
            raw.close()
