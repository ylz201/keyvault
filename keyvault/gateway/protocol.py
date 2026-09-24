"""Closed v1 contracts shared by CLI, MCP bridge and local RPC."""
from __future__ import annotations
import json
import re
from uuid import UUID
from urllib.parse import urlsplit

ERROR_CODES = frozenset(['ADMIN_OR_TRANSPORT_ERROR', 'CLIENT_NOT_CONFIGURED', 'CREDENTIAL_CHANGED', 'CREDENTIAL_UNAVAILABLE', 'DESTINATION_DENIED', 'DESTINATION_UNAVAILABLE', 'EFFECT_UNKNOWN', 'FORBIDDEN', 'GATEWAY_UNAVAILABLE', 'GRANT_DENIED', 'GRANT_EXHAUSTED', 'INTERNAL_ERROR', 'INVALID_CLIENT_TOKEN', 'INVALID_CREDENTIAL', 'INVALID_INPUT', 'INVALID_RESPONSE', 'INVALID_TARGET', 'NOT_FOUND', 'OUTPUT_REJECTED', 'REDIRECT_DENIED', 'REQUEST_CONFLICT', 'RESPONSE_TOO_LARGE', 'SOCKET_ALREADY_EXISTS', 'UNAUTHENTICATED', 'UNKNOWN_METHOD', 'UNSAFE_CLIENT_TOKEN_FILE', 'UNSAFE_CONFIGURATION', 'UNSAFE_SOCKET_DIRECTORY', 'UNSAFE_STATE_PERMISSIONS', 'UNSUPPORTED_PLATFORM', 'UNSUPPORTED_PROTOCOL', 'UPSTREAM_REJECTED'])

class GatewayError(Exception):
    """Only a fixed error code crosses the agent boundary; never exception text."""
    def __init__(self, code: str):
        self.code = code if isinstance(code, str) and code in ERROR_CODES else "INTERNAL_ERROR"
        super().__init__(self.code)

def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", value):
        raise GatewayError("INVALID_INPUT")
    return value

def request_id(value):
    try:
        if not isinstance(value, str) or str(UUID(value)) != value:
            raise ValueError()
    except (ValueError, AttributeError):
        raise GatewayError("INVALID_INPUT") from None
    return value

def closed(obj, required, optional=()):
    if not isinstance(obj, dict) or set(obj) - set(required) - set(optional) or not set(required) <= set(obj):
        raise GatewayError("INVALID_INPUT")

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)

def parse_json(data):
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError("duplicate key")
            result[k] = v
        return result
    def bad_constant(_):
        raise ValueError("non-finite number")
    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=bad_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise GatewayError("INVALID_INPUT") from None

def target(url):
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 33 or ord(c) > 126 for c in url):
        raise GatewayError("INVALID_TARGET")
    try:
        u = urlsplit(url)
        host = u.hostname or ""
        # Only a fixed public DNS host on HTTPS/443. No URL credentials or fragments.
        if u.scheme != "https" or u.username is not None or u.password is not None or u.port not in (None, 443):
            raise ValueError()
        if u.fragment or "#" in url or "\\" in url or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
            raise ValueError()
        labels = host.split(".")
        if len(labels) < 2 or any(not x or len(x) > 63 or x.startswith("-") or x.endswith("-") for x in labels):
            raise ValueError()
        import ipaddress
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError()
        if all(x.isdigit() for x in labels):
            raise ValueError()
        return host, (u.path or "/") + (("?" + u.query) if u.query else "")
    except ValueError:
        raise GatewayError("INVALID_TARGET") from None

def validate_operation(obj):
    closed(obj, ("id", "workspace", "credential", "url", "auth", "output"))
    identifier(obj["id"]); identifier(obj["workspace"])
    c = obj["credential"]
    closed(c, ("ref", "project", "key"))
    identifier(c["ref"]); identifier(c["project"])
    if not isinstance(c["key"], str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", c["key"]):
        raise GatewayError("INVALID_INPUT")
    target(obj["url"])
    closed(obj["auth"], ("header", "prefix"))
    if obj["auth"]["header"] not in ("Authorization", "X-API-Key") or obj["auth"]["prefix"] not in ("", "Bearer ", "Token "):
        raise GatewayError("INVALID_INPUT")
    output = obj["output"]
    if not isinstance(output, dict) or not 1 <= len(output) <= 16:
        raise GatewayError("INVALID_INPUT")
    for name, rule in output.items():
        identifier(name)
        closed(rule, ("pointer", "type"), ("enum",))
        if not isinstance(rule["pointer"], str) or not re.fullmatch(r"(?:/[A-Za-z0-9_-]+){1,8}", rule["pointer"]):
            raise GatewayError("INVALID_INPUT")
        if rule["type"] not in ("integer", "boolean", "string"):
            raise GatewayError("INVALID_INPUT")
        # No arbitrary strings/objects from an authenticated upstream in v1.
        if rule["type"] == "string":
            values = rule.get("enum")
            if not isinstance(values, list) or not 1 <= len(values) <= 32 or any(not isinstance(v, str) or len(v) > 128 for v in values):
                raise GatewayError("INVALID_INPUT")
        elif "enum" in rule:
            raise GatewayError("INVALID_INPUT")
    return obj

def project_output(payload, rules, secret):
    result = {}
    for name, rule in rules.items():
        value = payload
        for part in rule["pointer"].split("/")[1:]:
            if not isinstance(value, dict) or part not in value:
                raise GatewayError("OUTPUT_REJECTED")
            value = value[part]
        kind = rule["type"]
        if kind == "integer" and (type(value) is not int or abs(value) > 2**53 - 1):
            raise GatewayError("OUTPUT_REJECTED")
        if kind == "boolean" and type(value) is not bool:
            raise GatewayError("OUTPUT_REJECTED")
        if kind == "string" and (type(value) is not str or value not in rule["enum"]):
            raise GatewayError("OUTPUT_REJECTED")
        result[name] = value
    # Defense in depth, not a promise against a malicious trusted destination.
    import base64
    from urllib.parse import quote
    encoded = canonical(result)
    variants = (secret, quote(secret, safe=""), base64.b64encode(secret.encode()).decode())
    if any(v in encoded for v in variants):
        raise GatewayError("OUTPUT_REJECTED")
    return result
