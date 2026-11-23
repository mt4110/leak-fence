import asyncio
import json
import math
from dataclasses import dataclass
from types import MappingProxyType


class Denied(Exception):
    """Fixed reason codes only; never includes response data."""


@dataclass(frozen=True)
class Context:
    # Set ONLY by trusted authentication/authorization code, never headers.
    principal: str
    tenant: str
    permission: str
    record_ids: frozenset[str]

    def __post_init__(self):
        object.__setattr__(self, "record_ids", frozenset(self.record_ids))
        if not all(type(i) is str and i for i in self.record_ids):
            raise ValueError("invalid record ids")


@dataclass(frozen=True)
class Policy:
    permission: str
    fields: frozenset[str]
    tenant_field: str = "tenant_id"
    id_field: str = "id"
    max_records: int = 100
    max_bytes: int = 262144

    def __post_init__(self):
        object.__setattr__(self, "fields", frozenset(self.fields))
        if (not self.permission or not self.tenant_field
                or self.tenant_field not in self.fields
                or self.id_field not in self.fields
                or not all(isinstance(f, str) and f for f in self.fields)
                or type(self.max_records) is not int or self.max_records < 1
                or type(self.max_bytes) is not int or self.max_bytes < 1):
            raise ValueError("invalid policy")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Denied("duplicate_key")
        result[key] = value
    return result


def _constant(value):
    raise Denied("nonfinite_number")


def inspect(body: bytes, policy: Policy, context: Context) -> None:
    """Validate a flat record or array of flat records; no data is returned."""
    if (type(context) is not Context or type(context.principal) is not str
            or not context.principal or type(context.tenant) is not str
            or not context.tenant or context.permission != policy.permission):
        raise Denied("unauthorized")
    if len(body) > policy.max_bytes:
        raise Denied("byte_limit")
    try:
        data = json.loads(body.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise Denied("invalid_json") from None
    records = data if type(data) is list else [data]
    if len(records) > policy.max_records:
        raise Denied("record_limit")
    for record in records:
        if type(record) is not dict:
            raise Denied("record_shape")
        if record.get(policy.tenant_field) != context.tenant:
            raise Denied("tenant_mismatch")
        if type(record.get(policy.id_field)) is not str or record[policy.id_field] not in context.record_ids:
            raise Denied("object_unauthorized")
        if not record.keys() <= policy.fields:
            raise Denied("unapproved_field")
        for value in record.values():
            if type(value) not in (str, int, float, bool, type(None)):
                raise Denied("nested_value")
            if type(value) is float and not math.isfinite(value):
                raise Denied("nonfinite_number")


class Guard:
    """ASGI boundary. Every HTTP method/path needs an explicit contract.

    Install inside trusted auth middleware, outside response producers.
    Whole response is buffered; unsupported response modes fail closed.
    Only content-type survives: cookies, custom headers and trailers cannot
    carry unchecked data. Use a separate authenticated service for login.
    """

    def __init__(self, app, policies, timeout_seconds=5.0):
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("invalid timeout")
        self.app = app
        self.policies = MappingProxyType(dict(policies))
        self.timeout_seconds = timeout_seconds

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return
        policy = self.policies.get((scope.get("method"), scope.get("path")))
        context = scope.get("leakfence.context")
        if policy is None:
            return await self._deny(send)
        try:
            # Validate identity before invoking an application with side effects.
            inspect(b"[]", policy, context)
        except Denied:
            return await self._deny(send)
        start = None
        chunks = []
        size = 0
        ended = False
        failure = None

        async def capture(message):
            nonlocal start, size, ended, failure
            try:
                kind = message.get("type")
                if ended:
                    raise Denied("after_end")
                if kind == "http.response.start":
                    if start is not None or message.get("trailers"):
                        raise Denied("response_mode")
                    if type(message.get("status")) is not int or not 200 <= message["status"] < 300:
                        raise Denied("status")
                    headers = message.get("headers", [])
                    types = [v.lower().strip() for k, v in headers if k.lower() == b"content-type"]
                    if len(types) != 1 or types[0] not in (b"application/json", b"application/json; charset=utf-8"):
                        raise Denied("content_type")
                    if any(k.lower() == b"content-encoding" for k, v in headers):
                        raise Denied("encoding")
                    start = message["status"]
                elif kind == "http.response.body":
                    if start is None:
                        raise Denied("missing_start")
                    chunk = message.get("body", b"")
                    if type(chunk) is not bytes:
                        raise Denied("body_type")
                    size += len(chunk)
                    if size > policy.max_bytes:
                        raise Denied("byte_limit")
                    chunks.append(chunk)
                    ended = not message.get("more_body", False)
                else:
                    raise Denied("response_mode")
            except Exception:
                # Latch rejection even if downstream catches the exception.
                failure = True
                raise

        try:
            await asyncio.wait_for(self.app(scope, receive, capture), self.timeout_seconds)
            if failure or not ended or start is None:
                raise Denied("incomplete_response")
            body = b"".join(chunks)
            inspect(body, policy, context)
        except Exception:
            return await self._deny(send)
        await send({"type": "http.response.start", "status": start,
                    "headers": [(b"content-type", b"application/json"),
                                (b"cache-control", b"no-store"),
                                (b"x-content-type-options", b"nosniff")]})
        await send({"type": "http.response.body", "body": body})

    @staticmethod
    async def _deny(send):
        await send({"type": "http.response.start", "status": 403,
                    "headers": [(b"content-type", b"application/json"),
                                (b"cache-control", b"no-store")]})
        await send({"type": "http.response.body", "body": b'{"error":"disclosure_blocked"}'})
