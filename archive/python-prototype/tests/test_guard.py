import asyncio
import json
import unittest
from leakfence import Context, Denied, Guard, Policy, inspect

POLICY = Policy("customer:read", frozenset({"id", "tenant_id", "name"}), max_records=2, max_bytes=200)
CTX = Context("alice", "acme", "customer:read", frozenset({"1", "2"}))
ROW = {"id": "1", "tenant_id": "acme", "name": "customer"}


class Inspection(unittest.TestCase):
    def test_allowed(self):
        inspect(json.dumps(ROW).encode(), POLICY, CTX)
        inspect(b"[]", POLICY, CTX)

    def test_denials(self):
        cases = [
            ({**ROW, "tenant_id": "other"}, "tenant_mismatch"),
            ({**ROW, "id": "3"}, "object_unauthorized"),
            ({**ROW, "email": "secret@example.test"}, "unapproved_field"),
            ({**ROW, "name": {"secret": "nested"}}, "nested_value"),
            ({**ROW, "name": ["hidden"]}, "nested_value"),
            ([ROW] * 3, "record_limit"),
            ("scalar", "record_shape"),
            ({**ROW, "name": "x" * 201}, "byte_limit"),
        ]
        for data, reason in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(Denied, reason):
                inspect(json.dumps(data).encode(), POLICY, CTX)

    def test_parser_edges(self):
        for data in [b'{"id":"1","id":"2"}', b'NaN', b'Infinity', b'1e999', b'\xff', b'{']:
            with self.subTest(data=data), self.assertRaises(Denied):
                inspect(data, POLICY, CTX)

    def test_identity(self):
        for context in [None, {"tenant": "acme"}, Context("", "acme", "customer:read", {"1"}), Context("alice", "acme", "admin", {"1"})]:
            with self.subTest(context=context), self.assertRaises(Denied):
                inspect(b"[]", POLICY, context)

    def test_immutable_contract(self):
        fields = {"id", "tenant_id"}
        policy = Policy("read", fields)
        fields.add("password")
        self.assertNotIn("password", policy.fields)


class Boundary(unittest.IsolatedAsyncioTestCase):
    async def run_app(self, messages, context=CTX, path="/customers", throws=False, swallow=False):
        output = []
        async def app(scope, receive, send):
            for msg in messages:
                try:
                    await send(msg)
                except Exception:
                    if not swallow:
                        raise
                self.assertEqual(output, [], "bytes escaped before full validation")
            if throws:
                raise RuntimeError("SECRET")
        async def send(msg):
            output.append(msg)
        async def receive():
            return {"type": "http.disconnect"}
        await Guard(app, {("GET", "/customers"): POLICY})(
            {"type": "http", "method": "GET", "path": path, "leakfence.context": context}, receive, send)
        return output

    def messages(self, body=None, headers=None):
        return [{"type": "http.response.start", "status": 200,
                 "headers": headers if headers is not None else [(b"content-type", b"application/json")]},
                {"type": "http.response.body", "body": body if body is not None else json.dumps(ROW).encode()}]

    async def test_chunked_allowed(self):
        messages = self.messages()
        body = messages.pop()["body"]
        messages += [{"type": "http.response.body", "body": body[:20], "more_body": True},
                     {"type": "http.response.body", "body": body[20:]}]
        out = await self.run_app(messages)
        self.assertEqual(out[0]["status"], 200)
        self.assertEqual(out[1]["body"], body)

    async def test_blocked_responses(self):
        cases = [self.messages(b'{"secret":"SECRET"}'),
                 self.messages(headers=[(b"content-type", b"text/html")]),
                 self.messages(headers=[(b"content-type", b"application/json"), (b"content-type", b"text/html")]),
                 self.messages(headers=[(b"content-type", b"application/json"), (b"content-encoding", b"gzip")]),
                 self.messages(b"SECRET" * 100), self.messages()[:1], [],
                 self.messages()[1:], self.messages() + self.messages()[1:],
                 self.messages() + [{"type": "http.response.trailers", "headers": []}]]
        for messages in cases:
            with self.subTest(messages=messages):
                out = await self.run_app(messages)
                self.assertEqual(out[0]["status"], 403)
                self.assertNotIn(b"SECRET", out[1]["body"])

    async def test_auth_and_unconfigured_route(self):
        for args in [{"context": None}, {"path": "/unconfigured"}]:
            out = await self.run_app(self.messages(), **args)
            self.assertEqual(out[0]["status"], 403)

    async def test_exception_after_body(self):
        out = await self.run_app(self.messages(), throws=True)
        self.assertEqual(out[0]["status"], 403)

    async def test_swallowed_denial_is_latched(self):
        messages = self.messages() + [{"type": "unknown"}]
        out = await self.run_app(messages, swallow=True)
        self.assertEqual(out[0]["status"], 403)

    async def test_headers_do_not_leak(self):
        out = await self.run_app(self.messages(headers=[(b"content-type", b"application/json"),
                                                       (b"x-secret", b"SECRET"), (b"set-cookie", b"SECRET")]))
        self.assertEqual(out[0]["status"], 200)
        self.assertNotIn(b"SECRET", repr(out[0]).encode())

    async def test_websocket_denied(self):
        out = []
        async def send(msg):
            out.append(msg)
        await Guard(None, {})({"type": "websocket"}, None, send)
        self.assertEqual(out, [{"type": "websocket.close", "code": 1008}])


if __name__ == "__main__":
    unittest.main()
