import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createProtectedHandler, protectJson } from '../.local/adapter-js/packages/adapter/index.js';
import { createCustomerAPI } from '../.local/adapter-js/examples/integration/customer-api.js';
import { runtime, contracts, guardWorker, newState } from './runtime.mjs';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

const context = () => ({ principal: 'alice', tenant: 'acme', permission: 'customer:read', record_ids: ['1'] });
const body = '[{"id":"1","tenant_id":"acme","name":"synthetic-customer"}]';
const request = (method = 'GET') => new Request('https://api.example.invalid/customers', { method });
const options = (overrides = {}) => ({
  contract: 'sample.customers',
  binding: env => env.LEAK_FENCE,
  authorize: async () => ({ kind: 'allow', context: context() }),
  readJson: async () => body,
  ...overrides,
});
function binding(mf) {
  return { async fetch(req) {
    return mf.dispatchFetch(req.url, { method: req.method, headers: req.headers, body: await req.text() });
  } };
}
async function refusal(response, status) {
  assert.equal(response.status, status);
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  assert.equal(response.headers.get('X-Content-Type-Options'), 'nosniff');
  assert.ok(!(await response.text()).includes('synthetic-customer'));
}

test('authorization and method denial run neither data reads nor the guard', async () => {
  let reads = 0, calls = 0, authorizations = 0;
  for (const [decision, status] of [[{ kind: 'unauthenticated' }, 401], [{ kind: 'deny' }, 403]]) {
    const handler = createProtectedHandler(options({
      authorize: async () => { authorizations++; return decision; },
      readJson: async () => { reads++; return body; },
    }));
    const env = { LEAK_FENCE: { async fetch() { calls++; throw new Error(); } } };
    await refusal(await handler(request(), env), status);
    const response = await handler(request('POST'), env);
    assert.equal(response.headers.get('Allow'), 'GET');
    await refusal(response, 405);
  }
  assert.equal(authorizations, 2);
  assert.equal(reads, 0); assert.equal(calls, 0);
});

test('bad integration, authority, and binding fail before a data read', async () => {
  let reads = 0;
  const base = { readJson: async () => { reads++; return body; } };
  for (const overrides of [
    { contract: '' }, { authorize: async () => null }, { authorize: async () => ({ kind: 'unexpected' }) },
    { authorize: async () => ({ kind: 'allow', context: { ...context(), record_ids: ['1', undefined] } }) },
    { authorize: async () => ({ kind: 'allow', context: { ...context(), tenant: 'あ'.repeat(43) } }) },
    { authorize: async () => { throw new Error('synthetic-customer'); } },
    { binding: () => undefined },
  ]) {
    await refusal(await createProtectedHandler(options({ ...base, ...overrides }))(request(), {}), 503);
  }
  assert.equal(reads, 0);
});

test('reading and binding exceptions never return source data or exception text', async () => {
  const faulty = { async fetch() { throw new Error('synthetic-customer'); } };
  for (const overrides of [
    { readJson: async () => { throw new Error('synthetic-customer'); } },
    { readJson: async () => new Response(body) }, {},
  ]) {
    await refusal(await createProtectedHandler(options(overrides))(request(), { LEAK_FENCE: faulty }), 503);
  }
  await refusal(await protectJson(faulty, { contract: 'sample.customers', context: context(), response_body: body }), 503);
});

test('binding that ignores abort still times out without disclosing the original body', { timeout: 8000 }, async () => {
  let signal;
  const hung = { fetch(req) { signal = req.signal; return new Promise(() => {}); } };
  await refusal(await protectJson(hung, { contract: 'sample.customers', context: context(), response_body: body }), 503);
  assert.equal(signal.aborted, true);
});

test('protected handler uses the real Wasm guard and persistent concurrent quota', async () => {
  const mf = runtime({ policies: [{ ...contracts[0], daily_records: 3 }] });
  try {
    const env = { LEAK_FENCE: binding(mf) };
    for (const bad of [
      '[{"id":"1","tenant_id":"other","name":"synthetic-customer"}]',
      '[{"id":"2","tenant_id":"acme","name":"synthetic-customer"}]',
      '[{"id":"1","tenant_id":"acme","secret":"synthetic-customer"}]',
    ]) {
      const handler = createProtectedHandler(options({ readJson: async () => bad }));
      await refusal(await handler(request(), env), 403);
    }
    const handler = createProtectedHandler(options());
    const results = await Promise.all(Array.from({ length: 8 }, async () => {
      const response = await handler(request(), env);
      const text = await response.text();
      if (response.status === 200) assert.equal(text, body);
      else assert.ok(!text.includes('synthetic-customer'));
      return response.status;
    }));
    assert.equal(results.filter(s => s === 200).length, 3);
    assert.equal(results.filter(s => s === 429).length, 5);
  } finally { await mf.dispose(); }
});

test('data reads cannot mutate a shared authorization result to permit another record', async () => {
  const mf = runtime();
  try {
    const shared = context();
    const handler = createProtectedHandler(options({
      authorize: async () => ({ kind: 'allow', context: shared }),
      readJson: async (_req, _env, authority) => {
        assert.ok(Object.isFrozen(authority));
        assert.ok(Object.isFrozen(authority.record_ids));
        shared.record_ids.push('2');
        shared.tenant = 'other';
        return '[{"id":"2","tenant_id":"acme","name":"synthetic-customer"}]';
      },
    }));
    await refusal(await handler(request(), { LEAK_FENCE: binding(mf) }), 403);
  } finally { await mf.dispose(); }
});

test('disabled guard prevents disclosure through the protected handler', async () => {
  const mf = runtime({ enabled: 'false' });
  try {
    await refusal(await createProtectedHandler(options())(request(), { LEAK_FENCE: binding(mf) }), 503);
  } finally { await mf.dispose(); }
});

test('integration router protects the selected route and has no baseline or unknown-route fallback', async () => {
  const mf = runtime();
  let reads = 0, authorizations = 0;
  const api = createCustomerAPI({
    authorize: async () => { authorizations++; return { kind: 'allow', context: context() }; },
    readCustomers: async () => { reads++; return JSON.parse(body); },
  });
  const env = { LEAK_FENCE: binding(mf) };
  try {
    for (const path of ['/v1/baseline', '/unknown']) {
      await refusal(await api.fetch(new Request('https://api.example.invalid' + path), env), 404);
    }
    await refusal(await api.fetch(new Request('https://api.example.invalid/v1/customers', { method: 'HEAD' }), env), 405);
    assert.equal(reads, 0); assert.equal(authorizations, 0);
    const response = await api.fetch(new Request('https://api.example.invalid/v1/customers'), env);
    assert.equal(response.status, 200);
    assert.equal(await response.text(), body);
    assert.equal(reads, 1); assert.equal(authorizations, 1);
  } finally { await mf.dispose(); }
});

test('integration runs inside workerd through a private Service Binding to the Rust guard', async () => {
  for (const [scenario, expected] of [
    ['normal', 200], ['deny', 403], ['foreign-tenant', 403], ['foreign-id', 403], ['extra-field', 403], ['failure', 503],
  ]) {
    const mf = new Miniflare(convertV4MiniflareOptions({ resourcePersistencePath: newState(), workers: [
      { name: 'synthetic-protected-api', modules: [
        { type: 'ESModule', path: '.local/adapter-js/tests/fixtures/protected-api.js' },
        { type: 'ESModule', path: '.local/adapter-js/examples/integration/customer-api.js' },
        { type: 'ESModule', path: '.local/adapter-js/packages/adapter/index.js' },
      ], compatibilityDate: '2026-10-08', bindings: { FIXTURE_CASE: scenario }, serviceBindings: { LEAK_FENCE: 'leak-fence' } },
      guardWorker({ policies: [{ ...contracts[0], daily_records: 1 }] }),
    ] }));
    try {
      await refusal(await mf.dispatchFetch('https://synthetic.invalid/v1/customers'), 401);
      const result = await mf.dispatchFetch('https://synthetic.invalid/v1/customers', { headers: {
        Authorization: 'Bearer SYNTHETIC_READER', 'X-Tenant': 'other', 'X-Principal': 'admin',
      } });
      if (expected === 200) {
        assert.equal(result.status, 200);
        assert.equal(await result.text(), body);
        await refusal(await mf.dispatchFetch('https://synthetic.invalid/v1/customers', { headers: { Authorization: 'Bearer SYNTHETIC_READER' } }), 429);
      } else {
        const text = await result.clone().text();
        assert.ok(!text.includes('SYNTHETIC_REJECT_MARKER'));
        await refusal(result, expected);
      }
    } finally { await mf.dispose(); }
  }
});
