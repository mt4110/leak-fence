import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { runStagingCheck } from '../scripts/staging-check.mjs';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { guardWorker, newState, contracts } from './runtime.mjs';
const tokens = [randomBytes(32).toString('base64url'), randomBytes(32).toString('base64url')];
const users = tokens.map((t, i) => ({ token_sha256: createHash('sha256').update(t).digest('hex'),
  principal: `synthetic-user-${i}`, tenant: ['synthetic-acme', 'synthetic-beta'][i], record_ids: [String(i + 1)] }));
function runtime({ enabled = 'true', config = JSON.stringify(users), expires = new Date(Date.now() + 3600000).toISOString(), limit = 3 } = {}) {
  return new Miniflare(convertV4MiniflareOptions({ resourcePersistencePath: newState(), workers: [
    { name: 'validation-api', modules: [
      { type: 'ESModule', path: '.local/staging-js/examples/staging/api.js' },
      { type: 'ESModule', path: '.local/staging-js/packages/adapter/index.js' },
    ], compatibilityDate: '2026-10-08', bindings: { TEST_USERS_JSON: config, VALIDATION_EXPIRES_AT: expires }, serviceBindings: { LEAK_FENCE: 'leak-fence' } },
    guardWorker({ enabled, policies: [{ ...contracts[0], daily_records: limit }] }),
  ] }));
}
async function request(mf, path = '/v1/customers', token = tokens[0], extraHeaders = {}) {
  const r = await mf.dispatchFetch('https://validation.invalid' + path, {
    headers: { ...(token ? { Authorization: 'Bearer ' + token } : {}), ...extraHeaders },
  });
  return { status: r.status, body: await r.text(), headers: r.headers };
}
test('authentication and server authority survive forged client context', async () => {
  const mf = runtime();
  try {
    assert.equal((await request(mf, undefined, '')).status, 401);
    assert.equal((await request(mf, undefined, 'x'.repeat(43))).status, 401);
    const a = await request(mf, undefined, tokens[0], { 'X-Tenant': 'synthetic-beta', 'X-Principal': users[1].principal });
    assert.equal(a.status, 200);
    assert.deepEqual(JSON.parse(a.body), [{ id: '1', tenant_id: 'synthetic-acme', name: 'synthetic-customer-a' }]);
    assert.equal(a.headers.get('Cache-Control'), 'no-store');
    assert.match(a.headers.get('Server-Timing'), /^guard;dur=\d+\.\d{2}$/);
    assert.equal((await request(mf, '/v1/customers?tenant=synthetic-beta')).status, 400);
    const b = await request(mf, undefined, tokens[1]);
    assert.equal(JSON.parse(b.body)[0].tenant_id, 'synthetic-beta');
  } finally { await mf.dispose(); }
});
test('service binding rejects injected source bugs without consuming allowance', async () => {
  const mf = runtime();
  try {
    for (const c of ['foreign-tenant', 'foreign-id', 'field', 'nested', 'duplicate', 'oversize']) {
      const r = await request(mf, '/v1/customers?case=' + c);
      assert.equal(r.status, 403);
      assert.ok(!r.body.includes('SYNTHETIC_REJECT_MARKER') && !r.body.includes('synthetic-customer'));
    }
    for (let i = 0; i < 3; i++) assert.equal((await request(mf)).status, 200);
    assert.equal((await request(mf)).status, 429);
    assert.equal((await request(mf, undefined, tokens[1])).status, 200);
  } finally { await mf.dispose(); }
});
test('adapter faults and disabled guard never fall back; baseline uses only fixed synthetic rows', async () => {
  const mf = runtime({ enabled: 'false' });
  try {
    for (const path of ['/v1/customers', '/v1/customers?case=failure']) {
      const r = await request(mf, path);
      assert.equal(r.status, 503); assert.ok(!r.body.includes('synthetic-customer'));
    }
    assert.equal((await request(mf, '/v1/baseline')).status, 200);
    assert.equal((await request(mf, '/v1/baseline?case=field')).status, 400);
  } finally { await mf.dispose(); }
});
test('invalid authentication configuration stops the API', async () => {
  const mf = runtime({ config: JSON.stringify([users[0], users[0]]) });
  try { assert.equal((await request(mf)).status, 503); } finally { await mf.dispose(); }
});
test('expired or unconfigured validation window stops authenticated access', async () => {
  for (const expires of ['', 'invalid', new Date(Date.now() - 1000).toISOString()]) {
    const mf = runtime({ expires });
    try { assert.equal((await request(mf)).status, 503); } finally { await mf.dispose(); }
  }
});
test('bounded cloud-check procedure completes against real local Worker bindings without sending externally', async () => {
  const mf = runtime({ limit: 120 });
  const dir = newState();
  writeFileSync(resolve(dir, 'client.json'), JSON.stringify({ tokens }), { mode: 0o600, flag: 'wx' });
  try {
    const report = await runStagingCheck('https://leak-fence-validation-api.synthetic.workers.dev/', dir,
      (url, init) => mf.dispatchFetch(url.toString(), init));
    assert.equal(report.requests, 183);
    assert.equal(report.protected.count, 40);
    assert.equal(report.baseline.count, 40);
    const text = readFileSync(report.result, 'utf8');
    for (const token of tokens) assert.ok(!text.includes(token));
    assert.ok(!text.includes('synthetic-customer') && !text.includes('SYNTHETIC_REJECT_MARKER'));
    assert.equal(JSON.parse(text).billing_usage, 'not_measured');
  } finally { await mf.dispose(); }
});
