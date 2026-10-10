import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';
import { ztRuntime, ztRequest } from './zt-runtime.mjs';

const transport = randomBytes(32).toString('base64url');
const key = randomBytes(32).toString('base64url');
const token = 'e30.e30.e30'; // Mock SSO only in these transport tests.
const summary = { schema_version: 1, ingest_id: 'ing-a', tenant_id: 'synthetic-zt-a', kind: 'verify', received_at: '2026-10-10T00:00:00Z', reported_result: 'failed', reported_policy_decision: 'degraded', event_signature_verified: true };

function relayFactory({ scenario = 'normal', calls = { count: 0 } } = {}) {
  return async request => {
    calls.count++;
    assert.equal(request.headers.get('X-ZT-Edge-Secret'), transport);
    assert.equal(request.headers.get('X-ZT-Tenant-ID'), null);
    assert.equal(request.headers.get('X-ZT-Read-Authority'), null);
    assert.equal(request.headers.get('Cookie'), null);
    if (scenario === 'throw') throw new Error('private origin failure');
    if (scenario === 'denied') return new Response('SYNTHETIC_PRIVATE_DENIAL', { status: 404 });
    if (scenario === 'redirect') return new Response(null, { status: 302, headers: { Location: 'https://elsewhere.invalid' } });
    const proof = { version: 1, nonce: request.headers.get('X-ZT-Read-Nonce'), path: new URL(request.url).pathname,
      expires_at: Math.floor(Date.now() / 1000) + 30, context: {
        principal: 'a'.repeat(64), tenant: 'synthetic-zt-a', permission: 'verification-event-summary:read', record_ids: ['ing-a'],
      } };
    if (scenario === 'nonce') proof.nonce = '0'.repeat(32);
    if (scenario === 'expired') proof.expires_at -= 31;
    if (scenario === 'future') proof.expires_at += 60;
    if (scenario === 'scope') proof.context.record_ids.push('ing-b');
    if (scenario === 'path') proof.path = '/other';
    const payload = Buffer.from(JSON.stringify(proof)).toString('base64url');
    const mac = createHmac('sha256', Buffer.from(scenario === 'mac' ? randomBytes(32).toString('base64url') : key, 'base64url'))
      .update('zt-summary-authority-v1.' + payload).digest('base64url');
    let body = JSON.stringify(summary);
    if (scenario === 'tenant') body = JSON.stringify({ ...summary, tenant_id: 'synthetic-zt-b' });
    if (scenario === 'id') body = JSON.stringify({ ...summary, ingest_id: 'ing-b' });
    if (scenario === 'field') body = JSON.stringify({ ...summary, secret: 'SYNTHETIC_PRIVATE_FIELD' });
    if (scenario === 'duplicate') body = '{"ingest_id":"ing-a","ingest_id":"ing-b","tenant_id":"synthetic-zt-a"}';
    if (scenario === 'nested') body = JSON.stringify({ ...summary, reported_result: { secret: 'SYNTHETIC_PRIVATE_FIELD' } });
    if (scenario === 'oversize') body = JSON.stringify({ ...summary, reported_result: 'x'.repeat(4096) });
    return new Response(body, { headers: { 'Content-Type': 'application/json', 'X-ZT-Read-Authority': payload + '.' + mac } });
  };
}
function runtime(options = {}) {
  return ztRuntime({ origin: 'http://127.0.0.1:12345', transport, key, ...options });
}
function noData(result) {
  assert.ok(!result.body.includes('synthetic-zt-a') && !result.body.includes('SYNTHETIC_PRIVATE') && !result.body.includes('reported_result'));
  assert.equal(result.headers.get('X-ZT-Read-Authority'), null);
}

test('trusted origin proof authorizes exact flat body; client authority headers never propagate', async () => {
  const calls = { count: 0 };
  const mf = runtime({ relay: relayFactory({ calls }) });
  try {
    assert.equal((await ztRequest(mf, 'ing-a', '')).status, 401);
    assert.equal((await ztRequest(mf, 'ing-a', token, {}, 'POST')).status, 405);
    assert.equal(calls.count, 0);
    const good = await ztRequest(mf, 'ing-a', token, { 'X-ZT-Tenant-ID': 'synthetic-zt-b', 'X-ZT-Read-Authority': 'forged', 'X-ZT-Edge-Secret': 'forged', Cookie: 'private=value' });
    assert.equal(good.status, 200);
    assert.deepEqual(JSON.parse(good.body), summary);
    assert.equal(good.headers.get('X-ZT-Read-Authority'), null);
    assert.equal(good.headers.get('Cache-Control'), 'no-store');
  } finally { await mf.dispose(); }
});

test('nonce, MAC, expiry, path and scope failures do not release an origin body', async () => {
  for (const scenario of ['mac', 'nonce', 'expired', 'future', 'scope', 'path', 'throw', 'redirect']) {
    const mf = runtime({ relay: relayFactory({ scenario }) });
    try { const r = await ztRequest(mf, 'ing-a', token); assert.equal(r.status, 503, scenario); noData(r); }
    finally { await mf.dispose(); }
  }
});

test('real Rust guard rejects body mutations independently of valid origin authority', async () => {
  for (const scenario of ['tenant', 'id', 'field', 'duplicate', 'nested', 'oversize', 'denied']) {
    const mf = runtime({ relay: relayFactory({ scenario }) });
    try {
      const r = await ztRequest(mf, 'ing-a', token);
      assert.equal(r.status, scenario === 'oversize' ? 503 : scenario === 'denied' ? 404 : 403, scenario);
      noData(r);
    } finally { await mf.dispose(); }
  }
});

test('guard disabled fails closed and persistent quota bounds concurrent disclosures', async () => {
  const stopped = runtime({ relay: relayFactory(), enabled: 'false' });
  try { const r = await ztRequest(stopped, 'ing-a', token); assert.equal(r.status, 503); noData(r); }
  finally { await stopped.dispose(); }
  const mf = runtime({ relay: relayFactory(), limit: 2 });
  try {
    const results = await Promise.all(Array.from({ length: 5 }, () => ztRequest(mf, 'ing-a', token)));
    assert.equal(results.filter(r => r.status === 200).length, 2);
    assert.equal(results.filter(r => r.status === 429).length, 3);
    results.filter(r => r.status !== 200).forEach(noData);
  } finally { await mf.dispose(); }
});
