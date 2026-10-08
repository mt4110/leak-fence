import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runtime, newState, send, disclosure, contracts } from './runtime.mjs';

test('validated bytes only, fixed headers, and evaluation does not disclose or consume budget', async () => {
  const mf = runtime({ policies: [{ ...contracts[0], daily_records: 1 }] });
  try {
    const data = disclosure();
    const evaluated = await send(mf, data, '/v1/evaluate');
    assert.equal(evaluated.status, 200);
    assert.equal((await evaluated.json()).budget_check, 'not_performed');
    const response = await send(mf, data);
    assert.equal(response.status, 200);
    assert.equal(await response.text(), data.response_body);
    assert.equal(response.headers.get('Cache-Control'), 'no-store');
    assert.equal((await send(mf, data)).status, 429);
  } finally { await mf.dispose(); }
});

test('tenant, object, field, duplicate-key and unknown-contract violations never return body', async () => {
  const mf = runtime();
  try {
    const badBodies = [
      '{"id":"1","tenant_id":"other","name":"SECRET"}',
      '{"id":"3","tenant_id":"acme","name":"SECRET"}',
      '{"id":"1","tenant_id":"acme","secret":"SECRET"}',
      '{"id":"1","tenant_id":"acme","name":{"x":"SECRET"}}',
      '{"id":"1","id":"2","tenant_id":"acme","name":"SECRET"}',
      '[1]', 'null', 'NaN', 'x'.repeat(16385),
    ];
    for (const body of badBodies) {
      const response = await send(mf, disclosure({ body }));
      assert.equal(response.status, 403);
      assert.ok(!(await response.text()).includes('SECRET'));
    }
    assert.equal((await send(mf, disclosure({ contract: 'unknown' }))).status, 403);
    const missing = disclosure(); delete missing.context;
    assert.equal((await send(mf, missing)).status, 400);
    assert.equal((await send(mf, disclosure(), '/unknown')).status, 404);
  } finally { await mf.dispose(); }
});

test('parallel requests share one durable budget; identities and tenants remain isolated', async () => {
  const mf = runtime();
  try {
    const results = await Promise.all(Array.from({ length: 80 }, async () => {
      const response = await send(mf);
      return { status: response.status, body: await response.text() };
    }));
    assert.equal(results.filter(r => r.status === 200).length, 50);
    assert.equal(results.filter(r => r.status === 429).length, 30);
    for (const response of results) {
      if (response.status !== 200) assert.ok(!response.body.includes('synthetic-customer'));
      else assert.equal(response.body, disclosure().response_body);
    }
    assert.equal((await send(mf, disclosure({ principal: 'bob' }))).status, 200);
    assert.equal((await send(mf, disclosure({ tenant: 'other' }))).status, 200);
  } finally { await mf.dispose(); }
});

test('restart retains used quota and a route alias cannot create a fresh allowance', async () => {
  const state = newState();
  const p = { ...contracts[0], daily_records: 1 };
  const policies = [p, { ...p, id: 'alias' }];
  let mf = runtime({ state, policies });
  try { assert.equal((await send(mf)).status, 200); } finally { await mf.dispose(); }
  mf = runtime({ state, policies });
  try {
    assert.equal((await send(mf, disclosure({ contract: 'alias' }))).status, 429);
  } finally { await mf.dispose(); }
});

test('byte budget applies to the first response and counts UTF-8 bytes', async () => {
  const data = disclosure({ body: '[{"id":"1","tenant_id":"acme","name":"合成"}]' });
  const bytes = Buffer.byteLength(data.response_body);
  for (const limit of [bytes - 1, bytes]) {
    const mf = runtime({ policies: [{ ...contracts[0], daily_bytes: limit }] });
    try {
      assert.equal((await send(mf, data)).status, limit < bytes ? 429 : 200);
      assert.equal((await send(mf, data)).status, 429);
    } finally { await mf.dispose(); }
  }
});

test('disabled, missing storage and conflicting configuration fail closed', async () => {
  for (const options of [
    { enabled: 'false' }, { budgets: false },
    { policies: [contracts[0], { ...contracts[0], id: 'alias', daily_records: 51 }] },
  ]) {
    const mf = runtime(options);
    try {
      const response = await send(mf);
      assert.equal(response.status, 503);
      assert.ok(!(await response.text()).includes('synthetic-customer'));
    } finally { await mf.dispose(); }
  }
});

test('oversized envelope and compressed input are rejected', async () => {
  const mf = runtime();
  try {
    assert.equal((await send(mf, disclosure({ body: 'x'.repeat(1_700_001) }))).status, 413);
    const response = await mf.dispatchFetch('http://localhost/v1/protect', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' }, body: '{}',
    });
    assert.equal(response.status, 415);
  } finally { await mf.dispose(); }
});
