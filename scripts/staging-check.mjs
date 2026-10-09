// Explicit invocation sends only synthetic test requests to the supplied destination.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
export async function runStagingCheck(endpoint, directory, fetchImpl = fetch) {
const base = new URL(endpoint);
if (base.protocol !== 'https:' || base.pathname !== '/' || base.search || base.hash || base.username || base.password
  || !base.hostname.startsWith('leak-fence-validation-api.') || !base.hostname.endsWith('.workers.dev')) {
  throw new Error('Use the confirmed validation-api HTTPS workers.dev origin');
}
const { tokens } = JSON.parse(readFileSync(resolve(directory, 'client.json')));
let requests = 0;
const outcomes = [];
async function request(path, token = tokens[0], headers = {}) {
  if (++requests > 300) throw new Error('test_request_limit');
  const start = performance.now();
  const response = await fetchImpl(new URL(path, base), { redirect: 'error', signal: AbortSignal.timeout(10000),
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers } });
  const body = await response.text();
  const ms = performance.now() - start;
  const serverTiming = response.headers.get('Server-Timing') || '';
  return { status: response.status, body, ms, guardMs: /^guard;dur=(\d+(?:\.\d+)?)$/.test(serverTiming) ? Number(serverTiming.split('=')[1]) : null };
}
function check(r, status) {
  assert.equal(r.status, status);
  if (status !== 200) assert.ok(!r.body.includes('SYNTHETIC_REJECT_MARKER') && !r.body.includes('synthetic-customer'));
  outcomes.push({ status: r.status });
}
check(await request('/v1/customers', ''), 401);
check(await request('/v1/customers', 'x'.repeat(43)), 401);
for (const c of ['foreign-tenant', 'foreign-id', 'field', 'nested', 'duplicate', 'oversize']) {
  check(await request('/v1/customers?case=' + c), 403);
}
check(await request('/v1/customers?case=failure'), 503); // Explicit adapter fault injection, not a network outage.
const forged = await request('/v1/customers', tokens[0], { 'X-Tenant': 'synthetic-beta', 'X-Principal': 'synthetic-user-1' });
check(forged, 200); assert.equal(JSON.parse(forged.body)[0].tenant_id, 'synthetic-acme');
const second = await request('/v1/customers', tokens[1]);
check(second, 200); assert.equal(JSON.parse(second.body)[0].tenant_id, 'synthetic-beta');
const samples = { baseline: [], protected: [], guard: [] };
// Alternating order reduces, but does not eliminate, network/time drift. No automatic retry.
for (let i = 0; i < 40; i++) {
  for (const kind of i % 2 ? ['protected', 'baseline'] : ['baseline', 'protected']) {
    const r = await request(kind === 'baseline' ? '/v1/baseline' : '/v1/customers');
    check(r, 200); assert.deepEqual(JSON.parse(r.body), JSON.parse(forged.body));
    samples[kind].push(r.ms);
    if (kind === 'protected' && r.guardMs !== null) samples.guard.push(r.guardMs);
  }
}
// Complete the 120-record allowance using a bounded parallel batch. Prior allowed requests are 41.
const parallel = await Promise.all(Array.from({ length: 90 }, () => request('/v1/customers')));
assert.equal(parallel.filter(r => r.status === 200).length, 79);
assert.equal(parallel.filter(r => r.status === 429).length, 11);
for (const r of parallel) { check(r, r.status); if (r.status === 200) assert.deepEqual(JSON.parse(r.body), JSON.parse(forged.body)); }
check(await request('/v1/customers'), 429);
check(await request('/v1/customers', tokens[1]), 200);
function summary(a) {
  const s = a.toSorted((a, b) => a - b);
  const percentile = p => s.length ? s[Math.max(0, Math.ceil(p * s.length) - 1)] : null;
  return { count: s.length, p50_ms: percentile(.5), p95_ms: percentile(.95), p99_ms: percentile(.99) };
}
const report = { recorded_at: new Date().toISOString(), requests, scope: 'synthetic staging; client wall-clock includes network and complete body; guard is elapsed wall-clock, not CPU',
  billing_usage: 'not_measured', baseline: summary(samples.baseline), protected: summary(samples.protected), guard: summary(samples.guard),
  quota_parallel: { allowed: 79, denied: 11 }, outcomes };
const output = resolve(directory, `result-${Date.now()}.json`);
writeFileSync(output, JSON.stringify(report, null, 2), { mode: 0o600, flag: 'wx' });
return { result: output, requests, baseline: report.baseline, protected: report.protected, guard: report.guard };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  console.log(JSON.stringify(await runStagingCheck(...process.argv.slice(2))));
}
