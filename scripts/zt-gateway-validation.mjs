// Bounded real-product integration. Local by default; --cloud explicitly deploys
// dedicated Workers and a temporary Quick Tunnel, then closes both. Never uses
// existing databases, deletes resources, resets quota, or publishes evidence.
import assert from 'node:assert/strict';
import { randomBytes, createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, writeFileSync, appendFileSync, readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { setTimeout as pause } from 'node:timers/promises';
import { ztRuntime, ztRequest } from '../tests/zt-runtime.mjs';

const repo = resolve(process.argv[2] ?? '../zt-gateway');
const cloud = process.argv[3] === '--cloud';
const finalizeOnly = cloud && process.env.FINALIZE_DISABLED_GUARD === '1';
const auditResume = cloud && process.env.AUDIT_REMAINING_TENANT_B === '1';
const syntheticSubject = process.env.ADDITIONAL_SYNTHETIC_SUBJECT ?? '';
if (syntheticSubject && (!cloud || !process.env.RESUME_CLOUD_STATE || !/^synthetic-[a-z0-9-]{1,64}$/.test(syntheticSubject))) throw new Error('additional subject requires explicitly authorized retained cloud trial');
if (finalizeOnly && !process.env.RESUME_CLOUD_STATE) throw new Error('finalize requires retained deployment state');
if (auditResume && (!process.env.RESUME_CLOUD_STATE || !process.env.FINALIZATION_STATE)) throw new Error('audit requires retained deployment and completed stop evidence');
const account = process.env.CLOUDFLARE_ACCOUNT_ID;
if (cloud && (!/^[a-f0-9]{32}$/.test(account ?? '') || !existsSync(process.env.CLOUDFLARED_BIN ?? ''))) {
  throw new Error('--cloud requires explicit account ID and verified CLOUDFLARED_BIN');
}
mkdirSync('.local', { recursive: true });
const dir = mkdtempSync(resolve('.local/zt-validation-'));
const suffix = randomBytes(6).toString('hex');
const container = 'leakfence-zt-validation-' + suffix;
const database = 'leakfence_validation_' + suffix;
const password = randomBytes(32).toString('base64url');
const transport = randomBytes(32).toString('base64url');
const key = randomBytes(32).toString('base64url');
const jwtSecret = randomBytes(32).toString('base64url');
let fixture, fixtureExit, containerCreated = false, runtime;
let fixtureLog = '';
let tunnel, tunnelExit, apiDeployed = false, cloudOrigin;
let shutdownPath = '', shutdownToken = '';
let cloudRequests = 0;
let apiName = 'leak-fence-zt-' + suffix + '-api';
let guardName = 'leak-fence-zt-' + suffix + '-guard';
let priorCloudRequests = 0;
let previousBudgetDay;
if (cloud && process.env.RESUME_CLOUD_STATE) {
  const previous = resolve(process.env.RESUME_CLOUD_STATE);
  const closed = JSON.parse(readFileSync(resolve(previous, 'shutdown.json'), 'utf8'));
  const oldConfig = readFileSync(resolve(previous, 'api.wrangler.toml'), 'utf8');
  apiName = oldConfig.match(/^name = "(leak-fence-zt-[a-f0-9]{12}-api)"$/m)?.[1];
  assert.ok(apiName && oldConfig.includes(`account_id = "${account}"`) && closed.api_closed_deploy && closed.entry_check_status === 404, 'resume only this task closed validation deployment');
  guardName = apiName.replace(/-api$/, '-guard');
  priorCloudRequests = closed.cloud_http_requests;
  assert.ok(Number.isSafeInteger(priorCloudRequests) && priorCloudRequests >= 0 && priorCloudRequests < 300);
  const previousAttempt = JSON.parse(readFileSync(resolve(previous, 'attempt.json'), 'utf8'));
  previousBudgetDay = new Date(previousAttempt.started_at).toISOString().slice(0, 10);
}
let requests = 0, originRequests = 0;
let fault = 'normal';
let savedProof = '';
const cases = [];
const started = new Date().toISOString();
const budgetDay = started.slice(0, 10);
if (auditResume) assert.equal(previousBudgetDay, budgetDay, 'remaining-17 audit requires the same UTC budget day');

async function command(program, args, options = {}) {
  return await new Promise((resolveResult, reject) => {
    const p = spawn(program, args, { ...options, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '', diagnostic = '';
    p.stdout.on('data', b => { output += b; });
    p.stderr.on('data', b => { diagnostic += b; });
    p.on('error', () => reject(new Error('validation tool unavailable: ' + program)));
    p.on('exit', code => {
      if (code === 0) resolveResult(output.trim());
      else { const error = new Error('validation command failed: ' + program); error.diagnostic = output + diagnostic; reject(error); }
    });
  });
}
async function http(url, options) {
  if (++originRequests > 300) throw new Error('origin request ceiling');
  if (cloud && ++cloudRequests + priorCloudRequests > 300) throw new Error('cloud request ceiling');
  return fetch(url, { ...options, signal: AbortSignal.timeout(8000), redirect: 'manual' });
}
async function call(id, token, headers = {}, method = 'GET') {
  if (!cloud) return ztRequest(runtime, id, token, headers, method);
  if (++cloudRequests + priorCloudRequests > 300) throw new Error('cloud request ceiling');
  const response = await fetch(cloudOrigin + '/v1/verification-events/' + id + '/summary', {
    method, headers: { ...(token ? { Authorization: 'Bearer ' + token } : {}), ...headers },
    signal: AbortSignal.timeout(15000), redirect: 'manual',
  });
  return { status: response.status, body: await response.text(), headers: response.headers };
}
let wranglerRun = 0;
async function wrangler(args) {
  const file = resolve(dir, `wrangler-${++wranglerRun}.log`);
  try {
    const output = await command(resolve('node_modules/.bin/wrangler'), args);
    writeFileSync(file, output + '\n', { mode: 0o600, flag: 'wx' });
    return output;
  } catch (error) {
    writeFileSync(file, error.diagnostic ?? 'tool error', { mode: 0o600, flag: 'wx' });
    throw new Error('Wrangler failed; inspect private log ' + file);
  }
}
function noData(r) {
  assert.ok(!r.body.includes('synthetic-zt-') && !r.body.includes('SYNTHETIC_PRIVATE') && !r.body.includes('reported_result'));
  assert.equal(r.headers.get('X-ZT-Read-Authority'), null);
}
async function check(name, id, token, expected, headers = {}, method = 'GET') {
  if (++requests > 300) throw new Error('validation request ceiling');
  const r = await call(id, token, headers, method);
  if (r.status !== expected) writeFileSync(resolve(dir, 'failure.json'), JSON.stringify({ name, expected, actual: r.status,
    content_type: r.headers.get('Content-Type'), server: r.headers.get('Server'), cf_ray: r.headers.get('CF-Ray'),
    body_sha256: createHash('sha256').update(r.body).digest('hex'), body_excerpt: r.body.slice(0, 800) }), { mode: 0o600, flag: 'wx' });
  assert.equal(r.status, expected, name);
  if (expected === 200) {
    const body = JSON.parse(r.body);
    assert.equal(Object.keys(body).length, 8);
    assert.equal(body.ingest_id, id);
    assert.equal(body.reported_result, 'failed');
    assert.equal(body.reported_policy_decision, 'degraded');
    assert.equal(body.event_signature_verified, true);
    assert.equal(r.headers.get('X-ZT-Read-Authority'), null);
    for (const forbidden of ['SYNTHETIC_PRIVATE_FILENAME', 'SYNTHETIC_PRIVATE_REASON']) assert.ok(!r.body.includes(forbidden));
  } else noData(r);
  cases.push({ name, expected, actual: r.status });
  appendFileSync(resolve(dir, 'steps.jsonl'), JSON.stringify(cases.at(-1)) + '\n', { mode: 0o600 });
  return r;
}

try {
  await command('docker', ['run', '-d', '--name', container, '-p', '127.0.0.1::5432',
    '-e', 'POSTGRES_DB=' + database, '-e', 'POSTGRES_USER=validation', '-e', 'POSTGRES_PASSWORD=' + password, 'postgres:16']);
  containerCreated = true;
  const portLine = await command('docker', ['port', container, '5432/tcp']);
  const port = /^127\.0\.0\.1:(\d+)$/.exec(portLine)?.[1];
  assert.ok(port, 'database must bind only loopback');
  let ready = false;
  for (let i = 0; i < 40; i++) {
    try { await command('docker', ['exec', container, 'pg_isready', '-U', 'validation', '-d', database]); ready = true; break; }
    catch { await pause(250); }
  }
  assert.ok(ready, 'isolated PostgreSQL ready');
  writeFileSync(resolve(dir, 'config.json'), JSON.stringify({ DSN: `postgres://validation:${password}@127.0.0.1:${port}/${database}?sslmode=disable`,
    TransportSecret: transport, AuthorityKey: key, JWTSecret: jwtSecret, Directory: dir, SyntheticSubject: syntheticSubject }), { mode: 0o600, flag: 'wx' });
  fixture = spawn('go', ['test', './cmd/zt-control-plane', '-run', '^TestVerificationSummaryEdgeFixture$', '-count=1'], {
    cwd: resolve(repo, 'control-plane/api'), env: { ...process.env, ZT_CP_SUMMARY_EDGE_TEST_CONFIG: resolve(dir, 'config.json') }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  fixture.stdout.on('data', b => { fixtureLog += b; });
  fixture.stderr.on('data', b => { fixtureLog += b; });
  fixtureExit = new Promise(resolveExit => { fixture.on('error', () => resolveExit(-1)); fixture.on('exit', resolveExit); });
  for (let i = 0; i < 240 && !existsSync(resolve(dir, 'ready.json')); i++) {
    if (fixture.exitCode !== null) throw new Error('Go fixture failed before ready');
    await pause(100);
  }
  assert.ok(existsSync(resolve(dir, 'ready.json')), 'Go origin ready');
  const source = JSON.parse(readFileSync(resolve(dir, 'ready.json'), 'utf8'));
  if (auditResume) { source.ids.reverse(); source.tokens.reverse(); }
  shutdownPath = '/v1/verification-events/' + source.ids[1] + '/summary';
  shutdownToken = source.tokens[1];
  if (cloud) {
    tunnel = spawn(process.env.CLOUDFLARED_BIN, ['tunnel', '--url', source.origin, '--no-autoupdate', '--protocol', 'http2'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let tunnelLog = '';
    for (const stream of [tunnel.stdout, tunnel.stderr]) stream.on('data', b => { tunnelLog += b; });
    tunnelExit = new Promise(resolveExit => { tunnel.on('error', () => resolveExit(-1)); tunnel.on('exit', resolveExit); });
    let publicOrigin;
    for (let i = 0; i < 450; i++) {
      publicOrigin = tunnelLog.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/)?.[0];
      if (publicOrigin && tunnelLog.includes('Registered tunnel connection')) break;
      if (tunnel.exitCode !== null) throw new Error('temporary tunnel failed');
      await pause(100);
    }
    assert.ok(publicOrigin && tunnelLog.includes('Registered tunnel connection'), 'temporary tunnel ready');
    writeFileSync(resolve(dir, 'tunnel.log'), tunnelLog, { mode: 0o600, flag: 'wx' });
    source.origin = publicOrigin;
    for (const [name, workerName] of [['api', apiName], ['guard', guardName]]) {
      let config = readFileSync(`examples/zt-gateway/${name}.wrangler.toml`, 'utf8');
      config = `account_id = "${account}"\n` + config.replace(/^name = .*$/m, `name = "${workerName}"`)
        .replace(/^main = .*$/m, `main = ${JSON.stringify(resolve(name === 'api' ? 'examples/zt-gateway/api.ts' : 'crates/worker/build/worker/shim.mjs'))}`)
        .replace('service = "leak-fence-zt-validation-guard"', `service = "${guardName}"`);
      if (name === 'api') config = config.replace('workers_dev = false', 'workers_dev = true');
      writeFileSync(resolve(dir, `${name}.wrangler.toml`), config, { mode: 0o600, flag: 'wx' });
      writeFileSync(resolve(dir, `${name}.closed.wrangler.toml`), name === 'api' ? config.replace('workers_dev = true', 'workers_dev = false') : config.replace('SERVICE_ENABLED = "true"', 'SERVICE_ENABLED = "false"'), { mode: 0o600, flag: 'wx' });
    }
    await wrangler(['deploy', '--config', resolve(dir, finalizeOnly ? 'guard.closed.wrangler.toml' : 'guard.wrangler.toml')]);
    // Mark before deployment so cleanup also attempts closure after an uncertain outcome.
    apiDeployed = true;
    const deployed = await wrangler(['deploy', '--config', resolve(dir, 'api.wrangler.toml')]);
    cloudOrigin = deployed.match(new RegExp('https://' + apiName + '\\.[a-z0-9-]+\\.workers\\.dev'))?.[0];
    assert.ok(cloudOrigin, 'exact deployed Worker origin');
    writeFileSync(resolve(dir, 'secrets.json'), JSON.stringify({ ORIGIN_BASE_URL: source.origin,
      ORIGIN_EDGE_SECRET: transport, AUTHORITY_KEY: key, VALIDATION_EXPIRES_AT: new Date(Date.now() + 15*60000).toISOString() }), { mode: 0o600, flag: 'wx' });
    await wrangler(['secret', 'bulk', resolve(dir, 'secrets.json'), '--config', resolve(dir, 'api.wrangler.toml')]);
    await wrangler(['deploy', '--config', resolve(dir, 'api.wrangler.toml')]);
    // Observe only unauthenticated routing readiness. Provider HTML 404s are
    // deployment propagation, not business-case retries and never use quota.
    // All probes count toward the retained 300-request ceiling.
    let routingReady = false;
    for (let i = 0; i < 18; i++) {
      const probe = await call(source.ids[1], '');
      appendFileSync(resolve(dir, 'readiness.jsonl'), JSON.stringify({ attempt: i + 1, status: probe.status, content_type: probe.headers.get('Content-Type') }) + '\n', { mode: 0o600 });
      if (probe.status === 401) { routingReady = true; break; }
      assert.ok(probe.status === 404 && probe.headers.get('Content-Type')?.includes('text/html'), 'unexpected routing readiness response');
      await pause(5000);
    }
    assert.ok(routingReady, 'Worker routing did not become ready within 90 seconds');
    console.log(JSON.stringify({ phase: 'cloud deployment ready', api: apiName, guard: guardName }));
  }
  const relay = async request => {
    // Test harness only: fault selection never comes from a public request.
    const r = await http(request.url, { headers: request.headers });
    if (r.status !== 200) return r;
    const headers = new Headers(r.headers);
    const originalProof = headers.get('X-ZT-Read-Authority');
    let body = await r.text();
    if (fault === 'normal') savedProof = originalProof;
    if (fault === 'missing-proof') headers.delete('X-ZT-Read-Authority');
    if (fault === 'mac') headers.set('X-ZT-Read-Authority', originalProof.slice(0, -1) + (originalProof.endsWith('A') ? 'B' : 'A'));
    if (fault === 'replay') headers.set('X-ZT-Read-Authority', savedProof);
    if (['tenant', 'id', 'field', 'nested'].includes(fault)) {
      const parsed = JSON.parse(body);
      if (fault === 'tenant') parsed.tenant_id = 'synthetic-zt-b';
      if (fault === 'id') parsed.ingest_id = source.ids[1];
      if (fault === 'field') parsed.secret = 'SYNTHETIC_PRIVATE_FIELD';
      if (fault === 'nested') parsed.reported_result = { secret: 'SYNTHETIC_PRIVATE_FIELD' };
      body = JSON.stringify(parsed);
    }
    if (fault === 'failure') throw new Error('injected origin transport failure');
    headers.delete('Content-Length');
    return new Response(body, { status: r.status, headers });
  };
  if (!cloud) runtime = ztRuntime({ origin: source.origin, transport, key, relay });
  if (finalizeOnly) {
    await check('public Worker authentication probe', source.ids[1], '', 401);
    await check('disabled real guard with tenant B remaining quota', source.ids[1], source.tokens[1], 503);
    writeFileSync(resolve(dir, 'finalization.json'), JSON.stringify({ previous: process.env.RESUME_CLOUD_STATE,
      cases, prior_cloud_http_requests: priorCloudRequests, cloud_http_requests: cloudRequests, quota_reset: false }), { mode: 0o600, flag: 'wx' });
    console.log(JSON.stringify({ finalization: resolve(dir, 'finalization.json'), cloud_http_requests: cloudRequests, quota_reset: false }));
  } else {
  if (cloud) await check('public Worker authentication probe', source.ids[0], '', 401);
  await check('same-tenant signed ingest to guarded read', source.ids[0], source.tokens[0], 200);
  await check('forged client authority ignored', source.ids[0], source.tokens[0], 200,
    { 'X-ZT-Tenant-ID': 'synthetic-zt-b', 'X-ZT-Read-Authority': 'forged', 'X-ZT-Edge-Secret': 'forged' });
  await check('missing JWT', source.ids[0], '', 401);
  await check('invalid JWT', source.ids[0], 'e30.e30.e30', 401);
  await check('cross-tenant admin', source.ids[0], source.tokens[1], 404);
  await check('missing ID', 'ing-missing', source.tokens[0], 404);
  await check('non-GET', source.ids[0], source.tokens[0], 405, {}, 'POST');
  for (const [scenario, expected] of [['tenant', 403], ['id', 403], ['field', 403], ['nested', 403], ['missing-proof', 503], ['mac', 503], ['replay', 503], ['failure', 503]]) {
    fault = scenario;
    if (cloud) writeFileSync(resolve(dir, 'fault'), fault, { mode: 0o600 });
    await check('injected source ' + scenario, source.ids[0], source.tokens[0], expected);
  }
  fault = 'normal';
  if (cloud) writeFileSync(resolve(dir, 'fault'), fault, { mode: 0o600 });
  for (const path of ['/v1/dashboard/drilldown', '/healthz', '/v1/events/verify']) {
    const r = await http(source.origin + path, { headers: { Authorization: 'Bearer ' + source.tokens[0] } });
    assert.equal(r.status, 404, 'origin exposes only summary');
    cases.push({ name: 'origin denies other route', expected: 404, actual: r.status });
  }
  const direct = await http(source.origin + '/v1/verification-events/' + source.ids[0] + '/summary', { headers: { Authorization: 'Bearer ' + source.tokens[0] } });
  assert.equal(direct.status, 401, 'direct valid JWT cannot bypass edge secret');
  cases.push({ name: 'origin direct bypass denied', expected: 401, actual: direct.status });

  const baseline = [], protectedTimes = [];
  for (let i = 0; i < 10; i++) {
    let start = performance.now();
    const raw = await http(source.origin + '/v1/verification-events/' + source.ids[0] + '/summary', { headers: {
      Authorization: 'Bearer ' + source.tokens[0], 'X-ZT-Edge-Secret': transport, 'X-ZT-Read-Nonce': randomBytes(16).toString('hex'),
    } });
    assert.equal(raw.status, 200);
    const rawBody = await raw.text(); baseline.push(performance.now() - start);
    start = performance.now();
    const guarded = await check('paired normal read', source.ids[0], source.tokens[0], 200);
    protectedTimes.push(performance.now() - start);
    assert.equal(guarded.body, rawBody, 'normal body must be preserved exactly');
    appendFileSync(resolve(dir, 'timing.jsonl'), JSON.stringify({ pair: i + 1,
      baseline_ms: baseline.at(-1), protected_ms: protectedTimes.at(-1) }) + '\n', { mode: 0o600 });
  }
  assert.equal(new Date().toISOString().slice(0, 10), budgetDay, 'UTC budget day changed before concurrency; reassess remaining quota');
  const concurrent = await Promise.all(Array.from({ length: 35 }, async () => {
    if (++requests > 300) throw new Error('validation request ceiling');
    const start = performance.now();
    try {
      const response = await call(source.ids[0], source.tokens[0]);
      return { ...response, elapsed_ms: performance.now() - start };
    } catch {
      // Preserve the whole cohort even if a request has no complete response.
      // Do not infer an HTTP status or body safety for a transport failure.
      return { status: null, body: '', headers: new Headers(), transport_error: true,
        elapsed_ms: performance.now() - start };
    }
  }));
  const remaining = auditResume ? 17 : 18; // B previously consumed one record; preserve it.
  const concurrencyEvidence = concurrent.map((r, index) => {
    let error;
    try { const parsed = JSON.parse(r.body); if (Object.keys(parsed).length === 1 && typeof parsed.error === 'string') error = parsed.error; } catch {}
    return { index, status: r.status, elapsed_ms: r.elapsed_ms, error, transport_error: r.transport_error ?? false,
      source_markers_absent: r.transport_error ? null : !r.body.includes('synthetic-zt-') && !r.body.includes('SYNTHETIC_PRIVATE') && !r.body.includes('reported_result'),
      authority_header_absent: r.transport_error ? null : r.headers.get('X-ZT-Read-Authority') === null,
      body_sha256: r.transport_error ? null : createHash('sha256').update(r.body).digest('hex') };
  });
  // Persist before asserting, so an unexpected response never erases the rest
  // of the cohort. Cloud network failures may safely return 503; they are
  // availability results, not quota successes. Local deterministic tests still
  // require the exact allowed/429 split.
  writeFileSync(resolve(dir, 'concurrent.json'), JSON.stringify({ remaining, responses: concurrencyEvidence }), { mode: 0o600, flag: 'wx' });
  concurrent.filter(r => r.status !== 200).forEach(noData);
  for (const r of concurrent.filter(r => r.status === 200)) {
    const body = JSON.parse(r.body);
    assert.equal(Object.keys(body).length, 8);
    assert.equal(body.ingest_id, source.ids[0]);
    assert.equal(body.tenant_id, auditResume ? 'synthetic-zt-b' : 'synthetic-zt-a');
    assert.equal(r.headers.get('X-ZT-Read-Authority'), null);
  }
  const allowed = concurrent.filter(r => r.status === 200).length;
  const denied = concurrent.filter(r => r.status === 429).length;
  const unavailable = concurrent.filter(r => r.status === 503).length;
  assert.ok(allowed <= remaining, 'never disclose beyond remaining budget');
  assert.equal(allowed + denied + unavailable, 35, 'all statuses must be classified');
  if (!cloud) { assert.equal(allowed, remaining); assert.equal(denied, 35 - remaining); }
  cases.push({ name: `remaining ${remaining} records, 35 concurrent requests`, allowed, denied, unavailable, actual: 'bounded and every refusal checked' });
  appendFileSync(resolve(dir, 'steps.jsonl'), JSON.stringify(cases.at(-1)) + '\n', { mode: 0o600 });
  assert.equal(new Date().toISOString().slice(0, 10), budgetDay, 'UTC budget day changed during the trial; reassess remaining quota');
  const preservedExhaustion = (auditResume || syntheticSubject) && previousBudgetDay === budgetDay;
  await check(preservedExhaustion ? `previously exhausted tenant ${auditResume ? 'A' : 'B'} budget remains exhausted` : previousBudgetDay ? 'existing tenant budget is available on the new UTC day' : 'tenant B has independent budget',
    source.ids[1], source.tokens[1], preservedExhaustion ? 429 : 200);
  if (cloud) {
    await wrangler(['deploy', '--config', resolve(dir, 'guard.closed.wrangler.toml')]);
    await pause(15000);
  } else {
    await runtime.dispose(); runtime = undefined;
    runtime = ztRuntime({ origin: source.origin, transport, key, relay, enabled: 'false' });
  }
  if (!auditResume) await check('disabled real guard', source.ids[0], source.tokens[0], 503);
  else {
    const previousStop = JSON.parse(readFileSync(resolve(process.env.FINALIZATION_STATE, 'finalization.json'), 'utf8'));
    assert.ok(previousStop.quota_reset === false && previousStop.cases.some(c => c.name === 'disabled real guard with tenant B remaining quota' && c.actual === 503));
  }

  const median = values => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
  const snapshot = ['examples/zt-gateway/api.ts', 'packages/adapter/index.ts', 'examples/zt-gateway/contracts.json', 'crates/worker/build/index_bg.wasm', 'scripts/zt-gateway-validation.mjs']
    .map(path => ({ path, sha256: createHash('sha256').update(readFileSync(path)).digest('hex') }));
  const report = { started_at: started, completed_at: new Date().toISOString(), environment: cloud ? 'real Cloudflare Workers + Quick Tunnel + local Go + PostgreSQL 16' : 'local Go + real PostgreSQL 16 + workerd + Rust/Wasm + SQLite DO',
    cloud_deployed: cloud, production_data: false, client_requests: requests, cloud_http_requests: cloudRequests,
    prior_cloud_http_requests: priorCloudRequests, cumulative_cloud_http_requests: priorCloudRequests + cloudRequests,
    budget_day_utc: budgetDay, ...(previousBudgetDay ? { previous_budget_day_utc: previousBudgetDay } : {}),
    ...(syntheticSubject ? { additional_synthetic_subject: syntheticSubject, previous_budgets_retained: true } : {}),
    ...(auditResume ? { guard_stop_evidence: process.env.FINALIZATION_STATE, previous_tenant_b_records: 1, quota_reset: false } : {}),
    origin_http_requests_observed_by_harness: originRequests, cloud_worker_origin_fetch_count: cloud ? 'not measured' : 'included above', ingest_handler_invocations: 2,
    contract_daily_records: 30, cases, timing: { samples_per_path: 10, baseline_median_ms: median(baseline), protected_median_ms: median(protectedTimes),
      scope: cloud ? 'client full-body receipt through temporary tunnel; 10 pairs, not a production SLO' : 'local full-body receipt; origin relay harness overhead included; no cloud performance/SLO claim' },
    source_base: await command('git', ['rev-parse', 'HEAD'], { cwd: repo }), snapshot,
    billing_usage: 'not_measured; no inference of zero cost', resources: { database_container: container, disposition: 'stop and retain; no deletion or reset',
      ...(cloud ? { api: apiName, guard: guardName, public_entry: 'closure attempted in finally; see shutdown.json' } : {}) } };
  writeFileSync(resolve(dir, 'result.json'), JSON.stringify(report, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  console.log(JSON.stringify({ evidence: resolve(dir, 'result.json'), client_requests: requests, cloud_http_requests: cloudRequests, cases: cases.length, cloud_deployed: cloud }));
  }
} finally {
  if (apiDeployed) {
    try {
      await wrangler(['deploy', '--config', resolve(dir, 'api.closed.wrangler.toml')]);
      await wrangler(['deploy', '--config', resolve(dir, 'guard.closed.wrangler.toml')]);
      await pause(15000);
      const r = cloudOrigin ? await http(cloudOrigin + shutdownPath, { headers: { Authorization: 'Bearer ' + shutdownToken } }) : undefined;
      writeFileSync(resolve(dir, 'shutdown.json'), JSON.stringify({ api_closed_deploy: true, guard_disabled_deploy: true,
        entry_check_status: r?.status ?? 'no origin parsed', cloud_http_requests: cloudRequests + priorCloudRequests }), { mode: 0o600, flag: 'wx' });
      if (r) assert.ok([403, 404].includes(r.status), 'public entry closed');
    } catch {
      console.error('CLOUD ENTRY CLOSURE UNCONFIRMED; inspect private deployment logs immediately');
      process.exitCode = 1;
    }
  }
  if (tunnel) {
    tunnel.kill('SIGTERM');
    await Promise.race([tunnelExit, pause(5000)]);
  }
  if (runtime) await runtime.dispose();
  if (fixture) {
    writeFileSync(resolve(dir, 'stop'), 'stop\n', { mode: 0o600, flag: 'wx' });
    const exit = await Promise.race([fixtureExit, pause(5000).then(() => 'timeout')]);
    if (exit === 'timeout') fixture.kill('SIGTERM');
    writeFileSync(resolve(dir, 'fixture.log'), fixtureLog, { mode: 0o600, flag: 'wx' });
  }
  if (containerCreated) await command('docker', ['stop', container]);
  writeFileSync(resolve(dir, 'attempt.json'), JSON.stringify({ started_at: started, completed_at: new Date().toISOString(),
    cases, client_requests: requests, cloud_http_requests: cloudRequests, prior_cloud_http_requests: priorCloudRequests,
    quota_reset: false, production_data: false, cloud_deployed: cloud }), { mode: 0o600, flag: 'wx' });
}
