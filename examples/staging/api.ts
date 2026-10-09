import { protectJson, type GuardBinding } from '../../packages/adapter/index.js';

interface User {
  token_sha256: string;
  principal: string;
  tenant: string;
  record_ids: string[];
}
interface Env { TEST_USERS_JSON: string; VALIDATION_EXPIRES_AT: string; LEAK_FENCE: GuardBinding; }
const cases = new Set(['normal', 'foreign-tenant', 'foreign-id', 'field', 'nested', 'duplicate', 'oversize', 'failure']);
const identifier = (s: unknown): s is string => typeof s === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(s);
const rows = [
  { id: '1', tenant_id: 'synthetic-acme', name: 'synthetic-customer-a' },
  { id: '2', tenant_id: 'synthetic-beta', name: 'synthetic-customer-b' },
];
function json(status: number, value: unknown): Response {
  return new Response(JSON.stringify(value), { status, headers: {
    'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
  } });
}
function users(config: string): User[] {
  if (typeof config !== 'string' || config.length > 8192) throw new Error('configuration');
  const parsed: unknown = JSON.parse(config);
  if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 4) throw new Error('configuration');
  const hashes = new Set<string>();
  for (const u of parsed) {
    if (!u || typeof u !== 'object' || Object.keys(u).sort().join(',') !== 'principal,record_ids,tenant,token_sha256'
      || !/^[a-f0-9]{64}$/.test(u.token_sha256) || hashes.has(u.token_sha256)
      || !identifier(u.principal) || !identifier(u.tenant) || !u.tenant.startsWith('synthetic-')
      || !Array.isArray(u.record_ids) || u.record_ids.length > 2 || !u.record_ids.every(identifier)) {
      throw new Error('configuration');
    }
    hashes.add(u.token_sha256);
  }
  return parsed;
}
async function authenticate(request: Request, configured: User[]): Promise<User | undefined> {
  const header = request.headers.get('Authorization') || '';
  if (!/^Bearer [A-Za-z0-9_-]{43}$/.test(header)) return undefined;
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(header.slice(7))));
  const hex = [...digest].map(b => b.toString(16).padStart(2, '0')).join('');
  let found: User | undefined;
  for (const u of configured) {
    let mismatch = 0;
    for (let i = 0; i < 64; i++) mismatch |= hex.charCodeAt(i) ^ u.token_sha256.charCodeAt(i);
    if (mismatch === 0) found = u;
  }
  return found;
}
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const expires = Date.parse(env.VALIDATION_EXPIRES_AT);
      if (!Number.isFinite(expires) || expires <= Date.now()) return json(503, { error: 'validation_expired' });
      const url = new URL(request.url);
      if (request.method !== 'GET' || !['/v1/customers', '/v1/baseline'].includes(url.pathname)) {
        return json(404, { error: 'not_found' });
      }
      const user = await authenticate(request, users(env.TEST_USERS_JSON));
      if (!user) return json(401, { error: 'authentication' });
      // Authority comes only from server configuration, never from query/headers or returned rows.
      const own = rows.filter(r => r.tenant_id === user.tenant && user.record_ids.includes(r.id));
      if (url.pathname === '/v1/baseline') {
        if (url.search) return json(400, { error: 'invalid_case' });
        // Only fixed synthetic records; no DB or customer data is connected to this benchmark path.
        return json(200, own);
      }
      const scenario = url.searchParams.get('case') || 'normal';
      if (!cases.has(scenario) || [...url.searchParams.keys()].some(k => k !== 'case')
        || url.searchParams.getAll('case').length > 1) return json(400, { error: 'invalid_case' });
      let body = JSON.stringify(own);
      const row = own[0];
      if (scenario !== 'normal' && !row) return json(403, { error: 'no_fixture_record' });
      switch (scenario) {
        case 'foreign-tenant': body = JSON.stringify([{ ...row, tenant_id: 'synthetic-other' }]); break;
        case 'foreign-id': body = JSON.stringify([{ ...row, id: 'unauthorized' }]); break;
        case 'field': body = JSON.stringify([{ ...row, secret: 'SYNTHETIC_REJECT_MARKER' }]); break;
        case 'nested': body = JSON.stringify([{ ...row, name: { secret: 'SYNTHETIC_REJECT_MARKER' } }]); break;
        case 'duplicate': body = `[{"id":"${row.id}","id":"unauthorized","tenant_id":"${row.tenant_id}"}]`; break;
        case 'oversize': body = JSON.stringify([{ ...row, name: 'x'.repeat(16385) }]); break;
      }
      const binding = scenario === 'failure'
        ? { async fetch(): Promise<Response> { throw new Error('synthetic_fault_injection'); } }
        : env.LEAK_FENCE;
      const start = performance.now();
      const response = await protectJson(binding, {
        contract: 'sample.customers',
        context: { principal: user.principal, tenant: user.tenant, permission: 'customer:read', record_ids: user.record_ids },
        response_body: body,
      });
      // Diagnostic duration only; no identities or response body in telemetry.
      const headers = new Headers(response.headers);
      headers.set('Server-Timing', `guard;dur=${Math.max(0, performance.now() - start).toFixed(2)}`);
      return new Response(response.body, { status: response.status, headers });
    } catch {
      return json(503, { error: 'validation_unavailable' });
    }
  },
};
