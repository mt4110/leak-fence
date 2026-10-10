import { protectJson, type Authority, type GuardBinding } from '../../packages/adapter/index.js';

export interface Env {
  ORIGIN_BASE_URL: string;
  ORIGIN_EDGE_SECRET: string;
  AUTHORITY_KEY: string;
  VALIDATION_EXPIRES_AT: string;
  /** Local workerd only. Never enable HTTP/loopback origins in a cloud deployment. */
  ALLOW_LOCAL_ORIGIN?: string;
  LEAK_FENCE: GuardBinding;
  /** Test harness transport, still talking HTTP to the real Go origin. */
  ORIGIN_HTTP?: GuardBinding;
}

const encoder = new TextEncoder();
const route = /^\/v1\/verification-events\/([A-Za-z0-9][A-Za-z0-9._:-]{0,127})\/summary$/;
const domain = 'zt-summary-authority-v1.';
const permission = 'verification-event-summary:read';

function stop(status: number, error: string): Response {
  return new Response(JSON.stringify({ error }), { status, headers: {
    'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
    ...(status === 405 ? { Allow: 'GET' } : {}),
  } });
}
function decode(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('invalid_base64url');
  const bytes = Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  const canonical = btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  if (canonical !== value) throw new Error('invalid_base64url');
  return bytes;
}
function keys(value: unknown, expected: string): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === expected;
}
function identifier(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && encoder.encode(value).length <= 128
    && value.trim() === value && !/\p{Cc}/u.test(value);
}

// Authority is authenticated metadata from the origin's JWT + tenant SQL
// decision, not the response body, URL alone, or a client-supplied header.
export async function verifyAuthority(header: string, keyText: string, nonce: string, path: string, id: string): Promise<Authority> {
  if (header.length > 4096) throw new Error('invalid_authority');
  const parts = header.split('.');
  if (parts.length !== 2) throw new Error('invalid_authority');
  const rawKey = decode(keyText);
  if (rawKey.length !== 32) throw new Error('invalid_key');
  const key = await crypto.subtle.importKey('raw', rawKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const signature = decode(parts[1]);
  if (signature.length !== 32 || !await crypto.subtle.verify('HMAC', key, signature, encoder.encode(domain + parts[0]))) {
    throw new Error('invalid_authority');
  }
  const proof: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(decode(parts[0])));
  const now = Math.floor(Date.now() / 1000);
  if (!keys(proof, 'context,expires_at,nonce,path,version') || proof.version !== 1 || proof.nonce !== nonce || proof.path !== path
    || typeof proof.expires_at !== 'number' || !Number.isSafeInteger(proof.expires_at) || proof.expires_at <= now || proof.expires_at > now + 35
    || !keys(proof.context, 'permission,principal,record_ids,tenant')) throw new Error('invalid_authority');
  const ctx = proof.context;
  if (typeof ctx.principal !== 'string' || !/^[a-f0-9]{64}$/.test(ctx.principal) || !identifier(ctx.tenant)
    || ctx.permission !== permission || !Array.isArray(ctx.record_ids) || ctx.record_ids.length !== 1 || ctx.record_ids[0] !== id) {
    throw new Error('invalid_authority');
  }
  return Object.freeze({ principal: ctx.principal, tenant: ctx.tenant, permission, record_ids: Object.freeze([id]) });
}

function originURL(config: string, local: boolean, path: string): URL {
  const base = new URL(config);
  if (base.username || base.password || base.search || base.hash || base.pathname !== '/') throw new Error('invalid_origin');
  const loopback = ['127.0.0.1', '[::1]', 'localhost'].includes(base.hostname);
  if (local ? !(loopback && base.protocol === 'http:') : (loopback || base.protocol !== 'https:')) throw new Error('invalid_origin');
  return new URL(path, base);
}

async function boundedRead(response: Response): Promise<string> {
  if (!response.body) throw new Error('missing_body');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > 4096) throw new Error('oversize_origin');
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== 'GET') return stop(405, 'method_not_allowed');
    const match = route.exec(url.pathname);
    if (!match) return stop(404, 'not_found');
    if (url.search) return stop(400, 'bad_request');
    const authorization = request.headers.get('Authorization') ?? '';
    if (!/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(authorization) || authorization.length > 8192) return stop(401, 'unauthorized');
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      if (!Number.isFinite(Date.parse(env.VALIDATION_EXPIRES_AT)) || Date.parse(env.VALIDATION_EXPIRES_AT) <= Date.now()
        || decode(env.ORIGIN_EDGE_SECRET).length !== 32 || decode(env.AUTHORITY_KEY).length !== 32
        || env.ORIGIN_EDGE_SECRET === env.AUTHORITY_KEY || !env.LEAK_FENCE?.fetch) throw new Error('invalid_config');
      const origin = originURL(env.ORIGIN_BASE_URL, env.ALLOW_LOCAL_ORIGIN === 'true', url.pathname);
      const nonce = [...crypto.getRandomValues(new Uint8Array(16))].map(n => n.toString(16).padStart(2, '0')).join('');
      // Build fresh headers: never forward client context/proof/secret/cookies.
      const originRequest = new Request(origin, { method: 'GET', redirect: 'manual', signal: controller.signal, headers: {
        Authorization: authorization, 'X-ZT-Edge-Secret': env.ORIGIN_EDGE_SECRET, 'X-ZT-Read-Nonce': nonce,
      } });
      const read = async (): Promise<{ kind: 'deny'; response: Response } | { kind: 'allow'; authority: Authority; body: string }> => {
        const response = await (env.ORIGIN_HTTP ? env.ORIGIN_HTTP.fetch(originRequest) : fetch(originRequest));
        if (response.status !== 200) {
          await response.body?.cancel();
          if ([400, 401, 403, 404, 405].includes(response.status)) return { kind: 'deny', response: stop(response.status, 'origin_denied') };
          throw new Error('origin_unavailable');
        }
        if (!response.headers.get('Content-Type')?.toLowerCase().startsWith('application/json')) throw new Error('invalid_origin_response');
        const authority = await verifyAuthority(response.headers.get('X-ZT-Read-Authority') ?? '', env.AUTHORITY_KEY, nonce, url.pathname, match[1]);
        const body = await boundedRead(response);
        return { kind: 'allow', authority, body };
      };
      const deadline = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => { controller.abort(); reject(new Error('origin_timeout')); }, 6000);
      });
      const result = await Promise.race([read(), deadline]);
      clearTimeout(timer);
      if (result.kind === 'deny') return result.response;
      // Return only the guard result. Never return the raw origin Response or
      // copy its authority/diagnostic headers into the public response.
      return await protectJson(env.LEAK_FENCE, { contract: 'zt.verification-summary', context: result.authority, response_body: result.body });
    } catch {
      controller.abort();
      return stop(503, 'integration_unavailable');
    } finally { clearTimeout(timer); }
  },
};
