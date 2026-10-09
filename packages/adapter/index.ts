/** Trusted server integration only. Never build this context from client headers
 * or derive record_ids from the unfiltered response being checked.
 * Select contract from the server's route configuration, not client input.
 */
export interface Authority {
  readonly principal: string;
  readonly tenant: string;
  readonly permission: string;
  readonly record_ids: readonly string[];
}

export interface DisclosureRequest {
  contract: string;
  context: Authority;
  response_body: string;
}

export interface GuardBinding {
  fetch(request: Request): Promise<Response>;
}

/** Return this Response directly. An exception never falls back to the original data.
 * The guard is a PRIVATE Worker Service Binding in the caller's account.
 */
export async function protectJson(binding: GuardBinding, disclosure: DisclosureRequest): Promise<Response> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const deadline = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new Error('guard_timeout'));
      }, 6000);
    });
    const response = binding.fetch(new Request('https://leak-fence.internal/v1/protect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(disclosure),
      signal: controller.signal,
    }));
    // The deadline also settles our return value if a binding ignores abort.
    return await Promise.race([response, deadline]);
  } catch {
    return stop(503, 'guard_unavailable');
  } finally {
    clearTimeout(timer);
  }
}

function stop(status: number, error: string): Response {
  return new Response(JSON.stringify({ error }), { status, headers: {
    'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
    ...(status === 405 ? { Allow: 'GET' } : {}),
  } });
}

export type AuthorizationDecision =
  | { kind: 'allow'; context: Authority }
  | { kind: 'unauthenticated' }
  | { kind: 'deny' };

export interface ProtectedReadOptions<Env> {
  /** Constant from the server's route configuration. */
  contract: string;
  binding(env: Env): GuardBinding;
  /** Existing authentication AND object authorization. No data reads on denial. */
  authorize(request: Request, env: Env): Promise<AuthorizationDecision>;
  /** Read-only operation returning serialized JSON, never an HTTP Response. */
  readJson(request: Request, env: Env, authority: Authority): Promise<string>;
}

const encoder = new TextEncoder();
function validId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 128
    && encoder.encode(value).byteLength <= 128 && !/\p{Cc}/u.test(value);
}

function snapshot(context: Authority): Authority {
  if (!context || !validId(context.principal) || !validId(context.tenant) || !validId(context.permission)
    || !Array.isArray(context.record_ids) || context.record_ids.length > 1000) throw new Error('invalid_authority');
  const ids = [...context.record_ids];
  if (!ids.every(validId)) throw new Error('invalid_authority');
  return Object.freeze({
    principal: context.principal, tenant: context.tenant, permission: context.permission,
    record_ids: Object.freeze(ids),
  });
}

/** Bind this handler to one GET route and return its Response directly.
 * Authorization completes before reading. Errors never return the source body.
 * This does not discover bypass routes or validate your authorization rules.
 */
export function createProtectedHandler<Env>(options: ProtectedReadOptions<Env>):
  (request: Request, env: Env) => Promise<Response> {
  const { contract, binding, authorize, readJson } = options;
  return async (request, env) => {
    if (request.method !== 'GET') return stop(405, 'method_not_allowed');
    try {
      if (!validId(contract)) return stop(503, 'integration_unavailable');
      const decision = await authorize(request, env);
      if (!decision || typeof decision !== 'object') return stop(503, 'integration_unavailable');
      switch (decision.kind) {
        case 'unauthenticated': return stop(401, 'authentication');
        case 'deny': return stop(403, 'unauthorized');
        case 'allow': break;
        default: return stop(503, 'integration_unavailable');
      }
      // Copy and freeze the authorization result before the application read.
      // Mutating a shared ID array during readJson must not expand authority.
      const authority = snapshot(decision.context);
      const guard = binding(env);
      if (!guard || typeof guard.fetch !== 'function') return stop(503, 'guard_unavailable');
      const body = await readJson(request, env, authority);
      if (typeof body !== 'string') return stop(503, 'integration_unavailable');
      return await protectJson(guard, { contract, context: authority, response_body: body });
    } catch {
      return stop(503, 'integration_unavailable');
    }
  };
}
