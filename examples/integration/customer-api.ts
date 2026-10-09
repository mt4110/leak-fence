import {
  createProtectedHandler, type Authority, type AuthorizationDecision, type GuardBinding,
} from '../../packages/adapter/index.js';

export interface Customer {
  id: string;
  tenant_id: string;
  name: string;
}

export interface CustomerApplication<Env> {
  /** Authenticate and independently authorize IDs using your existing system.
   * Never copy X-Tenant / X-Principal or infer allowed IDs from readCustomers.
   */
  authorize(request: Request, env: Env): Promise<AuthorizationDecision>;
  /** Query only the authorized tenant and IDs; keep pagination bounded.
   * No writes, one-time consumption, tokens, or private columns.
   */
  readCustomers(env: Env, authority: Authority): Promise<readonly Customer[]>;
}

/** A router with one protected GET route and no data-returning fallback.
 * Supply real server-side authentication/authorization and DB functions.
 * No test authentication, fault-injection query, or benchmark bypass is included.
 */
export function createCustomerAPI<Env extends { LEAK_FENCE: GuardBinding }>(app: CustomerApplication<Env>) {
  const protectedRead = createProtectedHandler<Env>({
    contract: 'sample.customers',
    binding: env => env.LEAK_FENCE,
    authorize: (request, env) => app.authorize(request, env),
    readJson: async (_request, env, authority) => JSON.stringify(await app.readCustomers(env, authority)),
  });
  return {
    async fetch(request: Request, env: Env): Promise<Response> {
      if (new URL(request.url).pathname === '/v1/customers') return protectedRead(request, env);
      return new Response('{"error":"not_found"}', { status: 404, headers: {
        'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
      } });
    },
  };
}
