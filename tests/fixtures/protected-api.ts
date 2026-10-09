// Synthetic local test fixture only. This authentication is not for deployment.
import { createCustomerAPI } from '../../examples/integration/customer-api.js';
import type { GuardBinding } from '../../packages/adapter/index.js';

interface Env { LEAK_FENCE: GuardBinding; FIXTURE_CASE: string; }

export default createCustomerAPI<Env>({
  async authorize(request, env) {
    if (request.headers.get('Authorization') !== 'Bearer SYNTHETIC_READER') return { kind: 'unauthenticated' };
    if (env.FIXTURE_CASE === 'deny') return { kind: 'deny' };
    return { kind: 'allow', context: {
      principal: 'alice', tenant: 'acme', permission: 'customer:read', record_ids: ['1'],
    } };
  },
  async readCustomers(env) {
    switch (env.FIXTURE_CASE) {
      case 'foreign-tenant': return [{ id: '1', tenant_id: 'other', name: 'synthetic-customer' }];
      case 'foreign-id': return [{ id: '2', tenant_id: 'acme', name: 'synthetic-customer' }];
      case 'extra-field': return [{ id: '1', tenant_id: 'acme', name: 'synthetic-customer', secret: 'SYNTHETIC_REJECT_MARKER' }];
      case 'failure': throw new Error('SYNTHETIC_REJECT_MARKER');
      default: return [{ id: '1', tenant_id: 'acme', name: 'synthetic-customer' }];
    }
  },
});
