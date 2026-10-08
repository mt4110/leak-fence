import { readFileSync, mkdirSync, mkdtempSync } from 'node:fs';
import { resolve } from 'node:path';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

export const contracts = JSON.parse(readFileSync(new URL('../examples/contracts.json', import.meta.url)));
export function newState() {
  mkdirSync('.local', { recursive: true });
  // Preserve evidence; never reuse or delete an existing deployment's state.
  return mkdtempSync(resolve('.local/worker-test-'));
}
export function runtime({ state = newState(), policies = contracts, enabled = 'true', budgets = true } = {}) {
  return new Miniflare(convertV4MiniflareOptions({
    resourcePersistencePath: state,
    workers: [{
      name: 'leak-fence',
      modules: [
        { type: 'ESModule', path: 'crates/worker/build/index.js' },
        { type: 'CompiledWasm', path: 'crates/worker/build/index_bg.wasm' },
      ],
      compatibilityDate: '2026-10-08',
      bindings: { SERVICE_ENABLED: enabled, POLICIES_JSON: JSON.stringify(policies) },
      durableObjects: budgets ? { BUDGETS: { className: 'DisclosureBudget', useSQLite: true } } : {},
    }],
  }));
}
export function disclosure({ principal = 'alice', tenant = 'acme', body, contract = 'sample.customers' } = {}) {
  return {
    contract,
    context: { principal, tenant, permission: 'customer:read', record_ids: ['1', '2'] },
    response_body: body ?? JSON.stringify([{ id: '1', tenant_id: tenant, name: 'synthetic-customer' }]),
  };
}
export function send(mf, data = disclosure(), path = '/v1/protect') {
  return mf.dispatchFetch('http://localhost' + path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
  });
}
