import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { readFileSync } from 'node:fs';
import { guardWorker, newState } from './runtime.mjs';

export const ztContract = JSON.parse(readFileSync(new URL('../examples/zt-gateway/contracts.json', import.meta.url)))[0];

export function ztRuntime({ origin, transport, key, relay, enabled = 'true', limit = 30, state = newState() }) {
  return new Miniflare(convertV4MiniflareOptions({ resourcePersistencePath: state, workers: [
    { name: 'zt-api', modules: [
      { type: 'ESModule', path: '.local/zt-js/examples/zt-gateway/api.js' },
      { type: 'ESModule', path: '.local/zt-js/packages/adapter/index.js' },
    ], compatibilityDate: '2026-10-08', bindings: {
      ORIGIN_BASE_URL: origin, ORIGIN_EDGE_SECRET: transport, AUTHORITY_KEY: key,
      VALIDATION_EXPIRES_AT: new Date(Date.now() + 3600000).toISOString(), ALLOW_LOCAL_ORIGIN: 'true',
    }, serviceBindings: { LEAK_FENCE: 'leak-fence', ...(relay ? { ORIGIN_HTTP: relay } : {}) } },
    guardWorker({ enabled, policies: [{ ...ztContract, daily_records: limit }] }),
  ] }));
}

export async function ztRequest(mf, id, token, extra = {}, method = 'GET') {
  const response = await mf.dispatchFetch('https://zt-api.invalid/v1/verification-events/' + id + '/summary', {
    method, headers: { ...(token ? { Authorization: 'Bearer ' + token } : {}), ...extra },
  });
  return { status: response.status, body: await response.text(), headers: response.headers };
}
