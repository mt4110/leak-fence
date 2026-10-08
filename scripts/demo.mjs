import { runtime, send, disclosure, contracts } from '../tests/runtime.mjs';
const mf = runtime({ policies: [{ ...contracts[0], daily_records: 1 }] });
try {
  for (const [name, data] of [
    ['他テナントの返却', disclosure({ body: '[{"id":"1","tenant_id":"other"}]' })],
    ['許可された返却', disclosure()],
    ['日次上限超過', disclosure()],
  ]) {
    const response = await send(mf, data);
    console.log(`${name}: HTTP ${response.status}`);
    await response.arrayBuffer();
  }
} finally { await mf.dispose(); }
