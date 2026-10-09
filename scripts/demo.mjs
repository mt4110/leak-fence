import { runtime, send, disclosure, contracts } from '../tests/runtime.mjs';
const mf = runtime({ policies: [{ ...contracts[0], daily_records: 1 }] });
try {
  for (const [name, data, expected] of [
    ['他テナントの返却を拒否', disclosure({ body: '[{"id":"1","tenant_id":"other"}]' }), 403],
    ['未許可IDの返却を拒否', { ...disclosure(), context: { ...disclosure().context, record_ids: ['2'] } }, 403],
    ['秘密項目の追加を拒否', disclosure({ body: '[{"id":"1","tenant_id":"acme","secret":"SYNTHETIC_REJECT_MARKER"}]' }), 403],
    ['許可された返却', disclosure(), 200],
    ['日次上限超過を拒否', disclosure(), 429],
  ]) {
    const response = await send(mf, data);
    const body = await response.text();
    if (response.status !== expected || (expected === 200 && body !== data.response_body)
      || (expected !== 200 && (body.includes('SYNTHETIC_REJECT_MARKER') || body.includes('synthetic-customer')))) {
      throw new Error('デモの期待した許可・拒否と一致しません。導入前に調査してください。');
    }
    console.log(`${name}: HTTP ${response.status} ✓`);
  }
  console.log('合成データで内容検査と日次取得枠を確認しました。実APIの認可・適用経路は別途検証が必要です。');
} finally { await mf.dispose(); }
