// Local preparation only. Does not deploy, upload credentials, or print tokens.
import { randomBytes, createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
const account = process.argv[2];
if (!/^[a-f0-9]{32}$/.test(account || '')) throw new Error('Pass the explicitly selected Cloudflare account ID');
mkdirSync('.local', { recursive: true });
const dir = mkdtempSync(resolve('.local/staging-'));
const tokens = [randomBytes(32).toString('base64url'), randomBytes(32).toString('base64url')];
const users = tokens.map((t, i) => ({ token_sha256: createHash('sha256').update(t).digest('hex'),
  principal: `synthetic-user-${i}`, tenant: ['synthetic-acme', 'synthetic-beta'][i], record_ids: [String(i + 1)] }));
const secrets = { TEST_USERS_JSON: JSON.stringify(users), VALIDATION_EXPIRES_AT: new Date(Date.now() + 2 * 3600000).toISOString() };
writeFileSync(resolve(dir, 'secrets.json'), JSON.stringify(secrets), { mode: 0o600, flag: 'wx' });
writeFileSync(resolve(dir, 'client.json'), JSON.stringify({ tokens }), { mode: 0o600, flag: 'wx' });
for (const name of ['api', 'guard']) {
  let config = readFileSync(`examples/staging/${name}.wrangler.toml`, 'utf8');
  const main = name === 'api' ? resolve('examples/staging/api.ts') : resolve('crates/worker/build/worker/shim.mjs');
  config = config.replace(/^main = .*$/m, `main = ${JSON.stringify(main)}`);
  if (name === 'api') config = config.replace('workers_dev = false', 'workers_dev = true');
  // account_id is top-level, so put it before any TOML table.
  config = `account_id = "${account}"\n` + config;
  writeFileSync(resolve(dir, `${name}.wrangler.toml`), config, { mode: 0o600, flag: 'wx' });
  if (name === 'api') writeFileSync(resolve(dir, 'api.closed.wrangler.toml'),
    config.replace('workers_dev = true', 'workers_dev = false'), { mode: 0o600, flag: 'wx' });
}
console.log(dir);
