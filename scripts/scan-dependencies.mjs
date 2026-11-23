import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const imageFile = 'scripts/zt-postgres-image.txt';
const mode = process.argv[2];
const staged = mode === '--staged';
const temporary = mkdtempSync(join(tmpdir(), 'leak-fence-osv-'));

function read(path) {
  return staged ? execFileSync('git', ['show', `:${path}`]) : readFileSync(path);
}

function scanSource() {
  const lockfiles = ['Cargo.lock', 'package-lock.json'].map(name => {
    const path = join(temporary, name);
    writeFileSync(path, read(name));
    return `--lockfile=${path}`;
  });
  const result = spawnSync('osv-scanner', [
    'scan', 'source', '--all-vulns', '--format=json', ...lockfiles,
  ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], maxBuffer: 16 * 1024 * 1024 });
  if (result.error) throw result.error;
  if (result.status !== 0 && result.status !== 1) throw new Error('OSV source scan failed');

  const report = JSON.parse(result.stdout);
  let findings = 0;
  let blocking = 0;
  for (const source of report.results ?? []) {
    for (const entry of source.packages) {
      for (const advisory of entry.vulnerabilities ?? []) {
        findings++;
        // This advisory reports upstream maintenance status only. If OSV
        // associates it with any other ID, fail closed and review it again.
        const maintenanceNotice = advisory.id === 'RUSTSEC-2026-0543'
          && entry.package.name === 'chrono' && !advisory.aliases?.length;
        if (!maintenanceNotice) blocking++;
        console.error(`${maintenanceNotice ? 'Notice' : 'Blocked'}: ${entry.package.name} ${entry.package.version} https://osv.dev/${advisory.id}`);
      }
    }
  }
  if (blocking || (result.status === 1 && !findings)) {
    throw new Error('OSV source scan did not pass');
  }
  console.log('npm and Cargo lockfiles passed OSV policy');
}

function scanImage() {
  const image = read(imageFile).toString().trim();
  if (!/^postgres:17(?:[.a-z0-9-]*)@sha256:[a-f0-9]{64}$/.test(image)) {
    throw new Error('Expected a digest-pinned PostgreSQL 17 image');
  }
  execFileSync('docker', ['pull', image], { stdio: 'inherit', timeout: 180_000 });
  execFileSync('osv-scanner', ['scan', 'image', '--all-vulns', image], {
    stdio: 'inherit', cwd: temporary, timeout: 180_000,
  });
}

try {
  if (staged || mode === 'source') scanSource();
  if (staged || mode === 'image') scanImage();
  if (!staged && mode !== 'source' && mode !== 'image') {
    throw new Error('Usage: node scripts/scan-dependencies.mjs source|image|--staged');
  }
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
