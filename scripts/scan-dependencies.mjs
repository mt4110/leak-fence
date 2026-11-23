import { randomUUID } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dockerfile = 'docker/zt-postgres/Dockerfile';
const mode = process.argv[2];
const staged = mode === '--staged';
const prepareImage = mode === 'prepare-image';
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
  const image = `leak-fence/zt-postgres:${randomUUID()}`;
  const archive = join(temporary, 'postgres.tar');
  const options = { stdio: ['ignore', 'inherit', 'inherit'], timeout: 240_000 };
  execFileSync('docker', ['build', '--pull', '--no-cache', '--tag', image, '-'], {
    ...options, input: read(dockerfile), stdio: ['pipe', 2, 2],
  });
  let passed = false;
  try {
    const imageId = execFileSync('docker', ['image', 'inspect', '--format={{.Id}}', image], {
      encoding: 'utf8', timeout: 30_000,
    }).trim();
    if (!/^sha256:[a-f0-9]{64}$/.test(imageId)) throw new Error('Missing built image ID');
    execFileSync('docker', ['save', '--output', archive, imageId], options);
    execFileSync('osv-scanner', ['scan', 'image', '--all-vulns', '--archive', archive], {
      ...options, stdio: ['ignore', 2, 2], cwd: temporary,
    });
    passed = true;
    if (prepareImage) console.log(imageId);
  } finally {
    // Keep the scanned tag only when the validation command needs to run it.
    if (!prepareImage || !passed) execFileSync('docker', ['image', 'rm', image], options);
  }
}

try {
  if (staged || mode === 'source') scanSource();
  if (staged || prepareImage || mode === 'image') scanImage();
  if (!staged && !prepareImage && mode !== 'source' && mode !== 'image') {
    throw new Error('Usage: node scripts/scan-dependencies.mjs source|image|prepare-image|--staged');
  }
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
