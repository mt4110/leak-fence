import { spawnSync } from 'node:child_process';
const result = spawnSync(process.env.WORKER_BUILD || 'worker-build', ['--release'], {
  cwd: new URL('../crates/worker/', import.meta.url), stdio: 'inherit',
});
if (result.error) {
  process.stderr.write('worker-build 0.8.7 is required; see README.md\n');
}
process.exit(result.status ?? 1);
