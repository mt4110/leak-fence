import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

const source = readFileSync(new URL('../crates/core/src/lib.rs', import.meta.url), 'utf8');

function sql(name) {
  const statement = source.match(new RegExp(`^pub const ${name}: &str = "([^"]+)";`, 'm'));
  assert.ok(statement, `Missing Rust SQL constant ${name}`);
  return statement[1];
}

function budget(t) {
  const db = new DatabaseSync(':memory:');
  t.after(() => db.close());
  db.exec(sql('CREATE_BUDGET_SQL'));
  const chargeStatement = db.prepare(sql('CHARGE_SQL'));
  return {
    charge(day = 1, records = 1, bytes = 10, recordLimit = 2, byteLimit = 20) {
      const row = chargeStatement.get({ '?1': day, '?2': records, '?3': bytes, '?4': recordLimit, '?5': byteLimit });
      return row && [row.records, row.bytes];
    },
    usage() {
      const row = db.prepare('SELECT records, bytes FROM budget').get();
      return [row.records, row.bytes];
    },
  };
}

test('exact limit and rejection leave accounting intact', (t) => {
  const { charge, usage } = budget(t);
  assert.deepEqual(charge(), [1, 10]);
  assert.deepEqual(charge(), [2, 20]);
  assert.equal(charge(), undefined);
  assert.deepEqual(usage(), [2, 20]);
});

test('a new UTC day resets usage and clock rollback cannot reset it again', (t) => {
  const { charge } = budget(t);
  assert.deepEqual(charge(1, 2, 20), [2, 20]);
  assert.deepEqual(charge(2), [1, 10]);
  assert.equal(charge(1), undefined);
  assert.deepEqual(charge(2), [2, 20]);
});

test('lower limits do not clear usage', (t) => {
  const { charge, usage } = budget(t);
  assert.deepEqual(charge(), [1, 10]);
  assert.equal(charge(1, 1, 10, 1), undefined);
  assert.deepEqual(usage(), [1, 10]);
});

test('the byte limit is enforced independently of the record count', (t) => {
  const { charge } = budget(t);
  assert.deepEqual(charge(1, 0, 15), [0, 15]);
  assert.equal(charge(1, 0, 6), undefined);
  assert.deepEqual(charge(1, 0, 5), [0, 20]);
});
