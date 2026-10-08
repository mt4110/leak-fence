"""Exercise the actual Rust-exported SQL with SQLite, including UTC rollover."""
from pathlib import Path
import sqlite3
import unittest

SOURCE = (Path(__file__).parents[1] / 'crates/core/src/lib.rs').read_text()
def sql(name):
    return SOURCE.split(f'pub const {name}: &str = "', 1)[1].split('";', 1)[0]

class BudgetSQL(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.execute(sql('CREATE_BUDGET_SQL'))
    def tearDown(self):
        self.db.close()
    def charge(self, day=1, records=1, size=10, max_records=2, max_bytes=20):
        return self.db.execute(sql('CHARGE_SQL'), (day, records, size, max_records, max_bytes)).fetchone()
    def test_exact_limit_and_rejection_leave_accounting_intact(self):
        self.assertEqual(self.charge(), (1, 10))
        self.assertEqual(self.charge(), (2, 20))
        self.assertIsNone(self.charge())
        self.assertEqual(self.db.execute('SELECT records, bytes FROM budget').fetchone(), (2,20))
    def test_new_day_resets_but_clock_rollback_never_resets(self):
        self.charge(records=2, size=20)
        self.assertEqual(self.charge(day=2), (1,10))
        self.assertIsNone(self.charge(day=1))
        self.assertEqual(self.charge(day=2), (2,20))
    def test_lower_limits_do_not_clear_usage(self):
        self.charge()
        self.assertIsNone(self.charge(max_records=1))
    def test_repeated_records_are_charged_and_byte_limit_is_independent(self):
        self.assertEqual(self.charge(records=0,size=15), (0,15))
        self.assertIsNone(self.charge(records=0,size=6))
        self.assertEqual(self.charge(records=0,size=5), (0,20))
