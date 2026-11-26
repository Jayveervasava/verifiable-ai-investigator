import sqlite3
import threading
import unittest
import warnings

from ledger_test_helpers import KEY, make_ledger, tmp_db
from vai.ledger import (GENESIS_HASH, Ledger, LedgerTamperedError, canonical_json, copy_db,
                        payload_hash, tamper_demo)

N = 12


class CoreTests(unittest.TestCase):
    def test_canonical_json_order_independent(self):
        self.assertEqual(canonical_json({"b": 1, "a": [1, 2]}), canonical_json({"a": [1, 2], "b": 1}))
        self.assertEqual(payload_hash({"x": 1, "y": 2}), payload_hash({"y": 2, "x": 1}))
        with self.assertRaises(TypeError):
            canonical_json({"d": object()})

    def test_chain_links_and_genesis(self):
        led = make_ledger(self, 5)
        es = led.entries()
        self.assertEqual([e.seq for e in es], [1, 2, 3, 4, 5])
        self.assertEqual(es[0].prev_hash, GENESIS_HASH)
        for a, b in zip(es, es[1:]):
            self.assertEqual(b.prev_hash, a.hash)

    def test_verify_ok_and_empty(self):
        led = make_ledger(self, N)
        r = led.verify()
        self.assertTrue(r.ok); self.assertEqual(r.checked, N); self.assertIsNone(r.broken_at)
        db, _ = tmp_db(self)
        self.assertTrue(Ledger(db, hmac_key=KEY).verify().ok)

    def test_bad_input_rejected(self):
        led = make_ledger(self, 1)
        with self.assertRaises(ValueError):
            led.append("nonsense", "a", {})
        with self.assertRaises(ValueError):
            led.append("evidence", "", {})

    def test_append_only_triggers_block_normal_sql(self):
        led = make_ledger(self, 3)
        c = sqlite3.connect(led.db)
        with self.assertRaises(sqlite3.DatabaseError):
            c.execute("UPDATE entries SET actor='x' WHERE seq=1")
        with self.assertRaises(sqlite3.DatabaseError):
            c.execute("DELETE FROM entries WHERE seq=1")
        c.close()

    def test_reopen_and_continue(self):
        led = make_ledger(self, 4)
        db = led.db
        led.close()
        led2 = Ledger(db, hmac_key=KEY)
        e = led2.append("report", "x", {"k": 1})
        self.assertEqual(e.seq, 5)
        self.assertTrue(led2.verify().ok)
        led2.close()

    def test_threads_keep_chain_valid(self):
        led = make_ledger(self, 0)
        def work(t):
            for i in range(40):
                led.append("evidence", f"t{t}", {"i": i})
        ts = [threading.Thread(target=work, args=(t,)) for t in range(4)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(led.count(), 160)
        self.assertTrue(led.verify().ok)

    def test_wrong_key_detected_and_default_key_warns(self):
        led = make_ledger(self, 3)
        other = Ledger(led.db, hmac_key="another-key")
        self.assertFalse(other.verify().ok); self.assertEqual(other.verify().broken_at, 1)
        other.close()
        db, _ = tmp_db(self)
        import os
        os.environ.pop("LEDGER_HMAC_KEY", None)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Ledger(db).close()
        self.assertTrue(any("INSECURE" in str(x.message) for x in w))

    def test_every_attack_every_position_detected(self):
        """edit/delete/insert/reorder at EVERY position, with and without chain rebuild."""
        expected_positions = {
            "edit": range(1, N + 1), "delete": range(1, N + 1),
            "insert": range(1, N + 2), "reorder": range(1, N)}
        for mode, positions in expected_positions.items():
            for recompute in (False, True):
                for seq in positions:
                    with self.subTest(mode=mode, seq=seq, recompute=recompute):
                        led = make_ledger(self, N)
                        path = copy_db(led, led.db + f".{mode}{seq}{int(recompute)}")
                        rep = tamper_demo(path, seq, mode, recompute_chain=recompute, key=KEY)
                        self.assertTrue(rep["detected"], rep)
                        self.assertEqual(rep["broken_at"], seq, rep)
        # original untouched
        self.assertTrue(make_ledger(self, N).verify().ok)

    def test_tamper_demo_on_ledger_object(self):
        led = make_ledger(self, 6)
        rep = tamper_demo(led, 3, "edit")
        self.assertTrue(rep["detected"]); self.assertEqual(led.verify().broken_at, 3)

    def test_head_catches_truncation_even_when_chain_looks_fine(self):
        led = make_ledger(self, 8)
        c = sqlite3.connect(led.db)
        c.execute("DROP TRIGGER entries_no_delete")
        c.execute("DELETE FROM entries WHERE seq>=7"); c.commit(); c.close()
        r, why = led.verify_with_reason()
        self.assertFalse(r.ok); self.assertEqual(r.broken_at, 7); self.assertIn("truncated", why)

    def test_external_anchor(self):
        led = make_ledger(self, 6)
        anchor = led.anchor()
        led.append("report", "x", {"more": 1})
        self.assertTrue(led.verify(expected_head=anchor).ok)
        other = make_ledger(self, 6)  # different timestamps -> different hashes
        self.assertFalse(other.verify(expected_head=anchor).ok)

    def test_append_refuses_tampered_ledger(self):
        led = make_ledger(self, 5)
        c = sqlite3.connect(led.db)
        c.execute("DROP TRIGGER entries_no_delete")
        c.execute("DELETE FROM entries WHERE seq=5"); c.commit(); c.close()
        with self.assertRaises(LedgerTamperedError):
            led.append("report", "x", {})


if __name__ == "__main__":
    unittest.main()
