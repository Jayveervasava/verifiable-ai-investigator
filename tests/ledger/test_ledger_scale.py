import time
import unittest

from ledger_test_helpers import KEY, tmp_db
from vai.ledger import Ledger, verify_proof

COUNT = 100_000


class ScaleTests(unittest.TestCase):
    def test_100k_entries_timing(self):
        db, _ = tmp_db(self)
        led = Ledger(db, hmac_key=KEY, fast=True); self.addCleanup(led.close)
        items = [("agent_step", "agent", {"phase": "after", "n": i, "output_hash": "%064x" % i})
                 for i in range(COUNT)]
        t = time.perf_counter(); led.append_many(items); t_append = time.perf_counter() - t
        t = time.perf_counter(); r = led.verify(); t_verify = time.perf_counter() - t
        self.assertTrue(r.ok); self.assertEqual(r.checked, COUNT)
        t = time.perf_counter(); root = led.merkle_root(); t_root = time.perf_counter() - t
        t = time.perf_counter(); p = led.merkle_proof(54_321); t_proof = time.perf_counter() - t
        self.assertTrue(verify_proof(p, root))
        print(f"\n100k timing: append={t_append:.2f}s verify={t_verify:.2f}s "
              f"merkle_root={t_root:.2f}s proof={t_proof:.3f}s")
        for name, v in (("append", t_append), ("verify", t_verify), ("merkle", t_root)):
            self.assertLess(v, 60, f"{name} too slow")   # generous limit: machines differ


if __name__ == "__main__":
    unittest.main()
