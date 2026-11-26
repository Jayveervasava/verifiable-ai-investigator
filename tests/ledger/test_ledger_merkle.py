import copy
import unittest

from ledger_test_helpers import make_ledger
from vai.ledger import EMPTY_ROOT, verify_proof


class MerkleTests(unittest.TestCase):
    def test_all_proofs_valid_for_many_sizes(self):
        for n in (1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 31):
            led = make_ledger(self, n)
            root = led.merkle_root()
            for seq in range(1, n + 1):
                with self.subTest(n=n, seq=seq):
                    self.assertTrue(verify_proof(led.merkle_proof(seq), root))

    def test_empty_root(self):
        led = make_ledger(self, 0)
        self.assertEqual(led.merkle_root(), EMPTY_ROOT)

    def test_invalid_proofs_rejected(self):
        led = make_ledger(self, 9)
        root = led.merkle_root()
        p = led.merkle_proof(4)
        self.assertTrue(verify_proof(p))

        def bad(fn):
            q = copy.deepcopy(p); fn(q); return verify_proof(q, root)
        self.assertFalse(bad(lambda q: q["path"][0].update(hash="00" * 32)))
        self.assertFalse(bad(lambda q: q["entry"].update(hash="11" * 32)))
        self.assertFalse(bad(lambda q: q["entry"].update(actor="someone-else")))
        self.assertFalse(bad(lambda q: q.update(root="22" * 32)))
        self.assertFalse(bad(lambda q: q["path"].pop()))
        self.assertFalse(bad(lambda q: q["entry"].update(seq=5)))  # wrong position
        self.assertFalse(bad(lambda q: q.update(tree_size=3)))
        self.assertFalse(verify_proof(p, "33" * 32))               # wrong trusted root
        self.assertFalse(verify_proof({}, root)); self.assertFalse(verify_proof(None))

    def test_root_changes_after_append_and_old_proof_fails_new_root(self):
        led = make_ledger(self, 6)
        old_root, old_proof = led.merkle_root(), led.merkle_proof(2)
        led.append("report", "x", {"new": 1})
        self.assertNotEqual(old_root, led.merkle_root())
        self.assertFalse(verify_proof(old_proof, led.merkle_root()))
        self.assertTrue(verify_proof(led.merkle_proof(2), led.merkle_root()))

    def test_missing_seq(self):
        led = make_ledger(self, 3)
        with self.assertRaises(KeyError):
            led.merkle_proof(9)


if __name__ == "__main__":
    unittest.main()
