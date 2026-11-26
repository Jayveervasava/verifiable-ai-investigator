import json
import os
import subprocess
import sys
import unittest
import zipfile

from ledger_test_helpers import make_ledger, run_agent, tmp_db
from vai.ledger import Ledger
from vai.ledger import standalone_verify as sv


class ExportTests(unittest.TestCase):
    def _export(self, led):
        _, d = tmp_db(self)
        z = led.export_package(d / "pkg.zip", case_id="FIR-1427/2027")
        out = d / "out"
        with zipfile.ZipFile(z) as zf:
            zf.extractall(out)
        return z, out

    def test_package_contents_and_standalone_pass(self):
        led = make_ledger(self, 7); run_agent(led)
        z, out = self._export(led)
        names = set(os.listdir(out))
        self.assertTrue({"manifest.json", "entries.jsonl", "verify_ledger.py", "README.txt",
                         "ledger.sqlite"} <= names)
        with open(out / "manifest.json") as fh:
            m = json.load(fh)
        self.assertEqual(m["entry_count"], led.count()); self.assertEqual(m["merkle_root"], led.merkle_root())
        self.assertTrue(m["chain_verified_at_export"])
        r = subprocess.run([sys.executable, str(out / "verify_ledger.py"), str(out)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr); self.assertIn("PASS", r.stdout)

    def test_standalone_detects_changes(self):
        led = make_ledger(self, 6)
        for what in ("edit", "delete", "swap", "truncate"):
            with self.subTest(what=what):
                _, out = self._export(led)
                with open(out / "entries.jsonl", encoding="utf-8") as fh:
                    lines = fh.read().splitlines()
                if what == "edit":
                    e = json.loads(lines[2]); e["payload"] = e["payload"].replace("entry", "ENTRY"); lines[2] = json.dumps(e)
                elif what == "delete": del lines[2]
                elif what == "swap": lines[1], lines[2] = lines[2], lines[1]
                else: lines = lines[:-1]
                with open(out / "entries.jsonl", "w", encoding="utf-8") as fh:
                    fh.write("\n".join(lines) + "\n")
                probs, _, _ = sv.verify(str(out))
                self.assertTrue(probs, what)

    def test_standalone_agrees_with_main_code_and_hmac(self):
        led = make_ledger(self, 5); _, out = self._export(led)
        os.environ["LEDGER_HMAC_KEY"] = "test-key-123"
        try:
            self.assertEqual(sv.verify(str(out))[0], [])
            os.environ["LEDGER_HMAC_KEY"] = "wrong"
            self.assertTrue(sv.verify(str(out))[0])
        finally:
            os.environ.pop("LEDGER_HMAC_KEY", None)

    def test_no_overwrite_without_flag_and_sqlite_copy_verifies(self):
        led = make_ledger(self, 3); z, out = self._export(led)
        with self.assertRaises(FileExistsError):
            led.export_package(z)
        copy = Ledger(str(out / "ledger.sqlite"), hmac_key="test-key-123")
        self.assertTrue(copy.verify().ok); copy.close()


if __name__ == "__main__":
    unittest.main()
