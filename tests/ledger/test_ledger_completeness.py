import unittest

from ledger_test_helpers import make_ledger, run_agent, sample_plan


def codes(led, plan):
    return {p["code"] for p in led.completeness_report(plan)}


class CompletenessTests(unittest.TestCase):
    def test_honest_run_complete(self):
        led = make_ledger(self, 2); plan = run_agent(led)
        r = led.verify_completeness(plan)
        self.assertTrue(r.ok, r.missing_steps); self.assertEqual(r.missing_steps, [])
        a = led.full_audit(plan); self.assertTrue(a["ok"])

    def test_missing_after_and_before(self):
        led = make_ledger(self, 0); plan = run_agent(led, skip_after=(2,), skip_before=(3,))
        r = led.verify_completeness(plan)
        self.assertFalse(r.ok)
        self.assertEqual(codes(led, plan), {"MISSING_AFTER", "MISSING_BEFORE"})
        self.assertEqual(len(r.missing_steps), 2); self.assertIsNotNone(r.broken_at)

    def test_unplanned_fake_step(self):
        led = make_ledger(self, 0); plan = run_agent(led)
        led.step_started(99, "delete_logs", "x", "agent"); led.step_finished(99, "delete_logs", "y", "agent")
        self.assertIn("UNPLANNED_STEP", codes(led, plan))
        self.assertFalse(led.verify_completeness(plan).ok)

    def test_wrong_tool_and_input(self):
        led = make_ledger(self, 0); plan = sample_plan()
        led.commit_plan(plan, "agent")
        led.step_started(1, "read_evidence", "bb" * 32, "agent")   # planned other input
        led.step_finished(1, "read_evidence", "o", "agent")
        led.step_started(2, "other_tool", "i", "agent"); led.step_finished(2, "other_tool", "o", "agent")
        led.step_started(3, "map_legal", "i", "agent"); led.step_finished(3, "map_legal", "o", "agent")
        c = codes(led, plan)
        self.assertIn("INPUT_MISMATCH", c); self.assertIn("TOOL_MISMATCH", c)

    def test_wrong_order(self):
        led = make_ledger(self, 0); plan = sample_plan(); led.commit_plan(plan, "agent")
        for n in (2, 1, 3):
            s = plan[n - 1]
            led.step_started(n, s["tool"], s["input_hash"] or "i", "agent")
            led.step_finished(n, s["tool"], "o", "agent")
        self.assertIn("ORDER", codes(led, plan))

    def test_after_before_before(self):
        led = make_ledger(self, 0); plan = sample_plan(); led.commit_plan(plan, "agent")
        led.step_finished(1, "read_evidence", "o", "agent")
        led.step_started(1, "read_evidence", "aa" * 32, "agent")
        self.assertIn("ORDER", codes(led, plan))

    def test_no_plan_and_late_plan(self):
        led = make_ledger(self, 0); plan = run_agent(led, commit=False)
        self.assertIn("NO_PLAN_COMMIT", codes(led, plan))
        led2 = make_ledger(self, 0); p = sample_plan()
        led2.step_started(1, "read_evidence", "aa" * 32, "agent")
        led2.commit_plan(p, "agent")
        self.assertIn("RUN_BEFORE_PLAN", codes(led2, p))

    def test_plan_changed_after_commit(self):
        led = make_ledger(self, 0); plan = run_agent(led)
        changed = plan + [{"n": 4, "tool": "extra", "input_hash": ""}]
        self.assertIn("PLAN_MISMATCH", codes(led, changed))
        self.assertTrue(led.verify_completeness(plan).ok)

    def test_second_plan_and_duplicates(self):
        led = make_ledger(self, 0); plan = run_agent(led)
        led.commit_plan(plan[:1], "agent")
        led.step_started(1, "read_evidence", "aa" * 32, "agent")
        c = codes(led, plan)
        self.assertIn("MULTIPLE_PLAN_COMMITS", c); self.assertIn("DUPLICATE_BEFORE", c)

    def test_empty_output_and_object_plan(self):
        led = make_ledger(self, 0)
        class S:  # plan items may be objects (e.g. pydantic) not only dicts
            def __init__(self, n, tool): self.n, self.tool = n, tool
        plan = [S(1, "t1")]; led.commit_plan(plan, "agent")
        led.step_started(1, "t1", "i", "agent"); led.step_finished(1, "t1", "", "agent")
        self.assertIn("EMPTY_OUTPUT", codes(led, plan))

    def test_entries_argument_and_foreign_entry(self):
        led = make_ledger(self, 3); plan = run_agent(led)
        self.assertTrue(led.verify_completeness(plan, led.entries()).ok)
        other = make_ledger(self, 3); run_agent(other)
        r = led.verify_completeness(plan, other.entries())   # different ledger's entries
        self.assertFalse(r.ok)
        self.assertTrue(any("ENTRY_MISMATCH" in m for m in r.problems))


if __name__ == "__main__":
    unittest.main()
