"""Adversarial cases for the deliberately closed model."""
import unittest

from agent_core.model import (ClosedHost, Grant, Public, Secret,
                                            Send, UnknownCall, Verdict, check)


class RecipientFlowTests(unittest.TestCase):
    def setUp(self):
        self.values = {"patient": Secret("private"), "summary": Public("public")}
        self.grants = {"hospital": Grant("hospital-model", "patient")}
        self.recipients = frozenset({"hospital-model", "other-model"})

    def test_matching_grant(self):
        case = (Send("hospital-model", "patient", "hospital"),)
        host = ClosedHost(self.recipients)
        self.assertEqual(host.execute(case, self.values, self.grants).verdict, Verdict.PROVED)
        self.assertEqual(host.effects, [("hospital-model", "private")])

    def test_missing_grant(self):
        self.assertEqual(check((Send("other-model", "patient"),), self.values,
                               self.grants, self.recipients).verdict, Verdict.VIOLATED)

    def test_wrong_recipient(self):
        host = ClosedHost(self.recipients)
        result = host.execute((Send("other-model", "patient", "hospital"),),
                              self.values, self.grants)
        self.assertEqual(result.verdict, Verdict.VIOLATED)
        self.assertEqual(host.effects, [])

    def test_wrong_secret(self):
        values = {**self.values, "other": Secret("another secret")}
        result = check((Send("hospital-model", "other", "hospital"),),
                       values, self.grants, self.recipients)
        self.assertEqual(result.verdict, Verdict.VIOLATED)

    def test_public_value(self):
        self.assertEqual(check((Send("other-model", "summary"),), self.values,
                               self.grants, self.recipients).verdict, Verdict.PROVED)

    def test_unresolved_dispatch(self):
        result = check((UnknownCall("tools[name](patient)"),), self.values,
                       self.grants, self.recipients)
        self.assertEqual(result.verdict, Verdict.UNKNOWN)
        self.assertIn("tools[name]", result.reason)

    def test_unresolved_recipient(self):
        self.assertEqual(check((Send("runtime-selected", "patient", "hospital"),),
                               self.values, self.grants, self.recipients).verdict,
                         Verdict.UNKNOWN)

    def test_atomic_rejection_before_effects(self):
        host = ClosedHost(self.recipients)
        result = host.execute((Send("hospital-model", "patient", "hospital"),
                               Send("other-model", "patient", "hospital")),
                              self.values, self.grants)
        self.assertEqual(result.verdict, Verdict.VIOLATED)
        self.assertEqual(host.effects, [])


if __name__ == "__main__":
    unittest.main()
