import unittest

from agent_core.implicit_flow import analyze
from agent_core.model import Verdict


BASE = {
    "inputs": {"secret_flag": "sensitive", "message": "public"},
    "derive": [],
    "recipients": ["external-model"],
    "grants": [],
    "body": [],
}


class ImplicitFlowTests(unittest.TestCase):
    def test_sensitive_branch_controls_external_effect_even_with_public_payload(self):
        program = {**BASE, "body": [{
            "if": "secret_flag",
            "then": [{"send": "external-model", "value": "message"}],
            "else": [],
        }]}
        result = analyze(program)
        self.assertEqual(result.verdict, Verdict.VIOLATED)
        self.assertIn("sensitive data may influence send", result.reason)
        self.assertEqual(result.origins, ("message", "secret_flag"))

    def test_public_branch_does_not_taint_public_send(self):
        program = {**BASE, "inputs": {"flag": "public", "message": "public"},
                   "body": [{"if": "flag",
                             "then": [{"send": "external-model", "value": "message"}],
                             "else": []}]}
        self.assertEqual(analyze(program).verdict, Verdict.PROVED)

    def test_matching_explicit_grant_covers_the_modeled_sensitive_flow(self):
        program = {**BASE, "grants": [{"recipient": "external-model", "value": "message"}],
                   "body": [{"if": "secret_flag",
                             "then": [{"send": "external-model", "value": "message"}],
                             "else": []}]}
        self.assertEqual(analyze(program).verdict, Verdict.PROVED)

    def test_nested_sensitive_guards_preserve_both_origins(self):
        program = {**BASE, "inputs": {"flag_a": "sensitive", "flag_b": "sensitive",
                                      "message": "public"},
                   "body": [{"if": "flag_a", "then": [{"if": "flag_b",
                       "then": [{"send": "external-model", "value": "message"}],
                       "else": []}], "else": []}]}
        result = analyze(program)
        self.assertEqual(result.verdict, Verdict.VIOLATED)
        self.assertEqual(result.origins, ("flag_a", "flag_b", "message"))

    def test_unresolved_dynamic_condition_is_unknown(self):
        program = {**BASE, "body": [{"if": "runtime_condition()",
                                     "then": [], "else": []}]}
        result = analyze(program)
        self.assertEqual(result.verdict, Verdict.UNKNOWN)
        self.assertIn("unresolved condition", result.reason)

    def test_both_branches_without_effect_have_no_observed_flow(self):
        program = {**BASE, "body": [{"if": "secret_flag", "then": [], "else": []}]}
        self.assertEqual(analyze(program).verdict, Verdict.PROVED)


if __name__ == "__main__":
    unittest.main()
