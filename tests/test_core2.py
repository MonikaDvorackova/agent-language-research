import json
import unittest

from agent_core.core2 import analyze
from agent_core.model import Verdict


KEY = b"research-only-fixed-key-32-bytes-minimum"
HOST = {"version": 2, "inputs": {
    "patient": {"label": "sensitive", "text": "secret"},
    "prefix": {"label": "public", "text": "case"}},
    "recipients": ["a", "b"], "grants": {"g": {"recipient": "a", "value": "message"}}}
PROGRAM = {"version": 2, "derive": [
    {"name": "message", "concat": ["prefix", "patient"]}],
    "actions": [{"send": "a", "value": "message", "grant": "g"}]}


def result(program=PROGRAM, host=HOST):
    return analyze(json.dumps(program), json.dumps(host), host_key=KEY)


class CoreTwoTests(unittest.TestCase):
    def test_sensitive_taint_and_origins(self):
        finding = result()
        self.assertEqual(finding.verdict, Verdict.PROVED)
        self.assertIn(("message", True, ("patient", "prefix")), finding.values)

    def test_derived_sensitive_requires_grant(self):
        program = {**PROGRAM, "actions": [{"send": "a", "value": "message", "grant": None}]}
        self.assertEqual(result(program).verdict, Verdict.VIOLATED)

    def test_grant_to_source_does_not_grant_derived_value(self):
        host = {**HOST, "grants": {"g": {"recipient": "a", "value": "patient"}}}
        self.assertEqual(result(host=host).verdict, Verdict.VIOLATED)

    def test_recipient_swap_rejected(self):
        program = {**PROGRAM, "actions": [{"send": "b", "value": "message", "grant": "g"}]}
        self.assertEqual(result(program).verdict, Verdict.VIOLATED)

    def test_public_only_derivation(self):
        program = {**PROGRAM, "derive": [
            {"name": "message", "concat": ["prefix", "prefix"]}]}
        self.assertEqual(result(program).verdict, Verdict.PROVED)
        self.assertIn(("message", False, ("prefix",)), result(program).values)

    def test_unknown_operand_and_effect(self):
        program = {**PROGRAM, "derive": [
            {"name": "message", "concat": ["prefix", "missing"]}]}
        self.assertEqual(result(program).verdict, Verdict.UNKNOWN)
        self.assertIn("unresolved operands", result(program).reason)
        program = {**PROGRAM, "actions": [{"opaque": "plugin.send"}]}
        self.assertEqual(result(program).verdict, Verdict.UNKNOWN)

    def test_forward_reference_unknown(self):
        program = {**PROGRAM, "derive": [
            {"name": "first", "concat": ["later", "prefix"]},
            {"name": "later", "concat": ["patient", "prefix"]}],
            "actions": [{"send": "a", "value": "first", "grant": None}]}
        self.assertEqual(result(program).verdict, Verdict.UNKNOWN)

    def test_duplicate_name_and_unsupported_branch_rejected(self):
        program = {**PROGRAM, "derive": [
            {"name": "patient", "concat": ["prefix", "prefix"]}]}
        with self.assertRaises(ValueError):
            result(program)
        program = {**PROGRAM, "derive": [
            {"name": "message", "if": "patient", "concat": ["prefix", "prefix"]}]}
        with self.assertRaises(ValueError):
            result(program)

    def test_manifest_cannot_downgrade_derived_taint_without_mislabel(self):
        for name in ("prefix", "patient"):
            host = {**HOST, "inputs": {**HOST["inputs"],
                                      name: {"label": "sensitive", "text": "x"}}}
            self.assertIn(("message", True, ("patient", "prefix")), result(host=host).values)

    def test_exhaustive_concat_label_join(self):
        for first in ("public", "sensitive"):
            for second in ("public", "sensitive"):
                host = {**HOST, "inputs": {
                    "prefix": {"label": first, "text": "x"},
                    "patient": {"label": second, "text": "y"}}}
                with self.subTest(first=first, second=second):
                    expected = first == "sensitive" or second == "sensitive"
                    self.assertIn(("message", expected, ("patient", "prefix")),
                                  result(host=host).values)

    def test_duplicate_declaration_after_unresolved_is_rejected(self):
        program = {**PROGRAM, "derive": [
            {"name": "message", "concat": ["missing", "prefix"]},
            {"name": "message", "concat": ["patient", "prefix"]}]}
        with self.assertRaises(ValueError):
            result(program)


if __name__ == "__main__":
    unittest.main()
