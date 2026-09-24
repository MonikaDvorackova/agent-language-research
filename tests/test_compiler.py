import json
import unittest

from agent_core.compiler import compile_source
from agent_core.model import Verdict


HOST = {"recipients": ["model-a", "model-b"],
        "grants": {"g": {"recipient": "model-a", "value": "secret"}}}
PROGRAM = {"values": {"secret": {"label": "sensitive", "text": "x"}},
           "actions": [{"send": "model-a", "value": "secret", "grant": "g"}]}


def compile_case(program=PROGRAM, host=HOST):
    return compile_source(json.dumps(program), json.dumps(host))


class CoreTests(unittest.TestCase):
    def test_granted(self):
        self.assertEqual(compile_case().verdict, Verdict.PROVED)
        self.assertIn("all external effects", compile_case().obligations[1])

    def test_wrong_target(self):
        program = {**PROGRAM, "actions": [{"send": "model-b", "value": "secret", "grant": "g"}]}
        self.assertEqual(compile_case(program).verdict, Verdict.VIOLATED)

    def test_unresolved_effect(self):
        program = {**PROGRAM, "actions": [{"opaque": "plugin.send(secret)"}]}
        result = compile_case(program)
        self.assertEqual(result.verdict, Verdict.UNKNOWN)
        self.assertIn("plugin.send", result.reason)

    def test_source_cannot_define_own_grant(self):
        program = {**PROGRAM, "grants": HOST["grants"]}
        with self.assertRaises(ValueError):
            compile_case(program)

    def test_unknown_action_shape_rejected(self):
        program = {**PROGRAM, "actions": [{"eval": "send(secret)"}]}
        with self.assertRaises(ValueError):
            compile_case(program)

    def test_mislabelled_secret_is_unsolved(self):
        program = {"values": {"secret": {"label": "public", "text": "x"}},
                   "actions": [{"send": "model-b", "value": "secret", "grant": "g"}]}
        self.assertEqual(compile_case(program).verdict, Verdict.PROVED)


if __name__ == "__main__":
    unittest.main()
