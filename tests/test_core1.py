import json
import unittest

from agent_core.core1 import analyze, simulate
from agent_core.model import Verdict


PROGRAM = {"version": 1, "actions": [{"send": "model-a", "input": "patient", "grant": "g"}]}
HOST = {"version": 1, "inputs": {"patient": {"label": "sensitive", "text": "private"}},
        "recipients": ["model-a", "model-b"],
        "grants": {"g": {"recipient": "model-a", "input": "patient"}}}


def raw(program=PROGRAM, host=HOST):
    return json.dumps(program), json.dumps(host)


class CoreOneTests(unittest.TestCase):
    def test_exact_program_runs_in_simulation(self):
        p, h = raw()
        result = analyze(p, h)
        self.assertEqual(result.verdict, Verdict.PROVED)
        self.assertEqual(simulate(p, h, result), [("model-a", "private")])

    def test_source_cannot_claim_public_label_or_issue_grant(self):
        program = {**PROGRAM, "inputs": HOST["inputs"]}
        with self.assertRaises(ValueError):
            analyze(*raw(program))
        program = {**PROGRAM, "grants": HOST["grants"]}
        with self.assertRaises(ValueError):
            analyze(*raw(program))

    def test_wrong_recipient(self):
        program = {**PROGRAM, "actions": [{"send": "model-b", "input": "patient", "grant": "g"}]}
        self.assertEqual(analyze(*raw(program)).verdict, Verdict.VIOLATED)

    def test_unknown_dispatch_and_recipient(self):
        program = {**PROGRAM, "actions": [{"opaque": "tools[name](patient)"}]}
        result = analyze(*raw(program))
        self.assertEqual(result.verdict, Verdict.UNKNOWN)
        self.assertIn("tools[name]", result.reason)
        program = {**PROGRAM, "actions": [{"send": "dynamic", "input": "patient", "grant": "g"}]}
        self.assertEqual(analyze(*raw(program)).verdict, Verdict.UNKNOWN)

    def test_program_change_invalidates_analysis(self):
        p, h = raw()
        result = analyze(p, h)
        changed = {**PROGRAM, "actions": [{"send": "model-b", "input": "patient", "grant": "g"}]}
        with self.assertRaises(ValueError):
            simulate(*raw(changed), result)

    def test_manifest_change_invalidates_analysis_even_for_public_label(self):
        p, h = raw()
        result = analyze(p, h)
        changed = {**HOST, "inputs": {"patient": {"label": "public", "text": "private"}}}
        with self.assertRaises(ValueError):
            simulate(*raw(PROGRAM, changed), result)

    def test_manifest_inaccurate_label_is_still_unchecked(self):
        host = {**HOST, "inputs": {"patient": {"label": "public", "text": "private"}}}
        result = analyze(*raw(PROGRAM, host))
        self.assertEqual(result.verdict, Verdict.PROVED)
        self.assertIn("trusted host", result.assumptions[0])

    def test_reformatting_does_not_change_canonical_digest(self):
        p, h = raw()
        self.assertEqual(analyze(p, h).program_digest,
                         analyze(json.dumps(PROGRAM, indent=4), h).program_digest)


if __name__ == "__main__":
    unittest.main()
