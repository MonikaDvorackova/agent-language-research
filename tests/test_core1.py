import json
import unittest

from agent_core.core1 import analyze, simulate
from agent_core.model import Verdict


KEY = b"research-only-fixed-key-32-bytes-minimum"

PROGRAM = {"version": 1, "actions": [{"send": "model-a", "input": "patient", "grant": "g"}]}
HOST = {"version": 1, "inputs": {"patient": {"label": "sensitive", "text": "private"}},
        "recipients": ["model-a", "model-b"],
        "grants": {"g": {"recipient": "model-a", "input": "patient"}}}


def raw(program=PROGRAM, host=HOST):
    return json.dumps(program), json.dumps(host)


class CoreOneTests(unittest.TestCase):
    def test_exact_program_runs_in_simulation(self):
        p, h = raw()
        result = analyze(p, h, host_key=KEY)
        self.assertEqual(result.verdict, Verdict.PROVED)
        self.assertEqual(simulate(p, h, result, host_key=KEY), [("model-a", "private")])

    def test_source_cannot_claim_public_label_or_issue_grant(self):
        program = {**PROGRAM, "inputs": HOST["inputs"]}
        with self.assertRaises(ValueError):
            analyze(*raw(program), host_key=KEY)
        program = {**PROGRAM, "grants": HOST["grants"]}
        with self.assertRaises(ValueError):
            analyze(*raw(program), host_key=KEY)

    def test_wrong_recipient(self):
        program = {**PROGRAM, "actions": [{"send": "model-b", "input": "patient", "grant": "g"}]}
        self.assertEqual(analyze(*raw(program), host_key=KEY).verdict, Verdict.VIOLATED)

    def test_unknown_dispatch_and_recipient(self):
        program = {**PROGRAM, "actions": [{"opaque": "tools[name](patient)"}]}
        result = analyze(*raw(program), host_key=KEY)
        self.assertEqual(result.verdict, Verdict.UNKNOWN)
        self.assertIn("tools[name]", result.reason)
        program = {**PROGRAM, "actions": [{"send": "dynamic", "input": "patient", "grant": "g"}]}
        self.assertEqual(analyze(*raw(program), host_key=KEY).verdict, Verdict.UNKNOWN)

    def test_program_change_invalidates_analysis(self):
        p, h = raw()
        result = analyze(p, h, host_key=KEY)
        changed = {**PROGRAM, "actions": [{"send": "model-b", "input": "patient", "grant": "g"}]}
        with self.assertRaises(ValueError):
            simulate(*raw(changed), result, host_key=KEY)

    def test_manifest_change_invalidates_analysis_even_for_public_label(self):
        p, h = raw()
        result = analyze(p, h, host_key=KEY)
        changed = {**HOST, "inputs": {"patient": {"label": "public", "text": "private"}}}
        with self.assertRaises(ValueError):
            simulate(*raw(PROGRAM, changed), result, host_key=KEY)

    def test_manifest_inaccurate_label_is_still_unchecked(self):
        host = {**HOST, "inputs": {"patient": {"label": "public", "text": "private"}}}
        result = analyze(*raw(PROGRAM, host), host_key=KEY)
        self.assertEqual(result.verdict, Verdict.PROVED)
        self.assertIn("trusted host", result.assumptions[0])

    def test_reformatting_does_not_change_canonical_digest(self):
        p, h = raw()
        self.assertEqual(analyze(p, h, host_key=KEY).program_digest,
                         analyze(json.dumps(PROGRAM, indent=4), h, host_key=KEY).program_digest)

    def test_duplicate_json_keys_rejected(self):
        p, h = raw()
        with self.assertRaisesRegex(ValueError, "duplicate key"):
            analyze('{"version":1,"version":1,"actions":[]}', h, host_key=KEY)
        with self.assertRaisesRegex(ValueError, "duplicate key"):
            analyze(p, h.replace('"label": "sensitive"',
                                 '"label": "public", "label": "sensitive"'), host_key=KEY)

    def test_host_key_is_required_and_wrong_key_rejects_analysis(self):
        p, h = raw()
        with self.assertRaises(ValueError):
            analyze(p, h, host_key=b"short")
        result = analyze(p, h, host_key=KEY)
        with self.assertRaises(ValueError):
            simulate(p, h, result, host_key=b"another-research-key-at-least-32-bytes")

    def test_analysis_object_can_be_forged_but_recheck_rejects_it(self):
        from dataclasses import replace
        p, h = raw()
        result = analyze(p, h, host_key=KEY)
        with self.assertRaises(ValueError):
            simulate(p, h, replace(result, manifest_digest="0" * 64), host_key=KEY)

    def test_replay_is_not_solved(self):
        p, h = raw()
        result = analyze(p, h, host_key=KEY)
        self.assertEqual(simulate(p, h, result, host_key=KEY),
                         simulate(p, h, result, host_key=KEY))

    def test_exhaustive_two_recipient_grant_matrix(self):
        for label in ("public", "sensitive"):
            for destination in ("model-a", "model-b"):
                for grant_target in ("model-a", "model-b"):
                    host = {**HOST,
                            "inputs": {"patient": {"label": label, "text": "private"}},
                            "grants": {"g": {"recipient": grant_target, "input": "patient"}}}
                    program = {**PROGRAM, "actions": [
                        {"send": destination, "input": "patient", "grant": "g"}]}
                    expected = (Verdict.PROVED if label == "public" or
                                destination == grant_target else Verdict.VIOLATED)
                    with self.subTest(label=label, destination=destination,
                                      grant=grant_target):
                        self.assertEqual(analyze(*raw(program, host), host_key=KEY).verdict,
                                         expected)


if __name__ == "__main__":
    unittest.main()
