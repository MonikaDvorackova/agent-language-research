import unittest

from agent_core.model import Verdict
from comparison.python_ast_ifc import analyze_python


class PythonAstBaselineTests(unittest.TestCase):
    def test_sensitive_argument_directly_sent_is_violated(self):
        source = """\
def agent(secret: Sensitive):
    send("model", secret)
"""
        result = analyze_python(source)
        self.assertEqual(result.verdict, Verdict.VIOLATED)
        self.assertEqual(result.origins, ("secret",))

    def test_sensitive_branch_controling_public_send_is_violated(self):
        source = """\
def agent(secret_flag: Sensitive, message: Public):
    if secret_flag:
        send("model", message)
"""
        result = analyze_python(source)
        self.assertEqual(result.verdict, Verdict.VIOLATED)
        self.assertEqual(result.origins, ("message", "secret_flag"))

    def test_public_branch_and_public_payload_are_proved(self):
        source = """\
def agent(flag: Public, message: Public):
    if flag:
        send("model", message)
"""
        self.assertEqual(analyze_python(source).verdict, Verdict.PROVED)

    def test_alias_and_string_concatenation_propagate_sensitive_label(self):
        source = """\
def agent(secret: Sensitive):
    alias = secret
    joined = "prefix" + alias
    send("model", joined)
"""
        self.assertEqual(analyze_python(source).verdict, Verdict.VIOLATED)

    def test_assignment_under_sensitive_branch_remains_tainted_after_join(self):
        source = """\
def agent(secret_flag: Sensitive):
    if secret_flag:
        result = "yes"
    else:
        result = "no"
    send("model", result)
"""
        self.assertEqual(analyze_python(source).verdict, Verdict.VIOLATED)

    def test_matching_host_grant_permits_exact_recipient_and_value_name(self):
        source = """\
def agent(secret: Sensitive):
    send("model", secret)
"""
        self.assertEqual(analyze_python(
            source, grants=frozenset({("model", "secret")})).verdict, Verdict.PROVED)

    def test_unknown_dynamic_dispatch_is_unknown(self):
        source = """\
def agent(secret: Sensitive, tool: Public):
    tool.send("model", secret)
"""
        self.assertEqual(analyze_python(source).verdict, Verdict.UNKNOWN)

    def test_unknown_helper_call_is_not_assumed_pure(self):
        source = """\
def agent(secret: Sensitive):
    helper(secret)
"""
        self.assertEqual(analyze_python(source).verdict, Verdict.UNKNOWN)

    def test_unknown_decorator_forces_unknown(self):
        source = """\
@agent_wrapper
def agent(secret: Sensitive):
    send("model", secret)
"""
        self.assertEqual(analyze_python(source).verdict, Verdict.UNKNOWN)

    def test_eval_forces_unknown(self):
        source = """\
def agent(secret: Sensitive):
    eval("send('model', secret)")
"""
        self.assertEqual(analyze_python(source).verdict, Verdict.UNKNOWN)

    def test_loop_and_exception_control_flow_force_unknown(self):
        loop = """\
def agent(secret: Sensitive):
    for item in []:
        send("model", secret)
"""
        exceptional = """\
def agent(secret: Sensitive):
    try:
        send("model", secret)
    except Exception:
        pass
"""
        self.assertEqual(analyze_python(loop).verdict, Verdict.UNKNOWN)
        self.assertEqual(analyze_python(exceptional).verdict, Verdict.UNKNOWN)

    def test_nonliteral_send_recipient_is_unknown(self):
        source = """\
def agent(secret: Sensitive, destination: Public):
    send(destination, secret)
"""
        self.assertEqual(analyze_python(source).verdict, Verdict.UNKNOWN)

    def test_unresolved_program_semantics_downgrade_other_findings_to_unknown(self):
        source = """\
def agent(secret: Sensitive):
    send("model", secret)
    helper()
"""
        self.assertEqual(analyze_python(source).verdict, Verdict.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
