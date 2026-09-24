import unittest

from comparison.python_api import HostAPI, HostValue


class PythonBaselineTests(unittest.TestCase):
    def setUp(self):
        self.host = HostAPI({"patient": HostValue("private", True)},
                            frozenset({("patient", "model-a")}),
                            frozenset({"model-a", "model-b"}))

    def test_valid_send(self):
        self.host.send("patient", "model-a")
        self.assertEqual(self.host.effects, [("model-a", "private")])

    def test_wrong_target_rejected(self):
        with self.assertRaises(PermissionError):
            self.host.send("patient", "model-b")
        self.assertEqual(self.host.effects, [])

    def test_arbitrary_python_bypasses_host_api(self):
        # This represents another effect channel, not an actual network send.
        independent_transport: list[tuple[str, str]] = []
        independent_transport.append(("model-b", "private"))
        self.assertEqual(self.host.effects, [])
        self.assertEqual(independent_transport, [("model-b", "private")])


if __name__ == "__main__":
    unittest.main()
