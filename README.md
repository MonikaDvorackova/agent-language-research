# Agent Language Research

Experimental, independent research into a small language core for verifiable AI-agent effects and information flow. This is **not** a production security product, a deployed agent system, or part of AIGov. The human-facing language syntax has not been designed.

Core 0 checks a strict JSON serialization of value labels and recipient-bound send actions against a separate host manifest. Results are `PROVED`, `VIOLATED`, or `UNKNOWN` **only under explicit host and labeling assumptions**. Malicious Python callers can bypass the host or mislabel data. See [the RFC](docs/CORE_0.md).

```sh
python -m agent_core.compiler examples/program.json examples/host.json
python -m unittest discover -s tests -v
```

Historical evidence and the original Python analyzer are in [static-agent-verification-experiment](https://github.com/MonikaDvorackova/static-agent-verification-experiment); this repository imports no code from it. The next milestone is a closed effect host and a compiled comparison with an existing typed language, not premature syntax design.
