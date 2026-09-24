# Agent Language Research

Experimental, independent research into a small language core for verifiable AI-agent effects and information flow. This is **not** a production security product, a deployed agent system, or part of AIGov. The human-facing language syntax has not been designed.

Core 0 checks a strict JSON serialization of value labels and recipient-bound send actions against a separate host manifest. Results are `PROVED`, `VIOLATED`, or `UNKNOWN` **only under explicit host and labeling assumptions**. Malicious Python callers can bypass the host or mislabel data. See [the RFC](docs/CORE_0.md).

```sh
python -m agent_core.compiler examples/program.json examples/host.json
python -m unittest discover -s tests -v
```

Historical evidence and the original Python analyzer are in [static-agent-verification-experiment](https://github.com/MonikaDvorackova/static-agent-verification-experiment); this repository imports no code from it. The next milestone is a closed effect host and a compiled comparison with an existing typed language, not premature syntax design.

[Core 1](docs/CORE_1.md) moves labels and grants out of program source into a separate host manifest and binds an analysis to canonical input digests. This narrows one source-forgery path but does not authenticate the host, confine Python, or establish a proof certificate.

The [Core 1 semantics](docs/CORE_1_SEMANTICS.md) list the exact assumptions and a small exhaustive test matrix; an independent ordinary Python API baseline reaches the same narrow authorization check. Core 1 uses a host-secret HMAC over the manifest, because an ordinary digest of its sensitive text could reveal low-entropy data. `simulate` still allows replay and makes no network call.

[Current decision and the next research gates](docs/DECISION_RECORD.md) record the limits of the evidence and the criteria for extending the language.
