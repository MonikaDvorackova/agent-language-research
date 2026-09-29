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

[Core 2](docs/CORE_2.md) adds a pure `concat` derivation, sensitivity joins and source-origin sets. It rejects unsupported branching and returns UNKNOWN for unresolved sources; it does not execute external sends.

[An implicit-flow probe](docs/IMPLICIT_FLOW_PROBE.md) separately demonstrates how a sensitive branch can influence a public send. It is a small classical IFC experiment, not a Python verifier or a novelty claim.

[Python AST baseline](docs/PYTHON_AST_BASELINE.md) implements the same bounded explicit and implicit flow rules directly over Python's AST. Its purpose is to test whether a new language is needed for this narrow property; unsupported Python constructs return UNKNOWN.

[The process-boundary experiment](docs/PROCESS_BOUNDARY_EXPERIMENT.md) shows that a separate Python subprocess can bypass a broker through a raw loopback socket. Network namespace isolation was unavailable in this execution container, so complete mediation remains unproved.

[A narrower seccomp probe](docs/SECCOMP_NETWORK_FILTER_EXPERIMENT.md) blocks socket syscalls in a child while preserving its stdin/stdout broker pipe. It is one OS-level restriction, not a sandbox or a complete mediation proof.

[A seccomp + Landlock probe](docs/SECCOMP_LANDLOCK_PROBE.md) attempts to limit writes to a workspace. The current execution container returns `ENOSYS` for Landlock, so the positive filesystem restriction test is skipped here and no filesystem isolation result is claimed.

[The single-use approval probe](docs/APPROVAL_TRANSACTION_PROBE.md) records an authorized effect intent atomically with consuming its approval in SQLite. A [process crash-recovery probe](docs/PROCESS_CRASH_RECOVERY_PROBE.md) kills a child after a fake receiver commits and before the host records delivery; retry yields one local fake effect under the receiver's durable idempotency assumption. Neither executes a real external action or establishes exactly-once delivery by a provider.

The current bounded research phase is [closed](docs/RESEARCH_CLOSURE.md). Its evidence does not justify designing a new programming language. It identifies unresolved OS mediation and provider-contract questions, plus a future comparison against an existing compiled language, as separate research questions.
