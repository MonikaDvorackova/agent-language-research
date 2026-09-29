# Research phase closure: agent-language prototype

**Status:** this bounded prototype phase is closed as of 29 September 2026. No new programming language is proposed.

## Question and answer

Can selected agent safety properties be checked or enforced before effects occur, and does the evidence require a new language?

For a narrow subset, existing techniques work: a bounded Python AST analysis can report explicit-flow and approval-policy results with `PROVED`, `VIOLATED`, or `UNKNOWN`; a separate host can validate request-bound approval and atomically record an effect intent; and OS mechanisms can block some tested network syscalls. Their guarantees depend on explicit assumptions about source coverage, labels, process isolation, host configuration, and downstream behavior.

The evidence does **not** justify a new general-purpose language or distinctive syntax. The static policies are expressible with existing taint/IFC techniques, while complete mediation depends primarily on the host and operating-system boundary. Python's dynamic features make whole-program static guarantees difficult, but the experiments do not show that a new language alone would solve the effect-mediation problem.

## Evidence completed

- The original Python analyzer and language-core prototypes cover selected explicit/implicit information-flow, recipient, and authorization rules. Unsupported or unresolved Python constructs remain `UNKNOWN`; no arbitrary-Python soundness claim is made.
- The process-boundary experiment demonstrated that an unconstrained child can bypass an ordinary broker over a raw socket. A separate seccomp probe blocked the tested socket syscalls, including after `exec`, but did not establish a complete sandbox.
- Descriptor probes showed that an inherited socket can be closed while a socket deliberately wired to stdout remains usable. Host descriptor wiring is therefore part of the trusted base.
- Landlock could not be positively exercised in this environment because the syscall returned `ENOSYS`; filesystem isolation remains untested here.
- The approval/outbox experiment verified single-use request-bound approvals, atomic host-side intent recording, rejection of replay/mismatch, and retry behavior with an idempotent fake receiver.
- The crash-recovery probe killed a child process after the fake receiver committed but before host acknowledgment. Reopening the stores and retrying resulted in one receiver effect and a delivered host intent.
- The analyzer and prototypes are research artifacts, not a production security product. There is no formal proof of the complete system, independent security review, complete effect inventory, real provider test, or deployment-grade threat-model validation.

## What remains unproved

1. Whether a real external provider durably deduplicates idempotency keys across the full retry window and rejects conflicting reuse.
2. Complete mediation of every effect channel in a production OS configuration, including filesystem, IPC, descriptors, native extensions, and child processes.
3. Soundness or useful completeness for arbitrary Python programs. Reflection, monkey patching, dynamic imports, native code, and runtime dispatch remain fundamental sources of uncertainty.
4. Whether a constrained API in an existing compiled language materially improves guarantees or usability over the host protocol and Python checks.

These are limits on claims and possible future research questions, not evidence that new syntax is required. Any continuation should first compare the host protocol against an existing typed/compiled implementation and measure effect coverage and developer burden. A new language should be reconsidered only if that comparison identifies a specific guarantee that existing static and OS techniques cannot provide.

## Decision

Close this prototype phase without designing a language. Preserve the repository as a record of narrow experiments, counterexamples, and explicit trust assumptions. Do not describe the results as complete agent verification, sandboxing, or exactly-once external execution.
