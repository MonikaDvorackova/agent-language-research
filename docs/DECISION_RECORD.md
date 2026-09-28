# Decision record: where language research stands

24 September 2026. Scope: an independent experiment about agent programs, separate from AIGov and from the Python static analyzer.

## Evidence obtained in this repository

- Core 0 accepts a tiny JSON serialization, returns conditional PROVED/VIOLATED/UNKNOWN, and exposes host assumptions. It is not a human-facing language.
- Core 1 moves labels and grants to a host manifest and binds the checker result to exact canonical documents. A host-secret HMAC avoids publishing a bare digest of sensitive manifest content; this is not an authentication system for the host.
- Core 2 extends the inert language with pure sequential concatenation. Its abstract values join confidentiality labels and source origins; no arbitrary expressions or branches run.
- A separate implicit-flow probe joins sensitive branch guards into a program-counter label and catches an effect whose payload is public. It is explicitly a classical IFC rule, not a Python verifier or novelty claim.
- A bounded Python AST baseline implements the same explicit-flow, alias, concatenation, branch, and authorization rules. It returns UNKNOWN for unresolved/dynamic constructs and does not claim arbitrary-Python soundness.
- A process-boundary probe confirms that a separate unconfined Python child can reach a local effect endpoint without using the host broker. Network namespace creation is denied in the current container, so isolation itself could not be tested.
- A seccomp-BPF launcher blocks socket creation in a Python child and its subprocess after `exec`, while leaving stdin/stdout pipes available. This tests one syscall class only; filesystem and other effects remain open, and kernel documentation explicitly says seccomp filtering alone is not a sandbox.
- The same launcher has an optional Landlock write restriction and a combined probe. Landlock syscall discovery returns `ENOSYS` in this container, despite the kernel headers being present, so the positive filesystem restriction test is skipped; no filesystem isolation result is claimed.
- Descriptor probes confirm that the launcher closes an inherited socket above fd 2, but a socket deliberately wired to stdout remains writable. This makes the trusted host's stdio wiring an explicit part of the mediation assumption.
- Sixty-eight local unit tests are collected, including grant and flow cases, thirteen Python AST baseline cases, broker allow/deny, subprocess bypass, seccomp, descriptor-boundary, and combined seccomp/Landlock probes. Sixty-seven pass and the Landlock positive probe is skipped in this environment.
- An independent ordinary Python API enforces the same recipient check for calls that go through it. Other effect paths bypass it. Core 1 has the same mediation dependency; it has not shown a stronger guarantee than the baseline.

## Findings that constrain future claims

The bounded Python AST experiment reproduces the narrow policy without a new language. CodeQL and Pysa already provide substantial Python data-flow/taint analysis frameworks, with documented tradeoffs around call-graph resolution, modeling, false positives and false negatives. No evidence currently shows that new syntax is necessary for these source-to-sink and control-dependence rules.

The process experiment shows that complete mediation is an operating-system and deployment property. A separate process without namespace confinement remains able to perform a direct socket effect. This is a counterexample to treating a broker wrapper or subprocess as a security boundary; it does not show that a suitably confined runtime is impossible.

The seccomp probe demonstrates an existing host-side mechanism to block the tested socket path while preserving pipe IPC. This weakens any claim that new language syntax is necessary to forbid direct network syscalls. Complete effect mediation remains unproved because the child retains filesystem and other system effects.

The follow-up attempted to pair seccomp with Landlock filesystem write restrictions. The current execution environment reports `ENOSYS` for `landlock_create_ruleset`, so the combined positive result could not be tested. This is an environment limitation, not evidence that Landlock itself is unavailable on Linux generally. The launcher and conditional test are retained so a Landlock-enabled host can produce the missing measurement.

Replaying an analyzed program is still accepted. The effect list returned by `simulate` is data, not an executed network or payment operation. The host manifest may lie about a value's sensitivity. The HMAC key can be read if an adversary shares its Python process and privileges. No operating-system confinement, complete effect inventory, authenticated reviewer, formal soundness proof, or comparison against a compiled safe language exists here. `PROVED` must always be read with the three printed host assumptions.

## Next three research gates

1. Define an executable effect mediator outside the untrusted agent process and test that *all* external channels in that setting pass through it. Explicitly state the operating-system and dependency trust base. Do not call a Python wrapper a sandbox.
2. Define single-use approval in a durable transactional store, with atomic consume-and-effect or explicitly idempotent downstream operation. Test replay, concurrent use, interrupted execution and recovery. An in-memory set alone cannot establish exactly-once external effects.
3. Implement the same property and adversarial tests in a compiled existing language with a constrained effect API. Report the effect coverage, trusted base and ergonomics. Only evidence of a substantial remaining gap warrants distinctive language syntax or a new compiler.

Current recommendation: keep this repo as a narrow language research track while testing these gates. The work is meaningful as an explicit semantics and failure-boundary investigation even if the final useful artifact is a library, compiler plugin, or runtime protocol rather than a new language.
