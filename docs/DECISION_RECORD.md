# Decision record: where language research stands

24 September 2026. Scope: an independent experiment about agent programs, separate from AIGov and from the Python static analyzer.

## Evidence obtained in this repository

- Core 0 accepts a tiny JSON serialization, returns conditional PROVED/VIOLATED/UNKNOWN, and exposes host assumptions. It is not a human-facing language.
- Core 1 moves labels and grants to a host manifest and binds the checker result to exact canonical documents. A host-secret HMAC avoids publishing a bare digest of sensitive manifest content; this is not an authentication system for the host.
- Thirty-one local unit tests pass, including a finite eight-case grant matrix, key mismatch, duplicate JSON keys, changed manifest, replay and a deliberately dishonest host label.
- An independent ordinary Python API enforces the same recipient check for calls that go through it. Other effect paths bypass it. Core 1 has the same mediation dependency; it has not shown a stronger guarantee than the baseline.

## Findings that constrain future claims

Replaying an analyzed program is still accepted. The effect list returned by `simulate` is data, not an executed network or payment operation. The host manifest may lie about a value's sensitivity. The HMAC key can be read if an adversary shares its Python process and privileges. No operating-system confinement, complete effect inventory, authenticated reviewer, formal soundness proof, or comparison against a compiled safe language exists here. `PROVED` must always be read with the three printed host assumptions.

## Next three research gates

1. Define an executable effect mediator outside the untrusted agent process and test that *all* external channels in that setting pass through it. Explicitly state the operating-system and dependency trust base. Do not call a Python wrapper a sandbox.
2. Define single-use approval in a durable transactional store, with atomic consume-and-effect or explicitly idempotent downstream operation. Test replay, concurrent use, interrupted execution and recovery. An in-memory set alone cannot establish exactly-once external effects.
3. Implement the same property and adversarial tests in a compiled existing language with a constrained effect API. Report the effect coverage, trusted base and ergonomics. Only evidence of a substantial remaining gap warrants distinctive language syntax or a new compiler.

Current recommendation: keep this repo as a narrow language research track while testing these gates. The work is meaningful as an explicit semantics and failure-boundary investigation even if the final useful artifact is a library, compiler plugin, or runtime protocol rather than a new language.
