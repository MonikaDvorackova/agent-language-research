# RFC 0: a narrow agent language core

24 September 2026. **Experimental candidate; independent of AIGov.** This is an initial language development artifact, not a claim of a novel or production-safe language. The earlier decision not to invent general-purpose syntax remains: we start with a machine-readable surface, explicit semantics and falsifiable proof obligations. The question is whether a closed agent program can carry checkable evidence that selected effects respect typed confidentiality and authority boundaries.

## Problem and differentiator to test

Existing Python analysis leaves unknown effect paths and mutable contracts; an existing typed language with a confined host might already solve the narrow problem. The candidate's proposed *research* differentiator is a first-class compilation result containing the exact host obligations on which each static verdict depends, subsequently bound to an executable effect boundary. This has **not been shown novel or necessary**. No programming language can establish honest input labeling, authentic approval or remote-service behavior by syntax alone.

## Core 0 semantics

The source is a strict JSON object with exactly `values` and `actions`. A value has `label` (`public` or `sensitive`) and `text`. An action is either `{"send": recipient, "value": name, "grant": grant_id}` or `{"opaque": description}`. The host manifest is a separate trusted input listing known `recipients` and grants whose `(recipient, value)` pair is authorized. Source programs cannot define grants. JSON is a temporary serialization, not proposed human-facing syntax.

For a `send`, a sensitive value requires an exact grant pair. A public value needs none, although Core 0 still requires a syntactic `grant` field (it may name a missing grant). Known wrong grant yields VIOLATED. An unknown recipient or value yields UNKNOWN. An `opaque` action yields UNKNOWN. A well-formed list whose every modeled action satisfies the condition yields conditional PROVED. Ill-formed or unsupported source is rejected, rather than called UNKNOWN. Within a list, observed violations have precedence over uncertainty; the earlier Python analyzer uses a different precedence convention. This difference is intentional in this small experiment and must be reconciled before merging results across tools.

`Compilation.obligations` always lists assumptions: authenticated immutable host manifest; complete mediation of external effects; trusted sensitivity labels. These are **unproved text obligations**, not a proof certificate, cryptographic attestation, or enforced runtime contract. `agent_core/compiler.py` uses the checker in `agent_core/model.py`, copied and made standalone from the earlier experiment. This does not create an independent research baseline.

Run `python -m agent_core.compiler examples/program.json examples/host.json` and `python -m unittest discover -s tests -v`.

## Falsification and milestones

1. **Core 0 (here):** deterministic strict parser and modeled confidentiality judgment. Six tests include malformed effects, source-supplied grant, wrong recipient, opaque call and a deliberate mislabeled-secret counterexample. The last compiles as PROVED; it demonstrates why the label provenance obligation is indispensable.
2. **Core 1:** define formal small-step semantics for value flow and effects, enforce closed execution by a host process with no direct network/file capability in agent code, and bind a specific immutable manifest to the program digest. Require independent review of the trusted base and negative tests for effect escape routes.
3. **Core 2:** authenticate grant issuance, bind a grant to exact value identity, recipient and purpose, and support single-use or explicit reusable authority; compare replay, crashes and concurrency. Static typing alone cannot provide exactly-once execution.
4. **Comparison gate:** implement the *same* property in a compiled existing language with a trusted host and identical adversarial cases. Measure trusted base, effect coverage, ergonomics and UNKNOWN rate. Proceed to language syntax only if Core 1–2 provide a valuable guarantee that the existing-language version cannot achieve under acceptable constraints.

## Relationship to AIGov

The language experiment concerns permitted effect requests before execution. AIGov may separately retain decisions, versioned policy context and audit evidence after or around an effect. Neither codebase needs the other; no AIGov API, dashboard, policy engine or storage is imported here. Possible interoperability is a future external adapter carrying program and manifest digests, never a premise of the language's static judgment.

## Current decision

The explicit goal is now to *develop and test a language candidate*. The present Core 0 is a deliberately small beginning. It has no demonstrated advantage over a typed host API, cannot protect mislabeled data, cannot stop direct Python I/O, and cannot vouch for a manifest. Its next gate is evidence, not branding or syntax.
