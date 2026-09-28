# Experiment: control dependencies can disclose data

This probe tests one narrowly scoped information-flow rule absent from Core 2. Core 2 joins sensitivity through explicit `concat` data dependencies. A branch also affects observable behavior: if a sensitive boolean decides whether a request is sent, an observer can learn the boolean from the request's presence even when the payload is public.

Minimal program in the probe's inert statement format:

```json
{
  "inputs": {"secret_flag": "sensitive", "message": "public"},
  "derive": [],
  "recipients": ["external-model"],
  "grants": [],
  "body": [
    {"if": "secret_flag",
     "then": [{"send": "external-model", "value": "message"}],
     "else": []}
  ]
}
```

The probe tracks a program-counter sensitivity label (`pc`). Entering either arm of an `if` joins the guard's label into `pc`; a send is treated as sensitive when either its payload or `pc` is sensitive. This is the standard implicit-flow idea expressed in a tiny, inert IR. `UNKNOWN` is returned for unresolved guards and dynamic recipients/values. Unsupported statements are rejected.

## Result and boundary

The test suite demonstrates that explicit data-only taint misses the branch leak and that a program-counter label detects it. Nested guards retain their source origins. A matching explicit recipient/value grant allows the modeled send, and a public guard does not taint it.

This result is deliberately narrower than a verifier for Python. The IR has no assignments inside branches, loops, exceptions, callbacks, concurrency, timing model, or value semantics. It conservatively treats a sensitive guard as potentially controlling each effect in either arm; it does not prove observational equivalence between arms. For example, identical effects in both arms may be over-reported. Its `VIOLATED` result means a modeled may-flow has been found under the probe's abstraction, not that an arbitrary Python execution trace was witnessed.

The rule is established information-flow control, not evidence of novelty. It is a small experiment in expressing that rule compositionally. Existing languages and IFC analyses can already track explicit and implicit flows. No distinctive syntax or new language is justified by this result.

Run `python -m unittest discover -s tests -q`; the six probe tests run with the existing suite.
