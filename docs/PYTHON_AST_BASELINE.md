# Python AST baseline: the same rule without a new language

This repository now contains `comparison/python_ast_ifc.py`, a deliberately bounded analyzer over Python's built-in AST. It analyzes a single synchronous function with trusted `Public`/`Sensitive` parameter labels, local aliases, string concatenation, simple assignments, `if`/`else`, and a modeled call `send("recipient", value)`. It tracks explicit data dependencies and a program-counter label for implicit control dependencies. It never executes or imports the analyzed source.

The baseline returns:

- `VIOLATED` when a modeled sensitive value or sensitive control dependency reaches a send without an exact host grant for `(recipient, syntactic value name)`;
- conditional `PROVED` when all constructs in the supported subset are modeled and no such flow is found;
- `UNKNOWN` for unsupported or unresolved constructs such as dynamic dispatch, unknown helper calls, decorators, loops, exception handling, dynamic destinations, and untrusted parameter labels.

Parameter annotations in these examples are trusted labels supplied by the analysis contract; they are not self-authenticating Python types. Sink modeling, host grants, and complete mediation remain external assumptions. This probe does not handle interprocedural flow, attribute/container aliasing, reflection, monkey patching, dynamic imports, asynchronous behavior, or the whole Python runtime.

## What the comparison establishes

The same elementary explicit-flow and program-counter rules can be implemented over ordinary Python AST. The examples demonstrate that a new language is not required for this narrow property. The AST prototype is much smaller and less complete than established analyzers; it does not show that ordinary Python can be soundly verified in general. Unsupported constructs produce `UNKNOWN` rather than a safety claim.

The primary CodeQL documentation describes local and global data-flow and taint-tracking APIs for Python. It distinguishes expression nodes from control-flow nodes and lists runtime call-target discovery and aliasing among challenges for accurate, complete data-flow graphs. That establishes that substantial Python data-flow infrastructure already exists; it does not, by itself, establish that CodeQL implements this repo's exact confidentiality/authorization policy or complete implicit-flow semantics. See [CodeQL: analyzing data flow in Python](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/) and [About data-flow analysis](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/).

Pysa documents source-to-sink taint rules, taint propagation through operations, and user-authored models. Its documentation also records false positives from broadening and false negatives from missing type information or incomplete call graphs. These are relevant engineering tradeoffs, not proof that Pysa guarantees a three-valued sound result for arbitrary programs. See [Pysa basics](https://pyre-check.org/docs/pysa-basics/) and [false positives and negatives](https://pyre-check.org/docs/pysa-false-positives-negatives/).

## Current conclusion

The experiment weakens the case for a new language. Established static-analysis techniques and ordinary Python AST are adequate for this narrow, explicitly bounded policy. The unresolved research question is whether a restricted effect language can provide a materially stronger *enforceable* guarantee by making the modeled effect set complete and preventing bypasses. That requires an isolated host/process experiment and a comparison with mature analyzers; it is not demonstrated here.

Run from the repository root: `python -m unittest discover -s tests -q` (60 tests).
