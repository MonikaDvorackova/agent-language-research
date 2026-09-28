"""Research probe for implicit information flow through control dependencies.

This is a tiny inert statement language, independent of Python source parsing.
It demonstrates one classical IFC rule; it is not a Core 3 implementation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .model import Verdict


@dataclass(frozen=True)
class Finding:
    verdict: Verdict
    reason: str
    origins: tuple[str, ...] = ()


def analyze(program: dict[str, Any]) -> Finding:
    """Check sends in a restricted nested-if IR using a program-counter label.

    Each value has only a public/sensitive label and source origins. Derivations
    are immutable, sequential concatenations. Branches may contain sends and
    nested branches, but no assignments, loops, calls, or exceptions.
    """
    if set(program) != {"inputs", "derive", "body", "grants", "recipients"}:
        raise ValueError("program: unsupported top-level fields")
    inputs = program["inputs"]
    if not isinstance(inputs, dict):
        raise ValueError("inputs: expected object")

    values: dict[str, tuple[bool, frozenset[str]]] = {}
    for name, label in inputs.items():
        if not isinstance(name, str) or not name or label not in ("public", "sensitive"):
            raise ValueError("input: expected named public/sensitive label")
        values[name] = (label == "sensitive", frozenset({name}))

    for i, derivation in enumerate(program["derive"]):
        if not isinstance(derivation, dict) or set(derivation) != {"name", "concat"}:
            raise ValueError(f"derive[{i}]: unsupported derivation")
        name, args = derivation["name"], derivation["concat"]
        if not isinstance(name, str) or not name or name in values:
            raise ValueError(f"derive[{i}]: invalid or duplicate name")
        if not isinstance(args, list) or len(args) < 2 or any(a not in values for a in args):
            raise ValueError(f"derive[{i}]: unresolved concat operands")
        values[name] = (any(values[a][0] for a in args),
                        frozenset().union(*(values[a][1] for a in args)))

    recipients = program["recipients"]
    grants = program["grants"]
    if (not isinstance(recipients, list) or any(not isinstance(x, str) for x in recipients)
            or not isinstance(grants, list)):
        raise ValueError("host policy: malformed recipients or grants")
    grant_pairs = set()
    for grant in grants:
        if not isinstance(grant, dict) or set(grant) != {"recipient", "value"}:
            raise ValueError("grant: expected recipient and value")
        grant_pairs.add((grant["recipient"], grant["value"]))

    violations: list[tuple[str, frozenset[str]]] = []
    unknown: list[str] = []

    def walk(statements: object, pc_sensitive: bool, pc_origins: frozenset[str], path: str) -> None:
        if not isinstance(statements, list):
            raise ValueError(f"{path}: expected statement list")
        for index, statement in enumerate(statements):
            where = f"{path}[{index}]"
            if not isinstance(statement, dict):
                raise ValueError(f"{where}: expected statement object")
            if set(statement) == {"if", "then", "else"}:
                condition = statement["if"]
                if not isinstance(condition, str):
                    unknown.append(f"{where}: dynamic condition")
                    continue
                if condition not in values:
                    unknown.append(f"{where}: unresolved condition {condition}")
                    continue
                sensitive, origins = values[condition]
                next_origins = pc_origins | (origins if sensitive else frozenset())
                next_pc = pc_sensitive or sensitive
                walk(statement["then"], next_pc, next_origins, where + ".then")
                walk(statement["else"], next_pc, next_origins, where + ".else")
            elif set(statement) == {"send", "value"}:
                recipient, name = statement["send"], statement["value"]
                if not isinstance(recipient, str) or not isinstance(name, str):
                    unknown.append(f"{where}: dynamic recipient or value")
                    continue
                if recipient not in recipients or name not in values:
                    unknown.append(f"{where}: unresolved recipient or value")
                    continue
                value_sensitive, value_origins = values[name]
                effective_sensitive = value_sensitive or pc_sensitive
                origins = value_origins | pc_origins
                if effective_sensitive and (recipient, name) not in grant_pairs:
                    source = ", ".join(sorted(origins))
                    violations.append((
                        f"{where}: sensitive data may influence send of {name} to {recipient}"
                        + (f" (origins: {source})" if source else ""), origins))
            else:
                raise ValueError(f"{where}: unsupported statement")

    walk(program["body"], False, frozenset(), "body")
    if violations:
        return Finding(Verdict.VIOLATED, "; ".join(message for message, _ in violations),
                       tuple(sorted(set().union(*(set(origins) for _, origins in violations)))))
    if unknown:
        return Finding(Verdict.UNKNOWN, "; ".join(unknown))
    return Finding(Verdict.PROVED, "no modeled sensitive data or control dependency reaches a send")
