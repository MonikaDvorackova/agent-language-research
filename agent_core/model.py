"""A tiny closed instruction language and a sealed effect boundary.

This is an experiment, not a production security primitive. The host owns the
model connection and issues grants; agent instructions cannot create either.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Verdict(str, Enum):
    PROVED = "PROVED"
    VIOLATED = "VIOLATED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Public:
    value: str


@dataclass(frozen=True)
class Secret:
    value: str


@dataclass(frozen=True)
class Grant:
    recipient: str
    secret_name: str


@dataclass(frozen=True)
class Send:
    recipient: str
    value_name: str
    grant_name: str | None = None


@dataclass(frozen=True)
class UnknownCall:
    description: str


Instruction = Send | UnknownCall
Value = Public | Secret


@dataclass(frozen=True)
class Finding:
    verdict: Verdict
    reason: str


def check(instructions: tuple[Instruction, ...], values: dict[str, Value],
          grants: dict[str, Grant], allowed_recipients: frozenset[str]) -> Finding:
    """Check a fixed, closed effect inventory. Violations take precedence."""
    unknown: list[str] = []
    violations: list[str] = []
    for index, instruction in enumerate(instructions):
        if isinstance(instruction, UnknownCall):
            unknown.append(f"instruction {index}: unresolved call: {instruction.description}")
            continue
        if not isinstance(instruction, Send):
            unknown.append(f"instruction {index}: unsupported instruction")
            continue
        value = values.get(instruction.value_name)
        if value is None or instruction.recipient not in allowed_recipients:
            unknown.append(f"instruction {index}: unresolved value or recipient")
            continue
        if isinstance(value, Secret):
            grant = grants.get(instruction.grant_name or "")
            if grant != Grant(instruction.recipient, instruction.value_name):
                violations.append(f"instruction {index}: sensitive {instruction.value_name} "
                                  f"sent to {instruction.recipient} without matching grant")
    if violations:
        return Finding(Verdict.VIOLATED, "; ".join(violations))
    if unknown:
        return Finding(Verdict.UNKNOWN, "; ".join(unknown))
    return Finding(Verdict.PROVED, "all modeled sends satisfy recipient-specific grants")


class ClosedHost:
    """Simulated trusted host: the only modeled external send occurs here."""

    def __init__(self, recipients: frozenset[str]):
        self._recipients = recipients
        self.effects: list[tuple[str, str]] = []

    def execute(self, instructions: tuple[Instruction, ...], values: dict[str, Value],
                grants: dict[str, Grant]) -> Finding:
        finding = check(instructions, values, grants, self._recipients)
        if finding.verdict is not Verdict.PROVED:
            return finding
        for instruction in instructions:
            assert isinstance(instruction, Send)
            self.effects.append((instruction.recipient, values[instruction.value_name].value))
        return finding
