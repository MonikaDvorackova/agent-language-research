"""A minimal ordinary-Python host API baseline, independent of Core 1.

The trusted transport is simulated by appending to a list. An agent running
ordinary Python in the same process can call other effectful APIs directly.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HostValue:
    content: str
    sensitive: bool


class HostAPI:
    def __init__(self, inputs: dict[str, HostValue],
                 granted: frozenset[tuple[str, str]],
                 recipients: frozenset[str]):
        self._inputs = dict(inputs)
        self._granted = granted
        self._recipients = recipients
        self.effects: list[tuple[str, str]] = []

    def send(self, input_name: str, recipient: str) -> None:
        if input_name not in self._inputs or recipient not in self._recipients:
            raise ValueError("unknown input or recipient")
        value = self._inputs[input_name]
        if value.sensitive and (input_name, recipient) not in self._granted:
            raise PermissionError("missing matching grant")
        self.effects.append((recipient, value.content))
