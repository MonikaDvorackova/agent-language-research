"""Core 1: host-supplied labels and grants, with a bound analysis result.

This checks an inert JSON program. It does not confine arbitrary Python code,
authenticate the host, or prove remote effects. All effects are simulated.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

from .model import Grant, Public, Secret, Send, UnknownCall, Verdict, check


@dataclass(frozen=True)
class Analysis:
    verdict: Verdict
    reason: str
    program_digest: str
    manifest_digest: str
    assumptions: tuple[str, ...]


def _parse(raw: str, label: str) -> dict:
    def unique(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, entry in pairs:
            if key in result:
                raise ValueError(f"{label}: duplicate key {key}")
            result[key] = entry
        return result

    def reject_constant(value: str):
        raise ValueError(f"{label}: non-finite JSON constant {value}")

    value = json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)
    if not isinstance(value, dict):
        raise ValueError(f"{label}: expected object")
    return value


def _fields(value: object, expected: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{label}: expected exactly {sorted(expected)}")
    return value


def _name(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label}: expected nonempty string")
    return value


def _digest(value: dict) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _manifest_mac(value: dict, host_key: bytes) -> str:
    if not isinstance(host_key, bytes) or len(host_key) < 32:
        raise ValueError("host_key: expected at least 32 secret bytes")
    return hmac.new(host_key, _canonical(value), hashlib.sha256).hexdigest()


def _decode(program_raw: str, manifest_raw: str):
    program = _fields(_parse(program_raw, "program"), {"version", "actions"}, "program")
    manifest = _fields(_parse(manifest_raw, "manifest"),
                       {"version", "inputs", "recipients", "grants"}, "manifest")
    if type(program["version"]) is not int or program["version"] != 1:
        raise ValueError("program: unsupported version")
    if type(manifest["version"]) is not int or manifest["version"] != 1:
        raise ValueError("manifest: unsupported version")
    if not isinstance(program["actions"], list):
        raise ValueError("actions: expected list")
    if not isinstance(manifest["inputs"], dict) or not isinstance(manifest["grants"], dict):
        raise ValueError("manifest: expected input and grant maps")
    if not isinstance(manifest["recipients"], list):
        raise ValueError("recipients: expected list")
    recipients = frozenset(_name(x, "recipient") for x in manifest["recipients"])
    if len(recipients) != len(manifest["recipients"]):
        raise ValueError("recipients: duplicates")
    values = {}
    for key, entry in manifest["inputs"].items():
        _name(key, "input name")
        item = _fields(entry, {"label", "text"}, "input")
        content = _name(item["text"], "input text")
        if item["label"] == "sensitive":
            values[key] = Secret(content)
        elif item["label"] == "public":
            values[key] = Public(content)
        else:
            raise ValueError("input: invalid label")
    grants = {}
    for key, entry in manifest["grants"].items():
        _name(key, "grant id")
        item = _fields(entry, {"recipient", "input"}, "grant")
        grants[key] = Grant(_name(item["recipient"], "grant recipient"),
                            _name(item["input"], "grant input"))
    actions = []
    for index, entry in enumerate(program["actions"]):
        if isinstance(entry, dict) and set(entry) == {"send", "input", "grant"}:
            grant = entry["grant"]
            if grant is not None:
                _name(grant, "grant id")
            actions.append(Send(_name(entry["send"], "send recipient"),
                                _name(entry["input"], "send input"), grant))
        elif isinstance(entry, dict) and set(entry) == {"opaque"}:
            actions.append(UnknownCall(_name(entry["opaque"], "opaque call")))
        else:
            raise ValueError(f"action {index}: unsupported shape")
    return program, manifest, tuple(actions), values, grants, recipients


def analyze(program_raw: str, manifest_raw: str, *, host_key: bytes) -> Analysis:
    """A PROVED result remains conditional on independent host obligations."""
    program, manifest, actions, values, grants, recipients = _decode(program_raw, manifest_raw)
    result = check(actions, values, grants, recipients)
    return Analysis(result.verdict, result.reason, _digest(program), _manifest_mac(manifest, host_key), (
        "manifest and sensitivity labels issued by trusted host",
        "host signing key remains secret and manifest is unchanged before execution",
        "agent has no unmediated external effect paths",
    ))


def simulate(program_raw: str, manifest_raw: str, prior: Analysis, *,
             host_key: bytes) -> list[tuple[str, str]]:
    """Preflight again and simulate sends; never trust a supplied verdict alone."""
    current = analyze(program_raw, manifest_raw, host_key=host_key)
    if current != prior or current.verdict is not Verdict.PROVED:
        raise ValueError("analysis does not authorize this exact program and host manifest")
    _, _, actions, values, _, _ = _decode(program_raw, manifest_raw)
    return [(action.recipient, values[action.value_name].value)
            for action in actions if isinstance(action, Send)]
