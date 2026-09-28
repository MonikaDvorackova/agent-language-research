"""Core 2: abstract information flow through a tiny pure expression language.

Only host-supplied inputs and sequential concatenations exist. No Python
expression from the program is evaluated. Results are conditional on the host.
"""
from __future__ import annotations

from dataclasses import dataclass

from .core1 import _digest, _fields, _manifest_mac, _name, _parse
from .model import Verdict


@dataclass(frozen=True)
class AbstractValue:
    sensitive: bool
    origins: frozenset[str]


@dataclass(frozen=True)
class Core2Result:
    verdict: Verdict
    reason: str
    program_digest: str
    manifest_mac: str
    values: tuple[tuple[str, bool, tuple[str, ...]], ...]
    assumptions: tuple[str, ...]


def analyze(program_raw: str, manifest_raw: str, *, host_key: bytes) -> Core2Result:
    program = _fields(_parse(program_raw, "program"),
                      {"version", "derive", "actions"}, "program")
    manifest = _fields(_parse(manifest_raw, "manifest"),
                       {"version", "inputs", "recipients", "grants"}, "manifest")
    if type(program["version"]) is not int or program["version"] != 2:
        raise ValueError("program: expected version 2")
    if type(manifest["version"]) is not int or manifest["version"] != 2:
        raise ValueError("manifest: expected version 2")
    if not isinstance(program["derive"], list) or not isinstance(program["actions"], list):
        raise ValueError("program: expected lists of derivations and actions")
    if not isinstance(manifest["inputs"], dict) or not isinstance(manifest["grants"], dict):
        raise ValueError("manifest: expected input and grant maps")
    if not isinstance(manifest["recipients"], list):
        raise ValueError("manifest: expected recipient list")
    recipients_raw = [_name(x, "recipient") for x in manifest["recipients"]]
    if len(recipients_raw) != len(set(recipients_raw)):
        raise ValueError("manifest: duplicate recipient")
    recipients = frozenset(recipients_raw)
    values: dict[str, AbstractValue] = {}
    for name, entry in manifest["inputs"].items():
        _name(name, "input")
        item = _fields(entry, {"label", "text"}, f"input {name}")
        _name(item["text"], "input text")
        if item["label"] not in ("public", "sensitive"):
            raise ValueError(f"input {name}: invalid label")
        values[name] = AbstractValue(item["label"] == "sensitive", frozenset({name}))
    grants: dict[str, tuple[str, str]] = {}
    for name, entry in manifest["grants"].items():
        _name(name, "grant")
        item = _fields(entry, {"recipient", "value"}, f"grant {name}")
        grants[name] = (_name(item["recipient"], "grant recipient"),
                        _name(item["value"], "grant value"))
    unknown: list[str] = []
    violated: list[str] = []
    declared = set(values)
    for index, entry in enumerate(program["derive"]):
        item = _fields(entry, {"name", "concat"}, f"derivation {index}")
        name = _name(item["name"], "derived name")
        if name in declared:
            raise ValueError(f"derivation {index}: duplicate name {name}")
        declared.add(name)
        parts = item["concat"]
        if not isinstance(parts, list) or len(parts) < 2:
            raise ValueError(f"derivation {index}: concat requires at least two names")
        names = [_name(part, "concat operand") for part in parts]
        missing = [part for part in names if part not in values]
        if missing:
            unknown.append(f"derivation {index}: unresolved operands {missing}")
            continue
        operands = [values[part] for part in names]
        values[name] = AbstractValue(any(v.sensitive for v in operands),
                                     frozenset().union(*(v.origins for v in operands)))
    for index, entry in enumerate(program["actions"]):
        if isinstance(entry, dict) and set(entry) == {"send", "value", "grant"}:
            recipient = _name(entry["send"], "send recipient")
            name = _name(entry["value"], "send value")
            grant = entry["grant"]
            if grant is not None:
                _name(grant, "grant id")
            if recipient not in recipients or name not in values:
                unknown.append(f"action {index}: unresolved recipient or value")
            elif values[name].sensitive and grants.get(grant) != (recipient, name):
                violated.append(f"action {index}: sensitive {name} lacks matching grant for {recipient}")
        elif isinstance(entry, dict) and set(entry) == {"opaque"}:
            unknown.append(f"action {index}: unresolved effect {_name(entry['opaque'], 'opaque effect')}")
        else:
            raise ValueError(f"action {index}: unsupported action")
    verdict = Verdict.VIOLATED if violated else Verdict.UNKNOWN if unknown else Verdict.PROVED
    return Core2Result(verdict, "; ".join(violated or unknown) or "all modeled flows allowed",
                       _digest(program), _manifest_mac(manifest, host_key),
                       tuple(sorted((name, v.sensitive, tuple(sorted(v.origins)))
                                    for name, v in values.items())), (
                           "host labels and grants are correct and authentic",
                           "all effects are confined to checked actions",
                           "host key remains secret",
                       ))
