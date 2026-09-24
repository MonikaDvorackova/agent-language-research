"""Parse a tiny declarative language and type-check modeled disclosures.

The host manifest is a trusted *input* outside program source. This compiler
does not authenticate that manifest or restrict arbitrary Python effects.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from agent_core.model import Grant, Public, Secret, Send, UnknownCall, Verdict, check


@dataclass(frozen=True)
class Compilation:
    verdict: Verdict
    reason: str
    obligations: tuple[str, ...]


def _object(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label}: expected keys {sorted(keys)}")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label}: expected nonempty string")
    return value


def compile_source(source: str, host_manifest: str) -> Compilation:
    """Reject malformed source; return three-valued results for valid source."""
    def parse(raw: str) -> object:
        def unique(pairs: list[tuple[str, object]]) -> dict:
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"duplicate JSON key: {key}")
                result[key] = value
            return result

        def invalid_constant(value: str):
            raise ValueError(f"non-finite JSON constant: {value}")

        return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)

    program = _object(parse(source), {"values", "actions"}, "program")
    manifest = _object(parse(host_manifest), {"recipients", "grants"}, "host manifest")
    recipients_raw = manifest["recipients"]
    if not isinstance(recipients_raw, list) or any(not isinstance(x, str) or not x for x in recipients_raw):
        raise ValueError("host recipients: expected strings")
    recipients = frozenset(recipients_raw)
    values_raw = program["values"]
    if not isinstance(values_raw, dict):
        raise ValueError("values: expected object")
    values = {}
    for name, value in values_raw.items():
        _string(name, "value name")
        item = _object(value, {"label", "text"}, f"value {name}")
        label = item["label"]
        text = _string(item["text"], "value text")
        if label not in ("public", "sensitive"):
            raise ValueError(f"value {name}: invalid label")
        values[name] = Secret(text) if label == "sensitive" else Public(text)
    grants_raw = manifest["grants"]
    if not isinstance(grants_raw, dict):
        raise ValueError("grants: expected object")
    grants = {}
    for name, grant in grants_raw.items():
        _string(name, "grant name")
        item = _object(grant, {"recipient", "value"}, f"grant {name}")
        grants[name] = Grant(_string(item["recipient"], "grant recipient"),
                             _string(item["value"], "grant value"))
    actions_raw = program["actions"]
    if not isinstance(actions_raw, list):
        raise ValueError("actions: expected list")
    actions = []
    for index, action in enumerate(actions_raw):
        if not isinstance(action, dict):
            raise ValueError(f"action {index}: expected object")
        if set(action) == {"send", "value", "grant"}:
            actions.append(Send(_string(action["send"], "recipient"),
                                _string(action["value"], "value"),
                                _string(action["grant"], "grant")))
        elif set(action) == {"opaque"}:
            actions.append(UnknownCall(_string(action["opaque"], "opaque call")))
        else:
            raise ValueError(f"action {index}: unsupported shape")
    result = check(tuple(actions), values, grants, recipients)
    return Compilation(result.verdict, result.reason, (
        "host manifest authentic and immutable",
        "all external effects mediated by trusted host",
        "sensitive labels supplied by trusted source",
    ))


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Experimental agent core checker")
    parser.add_argument("program", type=Path)
    parser.add_argument("host_manifest", type=Path)
    args = parser.parse_args()
    result = compile_source(args.program.read_text(), args.host_manifest.read_text())
    print(json.dumps({"verdict": result.verdict.value, "reason": result.reason,
                      "assumptions": result.obligations}, indent=2))


if __name__ == "__main__":
    main()
