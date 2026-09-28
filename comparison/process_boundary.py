"""Minimal host-side effect gate used by the process-boundary experiment."""
from __future__ import annotations

from collections.abc import Callable


class EffectDenied(PermissionError):
    pass


def broker_send(recipient: str, value_name: str, payload: str, *,
                grants: frozenset[tuple[str, str]],
                transport: Callable[[str, str], None]) -> None:
    """Dispatch exactly one send if a host grant matches recipient and value."""
    if (recipient, value_name) not in grants:
        raise EffectDenied(f"no host grant for {recipient}:{value_name}")
    transport(recipient, payload)
