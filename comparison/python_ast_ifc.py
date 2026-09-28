"""Bounded Python-AST baseline for explicit and implicit information flow.

This is a research probe, not a whole-Python verifier. Unsupported constructs
produce UNKNOWN instead of being treated as safe.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass

from agent_core.model import Verdict


@dataclass(frozen=True)
class AstFinding:
    verdict: Verdict
    reason: str
    origins: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Value:
    sensitive: bool
    origins: frozenset[str]


def analyze_python(source: str, *, grants: frozenset[tuple[str, str]] = frozenset()) -> AstFinding:
    """Analyze one restricted function with AST, aliases, addition and branches.

    Function parameters annotated `Sensitive` or `Public` are trusted labels.
    Bare `send("recipient", value)` is the only modeled effect. `grants` is
    host-supplied and binds recipient to the syntactic variable name sent.
    """
    try:
        module = ast.parse(source)
    except SyntaxError as error:
        return AstFinding(Verdict.UNKNOWN, f"syntax could not be parsed: {error.msg}")
    functions = [node for node in module.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if len(module.body) != 1 or len(functions) != 1 or not isinstance(functions[0], ast.FunctionDef):
        return AstFinding(Verdict.UNKNOWN, "module must contain exactly one synchronous function")
    function = functions[0]
    if function.decorator_list:
        return AstFinding(Verdict.UNKNOWN, "unknown decorator may change function semantics")
    if (function.args.posonlyargs or function.args.vararg or function.args.kwarg
            or function.args.kwonlyargs or function.args.defaults):
        return AstFinding(Verdict.UNKNOWN, "unsupported dynamic/default function parameters")

    unknown: list[str] = []
    violations: list[tuple[str, frozenset[str]]] = []
    env: dict[str, _Value | None] = {}
    for arg in function.args.args:
        if isinstance(arg.annotation, ast.Name) and arg.annotation.id in ("Public", "Sensitive"):
            is_sensitive = arg.annotation.id == "Sensitive"
            env[arg.arg] = _Value(is_sensitive, frozenset({arg.arg}))
        else:
            env[arg.arg] = None
            unknown.append(f"line {arg.lineno}: parameter {arg.arg} has no recognized trusted label")

    def expression(node: ast.expr, where: str) -> _Value | None:
        if isinstance(node, ast.Name):
            if node.id not in env:
                unknown.append(f"{where}: unresolved name {node.id}")
                return None
            if env[node.id] is None:
                unknown.append(f"{where}: unknown value {node.id}")
            return env[node.id]
        if isinstance(node, ast.Constant):
            return _Value(False, frozenset())
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = expression(node.left, where), expression(node.right, where)
            if left is None or right is None:
                return None
            return _Value(left.sensitive or right.sensitive, left.origins | right.origins)
        unknown.append(f"{where}: unsupported expression {type(node).__name__}")
        return None

    def block(statements: list[ast.stmt], pc: _Value, path: str) -> None:
        for statement in statements:
            where = f"line {statement.lineno}"
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name):
                value = expression(statement.value, where)
                target = statement.targets[0].id
                env[target] = (None if value is None else
                               _Value(value.sensitive or pc.sensitive, value.origins | pc.origins))
            elif isinstance(statement, ast.If):
                condition = expression(statement.test, where)
                if condition is None:
                    # Analyze both arms under unknown control context to retain
                    # any independently provable violation; the final verdict
                    # remains UNKNOWN if no known violation is found.
                    branch_pc = _Value(True, frozenset())
                    unknown.append(f"{where}: branch condition unresolved")
                else:
                    branch_pc = _Value(pc.sensitive or condition.sensitive,
                                       pc.origins | condition.origins)
                before = dict(env)
                block(statement.body, branch_pc, path + ".then")
                then_env = dict(env)
                env.clear()
                env.update(before)
                block(statement.orelse, branch_pc, path + ".else")
                else_env = dict(env)
                env.clear()
                for name in before.keys() | then_env.keys() | else_env.keys():
                    left = then_env.get(name, before.get(name))
                    right = else_env.get(name, before.get(name))
                    if left is not None and right is not None:
                        env[name] = _Value(left.sensitive or right.sensitive,
                                           left.origins | right.origins)
                    else:
                        env[name] = None
                        if (name not in before and
                                (name in then_env or name in else_env)):
                            unknown.append(f"{where}: {name} is not assigned on every branch")
            elif isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
                call = statement.value
                if not isinstance(call.func, ast.Name) or call.func.id != "send":
                    unknown.append(f"{where}: unresolved call or dynamic dispatch")
                    continue
                if len(call.args) != 2 or call.keywords or not isinstance(call.args[0], ast.Constant) or not isinstance(call.args[0].value, str):
                    unknown.append(f"{where}: dynamic send target or unsupported arguments")
                    continue
                recipient = call.args[0].value
                payload = expression(call.args[1], where)
                if payload is None:
                    continue
                effective_sensitive = payload.sensitive or pc.sensitive
                origins = payload.origins | pc.origins
                payload_name = call.args[1].id if isinstance(call.args[1], ast.Name) else None
                if effective_sensitive and (recipient, payload_name) not in grants:
                    detail = ", ".join(sorted(origins))
                    violations.append((f"{where}: sensitive flow may reach send to {recipient}"
                                       + (f" (origins: {detail})" if detail else ""), origins))
            else:
                unknown.append(f"{where}: unsupported statement {type(statement).__name__}")

    block(function.body, _Value(False, frozenset()), function.name)
    if violations:
        return AstFinding(Verdict.VIOLATED,
                          "; ".join(message for message, _ in violations),
                          tuple(sorted(set().union(*(set(origins) for _, origins in violations)))))
    if unknown:
        return AstFinding(Verdict.UNKNOWN, "; ".join(dict.fromkeys(unknown)))
    return AstFinding(Verdict.PROVED, "no modeled sensitive data or control dependency reaches send")
