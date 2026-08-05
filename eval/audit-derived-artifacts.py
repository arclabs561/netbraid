#!/usr/bin/env python3
"""Audit ignored derived artifacts without reading their contents."""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shlex
import stat
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA = "netbraid.derived_artifact_contract.v0"
REPORT_SCHEMA = "netbraid.derived_artifact_audit.v0"
DEFAULT_CONTRACT = PurePosixPath("eval/derived-artifact-contract-v0.json")
DEFAULT_JUSTFILE = PurePosixPath("justfile")
CONTRACT_KEYS = frozenset({"schema", "derived_root", "artifacts"})
COMMON_ARTIFACT_KEYS = frozenset({"path", "format", "retention"})
SCRIPTED_ARTIFACT_KEYS = COMMON_ARTIFACT_KEYS | {"producer", "recipe"}
FORMATS = frozenset({"cap", "json", "npy", "tsv"})
SCRIPTED_RETENTION = "reproducibility_output"
REPORT_RETENTIONS = frozenset({"legacy/unknown", SCRIPTED_RETENTION})
RECIPE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*\Z")
PYTHON_COMMAND = re.compile(r"python(?:\d+(?:\.\d+)*)?\Z")
WINDOWS_ABSOLUTE = re.compile(r"[A-Za-z]:[\\/]")
PRIVATE_PATH_FRAGMENT = re.compile(
    r"(?:^|[/\\])(?:Users|home|private|Volumes)(?:[/\\])"
)
MAX_CONTRACT_BYTES = 1024 * 1024
MAX_JUSTFILE_BYTES = 2 * 1024 * 1024
MAX_PRODUCER_BYTES = 4 * 1024 * 1024
MAX_TRACKED_BYTES = 16 * 1024 * 1024
MAX_ARTIFACTS = 512
MAX_DIRECTORIES = 128
MAX_PATH_BYTES = 512
MAX_REPORT_BYTES = 16 * 1024


@dataclass(frozen=True)
class ScriptedArtifact:
    path: str
    format: str
    retention: str
    producer: str
    recipe: str


@dataclass(frozen=True)
class Contract:
    derived_root: str
    artifacts: tuple[ScriptedArtifact, ...]
    declared_entries: int


@dataclass(frozen=True)
class ProducerEvidence:
    output_literals: frozenset[str]
    output_options: frozenset[str]
    has_entrypoint: bool


@dataclass(frozen=True)
class _Sources:
    literals: frozenset[str] = frozenset()
    options: frozenset[str] = frozenset()
    attributes: tuple[tuple[str, _Sources], ...] = ()

    def attribute(self, name: str) -> _Sources:
        for attribute_name, sources in self.attributes:
            if attribute_name == name:
                return sources
        return _Sources(self.literals, self.options)


class AuditInputError(Exception):
    """A bounded, path-free error suitable for the aggregate report."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _relative_path(value: str) -> PurePosixPath | None:
    if (
        not value
        or len(value.encode("utf-8")) > MAX_PATH_BYTES
        or value.startswith(("/", "\\", "~"))
        or "\\" in value
        or WINDOWS_ABSOLUTE.match(value)
    ):
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    return path


def _contains_private_path(value: Any) -> int:
    if isinstance(value, str):
        return int(
            value.startswith(("/", "\\", "~"))
            or bool(WINDOWS_ABSOLUTE.match(value))
            or bool(PRIVATE_PATH_FRAGMENT.search(value))
        )
    if isinstance(value, list):
        return sum(_contains_private_path(item) for item in value)
    if isinstance(value, dict):
        return sum(
            _contains_private_path(key) + _contains_private_path(item)
            for key, item in value.items()
        )
    return 0


def _safe_file_path(root: Path, relative: PurePosixPath) -> Path | None:
    current = root
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            metadata = current.lstat()
        except OSError:
            return None
        final = index == len(relative.parts) - 1
        if stat.S_ISLNK(metadata.st_mode):
            return None
        if final:
            if not stat.S_ISREG(metadata.st_mode):
                return None
        elif not stat.S_ISDIR(metadata.st_mode):
            return None
    return current


def _read_bounded_file(
    root: Path, relative: PurePosixPath, limit: int, code: str
) -> str:
    path = _safe_file_path(root, relative)
    if path is None:
        raise AuditInputError(code)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise AuditInputError(code) from error
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise AuditInputError(code)
        payload = source.read(limit + 1)
    if len(payload) > limit:
        raise AuditInputError(code)
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AuditInputError(code) from error


def _load_contract(
    root: Path, relative: PurePosixPath, errors: Counter[str]
) -> Contract:
    try:
        text = _read_bounded_file(root, relative, MAX_CONTRACT_BYTES, "unsafe_contract")
        value = json.loads(text)
    except json.JSONDecodeError:
        errors["invalid_contract_json"] += 1
        return Contract("", (), 0)
    except AuditInputError as error:
        errors[error.code] += 1
        return Contract("", (), 0)

    private_values = _contains_private_path(value)
    if private_values:
        errors["private_or_absolute_contract_path"] += private_values
    if not isinstance(value, dict):
        errors["invalid_contract_schema"] += 1
        return Contract("", (), 0)
    if set(value) != CONTRACT_KEYS or value.get("schema") != SCHEMA:
        errors["invalid_contract_schema"] += 1

    raw_root = value.get("derived_root")
    root_path = _relative_path(raw_root) if isinstance(raw_root, str) else None
    if root_path is None:
        errors["invalid_derived_root"] += 1
        derived_root = ""
    else:
        derived_root = root_path.as_posix()

    raw_artifacts = value.get("artifacts")
    if not isinstance(raw_artifacts, list) or len(raw_artifacts) > MAX_ARTIFACTS:
        errors["invalid_contract_schema"] += 1
        return Contract(derived_root, (), 0)

    artifacts: list[ScriptedArtifact] = []
    seen: set[str] = set()
    for raw in raw_artifacts:
        if not isinstance(raw, dict):
            errors["invalid_contract_entry"] += 1
            continue
        retention = raw.get("retention")
        if retention != SCRIPTED_RETENTION:
            errors["invalid_retention"] += 1
            continue
        expected_keys = SCRIPTED_ARTIFACT_KEYS
        if set(raw) != expected_keys or not all(
            isinstance(raw[key], str) for key in expected_keys
        ):
            errors["invalid_contract_entry"] += 1
            continue

        artifact_path = _relative_path(raw["path"])
        valid = True
        if artifact_path is None or root_path is None:
            errors["invalid_artifact_path"] += 1
            valid = False
        elif artifact_path.parts[: len(root_path.parts)] != root_path.parts or len(
            artifact_path.parts
        ) <= len(root_path.parts):
            errors["artifact_outside_derived_root"] += 1
            valid = False
        if raw["format"] not in FORMATS:
            errors["invalid_artifact_format"] += 1
            valid = False
        elif artifact_path is not None and artifact_path.suffix != f".{raw['format']}":
            errors["artifact_format_mismatch"] += 1
            valid = False
        normalized = (
            artifact_path.as_posix() if artifact_path is not None else raw["path"]
        )
        if normalized in seen:
            errors["duplicate_contract_entry"] += 1
            valid = False
        seen.add(normalized)

        producer_path = _relative_path(raw["producer"])
        if producer_path is None or producer_path.suffix != ".py":
            errors["invalid_producer_path"] += 1
            valid = False
        if RECIPE_NAME.fullmatch(raw["recipe"]) is None:
            errors["invalid_recipe_name"] += 1
            valid = False
        if valid and producer_path is not None:
            artifacts.append(
                ScriptedArtifact(
                    path=normalized,
                    format=raw["format"],
                    retention=retention,
                    producer=producer_path.as_posix(),
                    recipe=raw["recipe"],
                )
            )
    return Contract(derived_root, tuple(artifacts), len(raw_artifacts))


def _parse_justfile(text: str, errors: Counter[str]) -> dict[str, tuple[str, ...]]:
    recipes: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        if line[:1].isspace():
            command = line.strip()
            if current is not None and command and not command.startswith("#"):
                recipes[current].append(command)
            continue
        current = None
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "[")) or ":=" in line:
            continue
        header, separator, _dependencies = line.partition(":")
        if not separator:
            continue
        name = header.split(maxsplit=1)[0]
        if RECIPE_NAME.fullmatch(name) is None:
            continue
        if name in recipes:
            errors["duplicate_recipe_definition"] += 1
            continue
        recipes[name] = []
        current = name
    return {name: tuple(commands) for name, commands in recipes.items()}


def _shell_tokens(command: str) -> tuple[str, ...] | None:
    command = command.lstrip("@-+")
    try:
        return tuple(shlex.split(command, comments=True, posix=True))
    except ValueError:
        return None


def _python_script_index(tokens: tuple[str, ...]) -> int | None:
    if not tokens:
        return None
    executable = PurePosixPath(tokens[0]).name
    if PYTHON_COMMAND.fullmatch(executable):
        return 1
    if len(tokens) >= 3 and tokens[:3] == ("{{", "python", "}}"):
        return 3
    if tokens[0].replace(" ", "") == "{{python}}":
        return 1
    return None


def _producer_invocation_tokens(command: str, producer: str) -> tuple[str, ...] | None:
    tokens = _shell_tokens(command)
    if tokens is None:
        return None
    script_index = _python_script_index(tokens)
    if script_index is not None:
        if len(tokens) > script_index and tokens[script_index] == producer:
            return tokens
        return None
    if len(tokens) < 3 or tokens[:2] != ("uv", "run"):
        return None
    if tokens[2] == "--script":
        if len(tokens) > 3 and tokens[3] == producer:
            return tokens
        return None
    nested_index = _python_script_index(tokens[2:])
    if nested_index is not None:
        absolute_index = 2 + nested_index
        if len(tokens) > absolute_index and tokens[absolute_index] == producer:
            return tokens
        return None
    return tokens if tokens[2] == producer else None


def _token_declares_output(
    token: str, artifact: str, *, directory_option: bool = False
) -> bool:
    basename = PurePosixPath(artifact).name
    token_name = PurePosixPath(token).name
    if token == artifact or token_name == basename:
        return True
    return directory_option and token_name == PurePosixPath(artifact).parent.name


def _invocation_declares_output(
    tokens: tuple[str, ...], artifact: str, output_options: frozenset[str]
) -> bool:
    for index, token in enumerate(tokens):
        option, separator, inline_value = token.partition("=")
        if option not in output_options:
            continue
        directory_option = option.replace("_", "-").endswith("-dir")
        if separator and _token_declares_output(
            inline_value, artifact, directory_option=directory_option
        ):
            return True
        for candidate in tokens[index + 1 :]:
            if candidate.startswith("-"):
                break
            if _token_declares_output(
                candidate, artifact, directory_option=directory_option
            ):
                return True
    return False


def _is_main_guard(node: ast.AST) -> bool:
    if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
        return False
    comparison = node.test
    if len(comparison.ops) != 1 or not isinstance(comparison.ops[0], ast.Eq):
        return False
    if len(comparison.comparators) != 1:
        return False
    operands = (comparison.left, comparison.comparators[0])
    has_name = any(
        isinstance(operand, ast.Name) and operand.id == "__name__"
        for operand in operands
    )
    has_main = any(
        isinstance(operand, ast.Constant) and operand.value == "__main__"
        for operand in operands
    )
    return (
        has_name
        and has_main
        and any(
            isinstance(descendant, ast.Call)
            for statement in node.body
            for descendant in ast.walk(statement)
        )
    )


def _merge_sources(*values: _Sources) -> _Sources:
    attributes: dict[str, _Sources] = {}
    for value in values:
        for name, sources in value.attributes:
            attributes[name] = _merge_sources(attributes.get(name, _Sources()), sources)
    return _Sources(
        literals=frozenset().union(*(value.literals for value in values)),
        options=frozenset().union(*(value.options for value in values)),
        attributes=tuple(sorted(attributes.items())),
    )


class _ProducerAnalyzer:
    def __init__(self, tree: ast.Module):
        self.functions = {
            node.name: node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.module_sources: dict[str, _Sources] = {}
        self.output_sources = _Sources()
        self.active_functions: set[str] = set()
        self._load_module_sources(tree)

    def _load_module_sources(self, tree: ast.Module) -> None:
        assignments = [
            node for node in tree.body if isinstance(node, (ast.Assign, ast.AnnAssign))
        ]
        for _ in range(len(assignments) + 1):
            before = dict(self.module_sources)
            for statement in assignments:
                value = self._expression(statement.value, self.module_sources, False)
                targets = (
                    statement.targets
                    if isinstance(statement, ast.Assign)
                    else [statement.target]
                )
                for target in targets:
                    self._assign(target, value, self.module_sources)
            if self.module_sources == before:
                break

    def _argparse_namespace(self, function: ast.AST) -> _Sources:
        attributes: dict[str, _Sources] = {}
        for node in ast.walk(function):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_argument"
            ):
                continue
            names = [
                argument.value
                for argument in node.args
                if isinstance(argument, ast.Constant)
                and isinstance(argument.value, str)
            ]
            destination = next(
                (
                    keyword.value.value
                    for keyword in node.keywords
                    if keyword.arg == "dest"
                    and isinstance(keyword.value, ast.Constant)
                    and isinstance(keyword.value.value, str)
                ),
                None,
            )
            if destination is None:
                option = next((name for name in names if name.startswith("--")), None)
                destination = (option or (names[0] if names else "")).lstrip("-")
                destination = destination.replace("-", "_")
            if not destination:
                continue
            default = next(
                (
                    keyword.value
                    for keyword in node.keywords
                    if keyword.arg == "default"
                ),
                None,
            )
            default_sources = (
                self._expression(default, self.module_sources, False)
                if default is not None
                else _Sources()
            )
            option_sources = _Sources(
                options=frozenset(name for name in names if name.startswith("-"))
            )
            attributes[destination] = _merge_sources(
                attributes.get(destination, _Sources()),
                default_sources,
                option_sources,
            )
        return _Sources(attributes=tuple(sorted(attributes.items())))

    def _assign(
        self, target: ast.AST, value: _Sources, environment: dict[str, _Sources]
    ) -> None:
        if isinstance(target, ast.Name):
            environment[target.id] = _merge_sources(
                environment.get(target.id, _Sources()), value
            )
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._assign(element, value, environment)

    def _record_output(self, sources: _Sources) -> None:
        self.output_sources = _merge_sources(self.output_sources, sources)

    @staticmethod
    def _write_mode(call: ast.Call, *, method: bool) -> bool:
        mode_node = next(
            (keyword.value for keyword in call.keywords if keyword.arg == "mode"), None
        )
        index = 0 if method else 1
        if mode_node is None and len(call.args) > index:
            mode_node = call.args[index]
        return (
            isinstance(mode_node, ast.Constant)
            and isinstance(mode_node.value, str)
            and any(flag in mode_node.value for flag in "wax+")
        )

    def _call(
        self, call: ast.Call, environment: dict[str, _Sources], follow_calls: bool
    ) -> _Sources:
        receiver = (
            self._expression(call.func.value, environment, follow_calls)
            if isinstance(call.func, ast.Attribute)
            else _Sources()
        )
        arguments = [
            self._expression(argument, environment, follow_calls)
            for argument in call.args
        ]
        keywords = {
            keyword.arg: self._expression(keyword.value, environment, follow_calls)
            for keyword in call.keywords
            if keyword.arg is not None
        }
        name = call.func.attr if isinstance(call.func, ast.Attribute) else None

        if follow_calls and isinstance(call.func, ast.Name):
            function = self.functions.get(call.func.id)
            if function is not None:
                returned = self._function(call.func.id, arguments, keywords)
                namespace = self._argparse_namespace(function)
                return _merge_sources(returned, namespace)

        if name in {"write_text", "write_bytes", "touch"}:
            self._record_output(receiver)
        elif name in {"write", "writelines", "writerow", "writerows"}:
            self._record_output(receiver)
        elif name == "open" and self._write_mode(call, method=True):
            self._record_output(receiver)
        elif (
            isinstance(call.func, ast.Name)
            and call.func.id == "open"
            and self._write_mode(call, method=False)
            and arguments
        ):
            self._record_output(arguments[0])
        elif (
            name in {"replace", "rename"}
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "os"
            and len(arguments) >= 2
        ):
            self._record_output(arguments[1])
        elif name == "replace" and arguments:
            self._record_output(arguments[0])
        elif name in {"copy", "copy2", "copyfile", "move"} and len(arguments) >= 2:
            self._record_output(arguments[1])
        elif name in {"save", "savez", "savez_compressed", "savetxt"} and arguments:
            self._record_output(arguments[0])
        elif name == "dump" and len(arguments) >= 2:
            self._record_output(arguments[1])
        elif (
            name is not None
            and name.startswith("write_")
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id.isupper()
            and arguments
        ):
            self._record_output(arguments[0])

        return _merge_sources(receiver, *arguments, *keywords.values())

    def _expression(
        self, node: ast.AST | None, environment: dict[str, _Sources], follow_calls: bool
    ) -> _Sources:
        if node is None:
            return _Sources()
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return _Sources(literals=frozenset({node.value}))
        if isinstance(node, ast.Name):
            return environment.get(node.id, _Sources())
        if isinstance(node, ast.Attribute):
            return self._expression(node.value, environment, follow_calls).attribute(
                node.attr
            )
        if isinstance(node, ast.Call):
            return self._call(node, environment, follow_calls)
        if isinstance(node, ast.NamedExpr):
            value = self._expression(node.value, environment, follow_calls)
            self._assign(node.target, value, environment)
            return value
        children: list[ast.AST] = []
        if isinstance(node, ast.BinOp):
            children = [node.left, node.right]
        elif isinstance(node, ast.IfExp):
            children = [node.test, node.body, node.orelse]
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            children = list(node.elts)
        elif isinstance(node, ast.Dict):
            children = [*filter(None, node.keys), *node.values]
        elif isinstance(node, ast.JoinedStr):
            children = list(node.values)
        elif isinstance(node, ast.FormattedValue):
            children = [node.value]
        elif isinstance(node, ast.Subscript):
            children = [node.value, node.slice]
        elif isinstance(node, (ast.BoolOp, ast.Compare)):
            children = list(ast.iter_child_nodes(node))
        return _merge_sources(
            *(self._expression(child, environment, follow_calls) for child in children)
        )

    def _block(
        self, statements: list[ast.stmt], environment: dict[str, _Sources]
    ) -> _Sources:
        returned = _Sources()
        for statement in statements:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = self._expression(statement.value, environment, True)
                targets = (
                    statement.targets
                    if isinstance(statement, ast.Assign)
                    else [statement.target]
                )
                for target in targets:
                    self._assign(target, value, environment)
            elif isinstance(statement, ast.AugAssign):
                value = _merge_sources(
                    self._expression(statement.target, environment, True),
                    self._expression(statement.value, environment, True),
                )
                self._assign(statement.target, value, environment)
            elif isinstance(statement, ast.Expr):
                self._expression(statement.value, environment, True)
            elif isinstance(statement, ast.Return):
                returned = _merge_sources(
                    returned, self._expression(statement.value, environment, True)
                )
            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                loop_environment = dict(environment)
                self._assign(
                    statement.target,
                    self._expression(statement.iter, environment, True),
                    loop_environment,
                )
                returned = _merge_sources(
                    returned,
                    self._block(statement.body, loop_environment),
                    self._block(statement.orelse, loop_environment),
                )
                for name, sources in loop_environment.items():
                    environment[name] = _merge_sources(
                        environment.get(name, _Sources()), sources
                    )
            elif isinstance(statement, (ast.If, ast.While)):
                self._expression(statement.test, environment, True)
                for branch in (statement.body, statement.orelse):
                    branch_environment = dict(environment)
                    returned = _merge_sources(
                        returned, self._block(branch, branch_environment)
                    )
                    for name, sources in branch_environment.items():
                        environment[name] = _merge_sources(
                            environment.get(name, _Sources()), sources
                        )
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                with_environment = dict(environment)
                for item in statement.items:
                    value = self._expression(item.context_expr, environment, True)
                    if item.optional_vars is not None:
                        self._assign(item.optional_vars, value, with_environment)
                returned = _merge_sources(
                    returned, self._block(statement.body, with_environment)
                )
            elif isinstance(statement, ast.Try):
                blocks = [statement.body, statement.orelse, statement.finalbody]
                blocks.extend(handler.body for handler in statement.handlers)
                for block in blocks:
                    returned = _merge_sources(
                        returned, self._block(block, dict(environment))
                    )
            elif isinstance(statement, ast.Raise):
                self._expression(statement.exc, environment, True)
            elif isinstance(statement, ast.Assert):
                self._expression(statement.test, environment, True)
        return returned

    def _function(
        self, name: str, arguments: list[_Sources], keywords: dict[str, _Sources]
    ) -> _Sources:
        if name in self.active_functions:
            return _Sources()
        function = self.functions[name]
        parameters = [*function.args.posonlyargs, *function.args.args]
        environment = dict(self.module_sources)
        defaults = [None] * (len(parameters) - len(function.args.defaults)) + list(
            function.args.defaults
        )
        for index, parameter in enumerate(parameters):
            value = (
                arguments[index]
                if index < len(arguments)
                else keywords.get(parameter.arg)
            )
            if value is None and defaults[index] is not None:
                value = self._expression(defaults[index], environment, False)
            environment[parameter.arg] = value or _Sources()
        self.active_functions.add(name)
        try:
            return self._block(function.body, environment)
        finally:
            self.active_functions.remove(name)

    def analyze(self, entrypoints: set[str]) -> _Sources:
        for entrypoint in entrypoints:
            self._function(entrypoint, [], {})
        return self.output_sources


def _producer_evidence(text: str) -> ProducerEvidence:
    tree = ast.parse(text)
    guards = [node for node in tree.body if _is_main_guard(node)]
    functions = {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    entrypoints = {
        descendant.func.id
        for guard in guards
        for statement in guard.body
        for descendant in ast.walk(statement)
        if isinstance(descendant, ast.Call)
        and isinstance(descendant.func, ast.Name)
        and descendant.func.id in functions
    }
    sources = _ProducerAnalyzer(tree).analyze(entrypoints)
    return ProducerEvidence(
        output_literals=sources.literals,
        output_options=sources.options,
        has_entrypoint=bool(entrypoints),
    )


def _tracked_paths(root: Path) -> set[str]:
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(root), "ls-files", "-z"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as error:
        raise AuditInputError("tracked_inventory_unavailable") from error
    if completed.returncode != 0 or len(completed.stdout) > MAX_TRACKED_BYTES:
        raise AuditInputError("tracked_inventory_unavailable")
    try:
        return {item.decode("utf-8") for item in completed.stdout.split(b"\0") if item}
    except UnicodeDecodeError as error:
        raise AuditInputError("tracked_inventory_unavailable") from error


def _inventory_derived(
    root: Path, relative: PurePosixPath, errors: Counter[str]
) -> set[str]:
    directory = root
    for part in relative.parts:
        directory = directory / part
        try:
            metadata = directory.lstat()
        except FileNotFoundError:
            return set()
        except OSError:
            errors["unsafe_derived_root"] += 1
            return set()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            errors["unsafe_derived_root"] += 1
            return set()

    files: set[str] = set()
    directory_count = 0

    def visit(current: Path, parts: tuple[str, ...]) -> None:
        nonlocal directory_count
        directory_count += 1
        if directory_count > MAX_DIRECTORIES:
            errors["inventory_bound_exceeded"] += 1
            return
        try:
            with os.scandir(current) as iterator:
                entries = list(iterator)
        except OSError:
            errors["unsafe_artifact_type"] += 1
            return
        for entry in entries:
            if len(files) >= MAX_ARTIFACTS:
                errors["inventory_bound_exceeded"] += 1
                return
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError:
                errors["unsafe_artifact_type"] += 1
                continue
            child_parts = (*parts, entry.name)
            if stat.S_ISLNK(metadata.st_mode):
                errors["unsafe_artifact_type"] += 1
            elif stat.S_ISDIR(metadata.st_mode):
                visit(Path(entry.path), child_parts)
            elif stat.S_ISREG(metadata.st_mode):
                relative_file = PurePosixPath(*relative.parts, *child_parts).as_posix()
                if len(relative_file.encode("utf-8")) > MAX_PATH_BYTES:
                    errors["inventory_bound_exceeded"] += 1
                else:
                    files.add(relative_file)
            else:
                errors["unsafe_artifact_type"] += 1

    visit(directory, ())
    return files


def audit_repository(
    root: Path,
    contract_path: PurePosixPath = DEFAULT_CONTRACT,
    justfile_path: PurePosixPath = DEFAULT_JUSTFILE,
    *,
    tracked_paths: set[str] | None = None,
) -> dict[str, Any]:
    root = root.absolute()
    errors: Counter[str] = Counter()
    contract = _load_contract(root, contract_path, errors)

    derived_path = (
        _relative_path(contract.derived_root) if contract.derived_root else None
    )
    actual_files = (
        _inventory_derived(root, derived_path, errors)
        if derived_path is not None
        else set()
    )
    declared_files = {artifact.path for artifact in contract.artifacts}
    errors["unclassified_artifact"] += len(actual_files - declared_files)

    try:
        justfile_text = _read_bounded_file(
            root, justfile_path, MAX_JUSTFILE_BYTES, "unsafe_justfile"
        )
    except AuditInputError as error:
        errors[error.code] += 1
        justfile_text = ""
    recipes = _parse_justfile(justfile_text, errors)

    if tracked_paths is None:
        try:
            tracked_paths = _tracked_paths(root)
        except AuditInputError as error:
            errors[error.code] += 1
            tracked_paths = set()
    if justfile_path.as_posix() not in tracked_paths:
        errors["untracked_justfile"] += 1
    if contract_path.as_posix() not in tracked_paths:
        errors["untracked_contract"] += 1

    scripted_artifacts = contract.artifacts

    producers = sorted({artifact.producer for artifact in scripted_artifacts})
    producer_evidence: dict[str, ProducerEvidence | None] = {}
    for producer in producers:
        relative = PurePosixPath(producer)
        try:
            producer_text = _read_bounded_file(
                root, relative, MAX_PRODUCER_BYTES, "missing_or_unsafe_producer"
            )
        except AuditInputError as error:
            errors[error.code] += 1
            producer_evidence[producer] = None
            continue
        if producer not in tracked_paths:
            errors["untracked_producer"] += 1
        try:
            evidence = _producer_evidence(producer_text)
        except SyntaxError:
            errors["invalid_producer_python"] += 1
            producer_evidence[producer] = None
            continue
        producer_evidence[producer] = evidence
        if not evidence.has_entrypoint:
            errors["producer_missing_entrypoint"] += 1

    for artifact in scripted_artifacts:
        recipe_commands = recipes.get(artifact.recipe)
        if recipe_commands is None:
            errors["missing_recipe"] += 1
            continue
        invocations = tuple(
            tokens
            for command in recipe_commands
            if (tokens := _producer_invocation_tokens(command, artifact.producer))
            is not None
        )
        if not invocations:
            errors["producer_not_invoked_by_recipe"] += 1
        evidence = producer_evidence.get(artifact.producer)
        output_literals = {artifact.path, PurePosixPath(artifact.path).name}
        declared_in_producer = evidence is not None and bool(
            output_literals & evidence.output_literals
        )
        declared_in_invocation = evidence is not None and any(
            _invocation_declares_output(tokens, artifact.path, evidence.output_options)
            for tokens in invocations
        )
        if not declared_in_producer and not declared_in_invocation:
            errors["artifact_not_declared_by_producer_or_recipe"] += 1

    error_counts = {key: count for key, count in sorted(errors.items()) if count}
    artifacts_by_path = {artifact.path: artifact for artifact in contract.artifacts}
    retained_artifacts = [
        artifacts_by_path[path] for path in actual_files if path in artifacts_by_path
    ]
    retention_counts = Counter(artifact.retention for artifact in retained_artifacts)
    format_counts = Counter(artifact.format for artifact in retained_artifacts)
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "ok": not error_counts,
        "artifact_count": len(actual_files),
        "contract_entry_count": contract.declared_entries,
        "scripted_output_count": len(scripted_artifacts),
        "exception_count": 0,
        "producer_count": len(producers),
        "custodian_count": 0,
        "recipe_count": len({artifact.recipe for artifact in scripted_artifacts}),
        "retention_counts": {
            retention: retention_counts[retention]
            for retention in sorted(REPORT_RETENTIONS)
        },
        "format_counts": {
            artifact_format: format_counts[artifact_format]
            for artifact_format in sorted(FORMATS)
        },
        "error_counts": error_counts,
    }
    if len(json.dumps(report, sort_keys=True).encode("utf-8")) > MAX_REPORT_BYTES:
        raise RuntimeError("aggregate report exceeded fixed bound")
    return report


def _arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--contract", type=PurePosixPath, default=DEFAULT_CONTRACT)
    parser.add_argument("--justfile", type=PurePosixPath, default=DEFAULT_JUSTFILE)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = _arguments(argv)
    if arguments.contract.is_absolute() or arguments.justfile.is_absolute():
        report = {
            "schema": REPORT_SCHEMA,
            "ok": False,
            "artifact_count": 0,
            "contract_entry_count": 0,
            "scripted_output_count": 0,
            "exception_count": 0,
            "producer_count": 0,
            "custodian_count": 0,
            "recipe_count": 0,
            "retention_counts": {name: 0 for name in sorted(REPORT_RETENTIONS)},
            "format_counts": {name: 0 for name in sorted(FORMATS)},
            "error_counts": {"absolute_cli_path": 1},
        }
    else:
        report = audit_repository(
            arguments.root, arguments.contract, arguments.justfile
        )
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        fallback = {
            "schema": REPORT_SCHEMA,
            "ok": False,
            "artifact_count": 0,
            "contract_entry_count": 0,
            "scripted_output_count": 0,
            "exception_count": 0,
            "producer_count": 0,
            "custodian_count": 0,
            "recipe_count": 0,
            "retention_counts": {name: 0 for name in sorted(REPORT_RETENTIONS)},
            "format_counts": {name: 0 for name in sorted(FORMATS)},
            "error_counts": {"internal_error": 1},
        }
        print(json.dumps(fallback, sort_keys=True, separators=(",", ":")))
        raise SystemExit(2) from None
