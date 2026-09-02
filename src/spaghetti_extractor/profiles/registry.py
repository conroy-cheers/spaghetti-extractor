"""Strict registry and validators for reusable repository profiles."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from ..components.interaction_contract import InteractionContractCatalogV1
from ..external.machine_abi import (
    parse_normal_call_abi_premise,
    resolve_machine_call_abi,
)
from ..external.machine_import_profiles import load_machine_import_profile_set
from ..external.interface_ast import validate_external_interface_extraction_spec


PROFILE_CATALOG_FORMAT = "spaghetti-extractor-profile-catalog-v1"

_CATALOG_FIELDS = frozenset({"format", "profiles"})
_REGISTRATION_FIELDS = frozenset({"path", "role", "validator_id"})
_TOKEN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ProfileRegistryError(ValueError):
    """Raised when the catalog or a registered profile is invalid."""


@dataclass(frozen=True)
class ProfileRegistration:
    path: str
    role: str
    validator_id: str


@dataclass(frozen=True)
class ValidatedProfile:
    registration: ProfileRegistration
    path: Path
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class ProfileRegistry:
    catalog_path: Path
    profiles: tuple[ValidatedProfile, ...]

    @property
    def registrations(self) -> tuple[ProfileRegistration, ...]:
        return tuple(profile.registration for profile in self.profiles)

    def by_path(self) -> dict[str, ValidatedProfile]:
        return {profile.registration.path: profile for profile in self.profiles}


ProfileValidator = Callable[[Path, Mapping[str, Any]], None]


def _exact_fields(
    value: Mapping[str, Any], expected: frozenset[str], context: str
) -> None:
    missing = sorted(expected - set(value))
    unexpected = sorted(set(value) - expected)
    if missing or unexpected:
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        raise ProfileRegistryError(
            f"{context} fields are invalid: {'; '.join(details)}"
        )


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ProfileRegistryError(f"{context} must be a JSON object")
    return value


def _array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise ProfileRegistryError(f"{context} must be an array")
    return value


def _nonempty_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProfileRegistryError(f"{context} must be a nonempty string")
    return value


def _natural(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ProfileRegistryError(f"{context} must be a natural number")
    return value


def _string_array(value: Any, context: str, *, nonempty: bool = False) -> list[str]:
    result = _array(value, context)
    if any(not isinstance(item, str) or (nonempty and not item) for item in result):
        raise ProfileRegistryError(f"{context} must contain only strings")
    if len(result) != len(set(result)):
        raise ProfileRegistryError(f"{context} contains duplicates")
    return result


def _expect_format(payload: Mapping[str, Any], expected: str) -> None:
    if payload.get("format") != expected:
        raise ProfileRegistryError(f"expected profile format {expected!r}")


def _validate_identity(value: Any, context: str) -> None:
    identity = _object(value, context)
    if not isinstance(identity.get("dll"), str) or not identity["dll"]:
        raise ProfileRegistryError(f"{context}.dll must be a nonempty string")
    variants = [key for key in ("symbol", "ordinal") if key in identity]
    if len(variants) != 1 or set(identity) != {"dll", variants[0]}:
        raise ProfileRegistryError(
            f"{context} must contain dll and exactly one of symbol or ordinal"
        )
    if variants[0] == "symbol":
        _nonempty_string(identity["symbol"], f"{context}.symbol")
    else:
        _natural(identity["ordinal"], f"{context}.ordinal")


def _validate_headers(value: Any, context: str) -> None:
    rows = _array(value, context)
    if not rows:
        raise ProfileRegistryError(f"{context} must not be empty")
    includes: list[str] = []
    for index, raw in enumerate(rows):
        row_context = f"{context}[{index}]"
        row = _object(raw, row_context)
        _exact_fields(row, frozenset({"include", "sha256"}), row_context)
        includes.append(_nonempty_string(row["include"], f"{row_context}.include"))
        digest = row.get("sha256")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise ProfileRegistryError(f"{row_context}.sha256 must be a SHA-256 digest")
    if len(includes) != len(set(includes)):
        raise ProfileRegistryError(f"{context} contains duplicate includes")


def _validate_c0_toolchain(path: Path, payload: Mapping[str, Any]) -> None:
    del path
    _expect_format(payload, "spaghetti-extractor-c0-toolchain-profile-v1")
    _exact_fields(
        payload,
        frozenset({"format", "id", "target", "tools", "flags", "runtime", "policy"}),
        "C0 toolchain profile",
    )
    _nonempty_string(payload.get("id"), "C0 toolchain profile.id")
    _nonempty_string(payload.get("target"), "C0 toolchain profile.target")
    tools = _object(payload.get("tools"), "C0 toolchain profile.tools")
    if set(tools) != {"compiler", "assembler", "linker"}:
        raise ProfileRegistryError("C0 toolchain profile.tools are incomplete")
    for name, raw in tools.items():
        tool = _object(raw, f"C0 toolchain profile.tools.{name}")
        _exact_fields(tool, frozenset({"path", "sha256"}), f"tool {name}")
        _nonempty_string(tool["path"], f"tool {name}.path")
        _nonempty_string(tool["sha256"], f"tool {name}.sha256")
    if not _string_array(
        payload.get("flags"), "C0 toolchain profile.flags", nonempty=True
    ):
        raise ProfileRegistryError("C0 toolchain profile.flags must not be empty")
    runtime = _object(payload.get("runtime"), "C0 toolchain profile.runtime")
    _exact_fields(runtime, frozenset({"profile", "sha256"}), "C0 runtime")
    _nonempty_string(runtime["profile"], "C0 runtime.profile")
    _nonempty_string(runtime["sha256"], "C0 runtime.sha256")
    policy = _object(payload.get("policy"), "C0 toolchain profile.policy")
    if not policy or any(not isinstance(value, bool) for value in policy.values()):
        raise ProfileRegistryError("C0 toolchain profile.policy must contain booleans")


def _validate_callable_external(path: Path, payload: Mapping[str, Any]) -> None:
    del path
    _expect_format(payload, "spaghetti-extractor-callable-external-profile-v2")
    _exact_fields(
        payload,
        frozenset({"format", "id", "model", "resolvers", "targets"}),
        "callable external profile",
    )
    _nonempty_string(payload.get("id"), "callable external profile.id")
    if payload.get("model") != "x86-pe32":
        raise ProfileRegistryError("callable external profile.model must be x86-pe32")
    resolver_ids: set[int] = set()
    for index, raw in enumerate(_array(payload.get("resolvers"), "resolvers")):
        context = f"resolvers[{index}]"
        resolver = _object(raw, context)
        _exact_fields(
            resolver,
            frozenset(
                {
                    "id",
                    "import",
                    "result_register",
                    "module_argument_index",
                    "identity_argument_indices",
                    "nullable",
                }
            ),
            context,
        )
        resolver_id = _natural(resolver.get("id"), f"{context}.id")
        if resolver_id in resolver_ids:
            raise ProfileRegistryError("callable external resolver IDs must be unique")
        resolver_ids.add(resolver_id)
        _validate_identity(resolver.get("import"), f"{context}.import")
        if resolver.get("result_register") not in {
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "ebp",
        }:
            raise ProfileRegistryError(f"{context}.result_register is unsupported")
        _natural(
            resolver.get("module_argument_index"), f"{context}.module_argument_index"
        )
        indices = _array(
            resolver.get("identity_argument_indices"),
            f"{context}.identity_argument_indices",
        )
        for item_index, item in enumerate(indices):
            _natural(item, f"{context}.identity_argument_indices[{item_index}]")
        if len(indices) != len(set(indices)):
            raise ProfileRegistryError(
                f"{context}.identity_argument_indices contains duplicates"
            )
        if not isinstance(resolver.get("nullable"), bool):
            raise ProfileRegistryError(f"{context}.nullable must be a boolean")
    if not resolver_ids:
        raise ProfileRegistryError("callable external profile has no resolvers")
    target_ids: set[int] = set()
    for index, raw in enumerate(_array(payload.get("targets"), "targets")):
        context = f"targets[{index}]"
        target = _object(raw, context)
        required = frozenset(
            {
                "id",
                "resolver_id",
                "module",
                "identity_arguments",
                "target",
                "machine_contract",
                "transfers",
            }
        )
        _exact_fields(target, required, context)
        target_id = _natural(target.get("id"), f"{context}.id")
        if target_id in target_ids:
            raise ProfileRegistryError("callable external target IDs must be unique")
        target_ids.add(target_id)
        if target.get("resolver_id") not in resolver_ids:
            raise ProfileRegistryError(f"{context} references an unknown resolver")
        _validate_identity(target.get("target"), f"{context}.target")
        transfers = _string_array(target.get("transfers"), f"{context}.transfers")
        if not transfers or not set(transfers) <= {"call", "jump"}:
            raise ProfileRegistryError(f"{context}.transfers are unsupported")
        contract = _object(
            target.get("machine_contract"), f"{context}.machine_contract"
        )
        if resolve_machine_call_abi(contract.get("abi_template")) is None:
            raise ProfileRegistryError(
                f"{context}.machine_contract has unsupported ABI"
            )
        module = _object(target.get("module"), f"{context}.module")
        _validate_identity(
            module.get("loader_import"), f"{context}.module.loader_import"
        )
        _natural(
            module.get("loader_name_argument_index"),
            f"{context}.module.loader_name_argument_index",
        )
        module_bytes = _array(module.get("bytes"), f"{context}.module.bytes")
        if not module_bytes or any(
            not isinstance(item, int) or isinstance(item, bool) or not 0 <= item <= 255
            for item in module_bytes
        ):
            raise ProfileRegistryError(f"{context}.module.bytes must be nonempty bytes")
    if not target_ids:
        raise ProfileRegistryError("callable external profile has no targets")


def _validate_machine_import(path: Path, payload: Mapping[str, Any]) -> None:
    if payload.get("format") not in {
        "spaghetti-extractor-external-environment-profile-v1",
        "spaghetti-extractor-static-machine-import-profile-v1",
        "spaghetti-extractor-static-machine-import-profile-v2",
    }:
        raise ProfileRegistryError("unsupported machine import profile format")
    load_machine_import_profile_set([path])


def _validate_interface_extraction(path: Path, payload: Mapping[str, Any]) -> None:
    del path
    validate_external_interface_extraction_spec(payload)


def _validate_function_extraction(path: Path, payload: Mapping[str, Any]) -> None:
    del path
    _expect_format(payload, "spaghetti-extractor-external-function-extraction-spec-v1")
    _exact_fields(
        payload,
        frozenset({"format", "id", "model", "headers", "dlls"}),
        "external function extraction spec",
    )
    _nonempty_string(payload.get("id"), "function extraction spec.id")
    if payload.get("model") != "x86-pe32":
        raise ProfileRegistryError("function extraction spec.model must be x86-pe32")
    _validate_headers(payload.get("headers"), "function extraction spec.headers")
    if not _string_array(
        payload.get("dlls"), "function extraction spec.dlls", nonempty=True
    ):
        raise ProfileRegistryError("function extraction spec.dlls must not be empty")


def _validate_normal_call_abi(path: Path, payload: Mapping[str, Any]) -> None:
    del path
    parse_normal_call_abi_premise(payload)


def _validate_indirect_target(path: Path, payload: Mapping[str, Any]) -> None:
    del path
    _expect_format(payload, "spaghetti-extractor-indirect-target-profile-v1")
    expected = {
        "id": "pe32-static-cutpoints-and-paired-callables-v1",
        "status": "accepted_assumption",
        "internal_target_domain": "all_checked_machine_ir_unit_starts",
        "external_target_domain": "paired_external_callable_resources",
        "runtime_rejection_required": True,
    }
    _exact_fields(
        payload,
        frozenset({"format", "assumption", *expected}),
        "indirect target profile",
    )
    if any(payload.get(key) != value for key, value in expected.items()):
        raise ProfileRegistryError("indirect target profile has unsupported policy")
    assumption = _object(payload.get("assumption"), "indirect target assumption")
    _exact_fields(
        assumption,
        frozenset({"id", "scope", "statement"}),
        "indirect target assumption",
    )
    for key in assumption:
        _nonempty_string(assumption[key], f"indirect target assumption.{key}")


def _validate_launch_assumption(path: Path, payload: Mapping[str, Any]) -> None:
    del path
    _expect_format(payload, "spaghetti-extractor-pe32-launch-assumption-template-v1")
    _exact_fields(
        payload,
        frozenset({"format", "schema_version", "assumptions", "feature_inventory"}),
        "launch assumption template",
    )
    if payload.get("schema_version") != 1:
        raise ProfileRegistryError(
            "launch assumption template schema_version must be 1"
        )
    assumptions = _object(payload.get("assumptions"), "launch assumptions")
    required = {"argv", "environment", "fs", "iat", "initial_stack", "relocations"}
    if set(assumptions) != required or any(
        not isinstance(value, Mapping) for value in assumptions.values()
    ):
        raise ProfileRegistryError("launch assumptions are incomplete")
    features = _object(payload.get("feature_inventory"), "launch feature inventory")
    expected_features = {
        "direct_syscalls",
        "executable_writes",
        "threads",
        "unknown_async_callbacks",
        "unmodelled_seh",
    }
    if set(features) != expected_features:
        raise ProfileRegistryError("launch feature inventory fields are incomplete")
    for key, value in features.items():
        _array(value, f"launch feature inventory.{key}")


def _validate_import_abi_policy(path: Path, payload: Mapping[str, Any]) -> None:
    del path
    _expect_format(payload, "spaghetti-extractor-import-abi-policy-v1")
    _exact_fields(payload, frozenset({"format", "id", "rules"}), "import ABI policy")
    _nonempty_string(payload.get("id"), "import ABI policy.id")
    dlls: set[str] = set()
    rules = _array(payload.get("rules"), "import ABI policy.rules")
    if not rules:
        raise ProfileRegistryError("import ABI policy.rules must not be empty")
    for index, raw in enumerate(rules):
        context = f"import ABI policy.rules[{index}]"
        rule = _object(raw, context)
        _exact_fields(rule, frozenset({"dll", "abi_template"}), context)
        dll = _nonempty_string(rule.get("dll"), f"{context}.dll").lower()
        if dll in dlls:
            raise ProfileRegistryError("import ABI policy contains duplicate DLLs")
        dlls.add(dll)
        if resolve_machine_call_abi(rule.get("abi_template")) is None:
            raise ProfileRegistryError(f"{context}.abi_template is unsupported")


def _validate_interaction_contract_catalog(
    path: Path, payload: Mapping[str, Any]
) -> None:
    del path
    _expect_format(
        payload, "spaghetti-extractor-interaction-contract-catalog-v1"
    )
    InteractionContractCatalogV1.parse(payload)


_VALIDATORS: Mapping[str, ProfileValidator] = {
    "c0-toolchain-v1": _validate_c0_toolchain,
    "callable-external-v2": _validate_callable_external,
    "external-function-extraction-v1": _validate_function_extraction,
    "external-interface-extraction-v1": _validate_interface_extraction,
    "import-abi-policy-v1": _validate_import_abi_policy,
    "indirect-target-profile-v1": _validate_indirect_target,
    "interaction-contract-catalog-v1": _validate_interaction_contract_catalog,
    "launch-assumption-template-v1": _validate_launch_assumption,
    "machine-import-profile-v1": _validate_machine_import,
    "normal-call-abi-premise-v1": _validate_normal_call_abi,
}
PROFILE_VALIDATOR_IDS = frozenset(_VALIDATORS)
PROFILE_ROLE_VALIDATORS: Mapping[str, frozenset[str]] = {
    "callable-external-resolution": frozenset({"callable-external-v2"}),
    "candidate-toolchain-policy": frozenset({"c0-toolchain-v1"}),
    "console-launch-assumption-template": frozenset(
        {"launch-assumption-template-v1"}
    ),
    "external-function-extraction": frozenset(
        {"external-function-extraction-v1"}
    ),
    "external-interface-extraction": frozenset(
        {"external-interface-extraction-v1"}
    ),
    "gui-launch-assumption-template": frozenset(
        {"launch-assumption-template-v1"}
    ),
    "import-abi-policy": frozenset({"import-abi-policy-v1"}),
    "indirect-target-assumption": frozenset({"indirect-target-profile-v1"}),
    "interaction-contract-catalog": frozenset(
        {"interaction-contract-catalog-v1"}
    ),
    "machine-import-environment": frozenset({"machine-import-profile-v1"}),
    "machine-import-runtime": frozenset({"machine-import-profile-v1"}),
    "normal-call-abi-premise": frozenset({"normal-call-abi-premise-v1"}),
}
PROFILE_ROLE_IDS = frozenset(PROFILE_ROLE_VALIDATORS)


def _read_json_object(path: Path, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileRegistryError(f"cannot read {context} {path}: {exc}") from exc
    return _object(value, context)


def _registration(value: Any, index: int) -> ProfileRegistration:
    context = f"profile catalog.profiles[{index}]"
    row = _object(value, context)
    _exact_fields(row, _REGISTRATION_FIELDS, context)
    path = _nonempty_string(row.get("path"), f"{context}.path")
    pure_path = PurePosixPath(path)
    if pure_path.name != path or pure_path.suffix != ".json" or path == "catalog.json":
        raise ProfileRegistryError(
            f"{context}.path must name one profile JSON file in the catalog directory"
        )
    role = _nonempty_string(row.get("role"), f"{context}.role")
    validator_id = _nonempty_string(row.get("validator_id"), f"{context}.validator_id")
    if _TOKEN.fullmatch(role) is None or role not in PROFILE_ROLE_VALIDATORS:
        raise ProfileRegistryError(f"{context}.role is not a supported profile role")
    if validator_id not in _VALIDATORS:
        raise ProfileRegistryError(
            f"{context}.validator_id is unknown: {validator_id!r}"
        )
    if validator_id not in PROFILE_ROLE_VALIDATORS[role]:
        raise ProfileRegistryError(
            f"{context}.validator_id {validator_id!r} cannot validate role {role!r}"
        )
    return ProfileRegistration(path=path, role=role, validator_id=validator_id)


def load_profile_registry(catalog_path: Path | str) -> ProfileRegistry:
    """Load the catalog, prove exact inventory closure, and validate every profile."""

    source = Path(catalog_path).resolve()
    payload = _read_json_object(source, "profile catalog")
    _exact_fields(payload, _CATALOG_FIELDS, "profile catalog")
    if payload.get("format") != PROFILE_CATALOG_FORMAT:
        raise ProfileRegistryError("unsupported profile catalog format")
    registrations = tuple(
        _registration(value, index)
        for index, value in enumerate(
            _array(payload.get("profiles"), "profile catalog.profiles")
        )
    )
    paths = [registration.path for registration in registrations]
    if paths != sorted(paths):
        raise ProfileRegistryError("profile catalog registrations must be path-sorted")
    if len(paths) != len(set(paths)):
        raise ProfileRegistryError("profile catalog contains duplicate paths")

    actual_paths = {
        path.name for path in source.parent.glob("*.json") if path.name != source.name
    }
    registered_paths = set(paths)
    if actual_paths != registered_paths:
        missing = sorted(actual_paths - registered_paths)
        absent = sorted(registered_paths - actual_paths)
        details: list[str] = []
        if missing:
            details.append("unregistered: " + ", ".join(missing))
        if absent:
            details.append("missing files: " + ", ".join(absent))
        raise ProfileRegistryError(
            "profile catalog does not exactly match the JSON inventory: "
            + "; ".join(details)
        )

    validated: list[ValidatedProfile] = []
    for registration in registrations:
        profile_path = source.parent / registration.path
        profile_payload = _read_json_object(profile_path, "registered profile")
        validator = _VALIDATORS[registration.validator_id]
        try:
            validator(profile_path, profile_payload)
        except (OSError, UnicodeError, ValueError) as exc:
            raise ProfileRegistryError(
                f"{registration.path}: validator {registration.validator_id!r} rejected the profile: {exc}"
            ) from exc
        validated.append(
            ValidatedProfile(
                registration=registration,
                path=profile_path,
                payload=profile_payload,
            )
        )
    return ProfileRegistry(catalog_path=source, profiles=tuple(validated))


def validate_profile_inventory(profiles_directory: Path | str) -> ProfileRegistry:
    """Validate the standard ``catalog.json`` in a profile directory."""

    return load_profile_registry(Path(profiles_directory) / "catalog.json")


__all__ = [
    "PROFILE_CATALOG_FORMAT",
    "PROFILE_ROLE_IDS",
    "PROFILE_ROLE_VALIDATORS",
    "PROFILE_VALIDATOR_IDS",
    "ProfileRegistration",
    "ProfileRegistry",
    "ProfileRegistryError",
    "ValidatedProfile",
    "load_profile_registry",
    "validate_profile_inventory",
]
