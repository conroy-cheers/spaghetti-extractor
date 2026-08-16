"""Content-bound reusable behavior packs for recognized library islands."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.formats import REUSABLE_LIBRARY_BEHAVIOR_PACK_V1_FORMAT
from ..components.compile_receipt import COMPONENT_COMPILE_RECEIPT_V1
from ..components.formats import (
    COMPONENT_REFINEMENT_RECEIPT_V1_FORMAT,
    COMPONENT_SOURCE_PROFILE_V1_FORMAT,
)
from ..components.interface_ir import PortableComponentInterfaceV2
from ..components.source import (
    component_operation_symbols,
    load_component_source_package,
)
from ..util import sha256_file, write_json
from .v4_adoption_records import (
    REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1,
    ReusableLibraryImplementationV1,
)
from .v4_record_support import canonical_sha256


class LibraryBehaviorPackError(ValueError):
    """A behavior pack is malformed, stale, or not statically qualified."""


@dataclass(frozen=True)
class ReusableLibraryBehaviorPackV1:
    root: Path
    manifest: Mapping[str, Any]
    implementation: ReusableLibraryImplementationV1
    source: Mapping[str, Any]
    interface: PortableComponentInterfaceV2
    source_profile: Mapping[str, Any]
    compile_receipt: Mapping[str, Any]
    qualification_receipt: Mapping[str, Any]

    @property
    def pack_sha256(self) -> str:
        return str(self.manifest["pack_sha256"])


def build_reusable_library_behavior_pack_v1(
    *,
    implementation: Path | str,
    source_package: Path | str,
    interface: Path | str,
    source_profile: Path | str,
    compile_receipt: Path | str,
    qualification_receipt: Path | str,
    out_dir: Path | str,
) -> ReusableLibraryBehaviorPackV1:
    """Copy exact checked inputs into one reusable, independently cached pack."""

    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1.write(
        output / "implementation.json",
        REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1.read(implementation),
    )
    _copy_tree(Path(source_package), output / "source-package")
    _copy_json_input(Path(interface), output / "portable-interface.json")
    _copy_json_input(Path(source_profile), output / "source-profile.json")
    _copy_json_input(Path(compile_receipt), output / "compile-receipt.json")
    _copy_json_input(
        Path(qualification_receipt), output / "qualification-receipt.json"
    )

    checked = _validate_pack_inputs(output)
    core = _manifest_core(checked, output)
    write_json(
        output / "behavior-pack.json",
        {**core, "pack_sha256": canonical_sha256(core)},
    )
    return load_reusable_library_behavior_pack_v1(output)


def load_reusable_library_behavior_pack_v1(
    value: Path | str,
) -> ReusableLibraryBehaviorPackV1:
    root = Path(value)
    if root.is_file():
        root = root.parent
    manifest = _read_json(root / "behavior-pack.json", "behavior-pack manifest")
    expected_fields = {
        "format",
        "id",
        "implementation_id",
        "implementation_sha256",
        "source_id",
        "source_package_sha256",
        "interface_contract_id",
        "interface_sha256",
        "effect_contract_ids",
        "compile_profile_id",
        "source_profile_receipt_sha256",
        "compile_receipt_sha256",
        "qualification_checker_id",
        "qualification_receipt_sha256",
        "artifacts",
        "pack_sha256",
    }
    if set(manifest) != expected_fields:
        raise LibraryBehaviorPackError(
            "behavior-pack manifest fields are not canonical"
        )
    if manifest.get("format") != REUSABLE_LIBRARY_BEHAVIOR_PACK_V1_FORMAT:
        raise LibraryBehaviorPackError("unsupported behavior-pack format")
    core = dict(manifest)
    claimed = core.pop("pack_sha256", None)
    if claimed != canonical_sha256(core):
        raise LibraryBehaviorPackError("behavior-pack manifest hash is stale")
    checked = _validate_pack_inputs(root)
    expected = _manifest_core(checked, root)
    if core != expected:
        raise LibraryBehaviorPackError(
            "behavior-pack manifest does not bind its checked inputs"
        )
    return ReusableLibraryBehaviorPackV1(
        root=root,
        manifest=manifest,
        implementation=checked["implementation"],
        source=checked["source"],
        interface=checked["interface"],
        source_profile=checked["source_profile"],
        compile_receipt=checked["compile_receipt"],
        qualification_receipt=checked["qualification_receipt"],
    )


def _validate_pack_inputs(root: Path) -> dict[str, Any]:
    implementation = REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1.read(
        root / "implementation.json"
    )
    if implementation.status != "complete":
        raise LibraryBehaviorPackError("behavior-pack implementation is not complete")
    source = load_component_source_package(root / "source-package")
    interface_payload = _read_json(
        root / "portable-interface.json", "portable interface"
    )
    interface = PortableComponentInterfaceV2.parse(interface_payload)
    source_profile = _read_json(root / "source-profile.json", "source profile")
    compile_receipt = _read_json(root / "compile-receipt.json", "compile receipt")
    qualification = _read_json(
        root / "qualification-receipt.json", "qualification receipt"
    )

    symbols = component_operation_symbols(source)
    mappings = {row.operation_id: row for row in implementation.operation_source_mappings}
    if set(mappings) != set(symbols) or set(symbols) != set(interface.operation_index()):
        raise LibraryBehaviorPackError(
            "implementation, source, and interface operation inventories differ"
        )
    source_id = str(source.get("lift_unit_id"))
    source_sha256 = str(source.get("implementation_sha256"))
    if source_id != interface.identity:
        raise LibraryBehaviorPackError(
            "source package and portable interface identities differ"
        )
    for operation_id, mapping in mappings.items():
        if (
            mapping.source_id != source_id
            or mapping.source_symbol != symbols[operation_id]
            or mapping.source_sha256 != source_sha256
        ):
            raise LibraryBehaviorPackError(
                f"operation {operation_id!r} has a stale source mapping"
            )
    if implementation.interface_contract_ids != (interface.identity,):
        raise LibraryBehaviorPackError(
            "implementation does not bind the exact portable interface"
        )
    effect_ids = tuple(sorted(row.identity for row in interface.effects))
    if implementation.effect_contract_ids != effect_ids:
        raise LibraryBehaviorPackError(
            "implementation does not bind the interface effect inventory"
        )

    _check_self_hash(source_profile, "receipt_sha256", "source profile")
    if (
        source_profile.get("format") != COMPONENT_SOURCE_PROFILE_V1_FORMAT
        or source_profile.get("status") != "satisfied"
        or source_profile.get("profile_id") != implementation.compile_profile_id
        or _binding(source_profile, "implementation_sha256") != source_sha256
        or _policy(source_profile, "operator_behavior_examples_used") is not False
    ):
        raise LibraryBehaviorPackError("source profile is incomplete or stale")

    _check_self_hash(compile_receipt, "receipt_sha256", "compile receipt")
    if (
        compile_receipt.get("format") != COMPONENT_COMPILE_RECEIPT_V1
        or compile_receipt.get("status") != "checked"
        or compile_receipt.get("interface_id") != interface.identity
        or _binding(compile_receipt, "interface_sha256") != interface.sha256
        or _binding(compile_receipt, "implementation_sha256") != source_sha256
        or _policy(compile_receipt, "host_and_pe32_abi_checked") is not True
        or _policy(compile_receipt, "component_mutable_globals_forbidden") is not True
    ):
        raise LibraryBehaviorPackError("compile receipt is incomplete or stale")

    _check_self_hash(qualification, "receipt_sha256", "qualification receipt")
    checker = qualification.get("checker")
    checker_id = checker.get("id") if isinstance(checker, Mapping) else None
    if (
        qualification.get("format") != COMPONENT_REFINEMENT_RECEIPT_V1_FORMAT
        or qualification.get("status") != "satisfied"
        or qualification.get("activation_authorized") is not True
        or checker_id != implementation.qualification_checker_id
        or qualification.get("receipt_sha256")
        != implementation.qualification_receipt_sha256
        or _binding(qualification, "interface_sha256") != interface.sha256
        or _binding(qualification, "implementation_sha256") != source_sha256
        or _policy(qualification, "original_binary_executed") is not False
        or _policy(qualification, "operator_behavior_examples_used") is not False
    ):
        raise LibraryBehaviorPackError(
            "static qualification receipt is incomplete or stale"
        )
    return {
        "implementation": implementation,
        "source": source,
        "interface": interface,
        "source_profile": source_profile,
        "compile_receipt": compile_receipt,
        "qualification_receipt": qualification,
    }


def _manifest_core(checked: Mapping[str, Any], root: Path) -> dict[str, Any]:
    implementation = checked["implementation"]
    source = checked["source"]
    interface = checked["interface"]
    source_profile = checked["source_profile"]
    compile_receipt = checked["compile_receipt"]
    qualification = checked["qualification_receipt"]
    checker = qualification["checker"]
    identity = {
        "implementation_id": implementation.implementation_id,
        "implementation_sha256": implementation.implementation_sha256,
        "source_package_sha256": source["implementation_sha256"],
        "interface_sha256": interface.sha256,
        "compile_receipt_sha256": compile_receipt["receipt_sha256"],
        "qualification_receipt_sha256": qualification["receipt_sha256"],
    }
    return {
        "format": REUSABLE_LIBRARY_BEHAVIOR_PACK_V1_FORMAT,
        "id": canonical_sha256(identity),
        "implementation_id": implementation.implementation_id,
        "implementation_sha256": implementation.implementation_sha256,
        "source_id": source["lift_unit_id"],
        "source_package_sha256": source["implementation_sha256"],
        "interface_contract_id": interface.identity,
        "interface_sha256": interface.sha256,
        "effect_contract_ids": list(implementation.effect_contract_ids),
        "compile_profile_id": implementation.compile_profile_id,
        "source_profile_receipt_sha256": source_profile["receipt_sha256"],
        "compile_receipt_sha256": compile_receipt["receipt_sha256"],
        "qualification_checker_id": checker["id"],
        "qualification_receipt_sha256": qualification["receipt_sha256"],
        "artifacts": {
            name: {"path": path, "sha256": sha256_file(root_path)}
            for name, path, root_path in (
                ("implementation", "implementation.json", root / "implementation.json"),
                ("source_manifest", "source-package/source-package.json", root / "source-package/source-package.json"),
                ("interface", "portable-interface.json", root / "portable-interface.json"),
                ("source_profile", "source-profile.json", root / "source-profile.json"),
                ("compile_receipt", "compile-receipt.json", root / "compile-receipt.json"),
                ("qualification_receipt", "qualification-receipt.json", root / "qualification-receipt.json"),
            )
        },
    }


def _copy_tree(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise LibraryBehaviorPackError("component source package must be a directory")
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)


def _copy_json_input(source: Path, destination: Path) -> None:
    if source.is_dir():
        candidates = tuple(sorted(source.glob("*.json")))
        if len(candidates) != 1:
            raise LibraryBehaviorPackError(
                f"expected one JSON artifact in {source}, observed {len(candidates)}"
            )
        source = candidates[0]
    destination.write_bytes(source.read_bytes())


def _read_json(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise LibraryBehaviorPackError(f"cannot read {description}: {error}") from error
    if not isinstance(value, Mapping):
        raise LibraryBehaviorPackError(f"{description} must be an object")
    return dict(value)


def _check_self_hash(payload: Mapping[str, Any], field: str, description: str) -> None:
    core = dict(payload)
    claimed = core.pop(field, None)
    if claimed != canonical_sha256_v3(core):
        raise LibraryBehaviorPackError(f"{description} self-hash is stale")


def _binding(payload: Mapping[str, Any], field: str) -> Any:
    bindings = payload.get("bindings")
    return bindings.get(field) if isinstance(bindings, Mapping) else None


def _policy(payload: Mapping[str, Any], field: str) -> Any:
    policy = payload.get("policy")
    return policy.get(field) if isinstance(policy, Mapping) else None


__all__ = [
    "LibraryBehaviorPackError",
    "ReusableLibraryBehaviorPackV1",
    "build_reusable_library_behavior_pack_v1",
    "load_reusable_library_behavior_pack_v1",
]
