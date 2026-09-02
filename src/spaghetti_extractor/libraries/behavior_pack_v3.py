"""V5-only reusable library behavior packs.

Recognition consumes only the lightweight manifest and reusable implementation
identity.  Adoption reopens this package and rechecks every content binding
before it may derive target-specific component authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import shutil
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary._canonical import (
    BoundaryModelError,
    array,
    canonical,
    digest,
    exact,
    identifier,
    object_,
)
from ..components.interface_package_v5 import (
    ComponentInterfaceIntentV1,
    compile_component_interface_v5,
)
from ..components.source import (
    component_operation_symbols,
    load_component_source_package,
)
from ..util import sha256_file, write_json
from .formats import (
    REUSABLE_LIBRARY_BEHAVIOR_PACK_V3_FORMAT,
    REUSABLE_LIBRARY_SOURCE_QUALIFICATION_V1_FORMAT,
)
from .v4_adoption_records import (
    REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1,
    ReusableLibraryImplementationV1,
)


class ReusableLibraryBehaviorPackV3Error(BoundaryModelError):
    """The V5 behavior pack is malformed, stale, or unqualified."""


@dataclass(frozen=True)
class ReusableLibrarySourceQualificationV1:
    component_id: str
    interface_sha256: str
    source_package_sha256: str
    proof_receipt_sha256s: tuple[str, ...]
    checks: tuple[Mapping[str, object], ...]
    receipt_sha256: str

    @classmethod
    def create(
        cls,
        *,
        component_id: str,
        interface_sha256: str,
        source_package_sha256: str,
        proof_receipt_sha256s: Sequence[str],
        checks: Sequence[Mapping[str, object]],
    ) -> "ReusableLibrarySourceQualificationV1":
        proofs = tuple(
            sorted(
                set(
                    digest(value, "reusable library static proof receipt")
                    for value in proof_receipt_sha256s
                )
            )
        )
        if not proofs:
            raise ReusableLibraryBehaviorPackV3Error(
                "reusable library qualification requires static proof receipts"
            )
        normalized_checks = tuple(
            canonical(dict(object_(value, f"library qualification check {index}")))
            for index, value in enumerate(checks)
        )
        if not normalized_checks:
            raise ReusableLibraryBehaviorPackV3Error(
                "reusable library qualification requires checked obligations"
            )
        core = {
            "format": REUSABLE_LIBRARY_SOURCE_QUALIFICATION_V1_FORMAT,
            "status": "checked",
            "component_id": identifier(component_id, "reusable library component"),
            "interface_sha256": digest(
                interface_sha256, "reusable library interface"
            ),
            "source_package_sha256": digest(
                source_package_sha256, "reusable library source package"
            ),
            "proof_receipt_sha256s": list(proofs),
            "checks": [canonical(dict(item)) for item in normalized_checks],
            "policy": {
                "original_binary_executed": False,
                "tests_authorize": False,
                "static_proof_required": True,
            },
        }
        return cls(
            str(core["component_id"]),
            str(core["interface_sha256"]),
            str(core["source_package_sha256"]),
            proofs,
            normalized_checks,
            canonical_sha256_v3(core),
        )

    @classmethod
    def parse(cls, value: object) -> "ReusableLibrarySourceQualificationV1":
        row = object_(value, "reusable library source qualification")
        exact(
            row,
            {
                "format",
                "status",
                "component_id",
                "interface_sha256",
                "source_package_sha256",
                "proof_receipt_sha256s",
                "checks",
                "policy",
                "receipt_sha256",
            },
            "reusable library source qualification",
        )
        if (
            row["format"] != REUSABLE_LIBRARY_SOURCE_QUALIFICATION_V1_FORMAT
            or row["status"] != "checked"
            or row["policy"]
            != {
                "original_binary_executed": False,
                "tests_authorize": False,
                "static_proof_required": True,
            }
        ):
            raise ReusableLibraryBehaviorPackV3Error(
                "unsupported reusable library qualification policy"
            )
        result = cls.create(
            component_id=str(row["component_id"]),
            interface_sha256=str(row["interface_sha256"]),
            source_package_sha256=str(row["source_package_sha256"]),
            proof_receipt_sha256s=[
                str(item)
                for item in array(
                    row["proof_receipt_sha256s"], "library qualification proofs"
                )
            ],
            checks=[
                dict(object_(item, f"library qualification check {index}"))
                for index, item in enumerate(
                    array(row["checks"], "library qualification checks")
                )
            ],
        )
        if result.to_payload() != dict(row):
            raise ReusableLibraryBehaviorPackV3Error(
                "reusable library qualification is stale"
            )
        return result

    def to_payload(self) -> dict[str, object]:
        core = {
            "format": REUSABLE_LIBRARY_SOURCE_QUALIFICATION_V1_FORMAT,
            "status": "checked",
            "component_id": self.component_id,
            "interface_sha256": self.interface_sha256,
            "source_package_sha256": self.source_package_sha256,
            "proof_receipt_sha256s": list(self.proof_receipt_sha256s),
            "checks": [canonical(dict(item)) for item in self.checks],
            "policy": {
                "original_binary_executed": False,
                "tests_authorize": False,
                "static_proof_required": True,
            },
        }
        return {**core, "receipt_sha256": self.receipt_sha256}


@dataclass(frozen=True)
class ReusableLibraryBehaviorPackV3:
    root: Path
    manifest: Mapping[str, object]
    implementation: ReusableLibraryImplementationV1
    interface_intent: ComponentInterfaceIntentV1
    source: Mapping[str, object]
    qualification: ReusableLibrarySourceQualificationV1

    @property
    def pack_sha256(self) -> str:
        return str(self.manifest["pack_sha256"])


def build_reusable_library_behavior_pack_v3(
    *,
    implementation: Path | str,
    interface_intent: Path | str,
    source_package: Path | str,
    qualification: Path | str,
    out_dir: Path | str,
) -> ReusableLibraryBehaviorPackV3:
    """Copy and content-bind one V5 interface and qualified portable source."""

    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1.write(
        output / "implementation.json",
        REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1.read(implementation),
    )
    _copy_json(Path(interface_intent), output / "component-interface-intent-v1.json")
    _copy_tree(Path(source_package), output / "source-package")
    _copy_json(Path(qualification), output / "source-qualification-v1.json")
    checked = _validate_inputs(output)
    core = _manifest_core(output, **checked)
    write_json(
        output / "behavior-pack.json",
        {**core, "pack_sha256": canonical_sha256_v3(core)},
    )
    return load_reusable_library_behavior_pack_v3(output)


def load_reusable_library_behavior_pack_v3(
    value: Path | str,
) -> ReusableLibraryBehaviorPackV3:
    root = Path(value)
    if root.is_file():
        root = root.parent
    manifest = _read_json(root / "behavior-pack.json", "behavior-pack manifest")
    expected_fields = {
        "format",
        "status",
        "id",
        "implementation_id",
        "implementation_sha256",
        "component_id",
        "interface_intent_sha256",
        "interface_sha256",
        "source_package_sha256",
        "operation_symbols",
        "qualification_receipt_sha256",
        "artifacts",
        "policy",
        "pack_sha256",
    }
    if set(manifest) != expected_fields:
        raise ReusableLibraryBehaviorPackV3Error(
            "reusable library behavior-pack fields are not canonical"
        )
    if manifest.get("format") != REUSABLE_LIBRARY_BEHAVIOR_PACK_V3_FORMAT:
        raise ReusableLibraryBehaviorPackV3Error(
            "unsupported reusable library behavior-pack format"
        )
    core = dict(manifest)
    claimed = core.pop("pack_sha256", None)
    if claimed != canonical_sha256_v3(core):
        raise ReusableLibraryBehaviorPackV3Error(
            "reusable library behavior-pack digest is stale"
        )
    try:
        checked = _validate_inputs(root)
    except ReusableLibraryBehaviorPackV3Error:
        raise
    except (OSError, ValueError) as error:
        raise ReusableLibraryBehaviorPackV3Error(
            f"reusable library behavior-pack artifact is invalid: {error}"
        ) from error
    if core != _manifest_core(root, **checked):
        raise ReusableLibraryBehaviorPackV3Error(
            "reusable library behavior-pack does not bind its artifacts"
        )
    return ReusableLibraryBehaviorPackV3(root, manifest, **checked)


def _validate_inputs(root: Path) -> dict[str, object]:
    implementation = REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1.read(
        root / "implementation.json"
    )
    if implementation.status != "complete":
        raise ReusableLibraryBehaviorPackV3Error(
            "reusable library implementation is incomplete"
        )
    interface_intent = ComponentInterfaceIntentV1.parse(
        _read_json(
            root / "component-interface-intent-v1.json", "component interface intent"
        )
    )
    interface = compile_component_interface_v5(interface_intent).interface
    source = load_component_source_package(root / "source-package")
    symbols = component_operation_symbols(source)
    qualification = ReusableLibrarySourceQualificationV1.parse(
        _read_json(
            root / "source-qualification-v1.json", "library source qualification"
        )
    )
    if (
        source.get("lift_unit_id") != interface.identity
        or set(symbols) != {item.identity for item in interface.operations}
        or qualification.component_id != interface.identity
        or qualification.interface_sha256 != interface.interface_sha256
        or qualification.source_package_sha256 != source.get("implementation_sha256")
        or implementation.interface_contract_ids != (interface.identity,)
        or implementation.effect_contract_ids
        != tuple(sorted(item.identity for item in interface.effects))
    ):
        raise ReusableLibraryBehaviorPackV3Error(
            "reusable library interface, source, implementation, or qualification disagrees"
        )
    mappings = {
        item.operation_id: item for item in implementation.operation_source_mappings
    }
    if set(mappings) != set(symbols):
        raise ReusableLibraryBehaviorPackV3Error(
            "reusable library operation source map is not total"
        )
    for operation_id, symbol in symbols.items():
        mapping = mappings[operation_id]
        if (
            mapping.source_id != interface.identity
            or mapping.source_symbol != symbol
            or mapping.source_sha256 != source["implementation_sha256"]
        ):
            raise ReusableLibraryBehaviorPackV3Error(
                f"reusable library operation {operation_id!r} source map is stale"
            )
    return {
        "implementation": implementation,
        "interface_intent": interface_intent,
        "source": source,
        "qualification": qualification,
    }


def _manifest_core(
    root: Path,
    *,
    implementation: ReusableLibraryImplementationV1,
    interface_intent: ComponentInterfaceIntentV1,
    source: Mapping[str, object],
    qualification: ReusableLibrarySourceQualificationV1,
) -> dict[str, object]:
    interface = compile_component_interface_v5(interface_intent).interface
    symbols = component_operation_symbols(source)
    identity = {
        "implementation_sha256": implementation.implementation_sha256,
        "interface_sha256": interface.interface_sha256,
        "source_package_sha256": source["implementation_sha256"],
        "qualification_receipt_sha256": qualification.receipt_sha256,
    }
    artifact_paths = {
        "implementation": "implementation.json",
        "interface_intent": "component-interface-intent-v1.json",
        "source_manifest": "source-package/source-package.json",
        "qualification": "source-qualification-v1.json",
    }
    return {
        "format": REUSABLE_LIBRARY_BEHAVIOR_PACK_V3_FORMAT,
        "status": "checked",
        "id": canonical_sha256_v3(identity),
        "implementation_id": implementation.implementation_id,
        "implementation_sha256": implementation.implementation_sha256,
        "component_id": interface.identity,
        "interface_intent_sha256": interface_intent.intent_sha256,
        "interface_sha256": interface.interface_sha256,
        "source_package_sha256": source["implementation_sha256"],
        "operation_symbols": symbols,
        "qualification_receipt_sha256": qualification.receipt_sha256,
        "artifacts": {
            name: {"path": relative, "sha256": sha256_file(root / relative)}
            for name, relative in sorted(artifact_paths.items())
        },
        "policy": {
            "recognition_authorizes": False,
            "adoption_requires_checked_island": True,
            "legacy_component_adapters_allowed": False,
            "tests_authorize": False,
        },
    }


def _copy_tree(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise ReusableLibraryBehaviorPackV3Error(
            "reusable library source package must be a directory"
        )
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)


def _copy_json(source: Path, destination: Path) -> None:
    if source.is_dir():
        candidates = tuple(sorted(source.glob("*.json")))
        if len(candidates) != 1:
            raise ReusableLibraryBehaviorPackV3Error(
                f"expected one JSON artifact in {source}"
            )
        source = candidates[0]
    destination.write_bytes(source.read_bytes())


def _read_json(path: Path, description: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReusableLibraryBehaviorPackV3Error(
            f"cannot read {description}: {error}"
        ) from error
    if not isinstance(value, Mapping):
        raise ReusableLibraryBehaviorPackV3Error(f"{description} must be an object")
    return dict(value)


__all__ = [
    "ReusableLibraryBehaviorPackV3",
    "ReusableLibraryBehaviorPackV3Error",
    "ReusableLibrarySourceQualificationV1",
    "build_reusable_library_behavior_pack_v3",
    "load_reusable_library_behavior_pack_v3",
]
