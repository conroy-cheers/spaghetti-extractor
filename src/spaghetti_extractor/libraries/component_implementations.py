"""Library-owned adapters into the universal component implementation model."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..components.implementation import (
    ComponentImplementationError,
    ComponentImplementationV3,
    create_component_implementation_v3,
)
from ..components.universal_binding import (
    ComponentMachineBindingV3,
    read_component_machine_binding_v3,
)
from ..components.universal_contract import (
    ComponentContractV3,
    read_component_contract_v3,
)
from .v4_adoption_records import CHECKED_LIBRARY_ISLAND_CODEC_V1
from .v4_behavior_pack import load_reusable_library_behavior_pack_v1


def adapt_library_behavior_pack_implementation_v3(
    *,
    implementation_id: str,
    contract: ComponentContractV3 | Path | str | Mapping[str, object],
    machine_binding: ComponentMachineBindingV3 | Path | str | Mapping[str, object],
    behavior_pack: Path | str,
    checked_island: Path | str,
    out: Path | str | None = None,
) -> ComponentImplementationV3:
    """Adapt an independently checked library source pack as portable C."""

    checked_contract = (
        contract
        if isinstance(contract, ComponentContractV3)
        else read_component_contract_v3(contract)
    )
    binding = (
        machine_binding
        if isinstance(machine_binding, ComponentMachineBindingV3)
        else read_component_machine_binding_v3(machine_binding)
    )
    pack = load_reusable_library_behavior_pack_v1(behavior_pack)
    island_path = Path(checked_island)
    if island_path.is_dir():
        island_path = island_path / "checked-library-island.json"
    island = CHECKED_LIBRARY_ISLAND_CODEC_V1.read(island_path)
    issues: list[dict[str, object]] = []
    if binding.contract_sha256 != checked_contract.contract_sha256:
        issues.append(
            {"status": "violated", "code": "library_machine_contract_stale"}
        )
    if not binding.authorizing:
        issues.append(
            {"status": "incomplete", "code": "library_machine_binding_not_checked"}
        )
    if island.status != "complete":
        issues.append(
            {"status": "incomplete", "code": "checked_library_island_incomplete"}
        )
    if island.implementation_sha256 != pack.implementation.implementation_sha256:
        issues.append(
            {"status": "violated", "code": "library_behavior_pack_binding_stale"}
        )
    if set(island.checked_operation_ids) != {
        item.operation_id for item in checked_contract.operations
    }:
        issues.append(
            {"status": "violated", "code": "library_operation_inventory_mismatch"}
        )
    source_sha256 = pack.source.get("implementation_sha256")
    if not isinstance(source_sha256, str):
        raise ComponentImplementationError(
            "reusable library behavior pack has no source implementation digest"
        )
    authority_sha256 = canonical_sha256_v3(
        {
            "behavior_pack_sha256": pack.pack_sha256,
            "checked_island_sha256": island.receipt_sha256,
            "machine_binding_sha256": binding.binding_sha256,
        }
    )
    return create_component_implementation_v3(
        implementation_id=implementation_id,
        contract=checked_contract,
        kind="portable_c",
        artifact_kind="reusable_library_source_package",
        artifact_sha256=source_sha256,
        authority_kind="checked_library_behavior_pack_adoption",
        authority_sha256=authority_sha256,
        realization={
            "kind": "native_component_runtime",
            "symbol_set": checked_contract.component_id,
        },
        issues=issues,
        out=out,
    )


def adapt_pinned_binary_implementation_v3(
    *,
    implementation_id: str,
    contract: ComponentContractV3 | Path | str | Mapping[str, object],
    checked_island: Path | str,
    pinned_artifact: Path | str,
    realization: Mapping[str, object],
    out: Path | str | None = None,
) -> ComponentImplementationV3:
    """Adapt one exactly identified library binary behind a checked contract."""

    checked_contract = (
        contract
        if isinstance(contract, ComponentContractV3)
        else read_component_contract_v3(contract)
    )
    island_path = Path(checked_island)
    if island_path.is_dir():
        island_path = island_path / "checked-library-island.json"
    island = CHECKED_LIBRARY_ISLAND_CODEC_V1.read(island_path)
    issues: list[dict[str, object]] = []
    if island.status != "complete":
        issues.append(
            {"status": "incomplete", "code": "checked_library_island_incomplete"}
        )
    if set(island.checked_operation_ids) != {
        item.operation_id for item in checked_contract.operations
    }:
        issues.append(
            {"status": "violated", "code": "pinned_operation_inventory_mismatch"}
        )
    return create_component_implementation_v3(
        implementation_id=implementation_id,
        contract=checked_contract,
        kind="pinned_binary",
        artifact_kind="pinned_library_binary",
        artifact_sha256=_file_sha256(Path(pinned_artifact)),
        authority_kind="checked_library_island_v1",
        authority_sha256=island.receipt_sha256,
        realization=realization,
        issues=issues,
        out=out,
    )


def _file_sha256(path: Path) -> str:
    if not path.is_file():
        raise ComponentImplementationError(
            "pinned binary implementation requires one exact file artifact"
        )
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "adapt_library_behavior_pack_implementation_v3",
    "adapt_pinned_binary_implementation_v3",
]
