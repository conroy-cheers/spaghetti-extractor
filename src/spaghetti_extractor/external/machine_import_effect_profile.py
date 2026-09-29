"""Compose explicit native call contracts with independently derived C ABIs.

The output remains a static machine-import profile V2. Header extraction grants
no effects, and this composition grants no implementation qualification.
"""

from dataclasses import replace
from pathlib import Path

from .environment_boundaries import lower_machine_import_boundary_v1
from .machine_import_profiles import (
    MachineImportProfileError, STATIC_MACHINE_IMPORT_PROFILE_V2_FORMAT,
    load_machine_import_profile_set,
)
from ..util import write_json


def compose_native_callthrough_profile(*, abi_profile: Path, effect_profile: Path,
                                      out: Path) -> dict:
    abi = load_machine_import_profile_set([abi_profile])
    effects = load_machine_import_profile_set([effect_profile])
    if not abi.contracts or not effects.contracts:
        raise MachineImportProfileError("ABI/effect composition requires nonempty profiles")
    by_identity = abi.by_identity()
    selected = effects.by_identity()
    if not set(selected) <= set(by_identity):
        raise MachineImportProfileError("effect contract names an import absent from the ABI profile")
    rows = []
    for contract in abi.contracts:
        original = dict(contract.contract)
        canonical = original.get("canonical_boundary")
        if canonical is None:
            raise MachineImportProfileError("effect composition requires a canonical physical ABI")
        if any(key in original for key in ("memory_effect", "world_effect", "effect_model")):
            raise MachineImportProfileError("ABI input already carries semantic effects")
        effect = selected.get(contract.identity)
        combined = original
        if effect is not None:
            explicit = dict(effect.contract)
            if explicit.get("effect_model", {}).get("kind") != "exact_native_dll_callthrough_v1":
                raise MachineImportProfileError("effect composition currently requires explicit native callthrough")
            if "canonical_boundary" in explicit:
                raise MachineImportProfileError("effect input must not replace the canonical physical ABI")
            for field in ("abi_template", "arity", "result_register_relations"):
                if explicit.get(field) != original.get(field):
                    raise MachineImportProfileError(f"effect contract disagrees with physical ABI: {field}")
            combined = {**explicit, "canonical_boundary": canonical,
                        "abi_provenance": original.get("provenance")}
        # Exercise the ordinary ABI checker, including hidden aggregate returns.
        # Its semantic-field restrictions remain in force.
        lower_machine_import_boundary_v1(
            replace(contract, contract=combined), abi_dialect="pe32-i386-gnu-v1")
        combined = dict(combined)
        for field in ("callback_effect", "profile_id", "source_profile_binding"):
            combined.pop(field, None)
        combined["override"] = True
        rows.append(combined)
    result = {
        "format": STATIC_MACHINE_IMPORT_PROFILE_V2_FORMAT,
        "id": effects.profiles[-1].profile_id + "-with-physical-abi",
        "status": "complete",
        "provenance": {
            "kind": "explicit_native_effects_with_canonical_abi",
            "abi_profiles": [{"id": p.profile_id, "sha256": p.sha256} for p in abi.profiles],
            "effect_profiles": [{"id": p.profile_id, "sha256": p.sha256} for p in effects.profiles],
        },
        "machine_import_signatures": rows,
    }
    write_json(out, result)
    return result
