"""Exact imported-call ABI inventories derived from reviewed DLL policies."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .machine_abi import MachineCallABI, resolve_machine_call_abi
from .machine_import_profiles import (
    MachineImportIdentity,
    load_machine_import_profile_set,
)
from .stage_binary import StageAInputError, _parse_stage_a_pe
from .util import sha256_file, write_json


IMPORT_ABI_POLICY_FORMAT = "stage-a-import-abi-policy-v1"
EXPANDED_IMPORT_ABI_FORMAT = "stage-a-static-machine-import-profile-v1"


@dataclass(frozen=True)
class SelectedImportABI:
    identity: MachineImportIdentity
    abi: MachineCallABI
    profile_id: str
    profile_sha256: str
    entry_key: str
    entry_index: int
    argument_words: int | None = None
    contract: Mapping[str, Any] | None = None

    def as_json(self) -> dict[str, Any]:
        imported: dict[str, Any] = {"dll": self.identity.dll}
        imported[self.identity.kind] = self.identity.value
        result = {
            "import": imported,
            "abi": self.abi.as_json(),
            "profile_binding": {
                "profile_id": self.profile_id,
                "profile_sha256": self.profile_sha256,
                "entry_key": self.entry_key,
                "entry_index": self.entry_index,
            },
        }
        if self.argument_words is not None:
            result["argument_words"] = self.argument_words
        contract = self.contract
        disposition = (
            contract.get("disposition")
            if isinstance(contract, Mapping)
            else None
        )
        if disposition in {"returns", "terminates"}:
            result["disposition"] = disposition
        return result


def expand_import_abi_policy(
    *, original_pe: Path, policy: Path, out: Path
) -> dict[str, Any]:
    """Expand reviewed DLL rules into exact identities from one pinned PE."""

    policy_path = Path(policy).resolve()
    try:
        payload = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read import ABI policy: {exc}") from exc
    if not isinstance(payload, Mapping) or payload.get("format") != IMPORT_ABI_POLICY_FORMAT:
        raise StageAInputError("unsupported import ABI policy format")
    policy_id = payload.get("id")
    rules = payload.get("rules")
    if not isinstance(policy_id, str) or not policy_id:
        raise StageAInputError("import ABI policy has no ID")
    if not isinstance(rules, list):
        raise StageAInputError("import ABI policy rules must be a list")

    by_dll: dict[str, str] = {}
    for index, raw in enumerate(rules):
        if not isinstance(raw, Mapping):
            raise StageAInputError(f"import ABI policy rule {index} must be an object")
        if set(raw) != {"dll", "abi_template"}:
            raise StageAInputError(
                f"import ABI policy rule {index} fields do not match"
            )
        dll = raw.get("dll")
        template = raw.get("abi_template")
        if not isinstance(dll, str) or not dll:
            raise StageAInputError(f"import ABI policy rule {index} has no DLL")
        normalized = dll.lower()
        if normalized in by_dll:
            raise StageAInputError(f"duplicate import ABI policy DLL {normalized}")
        if resolve_machine_call_abi(template) is None:
            raise StageAInputError(
                f"import ABI policy rule {index} has an unsupported template"
            )
        by_dll[normalized] = str(template)

    binary = _parse_stage_a_pe(Path(original_pe).resolve())
    try:
        rows: dict[tuple[str, str, str | int], dict[str, Any]] = {}
        missing: set[str] = set()
        for imported in binary.imports:
            dll = imported.dll.lower()
            template = by_dll.get(dll)
            if template is None:
                missing.add(dll)
                continue
            kind = "symbol" if imported.symbol is not None else "ordinal"
            value: str | int = (
                str(imported.symbol)
                if imported.symbol is not None
                else int(imported.ordinal)
            )
            identity = (dll, kind, value)
            import_row: dict[str, Any] = {"dll": dll, kind: value}
            rows[identity] = {
                "import": import_row,
                "abi_template": template,
                "provenance": {
                    "kind": "exact_pe_import_under_reviewed_dll_abi_policy",
                    "thunk_rva": int(imported.thunk_rva),
                    "policy_id": policy_id,
                },
            }
        if missing:
            raise StageAInputError(
                "import ABI policy does not cover DLLs: " + ", ".join(sorted(missing))
            )
        entries = []
        for index, identity in enumerate(sorted(rows)):
            entries.append({"id": index, **rows[identity]})
        result = {
            "format": EXPANDED_IMPORT_ABI_FORMAT,
            "id": f"{policy_id}:{binary.sha256[:16]}",
            "status": "complete",
            "source_policy": {
                "id": policy_id,
                "path": policy_path.name,
                "sha256": sha256_file(policy_path),
            },
            "source_binary": {
                "sha256": binary.sha256,
                "machine": binary.machine,
                "bitness": binary.bitness,
            },
            "machine_import_signatures": entries,
            "counts": {
                "imports": len(entries),
                "dlls": len({identity[0] for identity in rows}),
            },
        }
    finally:
        binary.pe.close()
    write_json(Path(out), result)
    return result


def load_selected_import_abis(
    profile_paths: Sequence[Path | str],
) -> dict[MachineImportIdentity, SelectedImportABI]:
    profile_set = load_machine_import_profile_set(profile_paths)
    result: dict[MachineImportIdentity, SelectedImportABI] = {}
    for selected in profile_set.contracts:
        abi = resolve_machine_call_abi(selected.contract.get("abi_template"))
        if abi is None:
            raise StageAInputError(
                "machine import profile entry has no supported ABI template: "
                f"{selected.identity.dll}!{selected.identity.value}"
            )
        result[selected.identity] = SelectedImportABI(
            identity=selected.identity,
            abi=abi,
            profile_id=selected.profile_id,
            profile_sha256=selected.profile_sha256,
            entry_key=selected.entry_key,
            entry_index=selected.entry_index,
            argument_words=selected.argument_words,
            contract=copy.deepcopy(dict(selected.contract)),
        )
    return result


__all__ = [
    "EXPANDED_IMPORT_ABI_FORMAT",
    "IMPORT_ABI_POLICY_FORMAT",
    "SelectedImportABI",
    "expand_import_abi_policy",
    "load_selected_import_abis",
]
