#!/usr/bin/env python3
"""Instantiate the constructive source inventory generator for GNU hello.

This driver treats generated Lean declarations and equality witnesses as inputs.
It derives numeric bindings from the exact JSON/Lean inventories, but never
manufactures proof terms when a generated module does not expose one.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from spaghetti_extractor.relational.lean.interpreter_mixed_constructive_source_inventory import (
    CheckedKernelEntryBinding,
    ConstructiveClassifierTerms,
    ConstructiveSourceInventorySpec,
    ConstructiveSourceInventoryGenerationError,
    ConstructiveSourceRuleBinding,
    ExactSemanticSourceBinding,
    build_constructive_source_inventory_plan,
    write_constructive_source_inventory_bundle,
)


DRIVER_FORMAT = "stage-a-gnu-hello-constructive-source-inventory-driver-v1"
BINDINGS_FORMAT = "stage-a-gnu-hello-constructive-source-bindings-v1"
MIXED_PLAN_FORMAT = "stage-a-interpreter-mixed-original-v1"
STATIC_REACHABILITY_FORMAT = (
    "stage-a-interpreter-mixed-original-static-reachability-v1"
)
KERNEL_DATA_FORMAT = "stage-a-interpreter-kernel-data-inventory-v7"
COMPILED_KERNEL_FORMAT = "stage-a-relational-interpreter-kernel-plan-v2"
KERNEL_ABI_FORMAT = "stage-a-relational-interpreter-kernel-abi-plan-v1"

EXPECTED_OPERATIONS = (
    "programLookup",
    "interpreterStep",
    "runFunction",
    "invokeCall",
)

_TARGET_ROW_RE = re.compile(
    r"\{\s*id := (?P<id>[0-9]+),\s*regionIndex := (?P<region>[0-9]+),"
    r"\s*rva := (?P<rva>[0-9]+),\s*aliases :="
)
_SOURCE_RVAS_RE = re.compile(
    r"def generatedInterpreterKernelDataCertificatePack"
    r"(?P<pack>[0-9]+)SourceRvas : List Nat :=\s*"
    r"\[(?P<body>[0-9,\s]*)\]",
    re.MULTILINE,
)
_CANDIDATE_ROOT_RE = re.compile(
    r"def generatedInterpreterKernelCandidatePe : PE32 :=\s*"
    r"\{[^\n]*?\bentrypointRva := (?P<rva>[0-9]+)"
)
_LEAN_DECL_RE_TEMPLATE = (
    r"(?m)^\s*(?:def|theorem|lemma|structure|class|abbrev)\s+{name}\b"
)
_LEAN_FIELD_RE_TEMPLATE = r"(?m)^\s+{name}\s*:"


class GnuHelloConstructiveSourceInventoryError(ValueError):
    """An exact input is malformed, contradictory, duplicate, or ambiguous."""


@dataclass(frozen=True)
class TypedBlocker:
    code: str
    required_type: str
    detail: str
    missing_count: int | None = None
    examples: tuple[str, ...] = ()

    def payload(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "code": self.code,
            "required_type": self.required_type,
            "detail": self.detail,
        }
        if self.missing_count is not None:
            result["missing_count"] = self.missing_count
        if self.examples:
            result["examples"] = list(self.examples)
        return result


@dataclass(frozen=True)
class DerivedGnuHelloInventory:
    reachable_target_ids: tuple[int, ...]
    target_source_rvas: tuple[tuple[int, int], ...]
    record_source_rvas: tuple[int, ...]
    candidate_record_count: int
    launch_root_target_id: int
    launch_root_source_rva: int
    candidate_root_rva: int
    operation_entries: tuple[tuple[str, int], ...]

    def payload(self) -> dict[str, Any]:
        record_index_by_rva = {
            source_rva: index
            for index, source_rva in enumerate(self.record_source_rvas)
        }
        source_rvas_json = json.dumps(
            list(self.record_source_rvas),
            separators=(",", ":"),
        ).encode("utf-8")
        return {
            "reachable_target_ids": list(self.reachable_target_ids),
            "target_source_rvas": [
                {"target_id": target_id, "source_rva": source_rva}
                for target_id, source_rva in self.target_source_rvas
            ],
            "source_record_bindings": [
                {
                    "target_id": target_id,
                    "source_rva": source_rva,
                    "record_index": record_index_by_rva[source_rva],
                }
                for target_id, source_rva in self.target_source_rvas
            ],
            "candidate_record_count": self.candidate_record_count,
            "record_source_rvas_sha256": hashlib.sha256(
                source_rvas_json
            ).hexdigest(),
            "launch_root_target_id": self.launch_root_target_id,
            "launch_root_source_rva": self.launch_root_source_rva,
            "candidate_root_rva": self.candidate_root_rva,
            "operation_entries": [
                {"operation": operation, "entry_rva": entry_rva}
                for operation, entry_rva in self.operation_entries
            ],
        }


@dataclass(frozen=True)
class GnuHelloConstructiveSourceInventoryPlan:
    derived: DerivedGnuHelloInventory
    input_sha256s: tuple[tuple[str, str], ...]
    blockers: tuple[TypedBlocker, ...]
    spec: ConstructiveSourceInventorySpec | None

    def payload(self) -> dict[str, Any]:
        return {
            "format": DRIVER_FORMAT,
            "acceptance_authority": False,
            "generator_spec_emitted": self.spec is not None,
            "inputs": {
                name: {"sha256": digest}
                for name, digest in self.input_sha256s
            },
            "derived": self.derived.payload(),
            "typed_blockers": [blocker.payload() for blocker in self.blockers],
        }


def _read_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GnuHelloConstructiveSourceInventoryError(
            f"{label} is not readable JSON: {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise GnuHelloConstructiveSourceInventoryError(
            f"{label} must be a JSON object: {path}"
        )
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise GnuHelloConstructiveSourceInventoryError(
            f"cannot hash exact input {path}: {exc}"
        ) from exc
    return digest.hexdigest()


def _expect_format(value: Mapping[str, Any], expected: str, *, label: str) -> None:
    actual = value.get("format")
    if actual != expected:
        raise GnuHelloConstructiveSourceInventoryError(
            f"{label} format must be {expected!r}, got {actual!r}"
        )


def _nat(value: Any, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise GnuHelloConstructiveSourceInventoryError(
            f"{label} must be a natural number"
        )
    return value


def _object(value: Any, *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise GnuHelloConstructiveSourceInventoryError(
            f"{label} must be an object"
        )
    return value


def _list(value: Any, *, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise GnuHelloConstructiveSourceInventoryError(
            f"{label} must be a list"
        )
    return value


def _string(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise GnuHelloConstructiveSourceInventoryError(
            f"{label} must be a non-empty string"
        )
    return value


def _nested(value: Mapping[str, Any], path: Sequence[str], *, label: str) -> Any:
    current: Any = value
    for component in path:
        if not isinstance(current, dict) or component not in current:
            joined = ".".join(path)
            raise GnuHelloConstructiveSourceInventoryError(
                f"{label} is missing {joined}"
            )
        current = current[component]
    return current


def _exact_nat_list(value: Any, *, label: str) -> tuple[int, ...]:
    result = tuple(
        _nat(item, label=f"{label}[{index}]")
        for index, item in enumerate(_list(value, label=label))
    )
    if tuple(sorted(result)) != result:
        raise GnuHelloConstructiveSourceInventoryError(
            f"{label} must be sorted"
        )
    if len(set(result)) != len(result):
        raise GnuHelloConstructiveSourceInventoryError(
            f"{label} contains duplicate target IDs"
        )
    return result


def _read_lean_sources(root: Path, pattern: str) -> tuple[tuple[Path, str], ...]:
    try:
        paths = sorted(root.glob(pattern))
    except OSError as exc:
        raise GnuHelloConstructiveSourceInventoryError(
            f"cannot inspect generated Lean root {root}: {exc}"
        ) from exc
    sources: list[tuple[Path, str]] = []
    for path in paths:
        try:
            sources.append((path, path.read_text(encoding="utf-8")))
        except OSError as exc:
            raise GnuHelloConstructiveSourceInventoryError(
                f"cannot read generated Lean module {path}: {exc}"
            ) from exc
    return tuple(sources)


def _parse_target_source_rvas(root: Path) -> dict[int, int]:
    sources = _read_lean_sources(
        root,
        "StageA/GeneratedRelationalInterpreterMixedOriginalFinalShard*.lean",
    )
    if not sources:
        raise GnuHelloConstructiveSourceInventoryError(
            "mixed-original generated source exposes no final target-index shards"
        )

    by_target: dict[int, int] = {}
    by_rva: dict[int, int] = {}
    for path, source in sources:
        for match in _TARGET_ROW_RE.finditer(source):
            target_id = int(match.group("id"))
            region_index = int(match.group("region"))
            source_rva = int(match.group("rva"))
            if target_id != region_index:
                raise GnuHelloConstructiveSourceInventoryError(
                    f"target {target_id} in {path} has regionIndex {region_index}"
                )
            if target_id in by_target:
                raise GnuHelloConstructiveSourceInventoryError(
                    f"duplicate target-to-RVA mapping for target {target_id}"
                )
            if source_rva in by_rva:
                raise GnuHelloConstructiveSourceInventoryError(
                    "ambiguous target-to-RVA mapping: "
                    f"targets {by_rva[source_rva]} and {target_id} both map to "
                    f"RVA {source_rva}"
                )
            by_target[target_id] = source_rva
            by_rva[source_rva] = target_id

    if not by_target:
        raise GnuHelloConstructiveSourceInventoryError(
            "mixed-original final shards contain no exact target-index rows"
        )
    return by_target


def _parse_record_source_rvas(
    root: Path,
    *,
    expected_pack_count: int,
    expected_record_count: int,
) -> tuple[int, ...]:
    sources = _read_lean_sources(
        root,
        "StageA/GeneratedInterpreterKernelDataAuthorityPack*.lean",
    )
    if not sources:
        raise GnuHelloConstructiveSourceInventoryError(
            "kernel-data generated source exposes no authority-pack modules"
        )

    by_pack: dict[int, tuple[int, ...]] = {}
    for path, source in sources:
        for match in _SOURCE_RVAS_RE.finditer(source):
            pack = int(match.group("pack"))
            values = tuple(
                int(item)
                for item in re.findall(r"[0-9]+", match.group("body"))
            )
            if pack in by_pack:
                raise GnuHelloConstructiveSourceInventoryError(
                    f"duplicate kernel-data source-RVA certificate pack {pack}"
                )
            if not values:
                raise GnuHelloConstructiveSourceInventoryError(
                    f"kernel-data source-RVA certificate pack {pack} in {path} "
                    "is empty"
                )
            by_pack[pack] = values

    expected_packs = set(range(expected_pack_count))
    actual_packs = set(by_pack)
    if actual_packs != expected_packs:
        missing = sorted(expected_packs - actual_packs)
        extra = sorted(actual_packs - expected_packs)
        raise GnuHelloConstructiveSourceInventoryError(
            "kernel-data source-RVA certificate packs do not match inventory: "
            f"missing={missing}, extra={extra}"
        )

    values = tuple(value for pack in sorted(by_pack) for value in by_pack[pack])
    if len(values) != expected_record_count:
        raise GnuHelloConstructiveSourceInventoryError(
            "kernel-data source-RVA count does not match inventory: "
            f"{len(values)} != {expected_record_count}"
        )
    if len(set(values)) != len(values):
        duplicates = sorted(
            {value for value in values if values.count(value) > 1}
        )
        raise GnuHelloConstructiveSourceInventoryError(
            f"duplicate kernel-data source RVAs: {duplicates}"
        )
    return values


def _parse_candidate_root_rva(root: Path) -> int:
    sources = _read_lean_sources(
        root,
        "StageA/GeneratedInterpreterKernelDataBase.lean",
    )
    matches: list[int] = []
    for _, source in sources:
        matches.extend(
            int(match.group("rva"))
            for match in _CANDIDATE_ROOT_RE.finditer(source)
        )
    if len(matches) != 1:
        raise GnuHelloConstructiveSourceInventoryError(
            "kernel-data generated source must expose exactly one "
            "generatedInterpreterKernelCandidatePe entrypointRva, "
            f"found {matches}"
        )
    return matches[0]


def _operation_map(
    compiled_kernel: Mapping[str, Any],
    kernel_abi: Mapping[str, Any],
) -> dict[str, int]:
    compiled_rows = _list(
        compiled_kernel.get("kernel_functions"),
        label="compiled-kernel kernel_functions",
    )
    compiled: dict[str, int] = {}
    for index, raw_row in enumerate(compiled_rows):
        row = _object(raw_row, label=f"kernel_functions[{index}]")
        role = row.get("role")
        if role not in EXPECTED_OPERATIONS:
            continue
        if role in compiled:
            raise GnuHelloConstructiveSourceInventoryError(
                f"duplicate compiled-kernel operation role {role}"
            )
        compiled[role] = _nat(
            row.get("rva_start"),
            label=f"kernel_functions[{index}].rva_start",
        )

    abi_rows = _list(kernel_abi.get("operations"), label="kernel-ABI operations")
    abi: dict[str, int] = {}
    for index, raw_row in enumerate(abi_rows):
        row = _object(raw_row, label=f"operations[{index}]")
        role = row.get("role")
        if role not in EXPECTED_OPERATIONS:
            raise GnuHelloConstructiveSourceInventoryError(
                f"unexpected kernel-ABI operation role {role!r}"
            )
        if role in abi:
            raise GnuHelloConstructiveSourceInventoryError(
                f"duplicate kernel-ABI operation role {role}"
            )
        abi[role] = _nat(
            row.get("image_offset"),
            label=f"operations[{index}].image_offset",
        )

    expected = set(EXPECTED_OPERATIONS)
    if set(compiled) != expected or set(abi) != expected:
        raise GnuHelloConstructiveSourceInventoryError(
            "compiled-kernel and ABI inventories must each expose exactly "
            f"{list(EXPECTED_OPERATIONS)}; "
            f"compiled={sorted(compiled)}, abi={sorted(abi)}"
        )
    for operation in EXPECTED_OPERATIONS:
        if compiled[operation] != abi[operation]:
            raise GnuHelloConstructiveSourceInventoryError(
                f"compiled-kernel/ABI entry mismatch for {operation}: "
                f"{compiled[operation]} != {abi[operation]}"
            )
    return compiled


def _validate_input_cross_links(
    *,
    mixed_plan_path: Path,
    mixed: Mapping[str, Any],
    static: Mapping[str, Any],
    kernel_data_path: Path,
    kernel_data: Mapping[str, Any],
    compiled_kernel_path: Path,
    compiled_kernel: Mapping[str, Any],
    kernel_abi: Mapping[str, Any],
) -> None:
    mixed_sha = _sha256(mixed_plan_path)
    static_mixed_sha = _nested(
        static,
        ("inputs", "mixed_original_plan", "sha256"),
        label="static-reachability plan",
    )
    if static_mixed_sha != mixed_sha:
        raise GnuHelloConstructiveSourceInventoryError(
            "static-reachability plan does not consume the supplied exact "
            f"mixed-original plan: {static_mixed_sha!r} != {mixed_sha!r}"
        )

    mixed_machine = mixed.get("state_machine_sha256")
    static_machine = _nested(
        static,
        ("inputs", "state_machine_sha256"),
        label="static-reachability plan",
    )
    data_machine = kernel_data.get("state_machine_sha256")
    if not all(
        isinstance(digest, str) and digest
        for digest in (mixed_machine, static_machine, data_machine)
    ):
        raise GnuHelloConstructiveSourceInventoryError(
            "state-machine digests must be non-empty strings"
        )
    if mixed_machine != static_machine or mixed_machine != data_machine:
        raise GnuHelloConstructiveSourceInventoryError(
            "mixed-original, static-reachability, and kernel-data inventories "
            "do not consume the same state-machine digest"
        )

    data_sha = _sha256(kernel_data_path)
    abi_data_sha = _nested(
        kernel_abi,
        ("inputs", "data_inventory", "sha256"),
        label="kernel-ABI plan",
    )
    if abi_data_sha != data_sha:
        raise GnuHelloConstructiveSourceInventoryError(
            "kernel-ABI plan does not consume the supplied exact kernel-data "
            f"inventory: {abi_data_sha!r} != {data_sha!r}"
        )

    compiled_sha = _sha256(compiled_kernel_path)
    abi_compiled_sha = _nested(
        kernel_abi,
        ("inputs", "kernel_plan", "sha256"),
        label="kernel-ABI plan",
    )
    if abi_compiled_sha != compiled_sha:
        raise GnuHelloConstructiveSourceInventoryError(
            "kernel-ABI plan does not consume the supplied exact "
            f"compiled-kernel plan: {abi_compiled_sha!r} != {compiled_sha!r}"
        )

    data_candidate = kernel_data.get("candidate_sha256")
    compiled_candidate = _nested(
        compiled_kernel,
        ("candidate", "pe_sha256"),
        label="compiled-kernel plan",
    )
    abi_candidate = kernel_abi.get("candidate_pe_sha256")
    if not all(
        isinstance(digest, str) and digest
        for digest in (data_candidate, compiled_candidate, abi_candidate)
    ):
        raise GnuHelloConstructiveSourceInventoryError(
            "candidate PE digests must be non-empty strings"
        )
    if len({data_candidate, compiled_candidate, abi_candidate}) != 1:
        raise GnuHelloConstructiveSourceInventoryError(
            "kernel-data, compiled-kernel, and ABI inventories do not consume "
            "the same candidate PE digest"
        )


def _declared_term(
    term: str,
    *,
    parameter_name: str,
    binding_source: str,
    all_sources: Sequence[str],
) -> bool:
    if term.startswith(parameter_name + "."):
        first_projection = term[len(parameter_name) + 1 :].split(".", 1)[0]
        return (
            re.search(
                _LEAN_FIELD_RE_TEMPLATE.format(
                    name=re.escape(first_projection)
                ),
                binding_source,
            )
            is not None
        )

    declaration = term.rsplit(".", 1)[-1]
    declaration_re = re.compile(
        _LEAN_DECL_RE_TEMPLATE.format(name=re.escape(declaration))
    )
    return any(declaration_re.search(source) for source in all_sources)


def _find_binding_source(
    roots: Sequence[Path],
    *,
    binding_module: str,
) -> tuple[str, tuple[str, ...]]:
    stem = binding_module.rsplit(".", 1)[-1] + ".lean"
    matches: list[Path] = []
    all_sources: list[str] = []
    for root in roots:
        for path in sorted(root.glob("StageA/*.lean")):
            try:
                source = path.read_text(encoding="utf-8")
            except OSError as exc:
                raise GnuHelloConstructiveSourceInventoryError(
                    f"cannot read generated Lean module {path}: {exc}"
                ) from exc
            all_sources.append(source)
            if path.name == stem:
                matches.append(path)
    unique_matches = tuple(dict.fromkeys(matches))
    if len(unique_matches) != 1:
        raise GnuHelloConstructiveSourceInventoryError(
            f"binding module {binding_module} must resolve to exactly one "
            f"generated Lean file, found {[str(path) for path in unique_matches]}"
        )
    return (
        unique_matches[0].read_text(encoding="utf-8"),
        tuple(all_sources),
    )


def _missing_binding_blockers(
    derived: DerivedGnuHelloInventory,
) -> tuple[TypedBlocker, ...]:
    blockers: list[TypedBlocker] = []
    reachable_count = len(derived.reachable_target_ids)
    record_count = derived.candidate_record_count

    blockers.extend(
        (
            TypedBlocker(
                code="constructive_classifier_terms_missing",
                required_type=(
                    "candidate : ExactNativeWorldProgram; "
                    "candidateAuthority : ExactNativeCandidateAuthority "
                    "candidate; kernelDispatches : KernelDispatchRelation; "
                    "relationContract : MixedRelationContract"
                ),
                detail=(
                    "the supplied generated modules expose the decoded original "
                    "terms, compiled program, and kernel ABI, but not these four "
                    "typed classifier inputs"
                ),
                missing_count=4,
            ),
            TypedBlocker(
                code="launch_root_target_id_equality_missing",
                required_type=(
                    "generatedOriginalLaunch.rootTargetId = "
                    f"{derived.launch_root_target_id}"
                ),
                detail="no supplied generated binding module names this equality",
            ),
            TypedBlocker(
                code="candidate_record_count_equality_missing",
                required_type=(
                    "candidateAuthority.semanticRecords.length = "
                    f"{record_count}"
                ),
                detail="no supplied generated binding module names this equality",
            ),
            TypedBlocker(
                code="reachability_target_ids_equality_missing",
                required_type=(
                    "exactReachability.targetIds = "
                    "generatedReachableTargetIds"
                ),
                detail="no supplied generated binding module names this equality",
            ),
            TypedBlocker(
                code="candidate_root_rva_equality_missing",
                required_type=(
                    "candidateRootRvaExact : requirements.candidate_root_rva = "
                    f"{derived.candidate_root_rva}"
                ),
                detail=(
                    "the exact candidate PE exposes this entrypoint RVA, but no "
                    "supplied generated module names the required equality"
                ),
            ),
        )
    )

    source_examples: list[str] = []
    record_index_by_rva = {
        source_rva: index
        for index, source_rva in enumerate(derived.record_source_rvas)
    }
    for target_id, source_rva in derived.target_source_rvas[:2]:
        record_index = record_index_by_rva.get(source_rva)
        source_examples.extend(
            (
                f"source{target_id}.targetId = {target_id}",
                f"source{target_id}.source.target.rva = {source_rva}",
            )
        )
        if record_index is not None:
            source_examples.append(
                "candidateAuthority.semanticRecords"
                f"[{record_index}]? = some source{target_id}.record"
            )
    blockers.append(
        TypedBlocker(
            code="exact_source_witness_inventory_missing",
            required_type=(
                "for each reachable target: ExactOriginalSemanticSource "
                "originalProgram candidate, plus named target-ID, source-RVA, "
                "and candidate-record lookup equalities"
            ),
            detail=(
                "the consumed generated modules do not expose the exact "
                "source-to-record witness inventory"
            ),
            missing_count=reachable_count,
            examples=tuple(source_examples),
        )
    )

    for operation, entry_rva in derived.operation_entries:
        blockers.append(
            TypedBlocker(
                code=f"{operation}_function_entry_equality_missing",
                required_type=(
                    "generatedCompiledKernelProgram.functionEntry? "
                    f"KernelOperation.{operation}.role = some {entry_rva}"
                ),
                detail=(
                    "the compiled-kernel/ABI inventories agree numerically, but "
                    "no supplied generated module names this equality"
                ),
            )
        )
    blockers.append(
        TypedBlocker(
            code="deterministic_source_rules_missing",
            required_type=(
                "one ConstructiveSourceRuleBinding for each exact source, "
                "with exactly one launch rule and all four operation entries used"
            ),
            detail=(
                "the consumed exact inventories do not define the constructive "
                "rule assignment"
            ),
            missing_count=reachable_count,
        )
    )
    return tuple(blockers)


def _build_spec_from_bindings(
    *,
    derived: DerivedGnuHelloInventory,
    bindings: Mapping[str, Any],
    source_roots: Sequence[Path],
) -> tuple[ConstructiveSourceInventorySpec | None, tuple[TypedBlocker, ...]]:
    _expect_format(bindings, BINDINGS_FORMAT, label="binding inventory")
    binding_module = _string(
        bindings.get("binding_module"),
        label="binding_inventory.binding_module",
    )
    parameter_name = _string(
        bindings.get("parameter_name"),
        label="binding_inventory.parameter_name",
    )
    parameter_type = _string(
        bindings.get("parameter_type"),
        label="binding_inventory.parameter_type",
    )
    namespace = _string(
        bindings.get("namespace"),
        label="binding_inventory.namespace",
    )
    terms_raw = _object(bindings.get("terms"), label="binding_inventory.terms")

    term_fields = tuple(ConstructiveClassifierTerms.__dataclass_fields__)
    missing_term_fields = sorted(set(term_fields) - set(terms_raw))
    extra_term_fields = sorted(set(terms_raw) - set(term_fields))
    if missing_term_fields or extra_term_fields:
        raise GnuHelloConstructiveSourceInventoryError(
            "binding inventory classifier terms must match the generic "
            f"generator exactly: missing={missing_term_fields}, "
            f"extra={extra_term_fields}"
        )
    term_values = {
        field: _string(terms_raw[field], label=f"terms.{field}")
        for field in term_fields
    }
    terms = ConstructiveClassifierTerms(**term_values)

    if "candidate_root_rva" in bindings:
        binding_candidate_root_rva = _nat(
            bindings.get("candidate_root_rva"),
            label="binding_inventory.candidate_root_rva",
        )
        if binding_candidate_root_rva != derived.candidate_root_rva:
            raise GnuHelloConstructiveSourceInventoryError(
                "binding inventory candidate_root_rva contradicts the exact "
                f"candidate PE: {binding_candidate_root_rva} != "
                f"{derived.candidate_root_rva}"
            )
    binding_source, all_sources = _find_binding_source(
        source_roots,
        binding_module=binding_module,
    )

    missing_terms = sorted(
        term
        for term in term_values.values()
        if not _declared_term(
            term,
            parameter_name=parameter_name,
            binding_source=binding_source,
            all_sources=all_sources,
        )
    )
    blockers: list[TypedBlocker] = []
    if missing_terms:
        blockers.append(
            TypedBlocker(
                code="named_classifier_terms_missing",
                required_type="all ConstructiveClassifierTerms fields",
                detail=(
                    "binding inventory references terms not declared by supplied "
                    f"generated modules: {missing_terms}"
                ),
                missing_count=len(missing_terms),
            )
        )

    expected_targets = set(derived.reachable_target_ids)
    target_rva_by_id = dict(derived.target_source_rvas)
    record_index_by_rva = {
        source_rva: index
        for index, source_rva in enumerate(derived.record_source_rvas)
    }

    source_rows = _list(bindings.get("sources"), label="binding_inventory.sources")
    source_by_target: dict[int, Mapping[str, Any]] = {}
    for index, raw_row in enumerate(source_rows):
        row = _object(raw_row, label=f"sources[{index}]")
        target_id = _nat(row.get("target_id"), label=f"sources[{index}].target_id")
        if target_id in source_by_target:
            raise GnuHelloConstructiveSourceInventoryError(
                f"duplicate exact source binding for target {target_id}"
            )
        source_by_target[target_id] = row

    extra_sources = sorted(set(source_by_target) - expected_targets)
    missing_sources = sorted(expected_targets - set(source_by_target))
    if extra_sources:
        raise GnuHelloConstructiveSourceInventoryError(
            f"source bindings contain unreachable target IDs {extra_sources}"
        )
    if missing_sources:
        blockers.append(
            TypedBlocker(
                code="exact_source_witness_inventory_incomplete",
                required_type=(
                    "one ExactOriginalSemanticSource and three named exact "
                    "equalities for every reachable target"
                ),
                detail=f"missing target IDs {missing_sources[:16]}",
                missing_count=len(missing_sources),
            )
        )

    source_bindings: list[ExactSemanticSourceBinding] = []
    witness_terms: list[str] = []
    for target_id in derived.reachable_target_ids:
        row = source_by_target.get(target_id)
        if row is None:
            continue
        source_rva = target_rva_by_id[target_id]
        if source_rva not in record_index_by_rva:
            raise GnuHelloConstructiveSourceInventoryError(
                f"reachable target {target_id} source RVA {source_rva} has no "
                "unique candidate semantic record"
            )
        record_index = record_index_by_rva[source_rva]
        source_term = _string(
            row.get("source_term"),
            label=f"source {target_id} source_term",
        )
        target_exact = _string(
            row.get("target_id_exact"),
            label=f"source {target_id} target_id_exact",
        )
        rva_exact = _string(
            row.get("source_rva_exact"),
            label=f"source {target_id} source_rva_exact",
        )
        record_exact = _string(
            row.get("record_at_index_exact"),
            label=f"source {target_id} record_at_index_exact",
        )
        witness_terms.extend(
            (source_term, target_exact, rva_exact, record_exact)
        )
        source_bindings.append(
            ExactSemanticSourceBinding(
                name=f"source{target_id:08d}",
                target_id=target_id,
                source_rva=source_rva,
                record_index=record_index,
                source_term=source_term,
                target_id_exact=target_exact,
                source_rva_exact=rva_exact,
                record_at_index_exact=record_exact,
            )
        )

    entry_equalities = _object(
        bindings.get("operation_entry_equalities"),
        label="binding_inventory.operation_entry_equalities",
    )
    if set(entry_equalities) != set(EXPECTED_OPERATIONS):
        raise GnuHelloConstructiveSourceInventoryError(
            "operation_entry_equalities must contain exactly "
            f"{list(EXPECTED_OPERATIONS)}"
        )
    entries: list[CheckedKernelEntryBinding] = []
    for operation, entry_rva in derived.operation_entries:
        exact = _string(
            entry_equalities[operation],
            label=f"operation_entry_equalities.{operation}",
        )
        witness_terms.append(exact)
        entries.append(
            CheckedKernelEntryBinding(
                name=f"{operation}Entry",
                operation=operation,
                entry_rva=entry_rva,
                function_entry_exact=exact,
            )
        )

    rule_rows = _list(bindings.get("rules"), label="binding_inventory.rules")
    rule_by_target: dict[int, Mapping[str, Any]] = {}
    for index, raw_row in enumerate(rule_rows):
        row = _object(raw_row, label=f"rules[{index}]")
        target_id = _nat(row.get("target_id"), label=f"rules[{index}].target_id")
        if target_id in rule_by_target:
            raise GnuHelloConstructiveSourceInventoryError(
                f"duplicate deterministic rule for target {target_id}"
            )
        rule_by_target[target_id] = row
    if set(rule_by_target) != expected_targets:
        raise GnuHelloConstructiveSourceInventoryError(
            "rules must map exactly the reachable target IDs: "
            f"missing={sorted(expected_targets - set(rule_by_target))}, "
            f"extra={sorted(set(rule_by_target) - expected_targets)}"
        )

    rules: list[ConstructiveSourceRuleBinding] = []
    for source in source_bindings:
        row = rule_by_target[source.target_id]
        kind = _string(
            row.get("kind"),
            label=f"rule {source.target_id} kind",
        )
        operation_value = row.get("operation")
        operation = (
            None
            if operation_value is None
            else _string(
                operation_value,
                label=f"rule {source.target_id} operation",
            )
        )
        candidate_rva_value = row.get("candidate_rva")
        candidate_rva = (
            None
            if candidate_rva_value is None
            else _nat(
                candidate_rva_value,
                label=f"rule {source.target_id} candidate_rva",
            )
        )
        rules.append(
            ConstructiveSourceRuleBinding(
                source=source.name,
                kind=kind,
                entry=(
                    None if operation is None else f"{operation}Entry"
                ),
                candidate_rva=candidate_rva,
            )
        )

    missing_witness_terms = sorted(
        term
        for term in witness_terms
        if not _declared_term(
            term,
            parameter_name=parameter_name,
            binding_source=binding_source,
            all_sources=all_sources,
        )
    )
    if missing_witness_terms:
        blockers.append(
            TypedBlocker(
                code="named_source_or_entry_witnesses_missing",
                required_type=(
                    "all source target-ID/source-RVA/record-index equalities and "
                    "all four functionEntry? equalities"
                ),
                detail=(
                    "binding inventory references witnesses not declared by "
                    f"supplied generated modules: {missing_witness_terms}"
                ),
                missing_count=len(missing_witness_terms),
            )
        )

    if blockers:
        return None, tuple(blockers)

    spec = ConstructiveSourceInventorySpec(
        binding_module=binding_module,
        parameter_name=parameter_name,
        parameter_type=parameter_type,
        namespace=namespace,
        terms=terms,
        candidate_root_rva=derived.candidate_root_rva,
        launch_root_target_id=derived.launch_root_target_id,
        expected_target_ids=derived.reachable_target_ids,
        candidate_record_count=derived.candidate_record_count,
        expected_operations=EXPECTED_OPERATIONS,
        sources=tuple(source_bindings),
        entries=tuple(entries),
        rules=tuple(rules),
    )
    try:
        build_constructive_source_inventory_plan(spec)
    except ConstructiveSourceInventoryGenerationError as exc:
        raise GnuHelloConstructiveSourceInventoryError(
            f"generic constructive source inventory rejected GNU binding: {exc}"
        ) from exc
    return spec, ()


def plan_gnu_hello_constructive_source_inventory(
    *,
    mixed_original_plan_path: Path,
    static_reachability_plan_path: Path,
    kernel_data_inventory_path: Path,
    compiled_kernel_plan_path: Path,
    kernel_abi_plan_path: Path,
    mixed_original_source_root: Path,
    kernel_data_source_root: Path,
    binding_inventory_path: Path | None = None,
    additional_source_roots: Sequence[Path] = (),
) -> GnuHelloConstructiveSourceInventoryPlan:
    mixed = _read_json(mixed_original_plan_path, label="mixed-original plan")
    static = _read_json(
        static_reachability_plan_path,
        label="static-reachability plan",
    )
    kernel_data = _read_json(
        kernel_data_inventory_path,
        label="kernel-data inventory",
    )
    compiled_kernel = _read_json(
        compiled_kernel_plan_path,
        label="compiled-kernel plan",
    )
    kernel_abi = _read_json(kernel_abi_plan_path, label="kernel-ABI plan")

    _expect_format(mixed, MIXED_PLAN_FORMAT, label="mixed-original plan")
    _expect_format(
        static,
        STATIC_REACHABILITY_FORMAT,
        label="static-reachability plan",
    )
    _expect_format(kernel_data, KERNEL_DATA_FORMAT, label="kernel-data inventory")
    _expect_format(
        compiled_kernel,
        COMPILED_KERNEL_FORMAT,
        label="compiled-kernel plan",
    )
    _expect_format(kernel_abi, KERNEL_ABI_FORMAT, label="kernel-ABI plan")
    _validate_input_cross_links(
        mixed_plan_path=mixed_original_plan_path,
        mixed=mixed,
        static=static,
        kernel_data_path=kernel_data_inventory_path,
        kernel_data=kernel_data,
        compiled_kernel_path=compiled_kernel_plan_path,
        compiled_kernel=compiled_kernel,
        kernel_abi=kernel_abi,
    )

    reachable_target_ids = _exact_nat_list(
        mixed.get("reachable_target_ids"),
        label="mixed-original reachable_target_ids",
    )
    declared_reachable_count = _nat(
        _nested(
            static,
            ("counts", "reachable_targets"),
            label="static-reachability plan",
        ),
        label="static-reachability counts.reachable_targets",
    )
    if declared_reachable_count != len(reachable_target_ids):
        raise GnuHelloConstructiveSourceInventoryError(
            "static-reachability target count does not match exact target IDs"
        )

    target_source_rvas = _parse_target_source_rvas(mixed_original_source_root)
    missing_target_rows = sorted(
        set(reachable_target_ids) - set(target_source_rvas)
    )
    if missing_target_rows:
        raise GnuHelloConstructiveSourceInventoryError(
            "reachable target IDs have no exact mixed-original target-index row: "
            f"{missing_target_rows}"
        )

    record_count = _nat(
        _nested(
            kernel_data,
            ("counts", "records"),
            label="kernel-data inventory",
        ),
        label="kernel-data counts.records",
    )
    pack_count = _nat(
        _nested(
            kernel_data,
            ("counts", "certificate_packs"),
            label="kernel-data inventory",
        ),
        label="kernel-data counts.certificate_packs",
    )
    record_source_rvas = _parse_record_source_rvas(
        kernel_data_source_root,
        expected_pack_count=pack_count,
        expected_record_count=record_count,
    )
    record_rvas = set(record_source_rvas)
    missing_record_bindings = [
        {"target_id": target_id, "source_rva": target_source_rvas[target_id]}
        for target_id in reachable_target_ids
        if target_source_rvas[target_id] not in record_rvas
    ]
    if missing_record_bindings:
        raise GnuHelloConstructiveSourceInventoryError(
            "reachable mixed-original sources have no unique kernel-data "
            f"semantic record: {missing_record_bindings[:16]}"
        )
    candidate_root_rva = _parse_candidate_root_rva(kernel_data_source_root)

    compiled_record_count = _nat(
        _nested(
            compiled_kernel,
            ("program", "transfer_count"),
            label="compiled-kernel plan",
        ),
        label="compiled-kernel program.transfer_count",
    )
    abi_record_count = _nat(
        kernel_abi.get("program_records"),
        label="kernel-ABI program_records",
    )
    if record_count != compiled_record_count or record_count != abi_record_count:
        raise GnuHelloConstructiveSourceInventoryError(
            "kernel-data, compiled-kernel, and ABI record counts differ: "
            f"{record_count}, {compiled_record_count}, {abi_record_count}"
        )

    operation_entries = _operation_map(compiled_kernel, kernel_abi)
    launch_rva = _nat(
        mixed.get("entry_rva"),
        label="mixed-original entry_rva",
    )
    launch_matches = [
        target_id
        for target_id, source_rva in target_source_rvas.items()
        if source_rva == launch_rva
    ]
    if len(launch_matches) != 1:
        raise GnuHelloConstructiveSourceInventoryError(
            "mixed-original launch RVA must map to exactly one target ID, "
            f"found {launch_matches}"
        )
    launch_target_id = launch_matches[0]
    if launch_target_id not in set(reachable_target_ids):
        raise GnuHelloConstructiveSourceInventoryError(
            f"launch target {launch_target_id} is not statically reachable"
        )

    selected_target_rvas = tuple(
        (target_id, target_source_rvas[target_id])
        for target_id in reachable_target_ids
    )
    derived = DerivedGnuHelloInventory(
        reachable_target_ids=reachable_target_ids,
        target_source_rvas=selected_target_rvas,
        record_source_rvas=record_source_rvas,
        candidate_record_count=record_count,
        launch_root_target_id=launch_target_id,
        launch_root_source_rva=launch_rva,
        candidate_root_rva=candidate_root_rva,
        operation_entries=tuple(
            (operation, operation_entries[operation])
            for operation in EXPECTED_OPERATIONS
        ),
    )

    bindings: Mapping[str, Any] | None = None
    if binding_inventory_path is not None:
        bindings = _read_json(
            binding_inventory_path,
            label="constructive source binding inventory",
        )

    if bindings is None:
        spec = None
        blockers = _missing_binding_blockers(derived)
    else:
        spec, blockers = _build_spec_from_bindings(
            derived=derived,
            bindings=bindings,
            source_roots=(
                mixed_original_source_root,
                kernel_data_source_root,
                static_reachability_plan_path.parent,
                compiled_kernel_plan_path.parent,
                kernel_abi_plan_path.parent,
                *additional_source_roots,
            ),
        )

    input_paths = (
        ("mixed_original_plan", mixed_original_plan_path),
        ("static_reachability_plan", static_reachability_plan_path),
        ("kernel_data_inventory", kernel_data_inventory_path),
        ("compiled_kernel_plan", compiled_kernel_plan_path),
        ("kernel_abi_plan", kernel_abi_plan_path),
    )
    input_sha256s = tuple(
        (name, _sha256(path)) for name, path in input_paths
    )
    if binding_inventory_path is not None:
        input_sha256s += (
            ("constructive_source_bindings", _sha256(binding_inventory_path)),
        )
    return GnuHelloConstructiveSourceInventoryPlan(
        derived=derived,
        input_sha256s=input_sha256s,
        blockers=blockers,
        spec=spec,
    )


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Instantiate the exact GNU hello constructive source inventory "
            "without manufacturing Lean proof terms"
        )
    )
    parser.add_argument("--mixed-original-plan", type=Path, required=True)
    parser.add_argument("--static-reachability-plan", type=Path, required=True)
    parser.add_argument("--kernel-data-inventory", type=Path, required=True)
    parser.add_argument("--compiled-kernel-plan", type=Path, required=True)
    parser.add_argument("--kernel-abi-plan", type=Path, required=True)
    parser.add_argument("--mixed-original-source-root", type=Path)
    parser.add_argument("--kernel-data-source-root", type=Path)
    parser.add_argument("--additional-source-root", type=Path, action="append")
    parser.add_argument("--binding-inventory", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    mixed_root = (
        args.mixed_original_source_root
        if args.mixed_original_source_root is not None
        else args.mixed_original_plan.parent
    )
    data_root = (
        args.kernel_data_source_root
        if args.kernel_data_source_root is not None
        else args.kernel_data_inventory.parent
    )

    try:
        plan = plan_gnu_hello_constructive_source_inventory(
            mixed_original_plan_path=args.mixed_original_plan,
            static_reachability_plan_path=args.static_reachability_plan,
            kernel_data_inventory_path=args.kernel_data_inventory,
            compiled_kernel_plan_path=args.compiled_kernel_plan,
            kernel_abi_plan_path=args.kernel_abi_plan,
            mixed_original_source_root=mixed_root,
            kernel_data_source_root=data_root,
            binding_inventory_path=args.binding_inventory,
            additional_source_roots=tuple(args.additional_source_root or ()),
        )
        args.out.mkdir(parents=True, exist_ok=True)
        if plan.spec is not None:
            write_constructive_source_inventory_bundle(
                args.out,
                build_constructive_source_inventory_plan(plan.spec),
            )
        _write_json(
            args.out / "gnu-hello-constructive-source-inventory-driver.json",
            plan.payload(),
        )
    except GnuHelloConstructiveSourceInventoryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if plan.blockers:
        for blocker in plan.blockers:
            print(
                f"typed blocker [{blocker.code}]: "
                f"{blocker.required_type}: {blocker.detail}",
                file=sys.stderr,
            )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
