from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Mapping, Sequence

from .interpreter_mixed_original import (
    INTERPRETER_MIXED_ORIGINAL_BASE_MODULE,
    InterpreterMixedOriginalPlan,
    _lean_finite_index_height,
    _lean_index_refs,
)


class InterpreterMixedOriginalCertificateDecompositionError(ValueError):
    """The generated base source no longer has the checked partition shape."""


@dataclass(frozen=True)
class InterpreterMixedOriginalCertificateDecomposition:
    paths: tuple[Path, ...]
    resources: Mapping[str, Mapping[str, object]]


@dataclass(frozen=True)
class _IndexTree:
    expression: str
    size: int
    height: int
    maximum_balance: int
    leaf_index: int | None = None
    left: _IndexTree | None = None
    right: _IndexTree | None = None


@dataclass(frozen=True)
class _StructuralProof:
    expression: str
    size: int
    height: int
    checked: str
    size_checked: str
    height_checked: str


@dataclass(frozen=True)
class _RangeProof:
    start: int
    size: int
    range_name: str
    checked_name: str
    before: int | None = None
    after: int | None = None


_CERTIFICATE_MARKER = "\ndef generatedExactOriginalCodeMapCertificate :"
_CARRIER_MARKER = "\ndef generatedOriginalStaticTargetIndex :"
_STATIC_INDIRECT = re.compile(
    r"^def generatedOriginalStaticIndirect([0-9]+)Behavior",
    re.MULTILINE,
)
_LAUNCH_MARKER = "\ndef generatedOriginalLaunch :"
_REACHABILITY_MARKER = "\ndef generatedReachableTargetIds :"
_DIAGNOSTIC_MARKER = "\n\n-- Generation is fail-closed;"


def decompose_interpreter_mixed_original_base(
    out: Path | str,
    plan: InterpreterMixedOriginalPlan,
) -> InterpreterMixedOriginalCertificateDecomposition:
    """Replace one monolithic base with independently cached proof shards.

    This is deliberately a post-generation phase.  The semantic generator
    remains responsible for the exact data and local claims; this phase only
    changes module ownership and replaces global reductions with kernel-checked
    shard certificates.
    """

    root = Path(out)
    stage_a = root / "StageA"
    base_path = stage_a / f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}.lean"
    source = base_path.read_text(encoding="utf-8")
    namespace = f"{plan.spec.namespace}Base"
    shard_regions = [
        plan.regions[offset : offset + plan.spec.shard_size]
        for offset in range(0, len(plan.regions), plan.spec.shard_size)
    ]
    if not shard_regions:
        raise InterpreterMixedOriginalCertificateDecompositionError(
            "mixed-original certificate decomposition requires at least one shard"
        )

    certificate_offset = _unique_offset(source, _CERTIFICATE_MARKER)
    carrier_offset = _unique_offset(source, _CARRIER_MARKER)
    launch_offset = _unique_offset(source, _LAUNCH_MARKER)
    reachability_offset = _unique_offset(source, _REACHABILITY_MARKER)
    if not certificate_offset < carrier_offset < launch_offset < reachability_offset:
        raise InterpreterMixedOriginalCertificateDecompositionError(
            "mixed-original base declarations are out of phase order"
        )

    static_matches = list(_STATIC_INDIRECT.finditer(source))
    static_offset = static_matches[0].start() if static_matches else launch_offset
    if not carrier_offset < static_offset <= launch_offset:
        raise InterpreterMixedOriginalCertificateDecompositionError(
            "static-indirect declarations are out of phase order"
        )

    diagnostic_offset = source.find(_DIAGNOSTIC_MARKER, reachability_offset)
    if diagnostic_offset < 0:
        final_end = f"\nend {namespace}\n"
        diagnostic_offset = source.rfind(final_end)
        if diagnostic_offset < 0:
            raise InterpreterMixedOriginalCertificateDecompositionError(
                "mixed-original base namespace terminator is absent"
            )
    diagnostics = source[diagnostic_offset:]
    if not diagnostics.rstrip().endswith(f"end {namespace}"):
        raise InterpreterMixedOriginalCertificateDecompositionError(
            "mixed-original diagnostic tail does not close the expected namespace"
        )

    target_refs = [
        (f"generatedOriginalTargetIndexShard{index}", len(regions))
        for index, regions in enumerate(shard_regions)
    ]
    address_counts = [
        sum(1 + len(region.alias_rvas) for region in regions)
        for regions in shard_regions
    ]
    address_refs = [
        (f"generatedOriginalAddressIndexShard{index}", count)
        for index, count in enumerate(address_counts)
    ]
    region_refs = [
        (f"generatedOriginalRegionIndexShard{index}", len(regions))
        for index, regions in enumerate(shard_regions)
    ]
    _require_generated_index(source, "generatedOriginalTargetIndex", target_refs)
    _require_generated_index(source, "generatedOriginalAddressIndex", address_refs)
    _require_generated_index(source, "generatedOriginalRegionIndex", region_refs)

    data_module = f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}Data"
    data_source = source[:certificate_offset] + f"\n\nend {namespace}\n"
    data_source = data_source.replace(
        "import StageA.RelationalInterpreterOriginalCarrierBinding\n", ""
    )
    data_path = _write_module(stage_a, data_module, data_source)

    check_modules: list[str] = []
    check_paths: list[Path] = []
    target_start = 0
    address_start = 0
    address_total = sum(address_counts)
    address_before = 0
    for index, regions in enumerate(shard_regions):
        module = (
            f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}"
            f"CertificateShard{index:04d}"
        )
        target_count = len(regions)
        address_count = address_counts[index]
        address_after = address_before + address_count
        source_text = _certificate_shard_source(
            namespace=namespace,
            data_module=data_module,
            shard_index=index,
            target_start=target_start,
            target_count=target_count,
            address_start=address_start,
            address_count=address_count,
            address_before=address_before,
            address_after=address_after,
        )
        check_modules.append(module)
        check_paths.append(_write_module(stage_a, module, source_text))
        target_start += target_count
        address_start += address_count
        address_before = address_after
    if target_start != len(plan.regions) or address_start != address_total:
        raise AssertionError("mixed-original shard counts did not compose")

    aggregate_module = (
        f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}CertificateAggregate"
    )
    aggregate_source = _certificate_aggregate_source(
        namespace=namespace,
        data_module=data_module,
        check_modules=check_modules,
        target_refs=target_refs,
        address_refs=address_refs,
        region_refs=region_refs,
        target_count=len(plan.regions),
        address_count=address_total,
        address_counts=address_counts,
    )
    aggregate_path = _write_module(
        stage_a, aggregate_module, aggregate_source
    )

    scalar_module = f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}ScalarChecks"
    scalar_source = _scalar_checks_source(namespace, data_module)
    scalar_path = _write_module(stage_a, scalar_module, scalar_source)

    certificate_module = (
        f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}ExactCertificate"
    )
    certificate_source = _exact_certificate_source(
        plan=plan,
        namespace=namespace,
        aggregate_module=aggregate_module,
        scalar_module=scalar_module,
    )
    certificate_path = _write_module(
        stage_a, certificate_module, certificate_source
    )

    carrier_module = f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}CarrierData"
    carrier_source = _owned_source(
        imports=[
            certificate_module,
            "RelationalInterpreterOriginalCarrierBinding",
        ],
        namespace=namespace,
        body=source[carrier_offset:static_offset].strip(),
    )
    carrier_path = _write_module(stage_a, carrier_module, carrier_source)

    static_modules: list[str] = []
    static_paths: list[Path] = []
    for block_index, match in enumerate(static_matches):
        start = match.start()
        stop = (
            static_matches[block_index + 1].start()
            if block_index + 1 < len(static_matches)
            else launch_offset
        )
        claim_index = int(match.group(1))
        block = source[start:stop].strip()
        foreign = {
            int(value)
            for value in re.findall(
                r"generatedOriginalStaticIndirect([0-9]+)", block
            )
            if int(value) != claim_index
        }
        if foreign:
            raise InterpreterMixedOriginalCertificateDecompositionError(
                f"static-indirect cluster {claim_index} depends on clusters "
                f"{sorted(foreign)}"
            )
        module = (
            f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}"
            f"StaticIndirect{claim_index:04d}"
        )
        static_modules.append(module)
        static_paths.append(
            _write_module(
                stage_a,
                module,
                _owned_source(
                    imports=[carrier_module],
                    namespace=namespace,
                    body=block,
                ),
            )
        )

    launch_module = f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}Launch"
    launch_source = _owned_source(
        imports=[carrier_module],
        namespace=namespace,
        body=source[launch_offset:reachability_offset].strip(),
    )
    launch_path = _write_module(stage_a, launch_module, launch_source)

    reachability_data_module = (
        f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}ReachabilityData"
    )
    reachability_data_source = _owned_source(
        imports=[carrier_module],
        namespace=namespace,
        body=(
            "def generatedReachableTargetIds : List Nat := "
            f"{list(plan.reachable_target_ids)}"
        ),
    )
    reachability_data_path = _write_module(
        stage_a, reachability_data_module, reachability_data_source
    )
    reachability_result = _write_reachability_certificates(
        stage_a=stage_a,
        namespace=namespace,
        data_module=reachability_data_module,
        target_count=len(plan.reachable_target_ids),
        shard_size=plan.spec.shard_size,
    )

    facade_imports = [
        launch_module,
        reachability_result[0],
        *static_modules,
    ]
    base_source = (
        "\n".join(f"import StageA.{module}" for module in facade_imports)
        + f"\n\nnamespace {namespace}\n"
        + diagnostics
    )
    base_path.write_text(base_source, encoding="utf-8")

    resources: dict[str, Mapping[str, object]] = {
        data_module: _resource("medium", 4096),
        aggregate_module: _resource("light", 1024),
        scalar_module: _resource("high-memory", 8192),
        certificate_module: _resource("light", 1024),
        carrier_module: _resource("high-memory", 8192),
        launch_module: _resource("medium", 4096),
        reachability_data_module: _resource("light", 1024),
        base_path.stem: _resource("light", 768),
        **{
            module: _resource("medium", 6144)
            for module in check_modules
        },
        **{
            module: _resource("medium", 4096)
            for module in static_modules
        },
        **reachability_result[2],
    }
    paths = (
        data_path,
        *check_paths,
        aggregate_path,
        scalar_path,
        certificate_path,
        carrier_path,
        *static_paths,
        launch_path,
        reachability_data_path,
        *reachability_result[1],
        base_path,
    )
    return InterpreterMixedOriginalCertificateDecomposition(
        paths=tuple(paths),
        resources=resources,
    )


def _certificate_shard_source(
    *,
    namespace: str,
    data_module: str,
    shard_index: int,
    target_start: int,
    target_count: int,
    address_start: int,
    address_count: int,
    address_before: int,
    address_after: int,
) -> str:
    prefix = f"generatedOriginalCertificateShard{shard_index}"
    target_range = f"{prefix}TargetRange"
    address_range = f"{prefix}AddressRange"
    body = f"""
def {target_range} : Span :=
  {{ start := {target_start}, size := {target_count} }}

def {address_range} : Span :=
  {{ start := {address_start}, size := {address_count} }}

theorem {prefix}TargetSize :
    generatedOriginalTargetIndexShard{shard_index}.size = {target_count} := by
  decide +kernel

theorem {prefix}TargetHeight :
    generatedOriginalTargetIndexShard{shard_index}.height =
      {_lean_finite_index_height(target_count)} := by
  decide +kernel

theorem {prefix}TargetStructurallyValid :
    generatedOriginalTargetIndexShard{shard_index}.structurallyValid 16 =
      true := by
  decide +kernel

theorem {prefix}AddressSize :
    generatedOriginalAddressIndexShard{shard_index}.size = {address_count} := by
  decide +kernel

theorem {prefix}AddressHeight :
    generatedOriginalAddressIndexShard{shard_index}.height =
      {_lean_finite_index_height(address_count)} := by
  decide +kernel

theorem {prefix}AddressStructurallyValid :
    generatedOriginalAddressIndexShard{shard_index}.structurallyValid 16 =
      true := by
  decide +kernel

theorem {prefix}RegionSize :
    generatedOriginalRegionIndexShard{shard_index}.size = {target_count} := by
  decide +kernel

theorem {prefix}RegionHeight :
    generatedOriginalRegionIndexShard{shard_index}.height =
      {_lean_finite_index_height(target_count)} := by
  decide +kernel

theorem {prefix}RegionStructurallyValid :
    generatedOriginalRegionIndexShard{shard_index}.structurallyValid 16 =
      true := by
  decide +kernel

theorem {prefix}EntriesValid :
    IndexedBoolRangeHolds generatedOriginalCodeMap.entryAtValid
      {target_range} :=
  indexedBoolRangeHolds_of_checked generatedOriginalCodeMap.entryAtValid
    {target_range} (by decide +kernel)

theorem {prefix}AddressesValid :
    IndexedBoolRangeHolds
      (generatedOriginalCodeMap.addressAtValid
        generatedOriginalStaticContext.pe) {address_range} :=
  indexedBoolRangeHolds_of_checked
    (generatedOriginalCodeMap.addressAtValid
      generatedOriginalStaticContext.pe) {address_range}
    (by decide +kernel)

theorem {prefix}TargetsRoundTrip :
    IndexedBoolRangeHolds
      (generatedOriginalCodeMap.targetRoundTripsAt
        generatedOriginalStaticContext.pe) {target_range} :=
  indexedBoolRangeHolds_of_checked
    (generatedOriginalCodeMap.targetRoundTripsAt
      generatedOriginalStaticContext.pe) {target_range}
    (by decide +kernel)

theorem {prefix}AliasesValid :
    IndexedBoolRangeHolds
      (generatedOriginalCodeMap.aliasesSemanticallyValidAt
        generatedOriginalStaticContext.pe generatedOriginalStaticContext.imports)
      {target_range} :=
  indexedBoolRangeHolds_of_checked
    (generatedOriginalCodeMap.aliasesSemanticallyValidAt
      generatedOriginalStaticContext.pe generatedOriginalStaticContext.imports)
    {target_range} (by decide +kernel)

theorem {prefix}SourcesValid :
    IndexedBoolRangeHolds generatedOriginalStaticContext.sourceAtValid
      {target_range} :=
  indexedBoolRangeHolds_of_checked
    generatedOriginalStaticContext.sourceAtValid {target_range}
    (by decide +kernel)

theorem {prefix}AddressCount :
    IndexedNatRangeFoldHolds generatedOriginalCodeMap.addressContribution
      {target_range} {address_before} {address_after} := by
  unfold IndexedNatRangeFoldHolds
  decide +kernel
""".strip()
    return _owned_source(
        imports=[
            data_module,
            "RelationalInterpreterMixedOriginalCertificates",
        ],
        namespace=namespace,
        body=body,
    )


def _certificate_aggregate_source(
    *,
    namespace: str,
    data_module: str,
    check_modules: Sequence[str],
    target_refs: Sequence[tuple[str, int]],
    address_refs: Sequence[tuple[str, int]],
    region_refs: Sequence[tuple[str, int]],
    target_count: int,
    address_count: int,
    address_counts: Sequence[int],
) -> str:
    target_tree = _index_tree(target_refs)
    address_tree = _index_tree(address_refs)
    region_tree = _index_tree(region_refs)
    structural_parts: list[str] = []
    for family, value_type, tree in (
        ("Target", "OriginalCodeTarget", target_tree),
        ("Address", "OriginalCodeAddress", address_tree),
        ("Region", "OriginalDecodedRegion", region_tree),
    ):
        proof = _emit_structural_proof_tree(
            structural_parts, family, value_type, tree
        )
        structural_parts.append(
            f"""theorem generatedOriginal{family}IndexTreeExact :
    generatedOriginal{family}Index = {proof.expression} := by
  rfl

theorem generatedOriginal{family}IndexStructurallyValid :
    generatedOriginal{family}Index.structurallyValid 16 = true := by
  rw [generatedOriginal{family}IndexTreeExact]
  exact {proof.checked}"""
        )

    target_starts = _prefix_starts([size for _, size in target_refs])
    address_starts = _prefix_starts(address_counts)
    range_parts: list[str] = []
    families = (
        (
            "Entries",
            "generatedOriginalCodeMap.entryAtValid",
            [
                _leaf_range(
                    index, target_starts[index], target_refs[index][1],
                    "Target", "EntriesValid"
                )
                for index in range(len(target_refs))
            ],
            "generatedAllChecks",
            target_count,
        ),
        (
            "Addresses",
            "(generatedOriginalCodeMap.addressAtValid "
            "generatedOriginalStaticContext.pe)",
            [
                _leaf_range(
                    index, address_starts[index], address_counts[index],
                    "Address", "AddressesValid"
                )
                for index in range(len(address_refs))
            ],
            "generatedAllAddressChecks",
            address_count,
        ),
        (
            "RoundTrip",
            "(generatedOriginalCodeMap.targetRoundTripsAt "
            "generatedOriginalStaticContext.pe)",
            [
                _leaf_range(
                    index, target_starts[index], target_refs[index][1],
                    "Target", "TargetsRoundTrip"
                )
                for index in range(len(target_refs))
            ],
            "generatedAllChecks",
            target_count,
        ),
        (
            "Aliases",
            "(generatedOriginalCodeMap.aliasesSemanticallyValidAt "
            "generatedOriginalStaticContext.pe "
            "generatedOriginalStaticContext.imports)",
            [
                _leaf_range(
                    index, target_starts[index], target_refs[index][1],
                    "Target", "AliasesValid"
                )
                for index in range(len(target_refs))
            ],
            "generatedAllChecks",
            target_count,
        ),
        (
            "Sources",
            "generatedOriginalStaticContext.sourceAtValid",
            [
                _leaf_range(
                    index, target_starts[index], target_refs[index][1],
                    "Target", "SourcesValid"
                )
                for index in range(len(target_refs))
            ],
            "generatedAllChecks",
            target_count,
        ),
    )
    global_names: dict[str, str] = {}
    for family, predicate, leaves, certificate, count in families:
        root = _emit_range_proof_tree(range_parts, family, predicate, leaves)
        theorem_name = f"generatedOriginal{family}IndexChecked"
        global_names[family] = theorem_name
        range_parts.append(
            f"""theorem {theorem_name} :
    {certificate}.Holds {predicate} {count} := by
  intro index before
  simpa [{root.range_name}] using {root.checked_name} index before"""
        )

    count_leaves = [
        _RangeProof(
            start=target_starts[index],
            size=target_refs[index][1],
            range_name=(
                f"generatedOriginalCertificateShard{index}TargetRange"
            ),
            checked_name=(
                f"generatedOriginalCertificateShard{index}AddressCount"
            ),
            before=address_starts[index],
            after=address_starts[index + 1],
        )
        for index in range(len(target_refs))
    ]
    count_root = _emit_fold_proof_tree(
        range_parts,
        "AddressCount",
        "generatedOriginalCodeMap.addressContribution",
        count_leaves,
    )
    range_parts.append(
        f"""theorem generatedOriginalAddressCountExact :
    generatedOriginalCodeMap.addresses.size =
      generatedOriginalCodeMap.expectedAddressCount := by
  have addressSize :
      generatedOriginalCodeMap.addresses.size = {address_count} := by
    simp [generatedOriginalCodeMap, generatedOriginalAddressIndex,
      FiniteIndex.size]
  have expectedSize :
      generatedOriginalCodeMap.expectedAddressCount = {address_count} := by
    unfold OriginalCodeMap.expectedAddressCount
    simpa [generatedOriginalCodeMap, generatedOriginalTargetIndex,
      IndexedNatRangeFoldHolds, {count_root.range_name}] using
      {count_root.checked_name}
  exact addressSize.trans expectedSize.symm"""
    )

    return _owned_source(
        imports=[
            data_module,
            "RelationalInterpreterMixedOriginalCertificates",
            *check_modules,
        ],
        namespace=namespace,
        body="\n\n".join([*structural_parts, *range_parts]),
    )


def _scalar_checks_source(namespace: str, data_module: str) -> str:
    body = """
theorem generatedOriginalLoaderImageValid :
    preferredBaseLoaderImageValid generatedOriginalStaticContext.pe = true := by
  decide +kernel

theorem generatedOriginalMachineContractsValid :
    machineImportCallContractsValid generatedOriginalStaticContext.imports
      generatedOriginalStaticContext.machineImportCallContracts = true := by
  decide +kernel
""".strip()
    return _owned_source(
        imports=[data_module],
        namespace=namespace,
        body=body,
    )


def _exact_certificate_source(
    *,
    plan: InterpreterMixedOriginalPlan,
    namespace: str,
    aggregate_module: str,
    scalar_module: str,
) -> str:
    bindings = plan.spec.bindings
    q = bindings.qualified
    body = f"""
def generatedExactOriginalCodeMapProofCertificate :
    OriginalCodeMapProofCertificate generatedOriginalStaticContext.pe
      generatedOriginalStaticContext.imports generatedOriginalCodeMap := {{
  entriesStructurallyValid :=
    generatedOriginalTargetIndexStructurallyValid
  addressesStructurallyValid :=
    generatedOriginalAddressIndexStructurallyValid
  entryChecks := generatedAllChecks
  entryChecksCoverage := by decide +kernel
  entriesValid := generatedOriginalEntriesIndexChecked
  addressCountExact := generatedOriginalAddressCountExact
  addressChecks := generatedAllAddressChecks
  addressChecksCoverage := by decide +kernel
  addressesValid := generatedOriginalAddressesIndexChecked
  roundTripChecks := generatedAllChecks
  roundTripChecksCoverage := by decide +kernel
  targetsRoundTrip := generatedOriginalRoundTripIndexChecked
  aliasChecks := generatedAllChecks
  aliasChecksCoverage := by decide +kernel
  aliasesValid := generatedOriginalAliasesIndexChecked
}}

def generatedExactOriginalCodeMapCertificate :
    OriginalCodeMapCertificate generatedOriginalStaticContext.pe
      generatedOriginalStaticContext.imports generatedOriginalCodeMap :=
  generatedExactOriginalCodeMapProofCertificate.toBooleanCertificate

def generatedExactOriginalDecodedProofAuthority :
    ExactOriginalDecodedProofAuthority generatedOriginalStaticContext := {{
  peParsed := by
    simpa [generatedOriginalStaticContext] using {q(bindings.pe_parsed)}
  importsParsed := by
    simpa [generatedOriginalStaticContext] using {q(bindings.imports_parsed)}
  relocationsParsed := by
    simpa [generatedOriginalStaticContext] using {q(bindings.relocations_parsed)}
  loaderImageValid := generatedOriginalLoaderImageValid
  codeMap := generatedExactOriginalCodeMapProofCertificate
  regionsStructurallyValid :=
    generatedOriginalRegionIndexStructurallyValid
  sourceChecks := generatedAllChecks
  sourceChecksCoverage := by decide +kernel
  sourcesValid := generatedOriginalSourcesIndexChecked
  machineContractsValid := generatedOriginalMachineContractsValid
}}

def generatedExactOriginalDecodedAuthority :
    ExactOriginalDecodedAuthority generatedOriginalStaticContext :=
  generatedExactOriginalDecodedProofAuthority.toBooleanAuthority
""".strip()
    return _owned_source(
        imports=[
            aggregate_module,
            scalar_module,
            "RelationalInterpreterMixedOriginalCertificates",
        ],
        namespace=namespace,
        body=body,
    )


def _write_reachability_certificates(
    *,
    stage_a: Path,
    namespace: str,
    data_module: str,
    target_count: int,
    shard_size: int,
) -> tuple[str, tuple[Path, ...], Mapping[str, Mapping[str, object]]]:
    leaves: list[_RangeProof] = []
    paths: list[Path] = []
    resources: dict[str, Mapping[str, object]] = {}
    modules: list[str] = []
    for index, start in enumerate(range(0, target_count, shard_size)):
        size = min(shard_size, target_count - start)
        module = (
            f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}"
            f"ReachabilityShard{index:04d}"
        )
        range_name = f"generatedOriginalReachabilityShard{index}Range"
        checked_name = f"generatedOriginalReachabilityShard{index}Checked"
        predicate = (
            "(originalReachabilityInventoryAt generatedOriginalStaticContext "
            "generatedReachableTargetIds)"
        )
        body = f"""
def {range_name} : Span := {{ start := {start}, size := {size} }}

theorem {checked_name} :
    IndexedBoolRangeHolds {predicate} {range_name} :=
  indexedBoolRangeHolds_of_checked {predicate} {range_name}
    (by decide +kernel)
""".strip()
        paths.append(
            _write_module(
                stage_a,
                module,
                _owned_source(
                    imports=[
                        data_module,
                        "RelationalInterpreterMixedOriginalReachabilityCertificates",
                    ],
                    namespace=namespace,
                    body=body,
                ),
            )
        )
        modules.append(module)
        resources[module] = _resource("medium", 4096)
        leaves.append(_RangeProof(start, size, range_name, checked_name))

    certificate_module = (
        f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}ReachabilityCertificate"
    )
    parts: list[str] = []
    if leaves:
        root = _emit_range_proof_tree(
            parts,
            "Reachability",
            "(originalReachabilityInventoryAt generatedOriginalStaticContext "
            "generatedReachableTargetIds)",
            leaves,
        )
        parts.append(
            f"""theorem generatedOriginalReachabilityIndexChecked :
    forall index, index < generatedReachableTargetIds.length ->
      originalReachabilityInventoryAt generatedOriginalStaticContext
        generatedReachableTargetIds index = true := by
  intro index before
  simpa [generatedReachableTargetIds, {root.range_name}] using
    {root.checked_name} index before

theorem generatedOriginalReachabilityInventoryChecked :
    originalReachabilityInventoryValid generatedOriginalStaticContext
      generatedReachableTargetIds = true :=
  originalReachabilityInventoryValid_of_indexed_holds
    generatedOriginalReachabilityIndexChecked"""
        )
    else:
        parts.append(
            """theorem generatedOriginalReachabilityInventoryChecked :
    originalReachabilityInventoryValid generatedOriginalStaticContext
      generatedReachableTargetIds = true := by
  decide +kernel"""
        )
    certificate_source = _owned_source(
        imports=[
            data_module,
            "RelationalInterpreterMixedOriginalReachabilityCertificates",
            *modules,
        ],
        namespace=namespace,
        body="\n\n".join(parts),
    )
    certificate_path = _write_module(
        stage_a, certificate_module, certificate_source
    )
    paths.append(certificate_path)
    resources[certificate_module] = _resource("light", 1024)
    return certificate_module, tuple(paths), resources


def _index_tree(refs: Sequence[tuple[str, int]]) -> _IndexTree:
    if not refs:
        raise InterpreterMixedOriginalCertificateDecompositionError(
            "finite-index certificate forest cannot be empty"
        )
    table: dict[tuple[int, int], dict[int, _IndexTree]] = {}
    for index, (name, size) in enumerate(refs):
        height = _lean_finite_index_height(size)
        table[(index, index + 1)] = {
            height: _IndexTree(name, size, height, 0, leaf_index=index)
        }
    count = len(refs)
    for width in range(2, count + 1):
        for start in range(0, count - width + 1):
            stop = start + width
            candidates: dict[int, tuple[tuple[int, int, int], _IndexTree]] = {}
            for split in range(start + 1, stop):
                for left in table.get((start, split), {}).values():
                    for right in table.get((split, stop), {}).values():
                        balance = abs(left.height - right.height)
                        if balance > 1:
                            continue
                        height = 1 + max(left.height, right.height)
                        maximum_balance = max(
                            balance,
                            left.maximum_balance,
                            right.maximum_balance,
                        )
                        expression = (
                            f".branch {left.size + right.size} {left.size} "
                            f"({left.expression}) ({right.expression})"
                        )
                        tree = _IndexTree(
                            expression,
                            left.size + right.size,
                            height,
                            maximum_balance,
                            left=left,
                            right=right,
                        )
                        score = (
                            maximum_balance,
                            abs(left.size - right.size),
                            split,
                        )
                        previous = candidates.get(height)
                        if previous is None or score < previous[0]:
                            candidates[height] = (score, tree)
            if candidates:
                table[(start, stop)] = {
                    height: row[1] for height, row in candidates.items()
                }
    complete = table.get((0, count), {})
    if not complete:
        raise InterpreterMixedOriginalCertificateDecompositionError(
            "finite-index shard witnesses cannot satisfy the AVL invariant"
        )
    tree = min(
        complete.values(),
        key=lambda item: (
            item.height,
            item.maximum_balance,
            item.expression,
        ),
    )
    if tree.expression != _lean_index_refs(refs):
        raise InterpreterMixedOriginalCertificateDecompositionError(
            "certificate tree diverged from the semantic index tree"
        )
    return tree


def _emit_structural_proof_tree(
    parts: list[str],
    family: str,
    value_type: str,
    tree: _IndexTree,
) -> _StructuralProof:
    if tree.leaf_index is not None:
        prefix = f"generatedOriginalCertificateShard{tree.leaf_index}"
        return _StructuralProof(
            tree.expression,
            tree.size,
            tree.height,
            f"{prefix}{family}StructurallyValid",
            f"{prefix}{family}Size",
            f"{prefix}{family}Height",
        )
    assert tree.left is not None and tree.right is not None
    left = _emit_structural_proof_tree(parts, family, value_type, tree.left)
    right = _emit_structural_proof_tree(parts, family, value_type, tree.right)
    node_index = sum(
        part.startswith(f"def generatedOriginal{family}StructuralNode")
        for part in parts
    )
    prefix = f"generatedOriginal{family}StructuralNode{node_index}"
    size_name = f"{prefix}Size"
    height_name = f"{prefix}Height"
    checked_name = f"{prefix}Checked"
    expression = prefix
    parts.extend(
        [
            f"""def {prefix} : FiniteIndex {value_type} :=
  .branch {tree.size} {left.size}
    ({left.expression}) ({right.expression})""",
            f"""theorem {size_name} :
    {prefix}.size = {tree.size} := by
  rfl""",
            f"""theorem {height_name} :
    {prefix}.height = {tree.height} := by
  simp only [{prefix}, FiniteIndex.height, {left.height_checked},
    {right.height_checked}]
  decide""",
            f"""theorem {checked_name} :
    {prefix}.structurallyValid 16 = true := by
  unfold {prefix}
  exact FiniteIndex.structurallyValid_branch 16 {tree.size} {left.size}
    ({left.expression}) ({right.expression})
    {left.checked} {right.checked}
    (by simp only [{left.size_checked}, {right.size_checked}])
    (by simp only [{left.size_checked}])
    (by simp only [{left.size_checked}]; decide)
    (by simp only [{right.size_checked}]; decide)
    (by simp only [{left.height_checked}, {right.height_checked}]; decide)
    (by simp only [{left.height_checked}, {right.height_checked}]; decide)""",
        ]
    )
    return _StructuralProof(
        expression,
        tree.size,
        tree.height,
        checked_name,
        size_name,
        height_name,
    )


def _leaf_range(
    index: int,
    start: int,
    size: int,
    range_family: str,
    theorem_suffix: str,
) -> _RangeProof:
    prefix = f"generatedOriginalCertificateShard{index}"
    return _RangeProof(
        start,
        size,
        f"{prefix}{range_family}Range",
        f"{prefix}{theorem_suffix}",
    )


def _emit_range_proof_tree(
    parts: list[str],
    family: str,
    predicate: str,
    leaves: Sequence[_RangeProof],
) -> _RangeProof:
    if not leaves:
        raise InterpreterMixedOriginalCertificateDecompositionError(
            f"{family} range certificate cannot be empty"
        )
    if len(leaves) == 1:
        return leaves[0]
    middle = len(leaves) // 2
    left = _emit_range_proof_tree(parts, family, predicate, leaves[:middle])
    right = _emit_range_proof_tree(parts, family, predicate, leaves[middle:])
    if right.start != left.start + left.size:
        raise InterpreterMixedOriginalCertificateDecompositionError(
            f"{family} certificate ranges are not adjacent"
        )
    index = sum(
        part.startswith(f"def generatedOriginal{family}RangeNode")
        for part in parts
    )
    range_name = f"generatedOriginal{family}RangeNode{index}"
    checked_name = f"{range_name}Checked"
    size = left.size + right.size
    parts.extend(
        [
            f"""def {range_name} : Span :=
  {{ start := {left.start}, size := {size} }}""",
            f"""theorem {checked_name} :
    IndexedBoolRangeHolds {predicate} {range_name} :=
  indexedBoolRangeHolds_append {predicate}
    {left.range_name} {right.range_name} (by decide)
    {left.checked_name} {right.checked_name}""",
        ]
    )
    return _RangeProof(left.start, size, range_name, checked_name)


def _emit_fold_proof_tree(
    parts: list[str],
    family: str,
    value: str,
    leaves: Sequence[_RangeProof],
) -> _RangeProof:
    if not leaves:
        raise InterpreterMixedOriginalCertificateDecompositionError(
            f"{family} fold certificate cannot be empty"
        )
    if len(leaves) == 1:
        return leaves[0]
    middle = len(leaves) // 2
    left = _emit_fold_proof_tree(parts, family, value, leaves[:middle])
    right = _emit_fold_proof_tree(parts, family, value, leaves[middle:])
    if (
        right.start != left.start + left.size
        or left.after is None
        or right.before != left.after
        or left.before is None
        or right.after is None
    ):
        raise InterpreterMixedOriginalCertificateDecompositionError(
            f"{family} fold certificates do not compose"
        )
    index = sum(
        part.startswith(f"def generatedOriginal{family}RangeNode")
        for part in parts
    )
    range_name = f"generatedOriginal{family}RangeNode{index}"
    checked_name = f"{range_name}Checked"
    size = left.size + right.size
    parts.extend(
        [
            f"""def {range_name} : Span :=
  {{ start := {left.start}, size := {size} }}""",
            f"""theorem {checked_name} :
    IndexedNatRangeFoldHolds {value} {range_name}
      {left.before} {right.after} :=
  indexedNatRangeFoldHolds_append {value}
    {left.range_name} {right.range_name}
    {left.before} {left.after} {right.after} (by decide)
    {left.checked_name} {right.checked_name}""",
        ]
    )
    return _RangeProof(
        left.start,
        size,
        range_name,
        checked_name,
        left.before,
        right.after,
    )


def _owned_source(
    *,
    imports: Sequence[str],
    namespace: str,
    body: str,
) -> str:
    imported = "\n".join(
        f"import StageA.{module}" for module in dict.fromkeys(imports)
    )
    return f"""{imported}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedOriginal
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{body}

end {namespace}
"""


def _write_module(stage_a: Path, module: str, source: str) -> Path:
    path = stage_a / f"{module}.lean"
    path.write_text(source, encoding="utf-8")
    return path


def _unique_offset(source: str, marker: str) -> int:
    first = source.find(marker)
    if first < 0 or source.find(marker, first + len(marker)) >= 0:
        raise InterpreterMixedOriginalCertificateDecompositionError(
            f"expected exactly one generated marker: {marker.strip()}"
        )
    return first


def _require_generated_index(
    source: str,
    name: str,
    refs: Sequence[tuple[str, int]],
) -> None:
    expression = _lean_index_refs(refs)
    pattern = re.compile(
        rf"def {re.escape(name)} : FiniteIndex [^:]+ :=\n"
        rf"  {re.escape(expression)}\n"
    )
    if pattern.search(source) is None:
        raise InterpreterMixedOriginalCertificateDecompositionError(
            f"{name} no longer matches the checked finite-index tree"
        )


def _prefix_starts(sizes: Sequence[int]) -> list[int]:
    result = [0]
    for size in sizes:
        result.append(result[-1] + size)
    return result


def _resource(resource_class: str, estimated_memory_mb: int) -> Mapping[str, object]:
    return {
        "resource_class": resource_class,
        "estimated_memory_mb": estimated_memory_mb,
    }


__all__ = [
    "InterpreterMixedOriginalCertificateDecomposition",
    "InterpreterMixedOriginalCertificateDecompositionError",
    "decompose_interpreter_mixed_original_base",
]
