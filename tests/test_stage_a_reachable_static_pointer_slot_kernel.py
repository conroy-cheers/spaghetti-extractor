from __future__ import annotations

import dataclasses
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.common import (
    _lean_byte_tree_definitions,
    _lean_import_certificate,
    _lean_pe,
    _lean_relocations,
)
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.reachable_static_pointer_slot import (
    GuardedNonzeroEdgeProposal,
    IndirectSlotSiteProposal,
    ReachableStaticPointerSlotCertificateSpec,
    RegionBindingProposal,
    WriteClassificationProposal,
    reachable_static_pointer_slot_source,
)
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS
from spaghetti_extractor.stage_binary import _parse_stage_a_pe
from tests.test_stage_a_nullable_code_pointer_table import (
    DATA_RVA,
    TEXT_RAW,
    TEXT_RVA,
    _nullable_table_pe,
)
from tests.test_stage_a_reachable_static_pointer_slot import minimal_spec


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)


def _copy_module_closure(source_root: Path, destination: Path, module: str) -> None:
    pending = [module]
    copied: set[str] = set()
    while pending:
        current = pending.pop()
        if current in copied:
            continue
        source = source_root / f"{current}.lean"
        text = source.read_text(encoding="utf-8")
        shutil.copyfile(source, destination / source.name)
        copied.add(current)
        pending.extend(_IMPORT.findall(text))


def _fixture_pe(
    *,
    slot_word: int = 0,
    other_slot_word: int | None = None,
    code: bytes = b"\xc3",
    relocation: bool = False,
) -> bytes:
    words = (
        (slot_word,)
        if other_slot_word is None
        else (slot_word, other_slot_word)
    )
    image = bytearray(
        _nullable_table_pe(
            words=words,
            table_offset=0x20,
            relocation_offsets=(0x20,) if relocation else (),
            writable_table=True,
        )
    )
    image[TEXT_RAW : TEXT_RAW + len(code)] = code
    return bytes(image)


def _authority_source(
    pe_path: Path,
    pe_bytes: bytes,
    code_size: int,
    *,
    entries: str | None = None,
    addresses: str | None = None,
    regions: str | None = None,
    check_size: int = 1,
) -> str:
    binary = _parse_stage_a_pe(pe_path)
    try:
        return _AUTHORITY.format(
            byte_tree=_lean_byte_tree_definitions("originalBytes", pe_bytes),
            pe_literal=_lean_pe(binary, "originalBytes"),
            imports_literal=_lean_import_certificate(binary),
            relocations_literal=_lean_relocations(binary),
            code_size=code_size,
            check_size=check_size,
            entries=entries
            or "{ id := 0, regionIndex := 0, rva := 0x1000 }",
            addresses=addresses
            or "{ targetId := 0, kind := .canonical }",
            regions=regions
            or (
                "{ id := 0, span := { start := 0x1000, size := "
                f"{code_size} }}, root := true, targets := [] }}"
            ),
        )
    finally:
        binary.pe.close()


_AUTHORITY = r"""import StageA.RelationalInterpreterMixedContext

namespace StageA.GeneratedReachableSlotFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{byte_tree}

def originalPe : PE32 :=
  {pe_literal}

def originalImportCertificate : ImportTableCertificate :=
  {imports_literal}

def originalRelocations : List BaseRelocation :=
  {relocations_literal}

def allChecks : IndexedBoolCertificate := {{
  ranges := [{{ start := 0, size := {check_size} }}]
}}

def originalCodeMap : OriginalCodeMap := {{
  entries := .leaf [{entries}]
  addresses := .leaf [{addresses}]
}}

def originalCodeMapCertificate : OriginalCodeMapCertificate
    originalPe originalImportCertificate.imports originalCodeMap := {{
  entriesStructurallyValid := by decide +kernel
  addressesStructurallyValid := by decide +kernel
  entryChecks := allChecks
  entryChecksValid := by decide +kernel
  addressCountExact := by decide +kernel
  addressChecks := allChecks
  addressChecksValid := by decide +kernel
  roundTripChecks := allChecks
  roundTripChecksValid := by decide +kernel
  aliasChecks := allChecks
  aliasChecksValid := by decide +kernel
}}

def originalContext : OriginalDecodedStaticContext := {{
  pe := originalPe
  importCertificate := originalImportCertificate
  relocations := originalRelocations
  codeMap := originalCodeMap
  regions := .leaf [{regions}]
}}

def originalAuthority : ExactOriginalDecodedAuthority originalContext := {{
  peParsed := by decide +kernel
  importsParsed := by decide +kernel
  relocationsParsed := by decide +kernel
  loaderImageValid := by decide +kernel
  codeMap := originalCodeMapCertificate
  regionsStructurallyValid := by decide +kernel
  sourceChecks := allChecks
  sourceChecksValid := by decide +kernel
  machineContractsValid := by decide +kernel
}}

#print axioms originalAuthority

end StageA.GeneratedReachableSlotFixture
"""


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAReachableStaticPointerSlotKernelTests(unittest.TestCase):
    source_root = (
        Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
    )

    def _compile(
        self,
        spec: ReachableStaticPointerSlotCertificateSpec,
        *,
        pe_bytes: bytes,
        code_size: int = 1,
        authority_options: dict[str, object] | None = None,
        expectation: str,
    ) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                self.source_root,
                stage_a,
                "RelationalReachableStaticPointerSlot",
            )
            pe_path = root / "fixture.exe"
            pe_path.write_bytes(pe_bytes)
            (stage_a / "GeneratedReachableSlotFixture.lean").write_text(
                _authority_source(
                    pe_path,
                    pe_bytes,
                    code_size,
                    **(authority_options or {}),
                ),
                encoding="utf-8",
            )
            (stage_a / "GeneratedReachableStaticPointerSlot.lean").write_text(
                reachable_static_pointer_slot_source(
                    spec, expectation=expectation
                ),
                encoding="utf-8",
            )
            return _run_lean_relational(
                root, bundle="GeneratedReachableStaticPointerSlot"
            )

    def _assert_kernel_checked(self, result: dict) -> None:
        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        self.assertNotIn("_native.native_decide", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 5, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, RELATIONAL_APPROVED_AXIOMS, report)

    def test_zero_initialized_slot_without_writers_is_kernel_checked(self) -> None:
        result = self._compile(
            minimal_spec(), pe_bytes=_fixture_pe(), expectation="accepted"
        )
        self._assert_kernel_checked(result)
        output = result["stdout"] + result["stderr"]
        self.assertIn("fixtureCertificateChecked", output)
        self.assertIn("Certificate.trace_preserves", output)

    def test_mutation_relocation_and_inventory_omissions_reject(self) -> None:
        base = minimal_spec()
        cases = (
            (
                "mutated-initial-word",
                dataclasses.replace(
                    base, definition_name="mutatedInitialCertificate"
                ),
                _fixture_pe(slot_word=1),
            ),
            (
                "relocation-over-zero",
                dataclasses.replace(
                    base, definition_name="relocatedZeroCertificate"
                ),
                _fixture_pe(relocation=True),
            ),
            (
                "omitted-reachable-region",
                dataclasses.replace(
                    base,
                    definition_name="omittedRegionCertificate",
                    reachable_target_ids=(),
                ),
                _fixture_pe(),
            ),
            (
                "omitted-write-classification",
                dataclasses.replace(
                    base,
                    definition_name="omittedWriteCertificate",
                    regions=(RegionBindingProposal(0, None),),
                ),
                _fixture_pe(),
            ),
            (
                "byte-mutation-invalidates-behavior",
                dataclasses.replace(
                    base, definition_name="mutatedBehaviorCertificate"
                ),
                _fixture_pe(code=b"\xcc"),
            ),
            (
                "unmodelled-alias",
                dataclasses.replace(
                    base,
                    definition_name="aliasCertificate",
                    aliases=(DATA_RVA + 0x24,),
                ),
                _fixture_pe(),
            ),
            (
                "unknown-reachable-inventory",
                dataclasses.replace(
                    base,
                    definition_name="unknownReachableCertificate",
                    reachable_target_ids=None,
                ),
                _fixture_pe(),
            ),
        )
        for label, spec, pe_bytes in cases:
            with self.subTest(label=label):
                self._assert_kernel_checked(
                    self._compile(
                        spec,
                        pe_bytes=pe_bytes,
                        expectation="rejected",
                    )
                )

    def test_exact_code_target_writer_produces_finite_nullable_set(self) -> None:
        slot_va = 0x18000000 + DATA_RVA + 0x20
        target_va = 0x18000000 + TEXT_RVA
        code = (
            b"\xc7\x05"
            + slot_va.to_bytes(4, "little")
            + target_va.to_bytes(4, "little")
            + b"\xc3"
            + b"\x90" * 5
            + b"\xff\x25"
            + slot_va.to_bytes(4, "little")
        )
        authority_options = {
            "check_size": 2,
            "entries": ", ".join(
                (
                    "{ id := 0, regionIndex := 0, rva := 0x1000 }",
                    "{ id := 1, regionIndex := 1, rva := 0x1010 }",
                )
            ),
            "addresses": ", ".join(
                (
                    "{ targetId := 0, kind := .canonical }",
                    "{ targetId := 1, kind := .canonical }",
                )
            ),
            "regions": ", ".join(
                (
                    "{ id := 0, span := { start := 0x1000, size := 11 }, "
                    "root := true, targets := [] }",
                    "{ id := 1, span := { start := 0x1010, size := 6 }, "
                    "root := true, targets := [0] }",
                )
            ),
        }
        spec = dataclasses.replace(
            minimal_spec(),
            definition_name="finiteWriterCertificate",
            reachable_target_ids=(0, 1),
            allowed_target_ids=(0,),
            regions=(
                RegionBindingProposal(
                    0,
                    (WriteClassificationProposal("slot_code_target", 0),),
                ),
            ),
            indirect_slot_sites=(IndirectSlotSiteProposal(1),),
        )
        self._assert_kernel_checked(
            self._compile(
                spec,
                pe_bytes=_fixture_pe(code=code),
                code_size=len(code),
                authority_options=authority_options,
                expectation="accepted",
            )
        )

        self._assert_kernel_checked(
            self._compile(
                dataclasses.replace(
                    spec,
                    definition_name="omittedWriterCertificate",
                    regions=(),
                ),
                pe_bytes=_fixture_pe(code=code),
                code_size=len(code),
                authority_options=authority_options,
                expectation="rejected",
            )
        )

        wrong_value = bytearray(code)
        wrong_value[6:10] = (target_va + 1).to_bytes(4, "little")
        self._assert_kernel_checked(
            self._compile(
                dataclasses.replace(
                    spec, definition_name="wrongWriterValueCertificate"
                ),
                pe_bytes=_fixture_pe(code=bytes(wrong_value)),
                code_size=len(code),
                authority_options=authority_options,
                expectation="rejected",
            )
        )

        self._assert_kernel_checked(
            self._compile(
                dataclasses.replace(
                    spec,
                    definition_name="unindexedWriterTargetCertificate",
                    allowed_target_ids=(2,),
                    regions=(
                        RegionBindingProposal(
                            0,
                            (
                                WriteClassificationProposal(
                                    "slot_code_target", 2
                                ),
                            ),
                        ),
                    ),
                ),
                pe_bytes=_fixture_pe(code=code),
                code_size=len(code),
                authority_options=authority_options,
                expectation="rejected",
            )
        )

    def test_exact_narrow_write_widths_are_redecoded(self) -> None:
        slot_va = 0x18000000 + DATA_RVA + 0x20
        disjoint_va = slot_va + 8
        cases = (
            (
                "byte",
                b"\xc6\x05" + disjoint_va.to_bytes(4, "little") + b"\x00\xc3",
                1,
            ),
            (
                "word",
                b"\x66\xc7\x05"
                + disjoint_va.to_bytes(4, "little")
                + b"\x00\x00\xc3",
                2,
            ),
        )
        for label, code, width in cases:
            with self.subTest(label=label):
                accepted = dataclasses.replace(
                    minimal_spec(),
                    definition_name=f"{label}WidthCertificate",
                    regions=(
                        RegionBindingProposal(
                            0,
                            (
                                WriteClassificationProposal(
                                    "absolute_disjoint", width=width
                                ),
                            ),
                        ),
                    ),
                )
                self._assert_kernel_checked(
                    self._compile(
                        accepted,
                        pe_bytes=_fixture_pe(code=code),
                        code_size=len(code),
                        expectation="accepted",
                    )
                )
                self._assert_kernel_checked(
                    self._compile(
                        dataclasses.replace(
                            accepted,
                            definition_name=f"{label}WidthMismatchCertificate",
                            regions=(
                                RegionBindingProposal(
                                    0,
                                    (
                                        WriteClassificationProposal(
                                            "absolute_disjoint", width=4
                                        ),
                                    ),
                                ),
                            ),
                        ),
                        pe_bytes=_fixture_pe(code=code),
                        code_size=len(code),
                        expectation="rejected",
                    )
                )

    def test_zero_slot_closes_exact_nonzero_guard_edge(self) -> None:
        slot_va = 0x18000000 + DATA_RVA + 0x20
        code = (
            b"\x83\x3d"
            + slot_va.to_bytes(4, "little")
            + b"\x00\x75\x01\xc3\xff\x25"
            + slot_va.to_bytes(4, "little")
        )
        regions = ", ".join(
            (
                "{ id := 0, span := { start := 0x1000, size := 9 }, "
                "root := true, targets := [1, 2] }",
                "{ id := 1, span := { start := 0x100a, size := 6 }, "
                "root := false, targets := [] }",
                "{ id := 2, span := { start := 0x1009, size := 1 }, "
                "root := false, targets := [] }",
            )
        )
        spec = dataclasses.replace(
            minimal_spec(),
            definition_name="guardedZeroCertificate",
            reachable_target_ids=(0, 1, 2),
            regions=(),
            guarded_nonzero_edges=(GuardedNonzeroEdgeProposal(0, 1),),
            indirect_slot_sites=(IndirectSlotSiteProposal(1),),
        )
        self._assert_kernel_checked(
            self._compile(
                spec,
                pe_bytes=_fixture_pe(code=code),
                code_size=len(code),
                authority_options={
                    "check_size": 3,
                    "entries": ", ".join(
                        (
                            "{ id := 0, regionIndex := 0, rva := 0x1000 }",
                            "{ id := 1, regionIndex := 1, rva := 0x100a }",
                            "{ id := 2, regionIndex := 2, rva := 0x1009 }",
                        )
                    ),
                    "addresses": ", ".join(
                        (
                            "{ targetId := 0, kind := .canonical }",
                            "{ targetId := 2, kind := .canonical }",
                            "{ targetId := 1, kind := .canonical }",
                        )
                    ),
                    "regions": regions,
                },
                expectation="accepted",
            )
        )

    def test_unknown_and_overlapping_write_addresses_reject(self) -> None:
        slot_va = 0x18000000 + DATA_RVA + 0x20
        dynamic_write = b"\xc7\x00\x00\x00\x00\x00\xc3"
        self._assert_kernel_checked(
            self._compile(
                dataclasses.replace(
                    minimal_spec(),
                    definition_name="unknownDynamicWriteCertificate",
                    regions=(RegionBindingProposal(0, None),),
                ),
                pe_bytes=_fixture_pe(code=dynamic_write),
                code_size=len(dynamic_write),
                expectation="rejected",
            )
        )

        overlapping_address = slot_va + 1
        overlapping_write = (
            b"\xc7\x05"
            + overlapping_address.to_bytes(4, "little")
            + (0).to_bytes(4, "little")
            + b"\xc3"
        )
        self._assert_kernel_checked(
            self._compile(
                dataclasses.replace(
                    minimal_spec(),
                    definition_name="overlappingWriteCertificate",
                    regions=(
                        RegionBindingProposal(
                            0,
                            (
                                WriteClassificationProposal(
                                    "absolute_disjoint"
                                ),
                            ),
                        ),
                    ),
                ),
                pe_bytes=_fixture_pe(code=overlapping_write),
                code_size=len(overlapping_write),
                expectation="rejected",
            )
        )

    def test_zero_slot_is_an_exact_indirect_jump_source(self) -> None:
        slot_va = 0x18000000 + DATA_RVA + 0x20
        code = b"\xff\x25" + slot_va.to_bytes(4, "little")
        spec = dataclasses.replace(
            minimal_spec(),
            definition_name="indirectZeroCertificate",
            indirect_slot_sites=(IndirectSlotSiteProposal(0),),
        )
        self._assert_kernel_checked(
            self._compile(
                spec,
                pe_bytes=_fixture_pe(code=code),
                code_size=len(code),
                expectation="accepted",
            )
        )

        self._assert_kernel_checked(
            self._compile(
                dataclasses.replace(
                    spec,
                    definition_name="omittedIndirectSiteCertificate",
                    indirect_slot_sites=(),
                ),
                pe_bytes=_fixture_pe(code=code),
                code_size=len(code),
                expectation="rejected",
            )
        )

        wrong_slot = b"\xff\x25" + (slot_va + 4).to_bytes(4, "little")
        self._assert_kernel_checked(
            self._compile(
                dataclasses.replace(
                    spec, definition_name="wrongIndirectSlotCertificate"
                ),
                pe_bytes=_fixture_pe(code=wrong_slot),
                code_size=len(wrong_slot),
                expectation="rejected",
            )
        )

    def test_unrelated_reachable_indirect_mechanisms_are_not_slot_sites(
        self,
    ) -> None:
        slot_va = 0x18000000 + DATA_RVA + 0x20
        other_slot_va = slot_va + 4
        code = (
            b"\xff\x25"
            + slot_va.to_bytes(4, "little")
            + b"\xff\x25"
            + other_slot_va.to_bytes(4, "little")
        )
        authority_options = {
            "check_size": 2,
            "entries": ", ".join(
                (
                    "{ id := 0, regionIndex := 0, rva := 0x1000 }",
                    "{ id := 1, regionIndex := 1, rva := 0x1006 }",
                )
            ),
            "addresses": ", ".join(
                (
                    "{ targetId := 0, kind := .canonical }",
                    "{ targetId := 1, kind := .canonical }",
                )
            ),
            "regions": ", ".join(
                (
                    "{ id := 0, span := { start := 0x1000, size := 6 }, "
                    "root := true, targets := [] }",
                    "{ id := 1, span := { start := 0x1006, size := 6 }, "
                    "root := true, targets := [] }",
                )
            ),
        }
        spec = dataclasses.replace(
            minimal_spec(),
            definition_name="oneOfTwoIndirectSlotsCertificate",
            reachable_target_ids=(0, 1),
            indirect_slot_sites=(IndirectSlotSiteProposal(0),),
        )
        pe_bytes = _fixture_pe(
            code=code, slot_word=0, other_slot_word=0
        )
        self._assert_kernel_checked(
            self._compile(
                spec,
                pe_bytes=pe_bytes,
                code_size=len(code),
                authority_options=authority_options,
                expectation="accepted",
            )
        )

        for definition_name, sites in (
            ("omittedOneOfTwoIndirectSlotsCertificate", ()),
            (
                "misclassifiedOneOfTwoIndirectSlotsCertificate",
                (IndirectSlotSiteProposal(1),),
            ),
        ):
            with self.subTest(definition_name=definition_name):
                self._assert_kernel_checked(
                    self._compile(
                        dataclasses.replace(
                            spec,
                            definition_name=definition_name,
                            indirect_slot_sites=sites,
                        ),
                        pe_bytes=pe_bytes,
                        code_size=len(code),
                        authority_options=authority_options,
                        expectation="rejected",
                    )
                )


if __name__ == "__main__":
    unittest.main()
