from __future__ import annotations

import dataclasses
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.nullable_code_pointer_table import (
    RvaRangeProposal,
    TableAliasProposal,
    TableWriterProposal,
    nullable_code_pointer_table_source,
)
from tests.test_stage_a_nullable_code_pointer_table import (
    DATA_RAW,
    DATA_RVA,
    TEXT_RVA,
    nonzero_spec,
    one_zero_spec,
    sentinel_empty_spec,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Quot.sound"}


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


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageANullableCodePointerTableKernelTests(unittest.TestCase):
    source_root = (
        Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
    )

    def _compile(self, spec, expectation: str) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                self.source_root,
                stage_a,
                "RelationalNullableCodePointerTable",
            )
            (stage_a / "GeneratedNullableCodePointerTable.lean").write_text(
                nullable_code_pointer_table_source(
                    spec, expectation=expectation
                ),
                encoding="utf-8",
            )
            return _run_lean_relational(
                root, bundle="GeneratedNullableCodePointerTable"
            )

    def _assert_checked(self, result: dict) -> None:
        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 1, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)

    def test_sentinel_and_single_zero_ranges_prove_dispatch_unreachable(self) -> None:
        for label, spec in (
            ("sentinel-minus-one-zero", sentinel_empty_spec()),
            ("caller-range-one-zero", one_zero_spec()),
        ):
            with self.subTest(label=label):
                self._assert_checked(self._compile(spec, "unreachable"))

    def test_nonzero_entry_requires_exact_relocation_target_and_edge(self) -> None:
        base = nonzero_spec()
        missing_relocation_bytes = bytearray(base.pe_bytes)
        optional_offset = 0x98
        directory_offset = optional_offset + 96 + 5 * 8
        missing_relocation_bytes[directory_offset : directory_offset + 8] = b"\0" * 8
        cases = (
            ("complete", base, "accepted"),
            (
                "missing-relocation",
                dataclasses.replace(
                    base,
                    definition_name="missingRelocationCertificate",
                    pe_bytes=bytes(missing_relocation_bytes),
                ),
                "rejected",
            ),
            (
                "omitted-code-target",
                dataclasses.replace(
                    base,
                    definition_name="omittedCodeTargetCertificate",
                    code_map=(),
                ),
                "rejected",
            ),
            (
                "omitted-context-target",
                dataclasses.replace(
                    base,
                    definition_name="omittedContextTargetCertificate",
                    non_null_target_ids=(),
                    edges=(),
                ),
                "rejected",
            ),
            (
                "omitted-edge",
                dataclasses.replace(
                    base,
                    definition_name="omittedEdgeCertificate",
                    edges=(),
                ),
                "rejected",
            ),
        )
        for label, spec, expectation in cases:
            with self.subTest(label=label):
                self._assert_checked(self._compile(spec, expectation))

    def test_mutation_writable_range_and_context_gaps_fail_closed(self) -> None:
        base = one_zero_spec()
        mutated = bytearray(base.pe_bytes)
        mutated[DATA_RAW + 0x20] = 1
        writable = bytearray(base.pe_bytes)
        section_offset = 0x98 + 224 + 40
        characteristics_offset = section_offset + 36
        writable[characteristics_offset + 3] |= 0x80
        cases = (
            (
                "word-mutation",
                dataclasses.replace(
                    base,
                    definition_name="mutatedCertificate",
                    pe_bytes=bytes(mutated),
                ),
            ),
            (
                "writable-table",
                dataclasses.replace(
                    base,
                    definition_name="writableCertificate",
                    pe_bytes=bytes(writable),
                ),
            ),
            (
                "wrong-caller-range",
                dataclasses.replace(
                    sentinel_empty_spec(),
                    definition_name="wrongRangeCertificate",
                    caller_range=RvaRangeProposal(DATA_RVA, DATA_RVA + 8),
                ),
            ),
            (
                "writer-present",
                dataclasses.replace(
                    base,
                    definition_name="writerCertificate",
                    writers=(TableWriterProposal(
                        TEXT_RVA,
                        RvaRangeProposal(DATA_RVA + 0x20, DATA_RVA + 0x24),
                    ),),
                ),
            ),
            (
                "alias-present",
                dataclasses.replace(
                    base,
                    definition_name="aliasCertificate",
                    aliases=(TableAliasProposal(
                        DATA_RVA + 0x80, DATA_RVA + 0x20
                    ),),
                ),
            ),
            (
                "unknown-range",
                dataclasses.replace(
                    base,
                    definition_name="unknownRangeCertificate",
                    caller_range=None,
                ),
            ),
            (
                "unknown-targets",
                dataclasses.replace(
                    base,
                    definition_name="unknownTargetsCertificate",
                    non_null_target_ids=None,
                ),
            ),
        )
        for label, spec in cases:
            with self.subTest(label=label):
                self._assert_checked(self._compile(spec, "rejected"))


if __name__ == "__main__":
    unittest.main()
