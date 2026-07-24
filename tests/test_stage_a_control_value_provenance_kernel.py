from __future__ import annotations

import copy
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any, Literal, TypedDict

from spaghetti_extractor.relational.lean.common import (
    _lean_byte_tree_definitions,
    _lean_import_certificate,
    _lean_pe,
    _lean_relocations,
)
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.control_value_provenance import (
    CONTROL_VALUE_PROVENANCE_LEAN_FILENAME,
    control_value_provenance_source,
)
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS
from spaghetti_extractor.stage_binary import StageABinary, _parse_stage_a_pe
from stage_a_relational_support import (
    _pe32_image,
    _pe32_image_with_immutable_word_branch,
    _pe32_import_image,
)
from test_stage_a_control_value_provenance import (
    FIXTURE_MODULE,
    _import,
    _location_pair,
    _register,
    _state,
    _static,
    _value,
    budget_overflow_certificate,
    context_only_certificate,
    spill_reload_certificate,
    zero_static_word_certificate,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_REPORT = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)


class _ContextMutations(TypedDict, total=False):
    original_tree_bytes: bytes
    original_imports: str
    original_relocations: str
    code_map: str


def _copy_module_closure(
    source_root: Path, destination: Path, module: str
) -> None:
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


def _spill_pe(*, aliasing_write: bool = False) -> bytes:
    if aliasing_write:
        first = bytes([0xB8, 0x20, 0x10, 0x40, 0, 0x89, 0x03, 0xEB, 0x07])
    else:
        first = bytes([
            0xB8, 0x20, 0x10, 0x40, 0, 0x89, 0x45, 0xFC, 0xEB, 0x06,
        ])
    code = bytearray(first)
    code.extend(b"\x90" * (0x10 - len(code)))
    code.extend(b"\x8b\x45\xfc\xeb\xfb")
    code.extend(b"\x90" * (0x20 - len(code)))
    code.append(0xC3)
    return _pe32_image(bytes(code))


def _code_map_literal(targets: list[tuple[int, int, int]]) -> str:
    if not targets:
        return """{
    entries := .empty
    originalAddresses := .empty
    candidateAddresses := .empty
  }"""
    entries = ",\n      ".join(
        "{ id := "
        + str(target_id)
        + ", regionIndex := "
        + str(region_id)
        + ", originalRva := "
        + str(rva)
        + ", candidateRva := "
        + str(rva)
        + " }"
        for target_id, region_id, rva in targets
    )
    addresses = ",\n      ".join(
        f"{{ targetId := {target_id}, kind := .canonical }}"
        for target_id, _, _ in sorted(targets, key=lambda row: row[2])
    )
    return f"""{{
    entries := .leaf [
      {entries}
    ]
    originalAddresses := .leaf [
      {addresses}
    ]
    candidateAddresses := .leaf [
      {addresses}
    ]
  }}"""


def _context_source(
    binary: StageABinary,
    pe_bytes: bytes,
    targets: list[tuple[int, int, int]],
    *,
    original_tree_bytes: bytes | None = None,
    original_imports: str | None = None,
    original_relocations: str | None = None,
    code_map: str | None = None,
) -> str:
    exact_imports = _lean_import_certificate(binary)
    exact_relocations = _lean_relocations(binary)
    original_bytes = pe_bytes if original_tree_bytes is None else original_tree_bytes
    return f"""import StageA.RelationalControlValueProvenance

namespace {FIXTURE_MODULE}

open StageA.Formal StageA.Relational

{_lean_byte_tree_definitions('originalBytes', original_bytes)}

{_lean_byte_tree_definitions('candidateBytes', pe_bytes)}

def originalPe : PE32 :=
  {_lean_pe(binary, 'originalBytes')}

def candidatePe : PE32 :=
  {_lean_pe(binary, 'candidateBytes')}

def exactContext : StaticProofContext := {{
  originalPe
  candidatePe
  originalImportCertificate := {
      exact_imports if original_imports is None else original_imports
  }
  candidateImportCertificate := {exact_imports}
  originalRelocations := {
      exact_relocations if original_relocations is None else original_relocations
  }
  candidateRelocations := {exact_relocations}
  codeMap := {code_map if code_map is not None else _code_map_literal(targets)}
  dataMap := {{ entries := #[], originalOrder := [], candidateOrder := [] }}
  roots := []
  observations := {{}}
}}

end {FIXTURE_MODULE}
"""


def _actual_import_call_certificate() -> dict[str, Any]:
    result = context_only_certificate()
    result["regions"] = [{
        "id": 0,
        "entry": True,
        "target_id": 0,
        "original_span": {"start": 0x1000, "size": 6},
        "candidate_span": {"start": 0x1000, "size": 6},
        "original_bytes": [0xFF, 0x15, 0x40, 0x20, 0x40, 0],
        "candidate_bytes": [0xFF, 0x15, 0x40, 0x20, 0x40, 0],
        "actions": [],
        "input": [],
        "output": [],
    }]
    result["call_references"] = [{
        "id": 0,
        "region_id": 0,
        "external_site_id": 0,
        "machine_contract_id": 0,
    }]
    result["sccs"] = [{
        "id": 0,
        "region_ids": [0],
        "edge_ids": [],
        "predecessor_ids": [],
        "successor_ids": [],
        "cyclic": False,
    }]
    result["component_order"] = [0]
    return result


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAControlValueProvenanceKernelTests(unittest.TestCase):
    source_root = (
        Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
    )

    def _compile(
        self,
        certificate: dict,
        pe_bytes: bytes,
        targets: list[tuple[int, int, int]],
        *,
        expectation: Literal["accepted", "rejected"] = "accepted",
        original_tree_bytes: bytes | None = None,
        original_imports: str | None = None,
        original_relocations: str | None = None,
        code_map: str | None = None,
    ) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                self.source_root,
                stage_a,
                "RelationalControlValueProvenance",
            )
            pe_path = root / "fixture.exe"
            pe_path.write_bytes(pe_bytes)
            binary = _parse_stage_a_pe(pe_path)
            (stage_a / "ControlValueProvenanceFixture.lean").write_text(
                _context_source(
                    binary,
                    pe_bytes,
                    targets,
                    original_tree_bytes=original_tree_bytes,
                    original_imports=original_imports,
                    original_relocations=original_relocations,
                    code_map=code_map,
                ),
                encoding="utf-8",
            )
            (stage_a / CONTROL_VALUE_PROVENANCE_LEAN_FILENAME).write_text(
                control_value_provenance_source(
                    certificate, expectation=expectation
                ),
                encoding="utf-8",
            )
            return _run_lean_relational(
                root, bundle="GeneratedRelationalControlValueProvenance"
            )

    def _assert_checked(self, result: dict) -> None:
        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertTrue(reports, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, RELATIONAL_APPROVED_AXIOMS, report)

    def test_spill_reload_zero_static_and_exact_import_context_recheck(self) -> None:
        cases = (
            (
                "spill-reload",
                spill_reload_certificate(),
                _spill_pe(),
                [(0, 0, 0x1000), (1, 1, 0x1010), (2, 0, 0x1020)],
            ),
            (
                "zero-static-word",
                zero_static_word_certificate(),
                _pe32_image_with_immutable_word_branch(0),
                [
                    (0, 0, 0x1000),
                    (1, 1, 0x1007),
                    (2, 2, 0x100C),
                    (3, 3, 0x100E),
                ],
            ),
            (
                "exact-import-context",
                context_only_certificate(),
                _pe32_import_image(b"\xc3", symbol="Dispatch"),
                [],
            ),
        )
        for label, certificate, pe_bytes, targets in cases:
            with self.subTest(label=label):
                self._assert_checked(
                    self._compile(certificate, pe_bytes, targets)
                )

    def test_region_byte_aliasing_write_omitted_edge_and_budget_reject(self) -> None:
        region_byte = copy.deepcopy(spill_reload_certificate())
        region_byte["regions"][0]["original_bytes"][0] = 0xB9

        aliasing = spill_reload_certificate()
        aliasing["regions"][0]["original_span"]["size"] = 9
        aliasing["regions"][0]["candidate_span"]["size"] = 9
        aliasing_bytes = [0xB8, 0x20, 0x10, 0x40, 0, 0x89, 0x03, 0xEB, 0x07]
        aliasing["regions"][0]["original_bytes"] = aliasing_bytes
        aliasing["regions"][0]["candidate_bytes"] = aliasing_bytes

        omitted_edge = copy.deepcopy(spill_reload_certificate())
        omitted_edge["edges"] = [omitted_edge["edges"][1]]

        cases = (
            ("region-byte", region_byte, _spill_pe()),
            ("aliasing-write", aliasing, _spill_pe(aliasing_write=True)),
            ("omitted-edge", omitted_edge, _spill_pe()),
            ("budget-overflow", budget_overflow_certificate(), _spill_pe()),
        )
        targets = [(0, 0, 0x1000), (1, 1, 0x1010), (2, 0, 0x1020)]
        for label, certificate, pe_bytes in cases:
            with self.subTest(label=label):
                self._assert_checked(
                    self._compile(
                        certificate,
                        pe_bytes,
                        targets,
                        expectation="rejected",
                    )
                )

    def test_ungrounded_import_and_actual_import_call_reject(self) -> None:
        pe_bytes = _pe32_import_image(
            b"\xff\x15\x40\x20\x40\x00\xc3", symbol="Dispatch"
        )
        ungrounded_import = context_only_certificate()
        ungrounded_import["locations"] = [
            _location_pair(0, _static(0x402040))
        ]
        ungrounded_import["static_seeds"] = [{
            "id": 0,
            "location_id": 0,
            "atom": _import("KERNEL32.dll", "NotDispatch"),
        }]

        for label, certificate, targets in (
            ("ungrounded-import", ungrounded_import, []),
            ("ungrounded-call", _actual_import_call_certificate(), [(0, 0, 0x1000)]),
        ):
            with self.subTest(label=label):
                self._assert_checked(
                    self._compile(
                        certificate,
                        pe_bytes,
                        targets,
                        expectation="rejected",
                    )
                )

    def test_pe_relocation_import_and_code_context_mutations_reject(self) -> None:
        invalid_header = bytearray(_spill_pe())
        invalid_header[0] = 0
        invalid_map = _code_map_literal([
            (0, 0, 0x1000),
            (1, 1, 0x5000),
            (2, 0, 0x1020),
        ])
        cases: tuple[
            tuple[
                str,
                dict[str, Any],
                bytes,
                list[tuple[int, int, int]],
                _ContextMutations,
            ],
            ...,
        ] = (
            (
                "pe-header",
                context_only_certificate(),
                _spill_pe(),
                [],
                {"original_tree_bytes": bytes(invalid_header)},
            ),
            (
                "relocation-inventory",
                context_only_certificate(),
                _pe32_image_with_immutable_word_branch(0),
                [],
                {"original_relocations": "[]"},
            ),
            (
                "import-table",
                context_only_certificate(),
                _pe32_import_image(b"\xc3", symbol="Dispatch"),
                [],
                {"original_imports": "{ descriptors := [] }"},
            ),
            (
                "code-map",
                context_only_certificate(),
                _spill_pe(),
                [],
                {"code_map": invalid_map},
            ),
        )
        for label, certificate, pe_bytes, targets, options in cases:
            with self.subTest(label=label):
                self._assert_checked(
                    self._compile(
                        certificate,
                        pe_bytes,
                        targets,
                        expectation="rejected",
                        original_tree_bytes=options.get("original_tree_bytes"),
                        original_imports=options.get("original_imports"),
                        original_relocations=options.get("original_relocations"),
                        code_map=options.get("code_map"),
                    )
                )

    def test_kernel_surface_is_canonical_and_exposes_semantic_frontier(self) -> None:
        source = (
            self.source_root / "RelationalControlValueProvenance.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "native_decide", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        for marker in (
            "import StageA.RelationalEnvironment",
            "StaticProofContext",
            "parsePE32Tree",
            "parseImports",
            "parseRelocations",
            "spanBytes",
            "regionBehaviorWithMachineCallContracts",
            "ExternalEnvironmentRefines",
            "MachineState",
            "RegionTransferClosed",
            "BranchGuardPathRelated",
            "AcceptanceIntegrationPremise",
        ):
            self.assertIn(marker, source)
        self.assertNotIn("SemanticallyValid", source)
        self.assertNotIn("def decodeBehavior", source)


if __name__ == "__main__":
    unittest.main()
