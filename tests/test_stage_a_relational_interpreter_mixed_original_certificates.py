from __future__ import annotations

import hashlib
import re
import tempfile
import unittest
from pathlib import Path

from test_stage_a_relational_interpreter_mixed_original import (
    _pe32_static_indirect_image,
    _spec,
    _static_indirect_rows,
    _write_jsonl,
)

from spaghetti_extractor.relational.lean.interpreter_mixed_original import (
    INTERPRETER_MIXED_ORIGINAL_BASE_MODULE,
    OriginalPERecoveryInput,
    plan_interpreter_mixed_original,
    write_relational_interpreter_mixed_original_base,
)
from spaghetti_extractor.relational.lean.interpreter_mixed_original_certificates import (
    _certificate_aggregate_source,
    decompose_interpreter_mixed_original_base,
)


class StageARelationalInterpreterMixedOriginalCertificateTests(
    unittest.TestCase
):
    def test_typed_authority_imports_and_unmatched_blockers_are_preserved(
        self,
    ) -> None:
        image = _pe32_static_indirect_image()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(image)
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(state_machine, _static_indirect_rows())
            plan = plan_interpreter_mixed_original(
                state_machine,
                _spec(
                    recovery_pe=OriginalPERecoveryInput(
                        pe, hashlib.sha256(image).hexdigest()
                    )
                ),
            )
            out = root / "out"
            write_relational_interpreter_mixed_original_base(out, plan)
            base_path = (
                out / "StageA" / f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}.lean"
            )
            source = base_path.read_text(encoding="utf-8")

            authority_import = (
                "import StageA.GeneratedExternalTailStaticPointerSlotAuthorities"
            )
            source = authority_import + "\n" + source
            static_matches = list(
                re.finditer(
                    r"^def generatedOriginalStaticIndirect[0-9]+Behavior",
                    source,
                    re.MULTILINE,
                )
            )
            self.assertGreaterEqual(len(static_matches), 1)
            authority_reference = """
def generatedOriginalStaticIndirectTypedAuthority :
    ExternalTailStaticPointerSlotStaticAuthority generatedContext
      generatedOriginalStaticContext generatedSlotCertificate
      generatedStaticIndirectSpec :=
  StageA.Generated.ExternalTailAuthorities.site0000
""".strip()
            first_cluster_end = (
                static_matches[1].start()
                if len(static_matches) > 1
                else source.index("\ndef generatedOriginalLaunch :")
            )
            source = (
                source[:first_cluster_end]
                + "\n\n"
                + authority_reference
                + "\n"
                + source[first_cluster_end:]
            )
            namespace = f"{plan.spec.namespace}Base"
            blocker_tail = f"""

-- Generation is fail-closed; this synthetic authority is unrelated.
-- unresolved_indirect_control: static_pointer_slot at 0xdead: no exact matching authority

end {namespace}
"""
            source = source.removesuffix(f"\nend {namespace}\n") + blocker_tail
            base_path.write_text(source, encoding="utf-8")

            decomposition = decompose_interpreter_mixed_original_base(out, plan)
            sources = {
                path.stem: path.read_text(encoding="utf-8")
                for path in decomposition.paths
                if path.suffix == ".lean"
            }

        data = sources["GeneratedRelationalInterpreterMixedOriginalBaseData"]
        base = sources["GeneratedRelationalInterpreterMixedOriginalBase"]
        static_sites = [
            source
            for module, source in sources.items()
            if "BaseStaticIndirect" in module
        ]
        self.assertEqual(data.count(authority_import), 1)
        self.assertEqual(
            sum(source.count(authority_reference) for source in static_sites),
            1,
        )
        self.assertTrue(base.endswith(blocker_tail))
        self.assertEqual(base.count("unresolved_indirect_control:"), 1)
        self.assertNotIn(authority_reference, base)

    def test_exact_base_is_partitioned_into_proof_shards(self) -> None:
        image = _pe32_static_indirect_image()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(image)
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(state_machine, _static_indirect_rows())
            plan = plan_interpreter_mixed_original(
                state_machine,
                _spec(
                    recovery_pe=OriginalPERecoveryInput(
                        pe, hashlib.sha256(image).hexdigest()
                    )
                ),
            )
            out = root / "out"
            write_relational_interpreter_mixed_original_base(out, plan)
            decomposition = decompose_interpreter_mixed_original_base(out, plan)
            sources = {
                path.stem: path.read_text(encoding="utf-8")
                for path in decomposition.paths
                if path.suffix == ".lean"
            }

        base = sources["GeneratedRelationalInterpreterMixedOriginalBase"]
        data = sources["GeneratedRelationalInterpreterMixedOriginalBaseData"]
        exact = sources[
            "GeneratedRelationalInterpreterMixedOriginalBaseExactCertificate"
        ]
        context = sources[
            "GeneratedRelationalInterpreterMixedOriginalBaseContextData"
        ]
        carrier = sources[
            "GeneratedRelationalInterpreterMixedOriginalBaseCarrierData"
        ]
        aggregate = sources[
            "GeneratedRelationalInterpreterMixedOriginalBaseCertificateAggregate"
        ]
        check_shards = [
            source
            for module, source in sources.items()
            if "BaseCertificateShard" in module
        ]
        static_sites = [
            source
            for module, source in sources.items()
            if "BaseStaticIndirect" in module
        ]

        self.assertTrue(plan.complete, plan.blockers)
        self.assertNotIn("decide +kernel", base)
        self.assertNotIn("generatedExactOriginalCodeMapCertificate", data)
        self.assertIn("OriginalCodeMapProofCertificate", exact)
        self.assertIn(".toBooleanCertificate", exact)
        self.assertIn("ExactOriginalDecodedProofAuthority", exact)
        self.assertIn(".toBooleanAuthority", exact)
        self.assertIn("def generatedOriginalCarrierContext", context)
        self.assertIn("def generatedOriginalCarrierInvariantAt", context)
        self.assertNotIn(
            "def generatedOriginalMachineImportBoundarySiteBindings", context
        )
        self.assertIn(
            "import StageA.GeneratedRelationalInterpreterMixedOriginalBaseContextData",
            carrier,
        )
        self.assertIn("generatedOriginalEntriesIndexChecked", aggregate)
        self.assertIn("FiniteIndex.structurallyValid_branch", aggregate)
        self.assertGreaterEqual(len(check_shards), 2)
        self.assertTrue(
            all("IndexedBoolRangeHolds" in source for source in check_shards)
        )
        self.assertGreater(len(static_sites), 0)
        self.assertTrue(
            all("generatedOriginalStaticIndirect" in source for source in static_sites)
        )
        self.assertNotIn("generatedOriginalStaticIndirect0Behavior", base)
        self.assertEqual(
            sum(
                source.count("def generatedExactOriginalDecodedAuthority")
                for source in sources.values()
            ),
            1,
        )
        self.assertLessEqual(
            max(
                int(resource["estimated_memory_mb"])
                for resource in decomposition.resources.values()
            ),
            8192,
        )

    def test_synthetic_8192_entry_aggregate_contains_only_composition(
        self,
    ) -> None:
        shard_count = 64
        shard_size = 128
        target_refs = [
            (f"generatedOriginalTargetIndexShard{index}", shard_size)
            for index in range(shard_count)
        ]
        address_refs = [
            (f"generatedOriginalAddressIndexShard{index}", shard_size)
            for index in range(shard_count)
        ]
        region_refs = [
            (f"generatedOriginalRegionIndexShard{index}", shard_size)
            for index in range(shard_count)
        ]
        source = _certificate_aggregate_source(
            namespace="StageA.GeneratedRelational.SyntheticBase",
            data_module="SyntheticBaseData",
            check_modules=[
                f"SyntheticCertificateShard{index:04d}"
                for index in range(shard_count)
            ],
            target_refs=target_refs,
            address_refs=address_refs,
            region_refs=region_refs,
            target_count=shard_count * shard_size,
            address_count=shard_count * shard_size,
            address_counts=[shard_size] * shard_count,
        )

        self.assertIn("generatedOriginalEntriesIndexChecked", source)
        self.assertIn("generatedOriginalAddressCountExact", source)
        self.assertIn("FiniteIndex.structurallyValid_branch", source)
        self.assertNotIn("indexedBoolRangeHolds_of_checked", source)
        self.assertNotIn("decide +kernel", source)
        self.assertNotIn("List.range 8192", source)
        self.assertLess(len(source), 600_000)


if __name__ == "__main__":
    unittest.main()
