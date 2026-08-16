from __future__ import annotations

import inspect

from tests.unit.candidate.native_engine._support import *


class StrictNativeEngineTests(NativeEngineTestCase):
    def test_public_api_has_no_diagnostic_or_deferred_mode(self) -> None:
        parameters = inspect.signature(plan_spx_native_engine).parameters
        self.assertNotIn("state_machine", parameters)
        self.assertNotIn("candidate_mode", parameters)
        self.assertNotIn("allow_deferred_potential_transfers", parameters)
        self.assertIn("machine_ir", parameters)
        self.assertIn("machine_ir_manifest", parameters)
        self.assertIn("canonical_external_sites", parameters)

    def test_complete_machine_ir_produces_one_exact_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unit = _machine_ir_transfer(rva=0x1000, size=1, mnemonic="ret")
            unit["semantics"]["outcome"] = {"kind": "return"}
            machine_ir, manifest, sites, authority = self._strict_inputs(root, [unit])
            plan = plan_spx_native_engine(
                machine_ir=machine_ir,
                machine_ir_manifest=manifest,
                canonical_external_sites=sites,
                entry_rva=0x1000,
                **authority,
            )
            self.assertEqual(plan.status, "ready", plan.blockers)
            payload = plan.payload(state_machine_sha256=sha256_bytes(machine_ir.read_bytes()))
            self.assertEqual(payload["semantic_coverage"]["status"], "complete")
            self.assertEqual(
                plan.implementation_dispatch_receipt.status, "complete"
            )

    def test_incomplete_reachability_cannot_produce_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entry = _machine_ir_transfer(rva=0x1000, size=1, mnemonic="nop")
            potential = _machine_ir_transfer(rva=0x2000, size=1, mnemonic="ret")
            machine_ir, manifest, sites, authority = self._strict_inputs(
                root,
                [entry, potential],
                roots=[entry["id"]],
                reachable=[entry["id"]],
                potential=[potential["id"]],
            )
            with self.assertRaisesRegex(ValueError, "complete frontier-free"):
                plan_spx_native_engine(
                    machine_ir=machine_ir,
                    machine_ir_manifest=manifest,
                    canonical_external_sites=sites,
                    entry_rva=0x1000,
                    **authority,
                )
            with self.assertRaisesRegex(ValueError, "complete frontier-free"):
                write_spx_native_engine_package(
                    machine_ir=machine_ir,
                    machine_ir_manifest=manifest,
                    canonical_external_sites=sites,
                    entry_rva=0x1000,
                    out=root / "package",
                    **authority,
                )
            self.assertFalse((root / "package").exists())

    def test_manifest_must_bind_exact_machine_ir(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unit = _machine_ir_transfer(rva=0x1000, size=1, mnemonic="ret")
            machine_ir, manifest, sites, authority = self._strict_inputs(root, [unit])
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["artifacts"]["machine_ir"]["sha256"] = "0" * 64
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ToolkitInputError, "does not bind"):
                plan_spx_native_engine(
                    machine_ir=machine_ir,
                    machine_ir_manifest=manifest,
                    canonical_external_sites=sites,
                    entry_rva=0x1000,
                    **authority,
                )

    def test_package_is_deterministic_and_strictly_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unit = _machine_ir_transfer(rva=0x1000, size=1, mnemonic="ret")
            unit["semantics"]["outcome"] = {"kind": "return"}
            machine_ir, manifest, sites, authority = self._strict_inputs(root, [unit])
            first = write_spx_native_engine_package(
                machine_ir=machine_ir,
                machine_ir_manifest=manifest,
                canonical_external_sites=sites,
                entry_rva=0x1000,
                out=root / "first",
                **authority,
            )
            second = write_spx_native_engine_package(
                machine_ir=machine_ir,
                machine_ir_manifest=manifest,
                canonical_external_sites=sites,
                entry_rva=0x1000,
                out=root / "second",
                **authority,
            )
            self.assertEqual(first, second)
            self.assertEqual(
                first["policy"]["execution_scope"],
                "structural-executable-v1",
            )


if __name__ == "__main__":
    unittest.main()
