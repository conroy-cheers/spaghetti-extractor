from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.lockstep_environment import (
    FULL_MACHINE_LOCKSTEP_ENVIRONMENT_FORMAT,
    relational_exact_lockstep_acceptance_source,
    relational_lockstep_environment_source,
)
from spaghetti_extractor.relational.schema import RELATIONAL_KERNEL_MODULES


def _artifact() -> dict[str, Any]:
    return {
        "format": FULL_MACHINE_LOCKSTEP_ENVIRONMENT_FORMAT,
        "exact_import_identities": [
            {
                "dll": "example.dll",
                "ordinal": 17,
            },
            {
                "dll": "kernel32.dll",
                "symbol": "GetTickCount",
            },
        ],
        "call_sites": [
            {
                "id": 4,
                "import": {
                    "dll": "kernel32.dll",
                    "symbol": "GetTickCount",
                },
                "boundary_invariant": {
                    "register_relations": [
                        {
                            "original": "eax",
                            "candidate": "eax",
                            "relation": "exact",
                        }
                    ],
                    "flag_bits": [10],
                },
                "target_invariant": {},
            },
            {
                "id": 9,
                "import": {
                    "dll": "example.dll",
                    "ordinal": 17,
                },
                "boundary_invariant": {},
                "target_invariant": {
                    "register_relations": [
                        {
                            "original": "esp",
                            "candidate": "esp",
                            "relation": "exact",
                        }
                    ],
                    "predicates": [
                        {
                            "original": {
                                "op": "bool_constant",
                                "value": True,
                            },
                            "candidate": {
                                "op": "bool_constant",
                                "value": True,
                            },
                        }
                    ],
                },
            },
        ],
    }


class StageALockstepEnvironmentGenerationTests(unittest.TestCase):
    def test_exact_lockstep_acceptance_bridge_requires_checked_returns(self) -> None:
        source = relational_exact_lockstep_acceptance_source()

        self.assertIn("structure ExactLockstepExternalEnvironmentsRefine", source)
        self.assertIn("externalRefines : ExternalEnvironmentRefines", source)
        self.assertIn("checkedReturns : forall site contract", source)
        self.assertIn("CheckedExactLockstepExternalReturn", source)
        self.assertIn(
            "externalEnvironmentRefinesAt_of_checkedExactLockstep", source
        )
        for required in (
            "site \u2208 sites",
            "machineImportCallContractById?",
            "contract.disposition = .returns",
        ):
            self.assertIn(required, source)
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_emits_only_static_lockstep_site_data_and_certificates(self) -> None:
        source = relational_lockstep_environment_source(_artifact())

        self.assertIn("import StageA.RelationalLockstepEnvironment", source)
        self.assertIn(
            "def fullMachineLockstepCallSite4 : FullMachineLockstepCallSite",
            source,
        )
        self.assertIn(
            "def fullMachineLockstepCallSite9 : FullMachineLockstepCallSite",
            source,
        )
        self.assertIn(
            "fullMachineLockstepImportIdentity0 : ExternalTarget", source
        )
        self.assertIn(
            "(.symbol [71, 101, 116, 84, 105, 99, 107, 67, 111, 117, "
            "110, 116])",
            source,
        )
        self.assertIn("(.ordinal 17)", source)
        self.assertIn("fullMachineLockstepCallSiteIdsUniqueChecked", source)
        self.assertIn(
            "fullMachineLockstepCallSiteStaticIdentitiesChecked", source
        )
        self.assertNotIn("FullMachineLockstepEnvironmentRefinesAt", source)
        self.assertNotIn("FullMachineLockstepEnvironmentsRefined", source)
        self.assertNotIn("Acceptance", source)
        for marker in ("sorry", "axiom"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_rejects_missing_or_ambiguous_call_site_authority(self) -> None:
        cases: list[tuple[str, dict[str, Any], str]] = []

        missing_sites = _artifact()
        missing_sites["call_sites"] = []
        cases.append(("missing sites", missing_sites, "at least one call site"))

        missing_identity = _artifact()
        missing_identity["call_sites"][0]["import"] = {
            "dll": "kernel32.dll",
            "symbol": "Missing",
        }
        cases.append(("missing identity", missing_identity, "exactly one exact import"))

        missing_identity_site = _artifact()
        missing_identity_site["exact_import_identities"].append({
            "dll": "user32.dll",
            "symbol": "MessageBoxA",
        })
        cases.append((
            "missing identity site",
            missing_identity_site,
            "identities lack.*call sites",
        ))

        ambiguous_import = _artifact()
        ambiguous_import["exact_import_identities"][1] = deepcopy(
            ambiguous_import["exact_import_identities"][0]
        )
        cases.append(("ambiguous import", ambiguous_import, "ambiguous"))

        ambiguous_site = _artifact()
        ambiguous_site["call_sites"][1]["id"] = 4
        cases.append(("ambiguous site", ambiguous_site, "ambiguous"))

        for name, artifact, message in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(StageAInputError, message):
                    relational_lockstep_environment_source(artifact)

    def test_rejects_noncanonical_or_malformed_artifacts(self) -> None:
        unordered = _artifact()
        unordered["call_sites"] = list(reversed(unordered["call_sites"]))
        with self.assertRaisesRegex(StageAInputError, "canonical site-id order"):
            relational_lockstep_environment_source(unordered)

        malformed = _artifact()
        malformed["call_sites"][0]["boundary_invariant"] = {"unknown": []}
        with self.assertRaisesRegex(StageAInputError, "unexpected fields: unknown"):
            relational_lockstep_environment_source(malformed)

        wrong_format = _artifact()
        wrong_format["format"] = "stage-a-relational-full-machine-lockstep-v0"
        with self.assertRaisesRegex(StageAInputError, "unsupported.*format"):
            relational_lockstep_environment_source(wrong_format)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_generated_source_is_kernel_checked(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        generated = relational_lockstep_environment_source(_artifact())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            for module in RELATIONAL_KERNEL_MODULES:
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )
            (stage_a / "GeneratedLockstepEnvironment.lean").write_text(
                generated,
                encoding="utf-8",
            )
            (stage_a / "LockstepEnvironmentGenerationKernel.lean").write_text(
                """import StageA.GeneratedLockstepEnvironment

namespace StageA.LockstepEnvironmentGenerationKernel
open StageA.Formal StageA.Relational StageA.GeneratedRelational

example : fullMachineLockstepCallSiteIdsUnique
    fullMachineLockstepCallSites = true :=
  fullMachineLockstepCallSiteIdsUniqueChecked

example : fullMachineLockstepCallSites.map
    (fun site => (site.id, site.imported)) =
      fullMachineLockstepCallSiteStaticIdentities :=
  fullMachineLockstepCallSiteStaticIdentitiesChecked

#print axioms fullMachineLockstepCallSiteIdsUniqueChecked
#print axioms fullMachineLockstepCallSiteStaticIdentitiesChecked

end StageA.LockstepEnvironmentGenerationKernel
""",
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="LockstepEnvironmentGenerationKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_exact_lockstep_acceptance_bridge_is_kernel_checked(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            for module in (*RELATIONAL_KERNEL_MODULES, "RelationalLockstepEnvironment"):
                shutil.copyfile(
                    source_root / f"{module}.lean", stage_a / f"{module}.lean"
                )
            (stage_a / "RelationalAcceptanceExactLockstep.lean").write_text(
                relational_exact_lockstep_acceptance_source(), encoding="utf-8"
            )
            (stage_a / "ExactLockstepAcceptanceKernel.lean").write_text(
                """import StageA.RelationalAcceptanceExactLockstep

namespace StageA.ExactLockstepAcceptanceKernel
open StageA.Formal StageA.Relational

example (context : StaticProofContext) (sites : List ExternalCallSiteContract)
    (original candidate : WorldExternalEnvironment)
    (refines : ExactLockstepExternalEnvironmentsRefine context sites
      original candidate)
    (site : ExternalCallSiteContract) (contract : MachineImportCallContract)
    (member : site \u2208 sites)
    (resolved : machineImportCallContractById? context site.machineContractId =
      some contract)
    (returns : contract.disposition = .returns) :
    ExternalEnvironmentRefinesAt context site contract original candidate :=
  refines.atReturning context sites original candidate site contract member
    resolved returns

#print axioms ExactLockstepExternalEnvironmentsRefine.atReturning

end StageA.ExactLockstepAcceptanceKernel
""",
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="ExactLockstepAcceptanceKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
