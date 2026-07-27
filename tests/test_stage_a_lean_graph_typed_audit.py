import json
import os
import shutil
import subprocess
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from spaghetti_extractor.relational.build import _locked_flake_input


class StageALeanGraphTypedAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(__file__).parents[1]
        self.evaluator = self.repo / "nix" / "stage-a-lean-graph.nix"

    def test_audit_builds_a_typed_canonical_witness(self) -> None:
        source = self.evaluator.read_text(encoding="utf-8")

        self.assertIn("theorem typedFinalTheorem", source)
        self.assertIn("PE32RawProgramsLinkedObservationallyEquivalent", source)
        self.assertNotIn("PE32RawProgramsObservationallyEquivalent", source)
        self.assertIn("#print axioms typedFinalTheorem", source)
        self.assertNotIn("#print axioms ${selectedAuditTheorem}", source)
        self.assertIn('"proposition_type_checked": True', source)
        self.assertIn('typed_witness = "StageA.FinalTheoremAudit.typedFinalTheorem"', source)
        self.assertIn("acceptanceNodeSteps = graph.acceptance.node_steps or null", source)
        self.assertIn("acceptanceNodeStepsValid", source)
        self.assertIn("selectedAuditTheorem = graph.expected_final_theorem", source)
        self.assertNotIn("auditTheorem ? null", source)

    @unittest.skipUnless(
        shutil.which("nix")
        and os.environ.get("SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION") == "1",
        "set SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION=1 to run Nix audit fixtures",
    )
    def test_nix_audit_rejects_same_named_theorem_with_weaker_type(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profiles = {
                "linked_closed": "linked-raw-pe32-closed",
                "linked_environment": "linked-raw-pe32-external-environment",
                "linked_protocol": "linked-raw-pe32-stateful-protocol",
            }
            for mode, expected_profile in profiles.items():
                with self.subTest(mode=mode):
                    valid = root / mode
                    self._write_fixture(valid, weakened=False, mode=mode)
                    valid_process = self._build_fixture(valid, mode=mode)
                    self.assertEqual(
                        valid_process.returncode, 0, valid_process.stderr[-4000:]
                    )
                    result_path = Path(
                        json.loads(valid_process.stdout)[0]["outputs"]["out"]
                    )
                    audit = json.loads(
                        (result_path / "audit.json").read_text(encoding="utf-8")
                    )
                    self.assertTrue(audit["proposition_type_checked"])
                    self.assertEqual(
                        audit["typed_witness"],
                        "StageA.FinalTheoremAudit.typedFinalTheorem",
                    )
                    self.assertEqual(
                        audit["canonical_proposition_profile"], expected_profile
                    )
                    self.assertEqual(audit["unexpected_axioms"], [])

            invalid = root / "invalid"
            self._write_fixture(invalid, weakened=True, mode="linked_closed")
            invalid_process = self._build_fixture(invalid, mode="linked_closed")
            self.assertNotEqual(invalid_process.returncode, 0)
            self.assertIn("stage-a-relational-proof-audit", invalid_process.stderr)

    def _write_fixture(self, root: Path, *, weakened: bool, mode: str) -> None:
        stage_a = root / "lean" / "StageA"
        stage_a.mkdir(parents=True)
        linked = mode.startswith("linked_")
        protocol = mode == "linked_protocol"
        parameterized = mode.endswith("environment") or protocol
        result_name = (
            "PE32RawProgramsLinkedObservationallyEquivalent"
            if linked
            else "PE32RawProgramsObservationallyEquivalent"
        )
        control_name = (
            "linkedProductControlProfile" if linked else "productControlProfile"
        )
        if protocol:
            program_definitions = """def originalWorldProgram
    (_environment : WorldExternalEnvironment)
    (_protocol : WorldExternalProtocolEnvironment) : DecodedWorldProgram := 0
def candidateWorldProgram
    (_environment : WorldExternalEnvironment)
    (_protocol : WorldExternalProtocolEnvironment) : DecodedWorldProgram := 0"""
            theorem_binders = """    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
    (originalProtocolEnvironment candidateProtocolEnvironment :
      WorldExternalProtocolEnvironment)
    (_environmentRefines : AcceptanceExternalEnvironmentsRefine
      originalEnvironment candidateEnvironment)
    (_protocolRefines : LinkedWorldExternalProtocolEnvironmentsRefine staticProofContext
      relationalProductGraph productInvariantTable
      relationalProductReachabilityEvidence linkedProductControlProfile
      protocolCallbackTargets externalCallSites
      originalProtocolEnvironment candidateProtocolEnvironment) :"""
            programs = (
                "(originalWorldProgram originalEnvironment originalProtocolEnvironment) "
                "(candidateWorldProgram candidateEnvironment candidateProtocolEnvironment)"
            )
        elif parameterized:
            program_definitions = """def originalWorldProgram
    (_environment : WorldExternalEnvironment) : DecodedWorldProgram := 0
def candidateWorldProgram
    (_environment : WorldExternalEnvironment) : DecodedWorldProgram := 0"""
            theorem_binders = """    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
    (_environmentRefines : AcceptanceExternalEnvironmentsRefine
      originalEnvironment candidateEnvironment) :"""
            programs = (
                "(originalWorldProgram originalEnvironment) "
                "(candidateWorldProgram candidateEnvironment)"
            )
        else:
            program_definitions = """def originalWorldProgram : DecodedWorldProgram := 0
def candidateWorldProgram : DecodedWorldProgram := 0"""
            theorem_binders = ":"
            programs = "originalWorldProgram candidateWorldProgram"
        canonical_type = (
            f"{result_name} staticProofContext relationalProductGraph "
            "productInvariantTable relationalProductReachabilityEvidence "
            f"{control_name} consoleLaunch {programs}"
        )
        theorem_type = "True" if weakened else canonical_type
        theorem_proof = "trivial" if weakened else "exact .intro"
        theorem_suffix = "Linked" if linked else ""
        source = f"""namespace StageA
namespace Formal
def auditMarker := 0
end Formal

namespace Relational
abbrev StaticProofContext := Nat
abbrev RelationalProductGraph := Nat
abbrev ProductInvariantTable := Nat
abbrev RelationalProductReachabilityEvidence := Nat
abbrev ProductControlProfile := Nat
abbrev LinkedControlAuthority := Nat
abbrev PE32ConsoleLaunchV2 := Nat
abbrev DecodedWorldProgram := Nat
abbrev WorldExternalEnvironment := Nat
abbrev WorldExternalProtocolEnvironment := Nat
abbrev ExternalCallSiteContract := Nat
abbrev ProtocolCallbackTargetProfile := Nat

inductive ExternalEnvironmentRefines
    (_context : StaticProofContext) (_sites : List ExternalCallSiteContract)
    (_original _candidate : WorldExternalEnvironment) : Prop where
  | intro

inductive AcceptanceExternalEnvironmentsRefine
    (_original _candidate : WorldExternalEnvironment) : Prop where
  | intro

inductive WorldExternalProtocolEnvironmentsRefine
    (_context : StaticProofContext) (_graph : RelationalProductGraph)
    (_invariants : ProductInvariantTable)
    (_reachability : RelationalProductReachabilityEvidence)
    (_control : ProductControlProfile)
    (_callbacks : ProtocolCallbackTargetProfile)
    (_sites : List ExternalCallSiteContract)
    (_original _candidate : WorldExternalProtocolEnvironment) : Prop where
  | intro

inductive LinkedWorldExternalProtocolEnvironmentsRefine
    (_context : StaticProofContext) (_graph : RelationalProductGraph)
    (_invariants : ProductInvariantTable)
    (_reachability : RelationalProductReachabilityEvidence)
    (_control : LinkedControlAuthority)
    (_callbacks : ProtocolCallbackTargetProfile)
    (_sites : List ExternalCallSiteContract)
    (_original _candidate : WorldExternalProtocolEnvironment) : Prop where
  | intro

inductive PE32RawProgramsObservationallyEquivalent
    (_context : StaticProofContext) (_graph : RelationalProductGraph)
    (_invariants : ProductInvariantTable)
    (_reachability : RelationalProductReachabilityEvidence)
    (_control : ProductControlProfile) (_launch : PE32ConsoleLaunchV2)
    (_original _candidate : DecodedWorldProgram) : Prop where
  | intro

inductive PE32RawProgramsLinkedObservationallyEquivalent
    (_context : StaticProofContext) (_graph : RelationalProductGraph)
    (_invariants : ProductInvariantTable)
    (_reachability : RelationalProductReachabilityEvidence)
    (_control : LinkedControlAuthority) (_launch : PE32ConsoleLaunchV2)
    (_original _candidate : DecodedWorldProgram) : Prop where
  | intro
end Relational

namespace GeneratedRelational
open StageA.Relational

def staticProofContext : StaticProofContext := 0
def relationalProductGraph : RelationalProductGraph := 0
def productInvariantTable : ProductInvariantTable := 0
def relationalProductReachabilityEvidence :
    RelationalProductReachabilityEvidence := 0
def productControlProfile : ProductControlProfile := 0
def linkedProductControlProfile : LinkedControlAuthority := 0
def consoleLaunch : PE32ConsoleLaunchV2 := 0
def externalCallSites : List ExternalCallSiteContract := []
def protocolCallbackTargets : ProtocolCallbackTargetProfile := 0
{program_definitions}

theorem candidatePE32ProgramsEquivalent{theorem_suffix}
{theorem_binders}
    {theorem_type} := by
  {theorem_proof}
end GeneratedRelational
end StageA
"""
        source_path = stage_a / "RelationalBundle.lean"
        source_path.write_text(source, encoding="utf-8")
        digest = sha256(source.encode()).hexdigest()
        theorem = "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent"
        selected_theorem = theorem + theorem_suffix
        node_kind = (
            "external_protocol" if protocol else "external_call" if parameterized else None
        )
        graph = {
            "format": "stage-a-lean-module-graph-v1",
            "lean": {"trust": 0},
            "root_module": "RelationalBundle",
            "final_node": "relationalbundle",
            "expected_final_theorem": selected_theorem,
            "acceptance": {
                "format": "stage-a-whole-program-acceptance-v1",
                "status": "ready",
                "required_theorem": selected_theorem,
                "theorem": selected_theorem,
                "node_steps": [] if node_kind is None else [{"kind": node_kind}],
                "linked_acceptance": {
                    "status": "ready" if linked else "incomplete",
                    "theorem": selected_theorem if linked else None,
                },
            },
            "approved_axioms": [],
            "modules": {
                "RelationalBundle": {
                    "source": "lean/StageA/RelationalBundle.lean",
                    "source_sha256": digest,
                    "imports": [],
                }
            },
            "nodes": [
                {
                    "id": "relationalbundle",
                    "modules": ["RelationalBundle"],
                    "dependencies": [],
                    "resource_class": "light",
                    "estimated_memory_mb": 512,
                    "source_sha256": digest,
                }
            ],
        }
        (root / "module-graph.json").write_text(
            json.dumps(graph, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (root / "prepared-proof.json").write_text("{}\n", encoding="utf-8")

    def _build_fixture(
        self, root: Path, *, mode: str
    ) -> subprocess.CompletedProcess[str]:
        locked_nixpkgs = _locked_flake_input(self.repo / "flake.lock", "nixpkgs")
        expression = "\n".join(
            [
                "let",
                "  nixpkgs = builtins.fetchTree (builtins.fromJSON "
                + json.dumps(json.dumps(locked_nixpkgs, sort_keys=True))
                + ");",
                "  pkgs = import nixpkgs { system = builtins.currentSystem; };",
                "in import (builtins.toPath "
                + json.dumps(str(self.evaluator))
                + ") {",
                "  inherit pkgs;",
                "  graphFile = builtins.path { name = \"typed-audit-graph.json\"; path = builtins.toPath "
                + json.dumps(str(root / "module-graph.json"))
                + "; };",
                "  preparedManifest = builtins.path { name = \"typed-audit-prepared.json\"; path = builtins.toPath "
                + json.dumps(str(root / "prepared-proof.json"))
                + "; };",
                "  sourceRoot = builtins.toPath " + json.dumps(str(root)) + ";",
                "}",
            ]
        )
        return subprocess.run(
            ["nix", "build", "--impure", "--no-link", "--json", "--expr", expression],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )


if __name__ == "__main__":
    unittest.main()
