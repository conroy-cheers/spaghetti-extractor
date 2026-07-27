import json
import os
import shutil
import subprocess
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from spaghetti_extractor.relational.build import _locked_flake_input


class StageALeanCompactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(__file__).parents[1]
        self.evaluator = self.repo / "nix" / "stage-a-lean-compact.nix"

    def test_compact_evaluator_preserves_the_acceptance_boundary(self) -> None:
        source = self.evaluator.read_text(encoding="utf-8")

        self.assertIn("theorem typedFinalTheorem", source)
        self.assertIn("PE32RawProgramsObservationallyEquivalent", source)
        self.assertIn("PE32RawProgramsLinkedObservationallyEquivalent", source)
        self.assertIn("#print axioms typedFinalTheorem", source)
        self.assertIn('lean -j 1 --trust=0', source)
        self.assertIn('cmp -s "$source"', source)
        self.assertIn('name = "stage-a-compact-module-graph.json";', source)
        self.assertIn('name = "stage-a-compact-prepared-proof.json";', source)
        self.assertIn("builtins.readFile graphInput", source)
        self.assertNotIn('cp "${effectiveGraphFile}"', source)
        self.assertIn('"lean_trust": 0', source)
        self.assertIn('"proposition_type_checked": True', source)
        self.assertIn("assert !positiveMode || acceptanceReady", source)
        self.assertNotIn("import ./stage-a-lean-graph.nix", source)

    @unittest.skipUnless(shutil.which("nix"), "Nix is required for syntax checking")
    def test_compact_evaluator_parses(self) -> None:
        process = subprocess.run(
            ["nix-instantiate", "--parse", str(self.evaluator)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)

    @unittest.skipUnless(
        shutil.which("nix")
        and os.environ.get("SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION") == "1",
        "set SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION=1 for compact Nix fixtures",
    )
    def test_compact_positive_and_negative_outputs_with_byte_checked_kernel(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._write_fixture(root)
            process = self._build_fixture(root)
            self.assertEqual(process.returncode, 0, process.stderr[-8000:])

            outputs = [
                Path(item["outputs"]["out"])
                for item in json.loads(process.stdout)
            ]
            positive_outputs = [path for path in outputs if (path / "audit.json").is_file()]
            negative_outputs = [path for path in outputs if (path / "bundle.json").is_file()]
            self.assertEqual(len(positive_outputs), 2)
            self.assertEqual(len(negative_outputs), 1)

            modes = []
            for output in positive_outputs:
                audit = json.loads((output / "audit.json").read_text(encoding="utf-8"))
                self.assertEqual(audit["status"], "checked")
                self.assertTrue(audit["proposition_type_checked"])
                self.assertEqual(audit["lean_trust"], 0)
                self.assertEqual(audit["unexpected_axioms"], [])
                self.assertTrue((output / "module-graph.json").is_file())
                self.assertTrue((output / "prepared-proof.json").is_file())
                self.assertEqual(
                    (output / "module-graph.json").read_bytes(),
                    (root / "module-graph.json").read_bytes(),
                )
                self.assertEqual(
                    (output / "prepared-proof.json").read_bytes(),
                    (root / "prepared-proof.json").read_bytes(),
                )
                provenance = json.loads(
                    (output / "node-provenance.json").read_text(encoding="utf-8")
                )
                self.assertEqual(
                    {node["id"] for node in provenance["nodes"]},
                    {"kernel", "relationalbundle"},
                )
                kernel = next(
                    node for node in provenance["nodes"] if node["id"] == "kernel"
                )
                modes.append(kernel["outputs"][0]["compile_mode"])
                self.assertTrue((output / "logs" / "Kernel.stdout").is_file())
            self.assertEqual(sorted(modes), ["compiled", "precompiled_kernel"])

            negative = negative_outputs[0]
            bundle = json.loads((negative / "bundle.json").read_text(encoding="utf-8"))
            self.assertEqual(bundle["lean_trust"], 0)
            self.assertEqual([node["id"] for node in bundle["nodes"]], ["counterexample"])
            node = json.loads(
                (negative / "module-result.json").read_text(encoding="utf-8")
            )
            self.assertEqual(node["id"], "counterexample")
            proof = node["outputs"][0]
            self.assertEqual(proof["module"], "RelationalCounterexample")
            self.assertTrue(proof["axiom_audit"]["complete"])
            self.assertEqual(
                proof["axiom_audit"]["inventories"]["reachableExactCounterexample"],
                [],
            )
            self.assertTrue(
                (negative / "StageA" / "RelationalCounterexample.lean").is_file()
            )
            self.assertTrue(
                (negative / "StageA" / "RelationalCounterexample.olean").is_file()
            )

    @unittest.skipUnless(
        shutil.which("nix")
        and os.environ.get("SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION") == "1",
        "set SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION=1 for compact Nix fixtures",
    )
    def test_compact_audit_rejects_a_same_named_weakened_theorem(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._write_fixture(root)
            bundle = root / "lean" / "StageA" / "RelationalBundle.lean"
            source = bundle.read_text(encoding="utf-8")
            declaration = source.index("theorem candidatePE32ProgramsEquivalent")
            namespace_end = source.index("end StageA.GeneratedRelational")
            weakened = (
                source[:declaration]
                + "theorem candidatePE32ProgramsEquivalent : True := by\n"
                + "  trivial\n"
                + source[namespace_end:]
            )
            self._replace_bundle_source(root, weakened)

            process = self._build_fixture(root)

            self.assertNotEqual(process.returncode, 0)
            self.assertIn("Type mismatch", process.stderr)

    @unittest.skipUnless(
        shutil.which("nix")
        and os.environ.get("SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION") == "1",
        "set SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION=1 for compact Nix fixtures",
    )
    def test_compact_audit_rejects_an_unapproved_axiom(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._write_fixture(root)
            bundle = root / "lean" / "StageA" / "RelationalBundle.lean"
            source = bundle.read_text(encoding="utf-8")
            theorem = "theorem candidatePE32ProgramsEquivalent :"
            axiom = """axiom compactUnsound :
    PE32RawProgramsObservationallyEquivalent staticProofContext
      relationalProductGraph productInvariantTable
      relationalProductReachabilityEvidence productControlProfile consoleLaunch
      originalWorldProgram candidateWorldProgram

"""
            source = source.replace(theorem, axiom + theorem, 1)
            source = source.replace("  exact .intro\n", "  exact compactUnsound\n", 1)
            self._replace_bundle_source(root, source)

            process = self._build_fixture(root)

            self.assertNotEqual(process.returncode, 0)
            self.assertIn("final theorem depends on unapproved axioms", process.stderr)

    def _write_fixture(self, root: Path) -> None:
        stage_a = root / "lean" / "StageA"
        stage_a.mkdir(parents=True)
        kernel = """namespace StageA
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

inductive WorldExternalProtocolEnvironmentsRefine
    (_context : StaticProofContext) (_graph : RelationalProductGraph)
    (_invariants : ProductInvariantTable)
    (_reachability : RelationalProductReachabilityEvidence)
    (_control : ProductControlProfile)
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
end StageA
"""
        bundle = """import StageA.Kernel

namespace StageA.GeneratedRelational
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
def originalWorldProgram : DecodedWorldProgram := 0
def candidateWorldProgram : DecodedWorldProgram := 0

theorem candidatePE32ProgramsEquivalent :
    PE32RawProgramsObservationallyEquivalent staticProofContext
      relationalProductGraph productInvariantTable
      relationalProductReachabilityEvidence productControlProfile consoleLaunch
      originalWorldProgram candidateWorldProgram := by
  exact .intro
end StageA.GeneratedRelational
"""
        counterexample = """import StageA.Kernel

namespace StageA.GeneratedRelationalCounterexample
theorem reachableExactCounterexample : True := by
  trivial
#print axioms reachableExactCounterexample
end StageA.GeneratedRelationalCounterexample
"""
        sources = {
            "Kernel": kernel,
            "RelationalBundle": bundle,
            "RelationalCounterexample": counterexample,
        }
        for module, source in sources.items():
            (stage_a / f"{module}.lean").write_text(source, encoding="utf-8")

        modules = {
            module: {
                "source": f"lean/StageA/{module}.lean",
                "source_sha256": sha256(source.encode()).hexdigest(),
                "imports": [] if module == "Kernel" else ["Kernel"],
            }
            for module, source in sources.items()
        }
        nodes = [
            self._node("kernel", ["Kernel"], [], sources),
            self._node(
                "relationalbundle", ["RelationalBundle"], ["kernel"], sources
            ),
            self._node(
                "counterexample", ["RelationalCounterexample"], ["kernel"], sources
            ),
        ]
        theorem = "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent"
        graph = {
            "format": "stage-a-lean-module-graph-v1",
            "lean": {"trust": 0},
            "root_module": "RelationalBundle",
            "final_node": "relationalbundle",
            "expected_final_theorem": theorem,
            "acceptance": {
                "format": "stage-a-whole-program-acceptance-v1",
                "status": "ready",
                "required_theorem": theorem,
                "theorem": theorem,
                "node_steps": [],
                "linked_acceptance": {"status": "incomplete", "theorem": None},
            },
            "approved_axioms": [],
            "modules": modules,
            "nodes": nodes,
        }
        (root / "module-graph.json").write_text(
            json.dumps(graph, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (root / "prepared-proof.json").write_text(
            json.dumps({"format": "compact-test-prepared-v1"}) + "\n",
            encoding="utf-8",
        )
        (root / "mismatched-kernel.lean").write_text(
            kernel.replace("def auditMarker := 0", "def auditMarker := 1"),
            encoding="utf-8",
        )

    @staticmethod
    def _node(
        node_id: str,
        modules: list[str],
        dependencies: list[str],
        sources: dict[str, str],
    ) -> dict[str, object]:
        return {
            "id": node_id,
            "modules": modules,
            "dependencies": dependencies,
            "resource_class": "light",
            "estimated_memory_mb": 128,
            "source_sha256": sha256("".join(
                sha256(sources[module].encode()).hexdigest()
                for module in modules
            ).encode()).hexdigest(),
        }

    @staticmethod
    def _replace_bundle_source(root: Path, source: str) -> None:
        bundle = root / "lean" / "StageA" / "RelationalBundle.lean"
        bundle.write_text(source, encoding="utf-8")
        graph_path = root / "module-graph.json"
        graph = json.loads(graph_path.read_text(encoding="utf-8"))
        digest = sha256(source.encode()).hexdigest()
        graph["modules"]["RelationalBundle"]["source_sha256"] = digest
        bundle_node = next(
            node for node in graph["nodes"] if node["id"] == "relationalbundle"
        )
        bundle_node["source_sha256"] = digest
        graph_path.write_text(
            json.dumps(graph, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def _build_fixture(self, root: Path) -> subprocess.CompletedProcess[str]:
        locked_nixpkgs = _locked_flake_input(self.repo / "flake.lock", "nixpkgs")
        kernel_source = root / "lean" / "StageA" / "Kernel.lean"
        mismatch_source = root / "mismatched-kernel.lean"
        expression = "\n".join(
            [
                "let",
                "  nixpkgs = builtins.fetchTree (builtins.fromJSON "
                + json.dumps(json.dumps(locked_nixpkgs, sort_keys=True))
                + ");",
                "  pkgs = import nixpkgs { system = builtins.currentSystem; };",
                "  makeKernel = name: source: pkgs.runCommand name "
                "{ nativeBuildInputs = [ pkgs.lean4 ]; } ''",
                "    mkdir -p source/StageA $out/StageA",
                "    cp ${source} source/StageA/Kernel.lean",
                "    lean --trust=0 -R source -o $out/StageA/Kernel.olean "
                "source/StageA/Kernel.lean",
                "    cp source/StageA/Kernel.lean $out/StageA/Kernel.lean",
                "  '';",
                "  exactKernel = makeKernel \"compact-exact-kernel\" "
                "(builtins.path { name = \"Kernel.lean\"; path = builtins.toPath "
                + json.dumps(str(kernel_source))
                + "; });",
                "  mismatchKernel = makeKernel \"compact-mismatch-kernel\" "
                "(builtins.path { name = \"Kernel.lean\"; path = builtins.toPath "
                + json.dumps(str(mismatch_source))
                + "; });",
                "  common = {",
                "    inherit pkgs;",
                "    graphFile = builtins.path { name = \"compact-graph.json\"; "
                "path = builtins.toPath "
                + json.dumps(str(root / "module-graph.json"))
                + "; };",
                "    preparedManifest = builtins.path { "
                "name = \"compact-prepared.json\"; path = builtins.toPath "
                + json.dumps(str(root / "prepared-proof.json"))
                + "; };",
                "    sourceRoot = builtins.toPath " + json.dumps(str(root)) + ";",
                "    contentAddressed = false;",
                "  };",
                "  evaluator = builtins.toPath " + json.dumps(str(self.evaluator)) + ";",
                "in [",
                "  (import evaluator (common // { precompiledKernel = exactKernel; }))",
                "  (import evaluator (common // { precompiledKernel = mismatchKernel; }))",
                "  (import evaluator (common // {",
                "    precompiledKernel = exactKernel;",
                "    targetNodes = [ \"counterexample\" ];",
                "    targetBundle = true;",
                "  }))",
                "]",
            ]
        )
        return subprocess.run(
            [
                "nix",
                "build",
                "--impure",
                "--no-link",
                "--json",
                "--print-build-logs",
                "--builders",
                "",
                "--max-jobs",
                "2",
                "--expr",
                expression,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )


if __name__ == "__main__":
    unittest.main()
