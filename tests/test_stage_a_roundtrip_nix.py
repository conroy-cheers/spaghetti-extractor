import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from hashlib import sha256
from pathlib import Path


class StageARoundtripNixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(__file__).parents[1]
        self.corpus_nix = self.repo / "nix" / "stage-a-roundtrip-corpus.nix"
        self.smoke_nix = self.repo / "nix" / "stage-a-roundtrip-smoke.nix"
        self.flake_nix = self.repo / "flake.nix"

    def test_static_smoke_has_no_runtime_executor_and_precedes_proofs(self) -> None:
        smoke = self.smoke_nix.read_text(encoding="utf-8")
        corpus = self.corpus_nix.read_text(encoding="utf-8")
        flake = self.flake_nix.read_text(encoding="utf-8")

        self.assertIn("stage-a-fuzz-run", smoke)
        self.assertIn("stage-a-fuzz-generate", corpus)
        self.assertIn("--stop-after-static-preflight", smoke)
        self.assertIn("expected-case-ids.json", smoke)
        self.assertIn("stage-a-relational-static-preflight-v1", smoke)
        self.assertIn('find "$out/corpus" -type f -exec chmod a-x', smoke)
        self.assertNotIn("prepared-proof.json", smoke)
        self.assertNotIn('mkdir -p "$out/prepared', smoke)
        self.assertNotRegex(smoke.lower(), r"(?m)^\s*(wine|wineserver|qemu)(\s|$)")
        self.assertIn(
            '"${smoke}/smoke/cases/${member.reference.id}/static-preflight.json"',
            corpus,
        )
        self.assertIn('"reran_proofs": False', corpus)
        self.assertIn('"executes_original_binary": False', corpus)
        self.assertNotIn("stage-a-build-relational", corpus)
        self.assertNotIn("nix build", corpus)
        self.assertIn("casePreparations", corpus)
        self.assertIn("preparationGraphBundle", corpus)
        self.assertIn("caseProofDags", corpus)
        self.assertIn("caseAudits", corpus)
        self.assertIn("caseResultBundle", corpus)
        self.assertIn("packResultBundle", corpus)
        self.assertIn("builtins.readFile args.preparationGraph", flake)
        self.assertNotIn(
            'builtins.readFile (args.preparation + "/module-graph.json")',
            flake,
        )
        self.assertIn('builtins.toFile "${caseId}-case-result.json"', corpus)
        self.assertIn(
            'builtins.toFile "${name}-${pack.id}-result.json"', corpus
        )
        self.assertGreaterEqual(
            corpus.count("builtins.unsafeDiscardStringContext"), 2
        )

    def test_flake_exports_stable_roundtrip_interfaces(self) -> None:
        flake = self.flake_nix.read_text(encoding="utf-8")

        self.assertIn("mkStageARoundtripCorpus", flake)
        self.assertIn("mkStageARoundtripSmoke", flake)
        self.assertIn("stage-a-roundtrip-static-smoke", flake)
        self.assertIn("stage-a-roundtrip-proof-smoke", flake)
        self.assertIn("stage-a-roundtrip-spike-corpus", flake)
        self.assertIn("stage-a-roundtrip-spike-pack-plan", flake)
        self.assertIn("stage-a-roundtrip-spike-check", flake)
        self.assertIn("stage-a-roundtrip-spike-corpus-root", flake)
        self.assertIn("stage-a-roundtrip-promoted-corpus", flake)
        self.assertIn("stage-a-roundtrip-promoted-pack-plan", flake)
        self.assertIn("stage-a-roundtrip-promoted-check", flake)
        self.assertIn("count = 75", flake)
        self.assertIn("pass = 50", flake)
        self.assertIn("violated = 25", flake)
        self.assertNotIn("root@acacia", flake)
        self.assertNotIn("root@banksia", flake)
        checks = flake[flake.index("checks = forAllSystems") :]
        self.assertIn("stage-a-roundtrip-spike-check", checks)
        self.assertIn("stage-a-roundtrip-promoted-check", checks)

    def test_flake_wires_real_non_recursive_proof_callbacks(self) -> None:
        flake = self.flake_nix.read_text(encoding="utf-8")
        start = flake.index("mkRoundtripCasePreparation =")
        end = flake.index("mkStageARoundtripQualification =", start)
        callbacks = flake[start:end]

        self.assertIn("stage-a-prepare-relational", callbacks)
        self.assertIn("import ./nix/stage-a-lean-compact.nix", callbacks)
        self.assertIn(
            "precompiledKernel = stage-a-relational-kernel-cache;", callbacks
        )
        self.assertIn('targetNode = negativeNode;', callbacks)
        self.assertIn('"relationalcounterexample"', callbacks)
        self.assertIn('"whole_program_lean"', callbacks)
        self.assertIn('__contentAddressed = true;', callbacks)
        self.assertNotIn("stage-a-fuzz-run", callbacks)
        self.assertNotIn("stage-a-build-relational", callbacks)
        self.assertNotIn("nix build", callbacks)
        self.assertNotIn("nix-store", callbacks)

        qualification_start = flake.index("mkStageARoundtripQualification =")
        qualification_end = flake.index(
            "stageARoundtripProofSmokeQualification =", qualification_start
        )
        qualification = flake[qualification_start:qualification_end]
        self.assertIn(
            "mkCasePreparation = mkRoundtripCasePreparation;", qualification
        )
        self.assertIn("mkCaseProofDag = mkRoundtripCaseProofDag;", qualification)
        self.assertIn("mkCaseAudit = mkRoundtripCaseAudit;", qualification)
        self.assertIn("caseMeasurementDefaults = {", qualification)
        self.assertIn('resourceClass = "whole-program-proof";', qualification)
        self.assertIn('resourceClass = "checked-witness";', qualification)
        self.assertIn(
            'measurementSource = "compact-spike-calibration-2026-07-22";',
            qualification,
        )

    def test_lean_graph_retains_focused_logs_and_axiom_metadata(self) -> None:
        graph = (self.repo / "nix" / "stage-a-lean-graph.nix").read_text(
            encoding="utf-8"
        )

        self.assertIn('mkdir -p "$out/StageA" "$out/logs"', graph)
        self.assertIn('compile_stdout": f"logs/{module}.stdout"', graph)
        self.assertIn('compile_stderr": f"logs/{module}.stderr"', graph)
        self.assertIn('"axiom_audit": {', graph)
        self.assertIn('"complete": all(value is not None', graph)
        self.assertIn('cp -L "${source}"/logs/* "$out/logs/"', graph)
        self.assertIn('contentAddressed ? true', graph)
        self.assertIn(
            'lib.optionalAttrs contentAddressed { __contentAddressed = true; }',
            graph,
        )
        self.assertIn('2> >(tee "$out/logs/${module}.stderr" >&2)', graph)

    def test_qualification_accepts_only_supported_whole_program_theorems(self) -> None:
        corpus = self.corpus_nix.read_text(encoding="utf-8")

        self.assertIn("candidatePE32ProgramsEquivalent\"", corpus)
        self.assertIn("candidatePE32ProgramsEquivalentLinked\"", corpus)
        self.assertNotIn(
            'acceptance.get("theorem")\n                    ==',
            corpus,
        )
        self.assertIn('"supported_acceptance_theorems"', corpus)

    @unittest.skipUnless(shutil.which("nix-instantiate"), "Nix is unavailable")
    def test_importable_nix_functions_parse(self) -> None:
        compact_nix = self.repo / "nix" / "stage-a-lean-compact.nix"
        for path in (self.smoke_nix, self.corpus_nix, compact_nix):
            process = subprocess.run(
                ["nix-instantiate", "--parse", str(path)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)

    @unittest.skipUnless(shutil.which("nix"), "Nix is unavailable")
    def test_pack_plan_is_deterministic_and_measurement_aware(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus = self._write_corpus(root / "corpus")
            expression = root / "plan.nix"
            expression.write_text(
                self._expression(corpus=corpus, result="qualification.packPlanPayload"),
                encoding="utf-8",
            )
            process = subprocess.run(
                ["nix", "eval", "--impure", "--json", "--file", str(expression)],
                cwd=self.repo,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr[-4000:])
            plan = json.loads(process.stdout)

        self.assertEqual(plan["format"], "stage-a-roundtrip-nix-pack-plan-v1")
        self.assertEqual(len(plan["packs"]), 3)
        self.assertEqual(
            [pack["cases"][0]["id"] for pack in plan["packs"]],
            ["case-a", "case-b", "case-c"],
        )
        self.assertTrue(all(pack["estimatedSeconds"] == 6 for pack in plan["packs"]))
        self.assertEqual(
            [pack["resourceClass"] for pack in plan["packs"]],
            ["standard", "standard", "high-memory"],
        )

    @unittest.skipUnless(shutil.which("nix"), "Nix is unavailable")
    def test_promoted_plan_represents_fifty_pass_and_twenty_five_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus = self._write_promoted_corpus(root / "corpus")
            expression = root / "promoted-plan.nix"
            expression.write_text(
                self._expression(
                    corpus=corpus,
                    result="qualification.packPlanPayload",
                    with_measurements=False,
                ),
                encoding="utf-8",
            )
            process = subprocess.run(
                ["nix", "eval", "--impure", "--json", "--file", str(expression)],
                cwd=self.repo,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr[-4000:])
            plan = json.loads(process.stdout)

        cases = [case for pack in plan["packs"] for case in pack["cases"]]
        self.assertEqual(len(cases), 75)
        self.assertEqual(sum(case["expected"] == "pass" for case in cases), 50)
        self.assertEqual(sum(case["expected"] == "violated" for case in cases), 25)
        self.assertTrue(all(len(pack["cases"]) <= 4 for pack in plan["packs"]))

    @unittest.skipUnless(
        shutil.which("nix")
        and os.environ.get("SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION") == "1",
        "set SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION=1 for the Nix build fixture",
    )
    def test_smoke_packs_and_aggregate_build_without_rerunning_cases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus = self._write_corpus(root / "corpus")
            expression = root / "build.nix"
            expression.write_text(
                self._expression(
                    corpus=corpus,
                    result="qualification.check",
                    with_fake_proofs=True,
                ),
                encoding="utf-8",
            )
            process = subprocess.run(
                [
                    "nix",
                    "build",
                    "--impure",
                    "--no-link",
                    "--json",
                    "--file",
                    str(expression),
                ],
                cwd=self.repo,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr[-8000:])
            output = Path(json.loads(process.stdout)[0]["outputs"]["out"])
            report = json.loads(
                (output / "run-result.json").read_text(encoding="utf-8")
            )
            plan = json.loads((output / "pack-plan.json").read_text(encoding="utf-8"))

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["counts"]["cases"], 3)
        self.assertEqual(report["counts"]["pass"], 2)
        self.assertEqual(report["counts"]["violated"], 1)
        self.assertTrue(report["counts"]["declared_expectations_match_manifest"])
        self.assertFalse(report["reran_proofs"])
        self.assertFalse(report["executes_original_binary"])
        self.assertEqual(len(report["packs"]), 3)
        self.assertTrue(all(
            pack["store_path"].startswith("/nix/store/")
            and pack["derivation_path"].endswith(".drv")
            for pack in report["packs"]
        ), report["packs"])
        self.assertTrue(all(
            case["preparation_store_path"].startswith("/nix/store/")
            and case["preparation_derivation_path"].endswith(".drv")
            and case["proof_dag_store_path"].startswith("/nix/store/")
            and case["proof_dag_derivation_path"].endswith(".drv")
            and case["audit_store_path"].startswith("/nix/store/")
            and case["audit_derivation_path"].endswith(".drv")
            for case in report["cases"]
        ))
        self.assertTrue(all(
            len({
                case["preparation_derivation_path"],
                case["proof_dag_derivation_path"],
                case["audit_derivation_path"],
            }) == 3
            for case in report["cases"]
        ))
        self.assertEqual(len(plan["packs"]), 3)

    @unittest.skipUnless(
        shutil.which("nix")
        and os.environ.get("SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION") == "1",
        "set SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION=1 for the real PE smoke",
    )
    def test_real_flake_smoke_generates_and_preflights_pe32_without_proof(self) -> None:
        process = subprocess.run(
            [
                "nix",
                "build",
                "--no-link",
                "--json",
                ".#stage-a-roundtrip-static-smoke",
            ],
            cwd=self.repo,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr[-8000:])
        output = Path(json.loads(process.stdout)[0]["outputs"]["out"])
        report = json.loads(
            (output / "smoke" / "run-result.json").read_text(encoding="utf-8")
        )
        manifest = json.loads(
            (output / "corpus" / "corpus.json").read_text(encoding="utf-8")
        )

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["stopped_after"], "static-preflight")
        self.assertEqual(len(report["cases"]), 4)
        self.assertEqual(len(manifest["cases"]), 4)
        for reference in manifest["cases"]:
            case = json.loads(
                (output / "corpus" / reference["path"]).read_text(encoding="utf-8")
            )
            for role in ("original_pe", "candidate_pe"):
                artifact = next(item for item in case["artifacts"] if item["role"] == role)
                binary = output / "corpus" / Path(reference["path"]).parent / artifact["path"]
                self.assertEqual(binary.read_bytes()[:2], b"MZ")
            phases = next(
                item["phases"] for item in report["cases"]
                if item["case_id"] == reference["id"]
            )
            self.assertFalse(any(
                phase["id"] in {"proof-preparation", "proof-build-and-audit"}
                for phase in phases
            ))

    def _write_corpus(self, root: Path) -> Path:
        root.mkdir(parents=True)
        specifications = (
            ("case-a", "pass", 0),
            ("case-b", "violated", 0),
            ("case-c", "pass", 1),
        )
        references = []
        for case_id, disposition, shard in specifications:
            case_root = root / "cases" / case_id
            case_root.mkdir(parents=True)
            case = {
                "format": "stage-a-roundtrip-case-v1",
                "id": case_id,
                "expectation": {"disposition": disposition},
                "shard": shard,
            }
            case_path = case_root / "case.json"
            encoded = json.dumps(case, indent=2, sort_keys=True) + "\n"
            case_path.write_text(encoded, encoding="utf-8")
            references.append({
                "id": case_id,
                "path": f"cases/{case_id}/case.json",
                "sha256": sha256(encoded.encode()).hexdigest(),
                "shard": shard,
            })
        manifest = {
            "format": "stage-a-roundtrip-corpus-v1",
            "generator_version": "nix-test-v1",
            "root_seed": 7,
            "capability_profile": "nix-test-profile",
            "toolchain": {
                "id": "nix-test",
                "target": "i686-windows",
                "compiler": "test",
                "compiler_version": "1",
                "linker": "test",
                "linker_version": "1",
            },
            "cases": references,
            "expected_counts": {"pass": 2, "violated": 1, "incomplete": 0},
            "shard_count": 2,
        }
        (root / "corpus.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return root

    def _write_promoted_corpus(self, root: Path) -> Path:
        root.mkdir(parents=True)
        references = []
        for index in range(75):
            case_id = f"promoted-{index:03d}"
            disposition = "violated" if index >= 50 else "pass"
            case_root = root / "cases" / case_id
            case_root.mkdir(parents=True)
            case = {
                "format": "stage-a-roundtrip-case-v1",
                "id": case_id,
                "expectation": {"disposition": disposition},
                "shard": index % 8,
            }
            case_path = case_root / "case.json"
            encoded = json.dumps(case, indent=2, sort_keys=True) + "\n"
            case_path.write_text(encoded, encoding="utf-8")
            references.append({
                "id": case_id,
                "path": f"cases/{case_id}/case.json",
                "sha256": sha256(encoded.encode()).hexdigest(),
                "shard": index % 8,
            })
        manifest = {
            "format": "stage-a-roundtrip-corpus-v1",
            "generator_version": "nix-promoted-test-v1",
            "root_seed": 11,
            "capability_profile": "nix-test-profile",
            "toolchain": {
                "id": "nix-test",
                "target": "i686-windows",
                "compiler": "test",
                "compiler_version": "1",
                "linker": "test",
                "linker_version": "1",
            },
            "cases": references,
            "expected_counts": {"pass": 50, "violated": 25, "incomplete": 0},
            "shard_count": 8,
        }
        (root / "corpus.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return root

    def _expression(
        self,
        *,
        corpus: Path,
        result: str,
        with_fake_proofs: bool = False,
        with_measurements: bool = True,
    ) -> str:
        fake_proofs = ""
        callbacks = ""
        if with_fake_proofs:
            fake_proofs = textwrap.dedent(
                """
                mkCasePreparation = args: pkgs.runCommand
                  ("roundtrip-preparation-" + args.caseId)
                  { }
                  ''
                    test -f ${args.staticPreflight}
                    mkdir -p "$out"
                    printf '%s\\n' ${builtins.toJSON args.caseId} \\
                      > "$out/prepared-proof.json"
                    printf '%s\\n' '{{}}' > "$out/module-graph.json"
                  '';
                mkCaseProofDag = args: pkgs.runCommand
                  ("roundtrip-proof-dag-" + args.caseId)
                  { }
                  ''
                    test -f ${args.preparation}/prepared-proof.json
                    mkdir -p "$out"
                    printf '%s\\n' ${builtins.toJSON args.caseId} \\
                      > "$out/proof-dag.json"
                  '';
                mkCaseAudit = args: pkgs.runCommand
                  ("roundtrip-audit-" + args.caseId)
                  { }
                  ''
                    test -f ${args.preparation}/prepared-proof.json
                    test -f ${args.proofDag}/proof-dag.json
                    mkdir -p "$out"
                    cat > "$out/result.json" <<'JSON'
                    {
                      "format": "stage-a-roundtrip-case-result-v1",
                      "case_id": ${builtins.toJSON args.caseId},
                      "mode": "proof-core",
                      "expected_disposition": ${builtins.toJSON args.case.expectation.disposition},
                      "actual_disposition": ${builtins.toJSON args.case.expectation.disposition},
                      "expectation_matched": true,
                      "phases": ${
                        if args.case.expectation.disposition == "pass"
                        then builtins.toJSON [{
                          id = "proof-build-and-audit";
                          status = "pass";
                        }]
                        else builtins.toJSON [{
                          id = "checked-violation-replay";
                          status = "violated";
                        }]
                      },
                      "acceptance": ${
                        if args.case.expectation.disposition == "pass"
                        then builtins.toJSON {
                          theorem = "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent";
                          authority = "whole_program_lean";
                        }
                        else builtins.toJSON {
                          theorem = null;
                          authority = null;
                        }
                      },
                      "frontiers": [],
                      "violation": ${
                        if args.case.expectation.disposition == "violated"
                        then builtins.toJSON {
                          format = "stage-a-checked-violation-result-v1";
                          status = "violated";
                          checks = { replay_checked = true; };
                          trust = {
                            role = "checked_inequivalence_witness";
                            can_authorize_pass = false;
                            raw_solver_status_sufficient = false;
                          };
                        }
                        else "null"
                      },
                      "error": null
                    }
                    JSON
                  '';
                """
            )
            callbacks = (
                "inherit mkCasePreparation mkCaseProofDag mkCaseAudit;"
            )
        measurements = ""
        if with_measurements:
            measurements = textwrap.dedent(
                """
                caseMeasurements = {
                  case-a = {
                    estimatedSeconds = 6;
                    estimatedMemoryMB = 1024;
                    resourceClass = "standard";
                  };
                  case-b = {
                    estimatedSeconds = 6;
                    estimatedMemoryMB = 2048;
                    resourceClass = "standard";
                  };
                  case-c = {
                    estimatedSeconds = 6;
                    estimatedMemoryMB = 8192;
                    resourceClass = "high-memory";
                  };
                };
                """
            )
        return textwrap.dedent(
            f"""
            let
              # Use the caller's pinned NIX_PATH.  Evaluating this orchestration
              # must not evaluate every output of the repository flake.
              pkgs = import <nixpkgs> {{ system = builtins.currentSystem; }};
              fakeTool = pkgs.writeShellScriptBin "spaghetti-extractor" ''
                set -euo pipefail
                command="$1"
                shift
                test "$command" = stage-a-fuzz-run
                output=""
                while [ "$#" -gt 0 ]; do
                  case "$1" in
                    --out) output="$2"; shift 2 ;;
                    *) shift ;;
                  esac
                done
                mkdir -p "$output"
                for case_id in case-a case-b case-c; do
                  mkdir -p "$output/cases/$case_id"
                  printf '%s\\n' '{{"format":"stage-a-relational-static-preflight-v1","status":"ready","acceptance_authority":false}}' \\
                    > "$output/cases/$case_id/static-preflight.json"
                done
                cat > "$output/run-result.json" <<'JSON'
                {{
                  "format": "stage-a-roundtrip-run-result-v1",
                  "status": "pass",
                  "mode": "proof-core",
                  "counts": {{"cases": 3}},
                  "cases": [
                    {{"case_id":"case-a","actual_disposition":"incomplete","acceptance":{{"authority":null}},"phases":[{{"id":"static-preflight","status":"ready"}}]}},
                    {{"case_id":"case-b","actual_disposition":"incomplete","acceptance":{{"authority":null}},"phases":[{{"id":"static-preflight","status":"ready"}}]}},
                    {{"case_id":"case-c","actual_disposition":"incomplete","acceptance":{{"authority":null}},"phases":[{{"id":"static-preflight","status":"ready"}}]}}
                  ],
                  "trust": {{"runner_has_proof_authority":false,"positive_pass_requires":"whole_program_lean"}},
                  "stopped_after": "static-preflight",
                  "expectations_evaluated": false,
                  "static_preflight_failure_case_ids": []
                }}
                JSON
                cat "$output/run-result.json"
              '';
              {fake_proofs}
              qualification = import {self.corpus_nix} {{
                inherit pkgs;
                spaghettiExtractor = fakeTool;
                corpusRoot = builtins.path {{
                  path = {corpus};
                  name = "stage-a-roundtrip-nix-test-corpus";
                }};
                {measurements}
                packPolicy = {{ maxEstimatedSeconds = 10; maxCases = 4; }};
                {callbacks}
              }};
            in
            {result}
            """
        )


if __name__ == "__main__":
    unittest.main()
