{ pkgs, pythonEnv, pythonSource }:

let
  intent = pkgs.writeText "component-v2-fixture-intent.json" (builtins.toJSON {
    format = "spaghetti-extractor-component-catalog-intent-v2";
    program_id = "component-v2-fixture";
    permitted_activation_profiles = [ "bounded-equivalence-v1" ];
    components = [
      {
        id = "a";
        label = "A";
        selector = { entry_rva = 4096; };
        evidence_profile = "bounded-equivalence-v1";
        interface_review = "reviews/a.json";
        source = { files = [ "source/a.c" ]; };
      }
      {
        id = "b";
        label = "B";
        selector = { entry_rva = 4112; };
        evidence_profile = "structural-draft-v1";
        interface_review = "reviews/b.json";
        source = { files = [ "source/b.c" ]; };
      }
    ];
    groups = [ ];
    configurations = [
      {
        id = "a-only";
        label = "A fallback";
        selections = [ {
          kind = "component";
          id = "a";
          activation = "enabled";
        } ];
      }
      {
        id = "b-only";
        label = "B fallback";
        selections = [ {
          kind = "component";
          id = "b";
          activation = "draft";
        } ];
      }
    ];
  });
  fixture = pkgs.runCommand "spaghetti-extractor-components-v2-fixture"
    { nativeBuildInputs = [ pythonEnv ]; __contentAddressed = true; } ''
      mkdir -p "$out"
      python - "$out" <<'PY'
      import hashlib
      import json
      import pathlib
      import sys

      root = pathlib.Path(sys.argv[1])

      def canonical(value):
          return hashlib.sha256(json.dumps(
              value, sort_keys=True, separators=(",", ":")
          ).encode("ascii")).hexdigest()

      def write(path, value):
          path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

      def unit(identity, start):
          return {
              "id": identity,
              "reachability": "reachable",
              "source": {"original": {"rva_start": start, "rva_end": start + 1}},
              "semantics": {
                  "outcome": {
                      "kind": "return",
                      "value": {
                          "op": "load", "width": 4,
                          "address": {"op": "reg", "name": "esp", "width": 32},
                      },
                  },
                  "memory_events": [], "external_events": [], "faults": [],
                  "register_writes": [], "flag_writes": [],
              },
          }
      units = [unit("unit:a", 4096), unit("unit:b", 4112)]
      ir = root / "machine-ir.jsonl"
      ir.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in units))
      ir_hash = hashlib.sha256(ir.read_bytes()).hexdigest()
      manifest = {
          "format": "stage-a-machine-ir-v2",
          "artifacts": {"machine_ir": {"path": "machine-ir.jsonl", "sha256": ir_hash}},
          "binary": {"sha256": "1" * 64},
          "control": {"roots": [{"kind": "pe_entrypoint", "rva": 4096, "checked": True}]},
      }
      manifest_path = root / "machine-ir-manifest.json"
      write(manifest_path, manifest)
      manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
      plan = {
          "format": "stage-b-reconstruction-plan-v1",
          "status": "incomplete",
          "inputs": {"machine_ir": {
              "format": "stage-a-machine-ir-v2",
              "sha256": ir_hash,
              "manifest_sha256": manifest_hash,
          }},
          "clusters": [],
      }
      plan["plan_sha256"] = canonical(plan)
      write(root / "reconstruction-plan.json", plan)
      proposals = {
          "format": "stage-b-component-proposal-set-v1",
          "executes_original_binary": False,
          "bindings": {
              "machine_ir_sha256": ir_hash,
              "machine_ir_manifest_sha256": manifest_hash,
              "reconstruction_plan_sha256": plan["plan_sha256"],
              "original_binary_sha256": "1" * 64,
          },
          "proposals": [
              {
                  "id": "proposal:a",
                  "proposal_kinds": ["singleton"],
                  "membership": {"unit_ids": ["unit:a"], "rva_start": 4096, "rva_end": 4097},
                  "bindings": {"membership_bindings_sha256": "2" * 64},
              },
              {
                  "id": "proposal:b",
                  "proposal_kinds": ["singleton"],
                  "membership": {"unit_ids": ["unit:b"], "rva_start": 4112, "rva_end": 4113},
                  "bindings": {"membership_bindings_sha256": "3" * 64},
              },
          ],
      }
      proposals["proposal_set_sha256"] = canonical(proposals)
      write(root / "component-proposals.json", proposals)
      PY
    '';
  mkDag = reviewRoot: sourceRoot: evidenceById: import ../stage-b-components-v2.nix {
    inherit pkgs pythonEnv pythonSource intent;
    machineIr = fixture;
    reconstructionPlan = fixture;
    componentProposals = fixture;
    inherit reviewRoot sourceRoot evidenceById;
    namePrefix = "spaghetti-extractor-components-v2-fixture";
  };
  seed = mkDag ./fixtures/components-v2/base ./fixtures/components-v2/source-base { };
  evidenceA = pkgs.runCommand "spaghetti-extractor-components-v2-fixture-a-evidence"
    { nativeBuildInputs = [ pkgs.python3 ]; __contentAddressed = true; } ''
      python - \
        ${seed.contracts.a}/contract.json \
        ${seed.sourcePackages.a}/source-package.json \
        "$out" <<'PY'
      import hashlib
      import json
      import pathlib
      import sys

      contract = json.loads(pathlib.Path(sys.argv[1]).read_text())
      implementation = json.loads(pathlib.Path(sys.argv[2]).read_text())
      core = {
          "format": "spaghetti-extractor-component-evidence-v2",
          "status": "satisfied",
          "lift_unit_id": "a",
          "evidence_profile": "bounded-equivalence-v1",
          "executes_original_binary": False,
          "bindings": {
              "contract_sha256": contract["contract_sha256"],
              "implementation_sha256": implementation["implementation_sha256"],
          },
          "method": {
              "kind": "exhaustive_finite_domain_v1",
              "complete_for_declared_domain": True,
          },
          "coverage": {"counterexamples": 0},
      }
      encoded = json.dumps(core, sort_keys=True, separators=(",", ":")).encode("ascii")
      result = {**core, "evidence_sha256": hashlib.sha256(encoded).hexdigest()}
      pathlib.Path(sys.argv[3]).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
      PY
    '';
  base = mkDag ./fixtures/components-v2/base ./fixtures/components-v2/source-base {
    a = evidenceA;
  };
  changed = mkDag ./fixtures/components-v2/changed ./fixtures/components-v2/source-base {
    a = evidenceA;
  };
  sourceChanged = mkDag ./fixtures/components-v2/base ./fixtures/components-v2/source-changed {
    a = evidenceA;
  };
in
assert base.resolution.drvPath == changed.resolution.drvPath;
assert base.contracts.a.drvPath == changed.contracts.a.drvPath;
assert base.contracts.b.drvPath != changed.contracts.b.drvPath;
assert base.activationPlans."a-only".drvPath == changed.activationPlans."a-only".drvPath;
assert base.activationPlans."b-only".drvPath != changed.activationPlans."b-only".drvPath;
assert base.resolution.drvPath == sourceChanged.resolution.drvPath;
assert base.contracts.a.drvPath == sourceChanged.contracts.a.drvPath;
assert base.sourcePackages.a.drvPath != sourceChanged.sourcePackages.a.drvPath;
assert base.sourcePackages.b.drvPath == sourceChanged.sourcePackages.b.drvPath;
assert base.qualifications.a.drvPath != sourceChanged.qualifications.a.drvPath;
assert base.activationPlans."a-only".drvPath != sourceChanged.activationPlans."a-only".drvPath;
pkgs.linkFarm "spaghetti-extractor-components-v2-check" [
  { name = "resolution"; path = base.resolution; }
  { name = "contract-a"; path = base.contracts.a; }
  { name = "contract-b"; path = base.contracts.b; }
  { name = "source-a"; path = base.sourcePackages.a; }
  { name = "source-b"; path = base.sourcePackages.b; }
  { name = "qualification-a"; path = base.qualifications.a; }
  { name = "activation-a-stale-source"; path = sourceChanged.activationPlans."a-only"; }
  { name = "activation-a"; path = base.activationPlans."a-only"; }
  { name = "activation-b"; path = base.activationPlans."b-only"; }
]
