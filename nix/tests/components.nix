# spaghetti-extractor-python-role: developer
{ pkgs, pythonEnv, pythonSource }:

let
  intentPayload = {
    format = "spaghetti-extractor-component-catalog-intent-v2";
    program_id = "component-v2-fixture";
    permitted_activation_profiles = [
      "bounded-equivalence-v1"
      "validation-backed-v1"
    ];
    components = [
      {
        id = "a";
        label = "A";
        selector = { entry_rva = 4096; };
        evidence_profile = "bounded-equivalence-v1";
        interface_review = "reviews/a.json";
        source = {
          files = [ "source/a.c" ];
          entry = { abi = "logical-c-v1"; symbol = "component_a"; };
        };
        verification = {
          producer = "exhaustive-finite-domain-v1";
          parameter_domains = [ {
            parameter_id = "input_eax";
            kind = "integer-range";
            minimum = 0;
            maximum = 255;
          } ];
        };
      }
      {
        id = "b";
        label = "B";
        selector = { entry_rva = 4112; };
        evidence_profile = "bounded-equivalence-v1";
        interface_review = "reviews/b.json";
        source = {
          files = [ "source/b.c" ];
          entry = { abi = "logical-c-v1"; symbol = "component_b"; };
        };
        verification = {
          producer = "exhaustive-finite-domain-v1";
          parameter_domains = [ {
            parameter_id = "input_eax";
            kind = "integer-range";
            minimum = 0;
            maximum = 0;
          } ];
        };
      }
      {
        id = "c";
        label = "C";
        selector = { entry_rva = 4128; };
        evidence_profile = "validation-backed-v1";
        interface_review = "reviews/c.json";
        source = {
          files = [ "source/c.c" ];
          entry = { abi = "logical-c-v1"; symbol = "component_c"; };
        };
        verification = {
          producer = "candidate-only-functional-suite-v1";
          cases = [
            { id = "zero"; arguments.input_eax = 0; expected = 0; }
            { id = "high"; arguments.input_eax = 255; expected = 255; }
          ];
        };
      }
      {
        id = "d";
        label = "D";
        selector = { entry_rva = 4144; };
        evidence_profile = "bounded-equivalence-v1";
        interface_review = "reviews/d.json";
        source = {
          files = [ "source/d.c" ];
          entry = { abi = "logical-c-v1"; symbol = "component_d"; };
        };
        verification = {
          producer = "exhaustive-finite-domain-v1";
          parameter_domains = [ {
            parameter_id = "value";
            kind = "integer-range";
            minimum = 0;
            maximum = 15;
          } ];
        };
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
      {
        id = "b-enabled";
        label = "B blocked";
        selections = [ {
          kind = "component";
          id = "b";
          activation = "enabled";
        } ];
      }
      {
        id = "c-enabled";
        label = "C validation backed";
        selections = [ {
          kind = "component";
          id = "c";
          activation = "enabled";
        } ];
      }
      {
        id = "d-enabled";
        label = "D scalar control";
        selections = [ {
          kind = "component";
          id = "d";
          activation = "enabled";
        } ];
      }
    ];
  };
  intent = pkgs.writeText "component-v3-fixture-intent.json"
    (builtins.toJSON intentPayload);
  unrelatedIntent = pkgs.writeText
    "component-v3-fixture-unrelated-intent.json"
    (builtins.toJSON (intentPayload // {
      components = map (row:
        if row.id == "b" then row // { label = "B changed"; } else row
      ) intentPayload.components;
    }));
  fixture = pkgs.runCommand "spaghetti-extractor-components-fixture"
    { nativeBuildInputs = [ pythonEnv ]; __contentAddressed = true; } ''
      mkdir -p "$out"
      export PYTHONPATH=${pythonSource}/src
      python - "$out" <<'PY'
      import copy
      import hashlib
      import json
      import pathlib
      import sys
      from spaghetti_extractor.components.proposal_package import (
          write_component_proposal_package_v2,
      )

      root = pathlib.Path(sys.argv[1])

      def canonical(value):
          return hashlib.sha256(json.dumps(
              value, sort_keys=True, separators=(",", ":")
          ).encode("ascii")).hexdigest()

      def write(path, value):
          path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

      def unit(identity, start):
          register_writes = (
              [{"register": "eax", "value": {
                  "op": "reg", "name": "eax", "width": 32,
              }}]
              if identity in {"unit:a", "unit:c"} else []
          )
          return {
              "id": identity,
              "reachability": "reachable",
              "source": {
                  "contract_sha256": canonical({"contract": identity}),
                  "instruction_bytes_sha256": canonical({"instructions": identity}),
                  "original": {"rva_start": start, "rva_end": start + 1},
              },
              "semantics": {
                  "outcome": {
                      "kind": "return",
                      "value": {
                          "op": "load", "width": 4,
                          "address": {"op": "reg", "name": "esp", "width": 32},
                      },
                  },
                  "memory_events": [], "external_events": [], "faults": [],
                  "register_writes": register_writes, "flag_writes": [],
              },
          }
      branch_condition = {
          "op": "not",
          "args": [{
              "op": "eq",
              "args": [
                  {"op": "reg", "name": "ecx", "width": 32},
                  {"op": "const", "value": 7, "width": 32},
              ],
          }],
      }
      branch_unit = unit("unit:d", 4144)
      branch_unit["semantics"]["outcome"] = {
          "kind": "branch",
          "condition": branch_condition,
          "true_target_rva": 8192,
          "false_target_rva": 12288,
      }
      units = [
          unit("unit:a", 4096),
          unit("unit:b", 4112),
          unit("unit:c", 4128),
          branch_unit,
      ]
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
      unit_bindings = {
          row["id"]: {
              "unit_id": row["id"],
              "contract_sha256": row["source"]["contract_sha256"],
              "instruction_bytes_sha256": row["source"]["instruction_bytes_sha256"],
          }
          for row in units
      }
      proposal_rows = [
              {
                  "id": "proposal:a",
                  "status": "proposed",
                  "proposal_kinds": ["singleton"],
                  "membership": {
                      "unit_ids": ["unit:a"], "unit_count": 1,
                      "rva_start": 4096, "rva_end": 4097,
                      "noncontiguous": False,
                  },
                  "bindings": {"membership_bindings_sha256": canonical([unit_bindings["unit:a"]])},
                  "blockers": [],
              },
              {
                  "id": "proposal:b",
                  "status": "proposed",
                  "proposal_kinds": ["singleton"],
                  "membership": {
                      "unit_ids": ["unit:b"], "unit_count": 1,
                      "rva_start": 4112, "rva_end": 4113,
                      "noncontiguous": False,
                  },
                  "bindings": {"membership_bindings_sha256": canonical([unit_bindings["unit:b"]])},
                  "blockers": [],
              },
              {
                  "id": "proposal:c",
                  "status": "proposed",
                  "proposal_kinds": ["singleton"],
                  "membership": {
                      "unit_ids": ["unit:c"], "unit_count": 1,
                      "rva_start": 4128, "rva_end": 4129,
                      "noncontiguous": False,
                  },
                  "bindings": {"membership_bindings_sha256": canonical([unit_bindings["unit:c"]])},
                  "blockers": [],
              },
              {
                  "id": "proposal:d",
                  "status": "proposed",
                  "proposal_kinds": ["singleton"],
                  "membership": {
                      "unit_ids": ["unit:d"], "unit_count": 1,
                      "rva_start": 4144, "rva_end": 4145,
                      "noncontiguous": False,
                  },
                  "bindings": {"membership_bindings_sha256": canonical([unit_bindings["unit:d"]])},
                  "blockers": [],
              },
          ]
      for proposal in proposal_rows:
          proposal["proposal_sha256"] = canonical(proposal)
      proposal_template = {
          "format": "spaghetti-extractor-component-discovery-result-v2",
          "status": "proposed",
          "authority": {
              "class": "untrusted_component_discovery_proposals",
              "can_authorize_replacement": False,
              "requires_operator_selection": True,
              "requires_interface_refinement": True,
          },
          "executes_original_binary": False,
          "bindings": {
              "machine_ir_sha256": ir_hash,
              "machine_ir_manifest_sha256": manifest_hash,
              "reconstruction_plan_sha256": plan["plan_sha256"],
              "original_binary_sha256": "1" * 64,
          },
          "limits": {
              "max_units_per_candidate": 512,
              "max_candidates_per_seed": 12,
              "path_search_depth": 64,
          },
          "graph_facts": {"nodes": list(unit_bindings.values())},
          "seed_index": [],
          "coverage": {},
          "issues": [],
      }

      def write_package(name, rows):
          payload = copy.deepcopy(proposal_template)
          payload["proposals"] = rows
          payload["discovery_result_sha256"] = canonical(payload)
          write_component_proposal_package_v2(
              payload=payload,
              out=root / name,
          )

      write_package("component-proposals", proposal_rows)
      unrelated_changed = copy.deepcopy(proposal_rows)
      unrelated_changed[3]["diagnostic_note"] = "unrelated-change"
      unrelated_changed[3].pop("proposal_sha256")
      unrelated_changed[3]["proposal_sha256"] = canonical(unrelated_changed[3])
      write_package("component-proposals-unrelated-changed", unrelated_changed)
      selected_diagnostic_changed = copy.deepcopy(proposal_rows)
      selected_diagnostic_changed[0]["diagnostic_note"] = "selected-diagnostic-change"
      selected_diagnostic_changed[0].pop("proposal_sha256")
      selected_diagnostic_changed[0]["proposal_sha256"] = canonical(
          selected_diagnostic_changed[0]
      )
      write_package(
          "component-proposals-selected-diagnostic-changed",
          selected_diagnostic_changed,
      )
      selected_changed = copy.deepcopy(proposal_rows)
      selected_changed[0]["id"] = "proposal:a-changed"
      selected_changed[0].pop("proposal_sha256")
      selected_changed[0]["proposal_sha256"] = canonical(selected_changed[0])
      write_package("component-proposals-selected-changed", selected_changed)
      PY
    '';
  mkDag = componentIntent: reviewRoot: sourceRoot: proposals: import ../stage-b-components.nix {
    inherit pkgs pythonEnv pythonSource;
    intent = componentIntent;
    machineIr = fixture;
    reconstructionPlan = fixture;
    componentProposals = proposals;
    inherit reviewRoot sourceRoot;
    namePrefix = "spaghetti-extractor-components-fixture";
    interpreterPackage = interpreter;
  };
  base = mkDag intent ./fixtures/components/base ./fixtures/components/source-base
    "${fixture}/component-proposals";
  changed = mkDag intent ./fixtures/components/changed ./fixtures/components/source-base
    "${fixture}/component-proposals";
  sourceChanged = mkDag intent ./fixtures/components/base ./fixtures/components/source-changed
    "${fixture}/component-proposals";
  unrelatedProposalChanged = mkDag
    intent
    ./fixtures/components/base
    ./fixtures/components/source-base
    "${fixture}/component-proposals-unrelated-changed";
  selectedDiagnosticChanged = mkDag
    intent
    ./fixtures/components/base
    ./fixtures/components/source-base
    "${fixture}/component-proposals-selected-diagnostic-changed";
  selectedProposalChanged = mkDag
    intent
    ./fixtures/components/base
    ./fixtures/components/source-base
    "${fixture}/component-proposals-selected-changed";
  unrelatedIntentChanged = mkDag
    unrelatedIntent
    ./fixtures/components/base
    ./fixtures/components/source-base
    "${fixture}/component-proposals";
  interpreter = pkgs.runCommand "spaghetti-extractor-components-interpreter-fixture"
    { nativeBuildInputs = [ pkgs.coreutils ]; __contentAddressed = true; } ''
      mkdir -p "$out"
      cat > "$out/state-machine-runtime.h" <<'EOF'
      #ifndef STAGE_B_STATE_MACHINE_RUNTIME_H
      #define STAGE_B_STATE_MACHINE_RUNTIME_H
      #include <stdint.h>
      typedef struct stage_b_runtime {
        void *context;
        uint32_t (*read)(void *, uint32_t, uint32_t, uint32_t *);
        void (*write)(void *, uint32_t, uint32_t, uint32_t, uint32_t *);
      } stage_b_runtime;
      typedef struct stage_b_machine_state {
        uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp;
        uint32_t cf, zf, sf, of, pf, df;
      } stage_b_machine_state;
      typedef struct stage_b_step_result {
        uint32_t kind, target_rva, value;
      } stage_b_step_result;
      enum {
        STAGE_B_FALLTHROUGH = 0,
        STAGE_B_JUMP = 1,
        STAGE_B_BRANCH = 2,
        STAGE_B_RETURN = 3,
        STAGE_B_MEMORY_FAULT = 6,
        STAGE_B_UNIMPLEMENTED = 7
      };
      #endif
      EOF
      printf 'fixture\n' > "$out/baseline-state-machine.c"
      baseline_sha="$(sha256sum "$out/baseline-state-machine.c" | cut -d ' ' -f 1)"
      cat > "$out/state-machine-interpreter-package.json" <<EOF
      {
        "program": {
          "path": "baseline-state-machine.c",
          "sha256": "$baseline_sha"
        }
      }
      EOF
    '';
  runtime = base.runtimeFor "a-only";
  controlRuntime = base.runtimeFor "d-enabled";
  blocked = pkgs.runCommand "spaghetti-extractor-components-blocked-fixture"
    { nativeBuildInputs = [ pkgs.jq ]; __contentAddressed = true; } ''
      jq -e '
        .format == "spaghetti-extractor-component-activation-plan-v3" and
        .status == "incomplete" and
        .counts.blocked == 1 and
        .counts.machine_ir_fallback == 3 and
        (.entries | map(select(.implementation_kind == "blocked")) | length) == 1 and
        (.selections | all(
          if .requested_activation == "enabled"
          then .ownership_state == "blocked"
          else true
          end
        ))
      ' ${base.activationPlans."b-enabled"}/activation-plan.json >/dev/null
      touch "$out"
    '';
in
assert base.resolution.drvPath == changed.resolution.drvPath;
assert base.contracts.a.drvPath == changed.contracts.a.drvPath;
assert base.contracts.b.drvPath != changed.contracts.b.drvPath;
assert base.activationPlans."a-only".drvPath == changed.activationPlans."a-only".drvPath;
assert base.activationPlans."b-only".drvPath != changed.activationPlans."b-only".drvPath;
assert base.resolution.drvPath == sourceChanged.resolution.drvPath;
assert base.proposalInput.preparation.drvPath !=
  unrelatedProposalChanged.proposalInput.preparation.drvPath;
assert base.proposalInput.selectedProposals ==
  unrelatedProposalChanged.proposalInput.selectedProposals;
assert base.resolution.drvPath == unrelatedProposalChanged.resolution.drvPath;
assert base.proposalInput.preparation.drvPath !=
  selectedDiagnosticChanged.proposalInput.preparation.drvPath;
assert base.proposalInput.selectedProposals ==
  selectedDiagnosticChanged.proposalInput.selectedProposals;
assert base.resolution.drvPath == selectedDiagnosticChanged.resolution.drvPath;
assert base.proposalInput.selectedProposals !=
  selectedProposalChanged.proposalInput.selectedProposals;
assert base.resolution.drvPath != selectedProposalChanged.resolution.drvPath;
assert base.resolution.drvPath != unrelatedIntentChanged.resolution.drvPath;
assert base.proposalInput.selectionByComponent.a ==
  unrelatedIntentChanged.proposalInput.selectionByComponent.a;
assert base.resolutionSlices.a.drvPath ==
  unrelatedIntentChanged.resolutionSlices.a.drvPath;
assert base.contracts.a.drvPath == unrelatedIntentChanged.contracts.a.drvPath;
assert base.contracts.b.drvPath != unrelatedIntentChanged.contracts.b.drvPath;
assert base.contracts.a.drvPath == sourceChanged.contracts.a.drvPath;
assert base.sourcePackages.a.drvPath != sourceChanged.sourcePackages.a.drvPath;
assert base.sourcePackages.b.drvPath == sourceChanged.sourcePackages.b.drvPath;
assert base.qualifications.a.drvPath != sourceChanged.qualifications.a.drvPath;
assert base.activationPlans."a-only".drvPath != sourceChanged.activationPlans."a-only".drvPath;
assert runtime.drvPath == base.runtimePackages."a-only".drvPath;
assert builtins.attrNames base.workPackages == [ "a" "b" "c" "d" ];
assert builtins.attrNames base.statusReports == [ "a" "b" "c" "d" ];
assert builtins.attrNames base.configurationStatusReports == [ "a-only" "b-enabled" "b-only" "c-enabled" "d-enabled" ];
pkgs.linkFarm "spaghetti-extractor-components-check" [
  { name = "resolution"; path = base.resolution; }
  { name = "contract-a"; path = base.contracts.a; }
  { name = "contract-b"; path = base.contracts.b; }
  { name = "source-a"; path = base.sourcePackages.a; }
  { name = "source-b"; path = base.sourcePackages.b; }
  { name = "evidence-a"; path = base.evidences.a; }
  { name = "qualification-a"; path = base.qualifications.a; }
  { name = "evidence-c"; path = base.evidences.c; }
  { name = "qualification-c"; path = base.qualifications.c; }
  { name = "check-c"; path = base.checkGates.c; }
  { name = "activation-c"; path = base.activationPlans."c-enabled"; }
  { name = "adapter-d"; path = base.adapterPlans.d; }
  { name = "evidence-d"; path = base.evidences.d; }
  { name = "qualification-d"; path = base.qualifications.d; }
  { name = "check-d"; path = base.checkGates.d; }
  { name = "activation-d"; path = base.activationPlans."d-enabled"; }
  { name = "runtime-d"; path = controlRuntime; }
  { name = "status-a"; path = base.statusReports.a; }
  { name = "work-package-a"; path = base.workPackages.a; }
  { name = "check-a"; path = base.checkGates.a; }
  { name = "activation-a-stale-source"; path = sourceChanged.activationPlans."a-only"; }
  { name = "activation-a"; path = base.activationPlans."a-only"; }
  { name = "activation-b"; path = base.activationPlans."b-only"; }
  { name = "activation-b-blocked"; path = blocked; }
  { name = "configuration-status-a"; path = base.configurationStatusReports."a-only"; }
  { name = "configuration-check-a"; path = base.configurationCheckGates."a-only"; }
  { name = "runtime-a"; path = runtime; }
]
