# spaghetti-extractor-python-role: developer
{ pkgs, pythonEnv, pythonSource }:

let
  fixturePythonSource = import ../python-module-closure.nix {
    inherit pkgs;
    phaseRole = "developer";
    name = "spaghetti-extractor-components-fixture-python-closure";
    modules = [
      "spaghetti_extractor.components.proposal_package"
      "spaghetti_extractor.components.machine_binding"
    ];
  };
  rootedProjectionSource = import ../python-module-closure.nix {
    inherit pkgs;
    phaseRole = "candidate";
    name = "spaghetti-extractor-components-rooted-projection-python-closure";
    modules = [
      "spaghetti_extractor.candidate.authority.rooted_projection"
    ];
  };
  peFixtureSource = pkgs.lib.fileset.toSource {
    root = ../..;
    fileset = pkgs.lib.fileset.unions [
      ../../tests/pe_fixtures.py
    ];
  };
  intentPayload = {
    format = "spaghetti-extractor-component-catalog-intent-v2";
    program_id = "component-v2-fixture";
    permitted_activation_profiles = [
      "bounded-equivalence-v1"
      "portable-component-v2"
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
        evidence_profile = "bounded-equivalence-v1";
        interface_review = "reviews/c.json";
        source = {
          files = [ "source/c.c" ];
          entry = { abi = "logical-c-v1"; symbol = "component_c"; };
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
      {
        id = "e";
        label = "E portable V2";
        selector = { entry_rva = 4160; };
        evidence_profile = "portable-component-v2";
        interface_review = "reviews/e.json";
        machine_binding = "bindings/e.json";
        source = {
          files = [ "source/e.c" ];
          operations.increment = "component_e_increment";
        };
      }
      {
        id = "f";
        label = "F portable V2 service path";
        selector = { entry_rva = 4176; };
        evidence_profile = "portable-component-v2";
        interface_review = "reviews/f.json";
        machine_binding = "bindings/f.json";
        source = {
          files = [ "source/f.c" ];
          operations.run = "component_service_branch_run";
        };
      }
      {
        id = "g";
        label = "G portable V2 draft without a machine binding";
        selector = { entry_rva = 4224; };
        evidence_profile = "portable-component-v2";
        interface_review = "reviews/g.json";
        source = {
          files = [ "source/g.c" ];
          operations.increment = "component_g_increment";
        };
      }
      {
        id = "h";
        label = "H portable V2 inductive loop";
        selector = { entry_rva = 4240; };
        evidence_profile = "portable-component-v2";
        interface_review = "reviews/h.json";
        machine_binding = "bindings/h.json";
        induction = "induction/h.json";
        source = {
          files = [ "source/h.c" ];
          operations.run = "component_h_run";
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
        label = "C machine-derived finite domain";
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
      {
        id = "e-enabled";
        label = "E portable V2";
        selections = [ {
          kind = "component";
          id = "e";
          activation = "enabled";
        } ];
      }
      {
        id = "f-enabled";
        label = "F service path";
        selections = [ {
          kind = "component";
          id = "f";
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
    { nativeBuildInputs = [ pkgs.python3 ]; __contentAddressed = true; } ''
      mkdir -p "$out"
      export PYTHONPATH=${fixturePythonSource}/src
      python3 - "$out" ${./fixtures/components/base/e.json} \
        ${./fixtures/components/base/f.json} <<'PY'
      import copy
      import hashlib
      import json
      import pathlib
      import sys
      from spaghetti_extractor.components.proposal_package import (
          write_component_proposal_package_v2,
      )
      from spaghetti_extractor.components.machine_binding import (
          COMPONENT_MACHINE_BINDING_DECLARATION_V2,
      )

      root = pathlib.Path(sys.argv[1])
      review = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
      portable_interface = review["overrides"]["portable_interface_ir"]

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
              "format": "spaghetti-extractor-machine-ir-v3",
              "record_kind": "unit",
              "id": identity,
              "status": "qualified",
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
      portable_unit = unit("unit:e", 4160)
      portable_unit["semantics"]["register_writes"] = [{
          "register": "eax",
          "value": {
              "op": "add32",
              "args": [
                  {"op": "reg", "name": "ecx", "width": 32},
                  {"op": "const", "value": 1, "width": 32},
              ],
              "width": 32,
          },
      }]
      response = {
          "op": "call_response", "call_index": 0,
          "register": "eax", "width": 32,
      }
      service_event = {
          "kind": "external_call", "dll": "test.dll", "symbol": "choose",
          "instruction_rva": 4180, "return_rva": 4192,
          "target_rva": 12288,
          "register_inputs": {
              "ecx": {"op": "reg", "name": "ecx", "width": 32},
          },
          "flag_inputs": {},
          "arguments": [{"op": "reg", "name": "ecx", "width": 32}],
          "stack_inputs": [],
      }
      service_call = unit("unit:f-call", 4176)
      service_call["semantics"].update({
          "outcome": {
              "kind": "branch", "true_target_rva": 4192,
              "false_target_rva": 4208,
          },
          "edge_conditions": [
              {"target_rva": 4192, "condition": {
                  "op": "eq", "args": [
                      response, {"op": "const", "value": 0, "width": 32},
                  ],
              }},
              {"target_rva": 4208, "condition": {
                  "op": "not", "args": [{
                      "op": "eq", "args": [
                          response, {"op": "const", "value": 0, "width": 32},
                      ],
                  }],
              }},
          ],
          "external_events": [service_event],
          "register_writes": [{"register": "eax", "value": response}],
      })
      service_success = unit("unit:f-success", 4192)
      service_success["semantics"]["register_writes"] = [{
          "register": "eax",
          "value": {"op": "const", "value": 11, "width": 32},
      }]
      service_failure = unit("unit:f-failure", 4208)
      loop_entry = unit("unit:h-entry", 4240)
      loop_entry["semantics"].update({
          "outcome": {"kind": "jump", "target_rva": 4256},
          "edge_conditions": [{"target_rva": 4256, "condition": {"op": "true"}}],
          "register_writes": [{
              "register": "edx",
              "value": {"op": "reg", "name": "ecx", "width": 32},
          }],
      })
      loop_condition = {
          "op": "not",
          "args": [{
              "op": "eq",
              "args": [
                  {"op": "reg", "name": "edx", "width": 32},
                  {"op": "const", "value": 0, "width": 32},
              ],
          }],
      }
      loop_head = unit("unit:h-head", 4256)
      loop_head["semantics"].update({
          "outcome": {
              "kind": "branch", "condition": loop_condition,
              "true_target_rva": 4272, "false_target_rva": 4288,
          },
          "edge_conditions": [
              {"target_rva": 4272, "condition": loop_condition},
              {"target_rva": 4288, "condition": {
                  "op": "not", "args": [loop_condition],
              }},
          ],
      })
      loop_body = unit("unit:h-body", 4272)
      loop_body["semantics"].update({
          "outcome": {"kind": "jump", "target_rva": 4256},
          "edge_conditions": [{"target_rva": 4256, "condition": {"op": "true"}}],
          "register_writes": [{
              "register": "edx",
              "value": {
                  "op": "sub32",
                  "args": [
                      {"op": "reg", "name": "edx", "width": 32},
                      {"op": "const", "value": 1, "width": 32},
                  ],
                  "width": 32,
              },
          }],
      })
      loop_exit = unit("unit:h-exit", 4288)
      loop_exit["semantics"]["register_writes"] = [{
          "register": "eax",
          "value": {"op": "reg", "name": "edx", "width": 32},
      }]
      units = [
          unit("unit:a", 4096),
          unit("unit:b", 4112),
          unit("unit:c", 4128),
          branch_unit,
      portable_unit,
      service_call,
      service_success,
      service_failure,
      unit("unit:g", 4224),
      loop_entry,
      loop_head,
      loop_body,
      loop_exit,
      ]
      ir = root / "machine-ir.jsonl"
      ir.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in units))
      ir_hash = hashlib.sha256(ir.read_bytes()).hexdigest()
      manifest = {
          "format": "spaghetti-extractor-machine-ir-v3",
          "artifacts": {"machine_ir": {"path": "machine-ir.jsonl", "sha256": ir_hash}},
          "binary": {"sha256": "1" * 64},
          "control": {"roots": [{"kind": "pe_entrypoint", "rva": 4096, "checked": True}]},
      }
      manifest_path = root / "machine-ir-manifest.json"
      write(manifest_path, manifest)
      manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
      plan = {
          "format": "spaghetti-extractor-reconstruction-plan-v1",
          "status": "incomplete",
          "inputs": {"machine_ir": {
              "format": "spaghetti-extractor-machine-ir-v3",
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
              {
                  "id": "proposal:e",
                  "status": "proposed",
                  "proposal_kinds": ["singleton"],
                  "membership": {
                      "unit_ids": ["unit:e"], "unit_count": 1,
                      "rva_start": 4160, "rva_end": 4161,
                      "noncontiguous": False,
                  },
                  "bindings": {"membership_bindings_sha256": canonical([unit_bindings["unit:e"]])},
                  "blockers": [],
              },
              {
                  "id": "proposal:f",
                  "status": "proposed",
                  "proposal_kinds": ["operator-cluster"],
                  "membership": {
                      "unit_ids": ["unit:f-call", "unit:f-failure", "unit:f-success"],
                      "unit_count": 3,
                      "rva_start": 4176, "rva_end": 4209,
                      "noncontiguous": False,
                  },
                  "bindings": {"membership_bindings_sha256": canonical([
                      unit_bindings["unit:f-call"],
                      unit_bindings["unit:f-failure"],
                      unit_bindings["unit:f-success"],
                  ])},
                  "blockers": [],
              },
              {
                  "id": "proposal:g",
                  "status": "proposed",
                  "proposal_kinds": ["singleton"],
                  "membership": {
                      "unit_ids": ["unit:g"], "unit_count": 1,
                      "rva_start": 4224, "rva_end": 4225,
                      "noncontiguous": False,
                  },
                  "bindings": {"membership_bindings_sha256": canonical([
                      unit_bindings["unit:g"],
                  ])},
                  "blockers": [],
              },
              {
                  "id": "proposal:h",
                  "status": "proposed",
                  "proposal_kinds": ["operator-cluster"],
                  "membership": {
                      "unit_ids": [
                          "unit:h-body", "unit:h-entry", "unit:h-exit", "unit:h-head"
                      ],
                      "unit_count": 4,
                      "rva_start": 4240, "rva_end": 4289,
                      "noncontiguous": False,
                  },
                  "bindings": {"membership_bindings_sha256": canonical([
                      unit_bindings["unit:h-body"],
                      unit_bindings["unit:h-entry"],
                      unit_bindings["unit:h-exit"],
                      unit_bindings["unit:h-head"],
                  ])},
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

      (root / "bindings").mkdir()
      write(root / "bindings" / "e.json", {
          "format": COMPONENT_MACHINE_BINDING_DECLARATION_V2,
          "id": "e",
          "unit_ids": ["unit:e"],
          "operations": [{
              "operation_id": "increment",
              "entry_unit_ids": ["unit:e"],
              "exit_unit_ids": ["unit:e"],
              "parameters": [{
                  "id": "value",
                  "projection": {
                      "kind": "register", "register": "ecx", "width": 32,
                      "at": "entry",
                  },
              }],
              "results": [{
                  "id": "result",
                  "projection": {
                      "kind": "register", "register": "eax", "width": 32,
                      "at": "exit",
                  },
              }],
              "state": [],
              "preserved_state_ids": [],
              "effects": [],
              "callback_operation_ids": [],
              "continuation_unit_ids": [],
          }],
          "services": [],
      })
      write(root / "bindings" / "f.json", {
          "format": COMPONENT_MACHINE_BINDING_DECLARATION_V2,
          "id": "f",
          "unit_ids": ["unit:f-call", "unit:f-failure", "unit:f-success"],
          "operations": [{
              "operation_id": "run",
              "entry_unit_ids": ["unit:f-call"],
              "exit_unit_ids": ["unit:f-failure", "unit:f-success"],
              "parameters": [{
                  "id": "value",
                  "projection": {
                      "kind": "register", "register": "ecx", "width": 32,
                      "at": "entry",
                  },
              }],
              "results": [{
                  "id": "result",
                  "projection": {
                      "kind": "register", "register": "eax", "width": 32,
                      "at": "exit",
                  },
              }],
              "state": [],
              "preserved_state_ids": [],
              "effects": [],
              "callback_operation_ids": [],
              "continuation_unit_ids": [],
          }],
          "services": [{
              "service_id": "choose",
              "mediation": "direct",
              "provider": {
                  "kind": "machine_events",
                  "events": [{
                      "unit_id": "unit:f-call",
                      "event_index": 0,
                      "arguments": [{
                          "kind": "register", "register": "ecx", "width": 32,
                          "at": "call",
                      }],
                      "result": {
                          "kind": "register", "register": "eax", "width": 32,
                          "at": "call",
                      },
                  }],
              },
          }],
      })
      write(root / "bindings" / "h.json", {
          "format": COMPONENT_MACHINE_BINDING_DECLARATION_V2,
          "id": "h",
          "unit_ids": [
              "unit:h-body", "unit:h-entry", "unit:h-exit", "unit:h-head"
          ],
          "operations": [{
              "operation_id": "run",
              "entry_unit_ids": ["unit:h-entry"],
              "exit_unit_ids": ["unit:h-exit"],
              "parameters": [{
                  "id": "count",
                  "projection": {
                      "kind": "register", "register": "ecx", "width": 32,
                      "at": "entry",
                  },
              }],
              "results": [{
                  "id": "result",
                  "projection": {
                      "kind": "register", "register": "eax", "width": 32,
                      "at": "exit",
                  },
              }],
              "state": [],
              "preserved_state_ids": [],
              "effects": [],
              "callback_operation_ids": [],
              "continuation_unit_ids": [],
          }],
          "services": [],
      })
      PY
    '';
  rootedBehavioralProjection = pkgs.runCommand
    "spaghetti-extractor-components-rooted-projection-fixture"
    { nativeBuildInputs = [ pythonEnv ]; } ''
      mkdir -p "$out"
      export PYTHONPATH=${rootedProjectionSource}/src
      ${pythonEnv}/bin/python3 - \
        ${fixture}/machine-ir.jsonl \
        "$out/rooted-behavioral-projection-v1.json" <<'PY'
      import json
      import pathlib
      import sys

      from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
      from spaghetti_extractor.candidate.authority.rooted_projection import (
          ROOTED_BEHAVIORAL_PROJECTION_V1_FORMAT,
      )

      machine_ir, output = map(pathlib.Path, sys.argv[1:])
      unit_ids = sorted(
          json.loads(line)["id"]
          for line in machine_ir.read_text(encoding="utf-8").splitlines()
          if line
      )
      core = {
          "format": ROOTED_BEHAVIORAL_PROJECTION_V1_FORMAT,
          "root_unit_ids": [unit_ids[0]],
          "reachable_unit_ids": unit_ids,
          "structural_unit_count": len(unit_ids),
          "bindings": {
              "root_closure_manifest_sha256": "a" * 64,
              "semantic_index_manifest_sha256": "b" * 64,
              "semantic_universe_sha256": "c" * 64,
          },
      }
      output.write_text(
          json.dumps(
              {**core, "projection_sha256": canonical_sha256_v3(core)},
              indent=2,
              sort_keys=True,
          ) + "\n",
          encoding="ascii",
      )
      PY
    '';
  mkDag = componentIntent: reviewRoot: sourceRoot: inductionRoot: proposals: import ../component-workflow.nix {
    inherit pkgs pythonEnv pythonSource;
    intent = componentIntent;
    machineIr = fixture;
    reconstructionPlan = fixture;
    componentProposals = proposals;
    inherit reviewRoot sourceRoot inductionRoot;
    bindingRoot = "${fixture}/bindings";
    namePrefix = "spaghetti-extractor-components-fixture";
    interpreterPackage = interpreter;
    inherit rootedBehavioralProjection;
  };
  base = mkDag intent ./fixtures/components/base ./fixtures/components/source-base
    ./fixtures/components/induction-base
    "${fixture}/component-proposals";
  changed = mkDag intent ./fixtures/components/changed ./fixtures/components/source-base
    ./fixtures/components/induction-base
    "${fixture}/component-proposals";
  sourceChanged = mkDag intent ./fixtures/components/base ./fixtures/components/source-changed
    ./fixtures/components/induction-base
    "${fixture}/component-proposals";
  inductionChanged = mkDag intent ./fixtures/components/base
    ./fixtures/components/source-base ./fixtures/components/induction-changed
    "${fixture}/component-proposals";
  unrelatedProposalChanged = mkDag
    intent
    ./fixtures/components/base
    ./fixtures/components/source-base
    ./fixtures/components/induction-base
    "${fixture}/component-proposals-unrelated-changed";
  selectedDiagnosticChanged = mkDag
    intent
    ./fixtures/components/base
    ./fixtures/components/source-base
    ./fixtures/components/induction-base
    "${fixture}/component-proposals-selected-diagnostic-changed";
  selectedProposalChanged = mkDag
    intent
    ./fixtures/components/base
    ./fixtures/components/source-base
    ./fixtures/components/induction-base
    "${fixture}/component-proposals-selected-changed";
  unrelatedIntentChanged = mkDag
    unrelatedIntent
    ./fixtures/components/base
    ./fixtures/components/source-base
    ./fixtures/components/induction-base
    "${fixture}/component-proposals";
  missingInductionRoot = import ../component-workflow.nix {
    inherit pkgs pythonEnv pythonSource intent;
    machineIr = fixture;
    reconstructionPlan = fixture;
    componentProposals = "${fixture}/component-proposals";
    reviewRoot = ./fixtures/components/base;
    sourceRoot = ./fixtures/components/source-base;
    bindingRoot = "${fixture}/bindings";
    namePrefix = "spaghetti-extractor-components-missing-induction-root";
    interpreterPackage = interpreter;
    inherit rootedBehavioralProjection;
  };
  missingInductionRootEvaluation = builtins.tryEval
    missingInductionRoot.inductionPackages.h.drvPath;
  interpreter = pkgs.runCommand "spaghetti-extractor-components-interpreter-fixture"
    { nativeBuildInputs = [ pkgs.coreutils ]; __contentAddressed = true; } ''
      mkdir -p "$out"
      cat > "$out/state-machine-runtime.h" <<'EOF'
      #ifndef SPX_STATE_MACHINE_RUNTIME_H
      #define SPX_STATE_MACHINE_RUNTIME_H
      #include <stdint.h>
      typedef struct spx_runtime {
        void *context;
        uint32_t (*read)(void *, uint32_t, uint32_t, uint32_t *);
        void (*write)(void *, uint32_t, uint32_t, uint32_t, uint32_t *);
      } spx_runtime;
      typedef struct spx_machine_state {
        uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp;
        uint32_t cf, zf, sf, of, pf, df;
      } spx_machine_state;
      typedef struct spx_step_result {
        uint32_t kind, target_rva, value;
      } spx_step_result;
      typedef struct spx_stack_input {
        uint32_t offset, width, value;
      } spx_stack_input;
      typedef enum spx_call_event_kind {
        SPX_CALL_EXTERNAL_IMPORT,
        SPX_CALL_INTERNAL_DIRECT,
        SPX_CALL_INDIRECT
      } spx_call_event_kind;
      typedef struct spx_call_event {
        spx_call_event_kind kind;
        uint32_t instruction_rva, call_index, target_rva, return_rva;
        const char *dll, *symbol;
        uint32_t ordinal, has_ordinal;
        const uint32_t *arguments;
        uint32_t argument_count;
        const spx_stack_input *stack_inputs;
        uint32_t stack_input_count;
      } spx_call_event;
      typedef enum spx_call_status {
        SPX_CALL_OK,
        SPX_CALL_UNIMPLEMENTED,
        SPX_CALL_DIVIDE_ERROR,
        SPX_CALL_MEMORY_FAULT,
        SPX_CALL_EXTERNAL_FAULT
      } spx_call_status;
      spx_call_status spx_invoke_call(
          spx_runtime *, const spx_call_event *,
          const spx_machine_state *, spx_machine_state *);
      enum {
        SPX_FALLTHROUGH = 0,
        SPX_JUMP = 1,
        SPX_BRANCH = 2,
        SPX_RETURN = 3,
        SPX_INDIRECT_JUMP = 4,
        SPX_EXTERNAL_FAULT = 5,
        SPX_MEMORY_FAULT = 6,
        SPX_UNIMPLEMENTED = 7,
        SPX_DIVIDE_ERROR = 8
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
  portableRuntime = base.runtimeFor "e-enabled";
  serviceRuntime = base.runtimeFor "f-enabled";
  reusableLibraryImplementation = pkgs.runCommand
    "spaghetti-extractor-library-behavior-fixture-implementation"
    {
      nativeBuildInputs = [ pythonEnv ];
      __contentAddressed = true;
    } ''
      set -euo pipefail
      export PYTHONPATH=${pythonSource}/src
      mkdir -p "$out"
      ${pythonEnv}/bin/python3 - \
        ${base.sourcePackages.e} \
        ${base.developmentContracts.e}/portable-interface.json \
        ${base.sourceProfiles.e}/source-profile.json \
        ${base.refinementReceipts.e}/refinement-receipt.json \
        "$out/implementation.json" <<'PY'
      import json
      import pathlib
      import sys

      from spaghetti_extractor.components.interface_ir import (
          PortableComponentInterfaceV2,
      )
      from spaghetti_extractor.components.source import (
          component_operation_symbols,
          load_component_source_package,
      )
      from spaghetti_extractor.libraries.v4_adoption_records import (
          REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1,
          LibraryOperationSourceMappingV1,
          ReusableLibraryImplementationV1,
      )

      source_root, interface_path, profile_path, qualification_path, output = (
          map(pathlib.Path, sys.argv[1:])
      )
      source = load_component_source_package(source_root)
      interface = PortableComponentInterfaceV2.parse(
          json.loads(interface_path.read_text(encoding="utf-8"))
      )
      profile = json.loads(profile_path.read_text(encoding="utf-8"))
      qualification = json.loads(
          qualification_path.read_text(encoding="utf-8")
      )
      symbols = component_operation_symbols(source)
      implementation = ReusableLibraryImplementationV1.create(
          family_id="fixture-runtime",
          recipe_id="recipe.fixture.increment-v1",
          compatible_release_ids=("fixture-runtime-1.0",),
          operation_source_mappings=(
              LibraryOperationSourceMappingV1.create(
                  operation_id=operation_id,
                  source_id=source["lift_unit_id"],
                  source_symbol=symbol,
                  source_sha256=source["implementation_sha256"],
              )
              for operation_id, symbol in symbols.items()
          ),
          interface_contract_ids=(interface.identity,),
          effect_contract_ids=tuple(
              sorted(effect.identity for effect in interface.effects)
          ),
          compile_profile_id=profile["profile_id"],
          qualification_checker_id=qualification["checker"]["id"],
          qualification_receipt_sha256=qualification["receipt_sha256"],
      )
      REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1.write(output, implementation)
      PY
    '';
  reusableLibraryBehaviorPack = import ../library-behavior-pack.nix {
    inherit pkgs pythonEnv pythonSource;
    name = "spaghetti-extractor-library-behavior-fixture";
    implementation = "${reusableLibraryImplementation}/implementation.json";
    sourcePackage = base.sourcePackages.e;
    interface = "${base.developmentContracts.e}/portable-interface.json";
    sourceProfile = "${base.sourceProfiles.e}/source-profile.json";
    compileReceipt = "${base.compileReceipts.e}/compile-receipt.json";
    qualificationReceipt =
      "${base.refinementReceipts.e}/refinement-receipt.json";
  };
  reusableLibraryBehaviorChecked = pkgs.runCommand
    "spaghetti-extractor-library-behavior-fixture-check"
    { nativeBuildInputs = [ pkgs.jq ]; __contentAddressed = true; } ''
      set -euo pipefail
      jq -e '
        .format == "spaghetti-extractor-reusable-library-behavior-pack-v1" and
        .interface_contract_id == "e" and
        .effect_contract_ids == [] and
        (.pack_sha256 | type == "string")
      ' ${reusableLibraryBehaviorPack}/behavior-pack.json >/dev/null
      mkdir -p "$out"
      ln -s ${reusableLibraryBehaviorPack} "$out/behavior-pack"
    '';
  libraryMachineFixture = pkgs.runCommand
    "spaghetti-extractor-library-machine-fixture"
    {
      nativeBuildInputs = [ pythonEnv ];
      __contentAddressed = true;
    } ''
      set -euo pipefail
      export PYTHONPATH=${pythonSource}/src:${peFixtureSource}
      mkdir -p "$out"
      ${pythonEnv}/bin/python3 - "$out" <<'PY'
      import hashlib
      import json
      import pathlib
      import sys

      from spaghetti_extractor.libraries.abi_records import (
          LibraryAbiProfileV3,
          StackCleanupV3,
          ValueLocationV3,
          VariadicPolicyV3,
      )
      from tests.pe_fixtures import pe32_import_image

      root = pathlib.Path(sys.argv[1])
      code = bytes.fromhex("8b44240440c39090")
      binary = pe32_import_image(code, symbol="WriteFile")
      binary_path = root / "fixture.exe"
      binary_path.write_bytes(binary)
      profile = LibraryAbiProfileV3(
          profile_id="fixture-x86-cdecl",
          architecture="x86",
          object_format="pe32",
          calling_convention="cdecl",
          stack_cleanup=StackCleanupV3("caller", 0),
          arguments=(ValueLocationV3("stack", 32, stack_offset=4),),
          returns=(ValueLocationV3("register", 32, register="eax"),),
          hidden_sret=False,
          variadic=VariadicPolicyV3("none", 1, None),
          preserved_registers=("ebp", "ebx", "edi", "esi"),
          callback_slots=(),
          structure_layout_ids=(),
          boundary_effects=(),
      )
      unit = {
          "format": "spaghetti-extractor-machine-ir-v3",
          "record_kind": "unit",
          "id": "unit:e",
          "status": "qualified",
          "function_id": "unit:e",
          "source": {
              "original": {"rva_start": 0x1000, "rva_end": 0x1008},
              "instruction_bytes_sha256": hashlib.sha256(code).hexdigest(),
          },
          "instructions": [],
          "semantics": {
              "external_events": [],
              "faults": [],
              "flag_writes": [],
              "memory_events": [],
              "outcome": {
                  "kind": "return",
                  "value": {
                      "op": "load",
                      "width": 4,
                      "address": {"op": "reg", "name": "esp", "width": 32},
                  },
              },
              "register_writes": [{
                  "register": "eax",
                  "value": {
                      "op": "add32",
                      "args": [
                          {
                              "op": "load",
                              "width": 4,
                              "address": {
                                  "op": "add32",
                                  "args": [
                                      {"op": "const", "value": 4, "width": 32},
                                      {"op": "reg", "name": "esp", "width": 32},
                                  ],
                              },
                          },
                          {"op": "const", "value": 1, "width": 32},
                      ],
                      "width": 32,
                  },
              }],
          },
          "control": {
              "kind": "return",
              "direct_targets": [],
              "has_indirect_target": False,
          },
          "abi_envelope": profile.to_payload(),
      }
      ir_path = root / "machine-ir.jsonl"
      ir_path.write_text(
          json.dumps(unit, sort_keys=True, separators=(",", ":")) + "\n",
          encoding="ascii",
      )
      manifest = {
          "format": "spaghetti-extractor-machine-ir-v3",
          "binary": {"sha256": hashlib.sha256(binary).hexdigest()},
          "artifacts": {
              "machine_ir": {
                  "path": "machine-ir.jsonl",
                  "sha256": hashlib.sha256(ir_path.read_bytes()).hexdigest(),
              }
          },
          "control": {
              "roots": [{"rva": 0x1000, "kind": "pe_entrypoint", "checked": True}]
          },
      }
      (root / "machine-ir-manifest.json").write_text(
          json.dumps(manifest, indent=2, sort_keys=True) + "\n",
          encoding="ascii",
      )
      PY
    '';
  libraryTargetSignatures = pkgs.runCommand
    "spaghetti-extractor-library-target-signature-fixture"
    {
      nativeBuildInputs = [ pythonEnv ];
      __contentAddressed = true;
    } ''
      set -euo pipefail
      export PYTHONPATH=${pythonSource}/src
      ${pythonEnv}/bin/python3 - \
        ${libraryMachineFixture} \
        ${libraryMachineFixture}/fixture.exe \
        "$out" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.libraries.signature_graph import (
          build_target_signature_graph,
      )

      build_target_signature_graph(
          machine_ir=pathlib.Path(sys.argv[1]),
          original_pe=pathlib.Path(sys.argv[2]),
          out=pathlib.Path(sys.argv[3]),
      )
      PY
    '';
  reusableLibraryCatalog = pkgs.runCommand
    "spaghetti-extractor-library-catalog-fixture"
    {
      nativeBuildInputs = [ pythonEnv ];
      __contentAddressed = true;
    } ''
      set -euo pipefail
      export PYTHONPATH=${pythonSource}/src
      mkdir -p "$out"
      ${pythonEnv}/bin/python3 - \
        ${libraryTargetSignatures} \
        "$out/library-abi-catalog.json" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.libraries.abi_catalog import (
          LIBRARY_ABI_CATALOG_CODEC_V3,
          LibraryAbiCatalogV3,
      )
      from spaghetti_extractor.libraries.abi_records import (
          LibraryFunctionSignatureV3,
      )
      from spaghetti_extractor.libraries.signature_graph import (
          TARGET_SIGNATURE_GRAPH_CODEC_V3,
      )

      graph = TARGET_SIGNATURE_GRAPH_CODEC_V3.read(pathlib.Path(sys.argv[1]))
      target = next(row for row in graph.functions if "unit:e" in row.unit_ids)
      if target.abi_profile is None:
          raise SystemExit("fixture library target lacks an ABI profile")
      function = LibraryFunctionSignatureV3(
          function_id="fixture-increment",
          catalog_id="fixture-runtime",
          family_id="fixture-runtime",
          release_id="fixture-runtime-1.0",
          member_id="fixture-increment.obj",
          symbols=("fixture_increment",),
          normalized_bytes_sha256=target.normalized_bytes_sha256,
          exact_bytes_sha256=target.exact_bytes_sha256,
          unit_merkle_sha256=target.unit_merkle_sha256,
          cfg_sha256=target.cfg_sha256,
          direct_callees=(),
          imports=target.imports,
          constants=target.constants,
          strings=target.strings,
          data_refs=target.data_refs,
          abi_profile_id=target.abi_profile.profile_id,
          object_size=target.rva_end - target.rva_start,
          retention_model="section_gc",
          operation_id="increment",
      )
      catalog = LibraryAbiCatalogV3.create(
          catalog_id="fixture-runtime",
          abi_profiles=(target.abi_profile,),
          functions=(function,),
          behaviors=(),
      )
      LIBRARY_ABI_CATALOG_CODEC_V3.write(pathlib.Path(sys.argv[2]), catalog)
      PY
    '';
  reusableLibraryManifest = builtins.fromJSON (
    builtins.readFile "${reusableLibraryBehaviorPack}/behavior-pack.json"
  );
  reusableLibraryImplementations = {
    ${reusableLibraryManifest.implementation_id} = reusableLibraryBehaviorPack;
  };
  libraryAuthorityFixture = pkgs.runCommand
    "spaghetti-extractor-library-authority-fixture"
    {
      nativeBuildInputs = [ pythonEnv ];
      __contentAddressed = true;
    } ''
      set -euo pipefail
      export PYTHONPATH=${pythonSource}/src
      mkdir -p "$out"
      ${pythonEnv}/bin/python3 - "$out" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.artifacts.artifact_set import ArtifactSetWriterV3
      from spaghetti_extractor.artifacts.formats import (
          CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
      )
      from spaghetti_extractor.authority.target_certificate_records import (
          INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
      )

      root = pathlib.Path(sys.argv[1])
      ArtifactSetWriterV3(
          artifact_kind=CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
          bindings=(),
      ).write(root / "canonical-external-sites", ())
      ArtifactSetWriterV3(
          artifact_kind=INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
          bindings=(),
      ).write(root / "target-certificates", ())
      PY
    '';
  discoveredLinkedLibrary = import ../linked-libraries.nix {
    inherit pkgs pythonEnv pythonSource;
    original = "${libraryMachineFixture}/fixture.exe";
    machineIr = libraryMachineFixture;
    namePrefix = "spaghetti-extractor-library-fixture";
    abiCatalogs = [ "${reusableLibraryCatalog}/library-abi-catalog.json" ];
    implementations = reusableLibraryImplementations;
    targetId = "component-v2-fixture";
  };
  reusableLibraryAdoption = pkgs.runCommand
    "spaghetti-extractor-library-adoption-fixture"
    {
      nativeBuildInputs = [ pythonEnv ];
      __contentAddressed = true;
    } ''
      set -euo pipefail
      export PYTHONPATH=${pythonSource}/src
      mkdir -p "$out"
      ${pythonEnv}/bin/python3 - \
        ${discoveredLinkedLibrary.releaseHypotheses} \
        ${reusableLibraryManifest.implementation_id} \
        "$out/adoption.json" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.libraries.v4_adoption_records import (
          LIBRARY_ADOPTION_INTENT_CODEC_V1,
          LibraryAdoptionIntentV1,
      )
      from spaghetti_extractor.libraries.v4_release_set import (
          read_library_release_set_v4,
      )

      releases = read_library_release_set_v4(pathlib.Path(sys.argv[1]))
      islands = [island for release in releases for island in release.islands]
      if len(islands) != 1:
          raise SystemExit(f"expected one fixture library island, got {len(islands)}")
      release = releases[0]
      island = islands[0]
      intent = LibraryAdoptionIntentV1.create(
          target_id="component-v2-fixture",
          island_id=island.island_id,
          hypotheses_sha256=release.hypotheses_sha256,
          implementation_id=sys.argv[2],
          mode="adopt",
      )
      LIBRARY_ADOPTION_INTENT_CODEC_V1.write(pathlib.Path(sys.argv[3]), intent)
      PY
    '';
  checkedLinkedLibrary = import ../linked-libraries.nix {
    inherit pkgs pythonEnv pythonSource;
    original = "${libraryMachineFixture}/fixture.exe";
    machineIr = libraryMachineFixture;
    namePrefix = "spaghetti-extractor-checked-library-fixture";
    abiCatalogs = [ "${reusableLibraryCatalog}/library-abi-catalog.json" ];
    implementations = reusableLibraryImplementations;
    adoptionIntents.fixture = "${reusableLibraryAdoption}/adoption.json";
    canonicalExternalSites =
      "${libraryAuthorityFixture}/canonical-external-sites";
    targetCertificates = "${libraryAuthorityFixture}/target-certificates";
    targetId = "component-v2-fixture";
  };
  libraryActivationPlan = pkgs.runCommand
    "spaghetti-extractor-library-activation-plan-fixture"
    {
      nativeBuildInputs = [ pythonEnv ];
      __contentAddressed = true;
    } ''
      set -euo pipefail
      export PYTHONPATH=${pythonSource}/src
      mkdir -p "$out"
      ${pythonEnv}/bin/python3 - \
        ${libraryMachineFixture} \
        ${checkedLinkedLibrary.generatedComponents.fixture} \
        "$out/activation-plan.json" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
      from spaghetti_extractor.components.configuration import (
          compose_component_configuration,
      )

      configuration_core = {
          "format": "spaghetti-extractor-component-configuration-resolution-v2",
          "id": "library-fixture",
          "label": "Generated library fixture",
          "status": "checked",
          "selections": [],
          "enabled_lift_unit_ids": [],
          "owned_unit_ids": [],
          "unit_owners": {},
      }
      configuration = {
          **configuration_core,
          "configuration_sha256": canonical_sha256_v3(configuration_core),
      }
      resolution_core = {
          "format": "spaghetti-extractor-component-resolution-v2",
          "status": "checked",
          "program_id": "component-v2-fixture",
          "executes_original_binary": False,
          "permitted_activation_profiles": [],
          "bindings": {},
          "components": [],
          "groups": [],
          "configurations": [configuration],
      }
      resolution = {
          **resolution_core,
          "resolution_sha256": canonical_sha256_v3(resolution_core),
      }
      compose_component_configuration(
          machine_ir=pathlib.Path(sys.argv[1]),
          resolution=resolution,
          configuration_id="library-fixture",
          contracts={},
          implementations={},
          qualifications={},
          adapter_plans={},
          generated_library_components={"fixture": pathlib.Path(sys.argv[2])},
          out=pathlib.Path(sys.argv[3]),
      )
      PY
    '';
  checkedLinkedLibraryRuntime = import ../component-runtime-package.nix {
    inherit pkgs pythonEnv pythonSource;
    machineIr = libraryMachineFixture;
    interpreterPackage = interpreter;
    namePrefix = "spaghetti-extractor-checked-library-fixture";
    componentConfiguration = {
      activationPlan = libraryActivationPlan;
      contracts = { };
      portableInterfaces = { };
      semanticContracts = { };
      implementations = { };
      qualifications = { };
      adapterPlans = { };
      activationReceipts = { };
      machineBindings = { };
      libraryComponents = checkedLinkedLibrary.generatedComponents;
    };
  };
  checkedLinkedLibraryFixture = pkgs.runCommand
    "spaghetti-extractor-checked-library-fixture-check"
    { nativeBuildInputs = [ pkgs.jq ]; __contentAddressed = true; } ''
      set -euo pipefail
      jq -e '.status == "complete"' \
        ${checkedLinkedLibrary.checkedIslands.fixture}/checked-library-island.json \
        >/dev/null
      jq -e '.status == "complete"' \
        ${checkedLinkedLibrary.generatedComponents.fixture}/library-component.json \
        >/dev/null
      jq -e '
        .status == "ready" and
        .counts.portable_components == 1 and
        .counts.portable_units == 1 and
        .counts.override_entries == 1 and
        .components[0].id == "e" and
        (.components[0].universal_implementation_sha256 | type == "string")
      ' ${checkedLinkedLibraryRuntime}/component-runtime-package.json >/dev/null
      jq -e '
        .status == "checked" and
        (.entries | length) == 1 and
        .entries[0].unit_id == "unit:e"
      ' ${checkedLinkedLibraryRuntime}/portable-component-selection.json >/dev/null
      mkdir -p "$out"
      ln -s ${checkedLinkedLibrary.generatedComponents.fixture} \
        "$out/generated-component"
      ln -s ${checkedLinkedLibraryRuntime} "$out/runtime-package"
    '';
  blocked = pkgs.runCommand "spaghetti-extractor-components-blocked-fixture"
    { nativeBuildInputs = [ pkgs.jq ]; __contentAddressed = true; } ''
      jq -e '
        .format == "spaghetti-extractor-component-activation-plan-v3" and
        .status == "incomplete" and
        .counts.blocked == 1 and
        .counts.machine_ir_fallback == 12 and
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
  portableChecked = pkgs.runCommand
    "spaghetti-extractor-components-portable-v2-fixture"
    { nativeBuildInputs = [ pkgs.jq ]; __contentAddressed = true; } ''
      set -euo pipefail
      jq -e '
        .status == "checked" and
        .activation_authorized and
        .component_id == "e" and
        (.facets | length) == 7 and
        ([.facets[].id] | index("semantic_refinement") != null)
      ' ${base.configurationActivationReceipts."e-enabled".e}/activation-receipt.json \
        >/dev/null
      jq -e '
        .status == "checked" and
        .counts.portable_replacement == 1 and
        .counts.machine_ir_fallback == 12 and
        .counts.blocked == 0 and
        (.selections[] | select(.id == "e") |
          .ownership_state == "portable_replacement")
      ' ${base.activationPlans."e-enabled"}/activation-plan.json >/dev/null
      jq -e '
        .format == "spaghetti-extractor-component-runtime-package-v3" and
        .status == "ready" and
        .counts.portable_components == 1 and
        .counts.portable_units == 1 and
        .counts.override_entries == 1
      ' ${portableRuntime}/component-runtime-package.json >/dev/null
      mkdir -p "$out"
      cp ${base.configurationActivationReceipts."e-enabled".e}/activation-receipt.json \
        "$out/activation-receipt.json"
      cp ${portableRuntime}/component-runtime-package.json "$out/runtime-package.json"
    '';
  servicePortableChecked = pkgs.runCommand
    "spaghetti-extractor-components-portable-service-v2-fixture"
    { nativeBuildInputs = [ pkgs.jq ]; __contentAddressed = true; } ''
      set -euo pipefail
      jq -e '
        .status == "checked" and
        .activation_authorized and
        .component_id == "f"
      ' ${base.configurationActivationReceipts."f-enabled".f}/activation-receipt.json \
        >/dev/null
      jq -e '
        .format == "spaghetti-extractor-component-refinement-receipt-v1" and
        .status == "satisfied" and .activation_authorized and
        .checks[0].model.kind == "finite-machine-paths-v1" and
        .checks[0].model.path_count == 2 and
        .checks[0].model.max_service_events == 1
      ' ${base.refinementReceipts.f}/refinement-receipt.json >/dev/null
      jq -e '
        .format == "spaghetti-extractor-component-runtime-package-v3" and
        .status == "ready" and
        .counts.portable_components == 1 and
        .counts.portable_units == 3 and
        .counts.override_entries == 1
      ' ${serviceRuntime}/component-runtime-package.json >/dev/null
      test -s ${serviceRuntime}/components/f/generated-adapter.c
      grep -F 'spx_invoke_call' \
        ${serviceRuntime}/components/f/generated-adapter.c >/dev/null
      mkdir -p "$out"
      cp ${base.configurationActivationReceipts."f-enabled".f}/activation-receipt.json \
        "$out/activation-receipt.json"
      cp ${serviceRuntime}/component-runtime-package.json "$out/runtime-package.json"
    '';
  portableDraftChecked = pkgs.runCommand
    "spaghetti-extractor-components-portable-draft-v2-fixture"
    { nativeBuildInputs = [ pkgs.jq pkgs.coreutils ]; __contentAddressed = true; } ''
      set -euo pipefail
      package=${base.workPackages.g}
      jq -e '
        .format == "spaghetti-extractor-component-work-package-v1" and
        .lift_unit_id == "g" and
        .policy.independently_buildable and
        (.policy.authorizes_runtime | not) and
        .contents.compile_receipt == "compile-receipt" and
        .contents.machine_binding == null and
        .contents.refinement_receipt == null and
        .contents.ownership == null and
        .contents.activation_receipt == "activation-receipt"
      ' "$package/work-package.json" >/dev/null
      jq -e '
        .format == "spaghetti-extractor-component-development-contract-v1" and
        .status == "checked" and
        (.authority.activation_authorized | not)
      ' "$package/contract/contract.json" >/dev/null
      jq -e '
        .format == "spaghetti-extractor-component-activation-receipt-v2" and
        .status == "incomplete" and
        (.activation_authorized | not) and
        ([.facets[] | select(
          .id == "machine_binding" or
          .id == "semantic_refinement" or
          .id == "ownership"
        ) | .status] | all(. == "incomplete"))
      ' "$package/status/status.json" >/dev/null
      test ! -e "$package/machine-binding"
      test ! -e "$package/refinement-receipt"
      test ! -e "$package/ownership"
      mkdir -p "$out"
      cp "$package/work-package.json" "$out/work-package.json"
      cp "$package/status/status.json" "$out/status.json"
    '';
  inductionChecked = pkgs.runCommand
    "spaghetti-extractor-components-induction-package-fixture"
    { nativeBuildInputs = [ pkgs.jq ]; __contentAddressed = true; } ''
      set -euo pipefail
      package=${base.inductionPackages.h}
      jq -e '
        .format == "spaghetti-extractor-inductive-package-v1" and
        .status == "checked" and
        .component_id == "h" and
        .operation_id == "run" and
        .policy.exact_machine_inventory_replayed
      ' "$package/induction-package.json" >/dev/null
      jq -e '
        .format == "spaghetti-extractor-inductive-source-plan-v1" and
        .interface_id == "h" and
        .operation_id == "run"
      ' "$package/source-plan.json" >/dev/null
      jq -e '
        .format == "spaghetti-extractor-component-compile-receipt-v1" and
        (.bindings.inductive_source_plan_sha256s | length) == 1 and
        .policy.inductive_public_wrappers_framework_generated
      ' ${base.compileReceipts.h}/compile-receipt.json >/dev/null
      jq -e '
        .format == "spaghetti-extractor-component-compile-receipt-v1" and
        .bindings.inductive_source_plan_sha256s == []
      ' ${base.compileReceipts.e}/compile-receipt.json >/dev/null
      jq -e '
        .contents.induction_package == "induction-package"
        and .contents.induction_draft_certificate == "induction-draft-certificate"
        and .contents.induction_source_receipt == "induction-source-receipt"
        and .contents.refinement_receipt == "refinement-receipt"
      ' ${base.workPackages.h}/work-package.json >/dev/null
      jq -e '
        .format == "spaghetti-extractor-inductive-source-refinement-receipt-v1" and
        .status == "satisfied" and
        .policy.all_properties_satisfied and
        (.policy.bounded_unwinding_used | not)
      ' ${base.inductionSourceReceipts.h}/source-receipt.json >/dev/null
      jq -e '
        .format == "spaghetti-extractor-inductive-refinement-receipt-v1" and
        .status == "satisfied" and .activation_authorized and
        .assurance.receipt_contents_replayed_by_this_checker
      ' ${base.refinementReceipts.h}/refinement-receipt.json >/dev/null
      jq -e '
        .format == "spaghetti-extractor-component-activation-receipt-v2" and
        .status == "checked" and .activation_authorized
      ' ${base.activationReceipts.h}/activation-receipt.json >/dev/null
      mkdir -p "$out"
      cp "$package/induction-package.json" "$out/induction-package.json"
      cp ${base.compileReceipts.h}/compile-receipt.json \
        "$out/compile-receipt.json"
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
assert !missingInductionRootEvaluation.success;
assert builtins.attrNames base.inductionPackages == [ "h" ];
assert builtins.any
  (asset: asset.role == "component_induction" && asset.owner == "h")
  base.assetInventory;
assert builtins.hasAttr "h" base.refinementReceipts;
assert base.semanticContracts.h.drvPath == inductionChanged.semanticContracts.h.drvPath;
assert base.sourcePackages.h.drvPath == inductionChanged.sourcePackages.h.drvPath;
assert base.inductionPackages.h.drvPath == inductionChanged.inductionPackages.h.drvPath;
assert base.compileReceipts.h.drvPath == inductionChanged.compileReceipts.h.drvPath;
assert base.inductionDraftCertificates.h.drvPath !=
  inductionChanged.inductionDraftCertificates.h.drvPath;
assert base.inductionSourceReceipts.h.drvPath !=
  inductionChanged.inductionSourceReceipts.h.drvPath;
assert base.refinementReceipts.h.drvPath != inductionChanged.refinementReceipts.h.drvPath;
assert base.compileReceipts.e.drvPath == inductionChanged.compileReceipts.e.drvPath;
assert base.semanticContracts.e.drvPath == inductionChanged.semanticContracts.e.drvPath;
assert runtime.drvPath == base.runtimePackages."a-only".drvPath;
assert builtins.attrNames base.workPackages == [ "a" "b" "c" "d" "e" "f" "g" "h" ];
assert builtins.attrNames base.statusReports == [ "a" "b" "c" "d" "e" "f" "g" "h" ];
assert builtins.attrNames base.externalSiteSlices == [ ];
assert builtins.attrNames base.configurationStatusReports == [ "a-only" "b-enabled" "b-only" "c-enabled" "d-enabled" "e-enabled" "f-enabled" ];
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
  { name = "compile-e"; path = base.compileReceipts.e; }
  { name = "source-profile-e"; path = base.sourceProfiles.e; }
  { name = "machine-binding-e"; path = base.machineBindingReceipts.e; }
  { name = "semantic-contract-e"; path = base.semanticContracts.e; }
  { name = "semantic-refinement-e"; path = base.refinementReceipts.e; }
  { name = "service-graph-e"; path = base.serviceGraphs.e; }
  { name = "configuration-service-graph-e"; path = base.configurationServiceGraphs."e-enabled"; }
  { name = "activation-receipt-e"; path = base.configurationActivationReceipts."e-enabled".e; }
  { name = "activation-e"; path = base.activationPlans."e-enabled"; }
  { name = "rooted-portable-gate-e"; path = base.portableGates."e-enabled"; }
  { name = "runtime-e"; path = portableRuntime; }
  { name = "portable-v2-e"; path = portableChecked; }
  { name = "reusable-library-behavior-e"; path = reusableLibraryBehaviorChecked; }
  { name = "checked-library-component-e"; path = checkedLinkedLibraryFixture; }
  { name = "compile-f"; path = base.compileReceipts.f; }
  { name = "machine-binding-f"; path = base.machineBindingReceipts.f; }
  { name = "semantic-contract-f"; path = base.semanticContracts.f; }
  { name = "semantic-refinement-f"; path = base.refinementReceipts.f; }
  { name = "activation-receipt-f"; path = base.configurationActivationReceipts."f-enabled".f; }
  { name = "runtime-f"; path = serviceRuntime; }
  { name = "portable-v2-service-f"; path = servicePortableChecked; }
  { name = "portable-v2-draft-g"; path = portableDraftChecked; }
  { name = "induction-package-h"; path = base.inductionPackages.h; }
  { name = "induction-draft-h"; path = base.inductionDraftCertificates.h; }
  { name = "induction-source-h"; path = base.inductionSourceReceipts.h; }
  { name = "induction-refinement-h"; path = base.refinementReceipts.h; }
  { name = "compile-h"; path = base.compileReceipts.h; }
  { name = "induction-checked-h"; path = inductionChecked; }
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
