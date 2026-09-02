# spaghetti-extractor-python-role: developer
{ pkgs, pythonEnv }:

let
  moduleInterface = import ../ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "spaghetti-extractor-semantic-object-module-interface-fixture";
    kind = "semantic-object-module-interface-fixture";
    artifactName = "module-interface.json";
    expectedFormat = "spaghetti-extractor-pe32-module-interface-v2";
    allowedStatuses = [ "complete" ];
    pythonModules = [
      "spaghetti_extractor.candidate.project"
      "spaghetti_extractor.roundtrip_fuzz.image_io"
    ];
    phaseRole = "developer";
    inputs = { };
    program = ''
      import struct

      from spaghetti_extractor.candidate.project import (
          write_pe32_module_interface,
      )
      from spaghetti_extractor.roundtrip_fuzz.image_io import (
          write_spx_load_image_contract,
      )

      code = b"\x40\x40\xc3"
      file_alignment = 0x200
      section_alignment = 0x1000
      headers_size = 0x200
      text_rva = 0x1000
      text_raw_size = 0x200
      size_of_image = 0x2000
      dos = bytearray(0x80)
      dos[0:2] = b"MZ"
      struct.pack_into("<I", dos, 0x3C, 0x80)
      coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x010F)
      optional_prefix = struct.pack(
          "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
          0x10B, 0, 0, text_raw_size, 0, 0, text_rva, text_rva, 0,
          0x400000, section_alignment, file_alignment, 4, 0, 0, 0, 4, 0,
          0, size_of_image, headers_size, 0, 3, 0, 0x100000, 0x1000,
          0x100000, 0x1000, 0, 16,
      )
      optional = optional_prefix + (b"\0" * (16 * 8))
      section = struct.pack(
          "<8sIIIIIIHHI", b".text\0\0\0", len(code), text_rva,
          text_raw_size, headers_size, 0, 0, 0, 0, 0x60000020,
      )
      original = output.parent / "fixture.exe"
      original.write_bytes(
          (bytes(dos) + b"PE\0\0" + coff + optional + section).ljust(
              headers_size, b"\0"
          ) + code.ljust(text_raw_size, b"\0")
      )
      contract = output.parent / "load-image-contract.json"
      write_spx_load_image_contract(original_pe=original, out=contract)
      generated = output.parent / "generated-interface"
      write_pe32_module_interface(
          image_id="fixture.exe", original_pe=original,
          load_image_contract=contract, out=generated,
      )
      output.write_bytes((generated / "module-interface.json").read_bytes())
    '';
  };
  transferPlan = import ../ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "spaghetti-extractor-semantic-object-transfer-fixture";
    kind = "semantic-object-transfer-fixture";
    artifactName = "executable-transfer-plan.json";
    expectedFormat = "spaghetti-extractor-executable-transfer-plan-v2";
    allowedStatuses = [ "complete" ];
    pythonModules = [ "spaghetti_extractor.testkit.transfer_fixture" ];
    phaseRole = "developer";
    inputs = { module_interface = moduleInterface.artifact; };
    program = ''
      import json

      from spaghetti_extractor.testkit.transfer_fixture import (
          as_machine_ir_unit,
          transfer_row,
          write_fixture_transfer_plan,
      )

      interface = json.loads(inputs["module_interface"].read_text(encoding="utf-8"))
      machine = output.parent / "machine-ir.jsonl"
      machine.write_text(
          json.dumps(as_machine_ir_unit(transfer_row()), sort_keys=True) + "\n",
          encoding="utf-8",
      )
      generated = write_fixture_transfer_plan(
          machine, pe_sha256=interface["identity"]["pe_sha256"]
      )
      output.write_bytes(generated.read_bytes())
    '';
  };
  resolvedEnvironment = import ../ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "spaghetti-extractor-semantic-object-environment-fixture";
    kind = "semantic-object-environment-fixture";
    artifactName = "resolved-external-environment.json";
    expectedFormat =
      "spaghetti-extractor-resolved-external-environment-v1";
    allowedStatuses = [ "complete" ];
    pythonModules = [ "spaghetti_extractor.external.resolved" ];
    phaseRole = "developer";
    inputs = { module_interface = moduleInterface.artifact; };
    program = ''
      import json

      from spaghetti_extractor.artifacts.artifact_set import (
          canonical_sha256_v3,
      )
      from spaghetti_extractor.external.resolved import (
          ResolvedExternalEnvironmentV1,
          bind_launch_policy_v1,
      )
      from spaghetti_extractor.util import write_json

      interface = json.loads(
          inputs["module_interface"].read_text(encoding="utf-8")
      )
      core = {
          "format": "spaghetti-extractor-resolved-external-environment-v1",
          "status": "complete",
          "bindings": {
              "module_interface_sha256": interface["interface_sha256"],
              "module_pe_sha256": interface["identity"]["pe_sha256"],
              "environment_intent_sha256": "1" * 64,
              "runtime_profile_pack_sha256s": ["2" * 64],
              "interface_profile_pack_sha256s": [],
          },
          "target": {
              "abi": "pe32-i686-mingw32",
              "data_layout": "pe32-ilp32-v1",
          },
          "launch_policy": bind_launch_policy_v1(
              {
                  "format": "spaghetti-extractor-pe32-launch-assumption-template-v1",
                  "schema_version": 1,
              },
              source_sha256="0" * 64,
              filename="fixture-launch.json",
          ),
          "canonical_boundaries": [],
          "interface_method_catalogs": [],
          "machine_import_contracts": [],
          "original_semantic_imports": [],
          "generated_runtime_support_imports": [],
          "loader_service_contracts": [],
          "static_authority_bindings": [],
          "checked_exception_protocols": [],
          "blockers": [],
          "authority": "checked_static_environment",
      }
      payload = {
          **core,
          "resolved_environment_sha256": canonical_sha256_v3(core),
      }
      ResolvedExternalEnvironmentV1.parse(
          payload, module_interface=interface
      )
      write_json(output, payload)
    '';
  };
  semanticObject = import ../semantic-object.nix {
    inherit pkgs pythonEnv;
    transferPlan = transferPlan.artifact;
    moduleInterface = moduleInterface.artifact;
    resolvedExternalEnvironment = resolvedEnvironment.derivation;
    namePrefix = "spaghetti-extractor-semantic-object-fixture";
  };
in
pkgs.runCommand "spaghetti-extractor-semantic-object-v1-check" {
  nativeBuildInputs = [ pkgs.jq pythonEnv ];
} ''
  set -euo pipefail
  jq -e '
    .format == "spaghetti-extractor-semantic-object-v1" and
    .status == "complete" and .role == "checked_relocatable" and
    .authority == false and
    .members.transfer_plan.path == "executable-transfer-plan.json" and
    .members.resolved_external_environment.path ==
      "resolved-external-environment.json" and
    .platform_selection == null and
    .counts.transfers == 1 and
    .counts.isa_occurrences == 0 and
    .definitions[0].body.language == "executable-transfer-plan-v2" and
    ([.holes[].kind] | index("qualified_platform_selection_missing") != null) and
    (.holes | length > 0) and
    (.semantic_object_sha256 | test("^[0-9a-f]{64}$"))
  ' ${semanticObject.semanticObject} >/dev/null
  test -L ${semanticObject.derivation}/executable-transfer-plan.json
  test -L ${semanticObject.derivation}/module-interface.json
  test -f ${semanticObject.derivation}/machine-object-authority.json
  test -L ${semanticObject.derivation}/resolved-external-environment.json
  cmp ${transferPlan.artifact} \
    ${semanticObject.derivation}/executable-transfer-plan.json
  cmp ${moduleInterface.artifact} \
    ${semanticObject.derivation}/module-interface.json
  cmp ${resolvedEnvironment.artifact} \
    ${semanticObject.derivation}/resolved-external-environment.json
  jq -e '
    .format == "spaghetti-extractor-machine-object-authority-v2" and
    (.rules | type == "array") and
    (.authority_sha256 | test("^[0-9a-f]{64}$"))
  ' ${semanticObject.derivation}/machine-object-authority.json >/dev/null
  touch "$out"
''
