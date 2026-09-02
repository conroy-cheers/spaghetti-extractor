# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  moduleInterface,
  resolvedExternalEnvironment,
  namePrefix,
}:

let
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-single-module-project-intent-v1";
    kind = "pe32-single-module-project-intent";
    artifactName = "project-intent.json";
    expectedFormat = "spaghetti-extractor-pe32-project-intent-v1";
    allowedStatuses = [ ];
    pythonModules = [
      "spaghetti_extractor.pe32.formats"
      "spaghetti_extractor.external.formats"
    ];
    phaseRole = "candidate";
    inputs = {
      module_interface = "${moduleInterface}/module-interface.json";
      resolved_environment = "${resolvedExternalEnvironment}/resolved-external-environment.json";
    };
    program = ''
      import json

      from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
      from spaghetti_extractor.external.formats import (
          RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT,
      )
      from spaghetti_extractor.pe32.formats import (
          PE32_MODULE_INTERFACE_FORMAT,
          PE32_PROJECT_INTENT_FORMAT,
      )
      from spaghetti_extractor.util import write_json

      interface = json.loads(inputs["module_interface"].read_text(encoding="utf-8"))
      environment = json.loads(inputs["resolved_environment"].read_text(encoding="utf-8"))
      interface_core = {
          key: value for key, value in interface.items()
          if key != "interface_sha256"
      }
      environment_core = {
          key: value for key, value in environment.items()
          if key != "resolved_environment_sha256"
      }
      if (
          interface.get("format") != PE32_MODULE_INTERFACE_FORMAT
          or interface.get("status") != "complete"
          or interface.get("interface_sha256") != canonical_sha256_v3(interface_core)
      ):
          raise SystemExit("single-module project interface is incomplete")
      if (
          environment.get("format") != RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT
          or environment.get("status") != "complete"
          or environment.get("blockers") != []
          or environment.get("resolved_environment_sha256")
          != canonical_sha256_v3(environment_core)
      ):
          raise SystemExit("single-module project environment is incomplete")
      image_id = interface["image_id"]
      write_json(output, {
          "format": PE32_PROJECT_INTENT_FORMAT,
          "project_id": f"single-module:{image_id}",
          "root_image_id": image_id,
          "target_distribution_roots": ["."],
          "host_environment": {
              "id": f"resolved:{image_id}",
              "sha256": environment["resolved_environment_sha256"],
          },
          "images": [{
              "image_id": image_id,
              "filename": interface["image_id"],
              "aliases": [],
              "ownership": "target",
              "implementation": "behavioral_c",
          }],
      })
    '';
  };
in
phase.derivation
