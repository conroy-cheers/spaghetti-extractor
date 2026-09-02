# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  transferPlan,
  moduleInterface,
  resolvedExternalEnvironment,
  isaRequirements ? null,
  qualifiedPlatform ? null,
  namePrefix,
}:

let
  lib = pkgs.lib;
  hasPlatformSelection =
    isaRequirements != null && qualifiedPlatform != null;
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-semantic-object-v1";
    kind = "semantic-object";
    artifactName = "semantic-object.json";
    expectedFormat = "spaghetti-extractor-semantic-object-v1";
    allowedStatuses = [ "complete" ];
    pythonModules = [
      "spaghetti_extractor.semantic_objects.replay"
      "spaghetti_extractor.semantic_objects.semantic_object"
    ];
    phaseRole = "candidate";
    inputs = {
      transfer_plan = transferPlan;
      module_interface = moduleInterface;
      resolved_external_environment =
        "${resolvedExternalEnvironment}/resolved-external-environment.json";
    } // lib.optionalAttrs hasPlatformSelection {
      isa_requirements = isaRequirements;
      qualified_platform = qualifiedPlatform;
    };
    program = ''
      import json

      from spaghetti_extractor.semantic_objects.object_authority import (
          derive_pe32_machine_object_authority_v2,
      )
      from spaghetti_extractor.semantic_objects.semantic_object import (
          write_semantic_object_v1,
      )
      from spaghetti_extractor.util import sha256_file, write_json

      authority_path = output.parent / "machine-object-authority.json"
      authority = derive_pe32_machine_object_authority_v2(
          module_interface=json.loads(
              inputs["module_interface"].read_text(encoding="utf-8")
          ),
          module_interface_sha256=sha256_file(inputs["module_interface"]),
      )
      write_json(authority_path, authority.to_payload())

      write_semantic_object_v1(
          transfer_plan=inputs["transfer_plan"],
          module_interface=inputs["module_interface"],
          machine_object_authority=authority_path,
          resolved_external_environment=inputs[
              "resolved_external_environment"
          ],
          isa_requirements=inputs.get("isa_requirements"),
          qualified_platform=inputs.get("qualified_platform"),
          out=output,
          link_members=True,
      )
    '';
  };
in
assert (isaRequirements == null) == (qualifiedPlatform == null);
{
  inherit (phase) derivation manifest artifact phasePythonSource;
  python = "${pythonEnv}/bin/python3";
  semanticObject = phase.artifact;
}
