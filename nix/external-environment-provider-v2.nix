# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  linkedSemanticModule,
  providerId ? "external.environment",
  namePrefix,
}:

let
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-external-environment-provider-v2";
    kind = "semantic-provider-qualification";
    artifactName = "semantic-provider-qualification.json";
    expectedFormat =
      "spaghetti-extractor-semantic-provider-qualification-v2";
    allowedStatuses = [ "complete" "incomplete" ];
    pythonModules = [
      "spaghetti_extractor.semantic_providers.intrinsic"
    ];
    phaseRole = "candidate";
    inputs = {
      linked_semantic_module = linkedSemanticModule;
    };
    program = ''
      from spaghetti_extractor.semantic_providers.intrinsic import (
          write_external_environment_provider_v2,
      )

      qualification = write_external_environment_provider_v2(
          linked_semantic_module=inputs["linked_semantic_module"],
          provider_id=${builtins.toJSON providerId},
          out=output.parent,
      )
      if (
          qualification.get("provider_kind") != "external_environment"
          or not (output.parent / "definition-choices.json").is_file()
      ):
          raise SystemExit("external-environment V2 provider is malformed")
    '';
  };
in
phase.derivation
