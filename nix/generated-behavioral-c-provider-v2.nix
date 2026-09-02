# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  linkedSemanticModule,
  behavioralCPackage,
  compiler ? pkgs.pkgsCross.mingw32.stdenv.cc,
  providerId ? "generated.behavioral-c",
  namePrefix,
}:

let
  compilerBinary = "${compiler}/bin/${compiler.targetPrefix}cc";
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-generated-c-provider-v2";
    kind = "generated-behavioral-c-provider";
    artifactName = "semantic-provider-qualification.json";
    expectedFormat =
      "spaghetti-extractor-semantic-provider-qualification-v2";
    allowedStatuses = [ "complete" ];
    pythonModules = [
      "spaghetti_extractor.semantic_providers.generated_c"
    ];
    phaseRole = "candidate";
    extraNativeBuildInputs = [ compiler ];
    inputs = {
      linked_semantic_module = linkedSemanticModule;
      behavioral_c_package = behavioralCPackage;
      compiler = compilerBinary;
    };
    program = ''
      from spaghetti_extractor.semantic_providers.generated_c import (
          write_generated_behavioral_c_provider_v2,
      )

      qualification = write_generated_behavioral_c_provider_v2(
          linked_semantic_module=inputs["linked_semantic_module"],
          behavioral_c_package=inputs["behavioral_c_package"],
          compiler=inputs["compiler"],
          provider_id=${builtins.toJSON providerId},
          out=output.parent,
      )
      definitions = qualification.get("definition_materializations")
      if (
          qualification.get("provider_kind") != "generated_behavioral_c"
          or qualification.get("blockers") != []
          or not isinstance(definitions, list)
          or not definitions
          or any(len(row.get("object_sha256s", [])) != 1 for row in definitions)
          or not (output.parent / "compile-receipt.json").is_file()
          or not (output.parent / "definition-choices.json").is_file()
          or not (output.parent / "objects").is_dir()
          or not (output.parent / "behavioral-c-package").is_dir()
      ):
          raise SystemExit("generated Behavioral-C V2 provider is incomplete")
    '';
  };
in
phase.derivation
