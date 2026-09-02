# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  linkedSemanticModule,
  implementationSelection,
  providerQualifications,
  compiler ? pkgs.pkgsCross.mingw32.stdenv.cc,
  loadImageContract,
  candidateFilename,
  namePrefix,
  recoveredExecutableData ? null,
}:

assert builtins.isList providerQualifications;
assert providerQualifications != [ ];
assert builtins.isString candidateFilename && candidateFilename != "";
let
  lib = pkgs.lib;
  qualificationInputs = builtins.listToAttrs (
    lib.imap0 (index: value: {
      name = "provider_qualification_${lib.fixedWidthNumber 4 index}";
      inherit value;
    }) providerQualifications
  );
  recoveredInput = lib.optionalAttrs (recoveredExecutableData != null) {
    recovered_executable_data = recoveredExecutableData;
  };
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-native-realization-v2";
    kind = "native-realization";
    artifactName = "native-realization.json";
    expectedFormat = "spaghetti-extractor-native-realization-v2";
    allowedStatuses = [ "complete" "incomplete" ];
    pythonModules = [
      "spaghetti_extractor.candidate.build"
      "spaghetti_extractor.candidate.build_objects"
      "spaghetti_extractor.candidate.module_composer"
      "spaghetti_extractor.candidate.project"
      "spaghetti_extractor.native_realization.build"
      "spaghetti_extractor.native_realization.build_v2"
      "spaghetti_extractor.native_realization.receipt_v2"
      "spaghetti_extractor.pe32.image"
      "spaghetti_extractor.roundtrip_fuzz.image_io"
    ];
    phaseRole = "candidate";
    extraNativeBuildInputs = [ compiler ];
    inputs = qualificationInputs // recoveredInput // {
      linked_semantic_module = linkedSemanticModule;
      implementation_selection = implementationSelection;
      load_image_contract = loadImageContract;
    };
    program = ''
      from pathlib import Path

      from spaghetti_extractor.native_realization.build_v2 import (
          write_native_realization_v2_candidate,
      )

      write_native_realization_v2_candidate(
          linked_semantic_module=inputs["linked_semantic_module"],
          implementation_selection=inputs["implementation_selection"],
          provider_qualifications=tuple(
              inputs[name] for name in sorted(inputs)
              if name.startswith("provider_qualification_")
          ),
          load_image_contract=inputs["load_image_contract"],
          compiler=Path(
              ${builtins.toJSON "${compiler}/bin/i686-w64-mingw32-gcc"}
          ),
          nm=Path(
              ${builtins.toJSON "${compiler}/bin/i686-w64-mingw32-nm"}
          ),
          recovered_executable_data=inputs.get("recovered_executable_data"),
          candidate_filename=${builtins.toJSON candidateFilename},
          out=output.parent,
      )
    '';
  };
in
{
  inherit (phase) artifact derivation manifest;
  receipt = phase.artifact;
  candidate = "${phase.derivation}/${candidateFilename}";
  candidateInterface =
    "${phase.derivation}/candidate-interface/module-interface.json";
  candidateLoadImageContract =
    "${phase.derivation}/candidate-load-image-contract.json";
  compositionManifest =
    "${phase.derivation}/pe-composition-manifest.json";
}
