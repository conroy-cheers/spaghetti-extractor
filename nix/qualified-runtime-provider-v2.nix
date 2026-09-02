# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  linkedSemanticModule,
  behavioralCPackage,
  compiler ? pkgs.pkgsCross.mingw32.stdenv.cc,
  providerId ? "runtime.generated-v2",
  namePrefix,
  pinnedLayoutAuthorities ? [ ],
  recoveredExecutableData ? null,
}:

assert builtins.isList pinnedLayoutAuthorities;
let
  lib = pkgs.lib;
  compilerBinary = "${compiler}/bin/${compiler.targetPrefix}cc";
  nmBinary = "${compiler}/bin/${compiler.targetPrefix}nm";
  pinnedLayoutInputs = builtins.listToAttrs (
    lib.imap0 (index: value: {
      name = "pinned_layout_authority_${lib.fixedWidthNumber 4 index}";
      inherit value;
    }) pinnedLayoutAuthorities
  );
  recoveredInput = pkgs.lib.optionalAttrs (recoveredExecutableData != null) {
    recovered_executable_data = recoveredExecutableData;
  };
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-qualified-runtime-provider-v2";
    kind = "qualified-runtime-provider";
    artifactName = "semantic-provider-qualification.json";
    expectedFormat =
      "spaghetti-extractor-semantic-provider-qualification-v2";
    allowedStatuses = [ "complete" "incomplete" ];
    pythonModules = [
      "spaghetti_extractor.native_realization.runtime_provider_v2"
    ];
    phaseRole = "candidate";
    extraNativeBuildInputs = [ compiler ];
    inputs = pinnedLayoutInputs // {
      linked_semantic_module = linkedSemanticModule;
      behavioral_c_package = behavioralCPackage;
      compiler = compilerBinary;
      nm = nmBinary;
    } // recoveredInput;
    program = ''
      import json

      from spaghetti_extractor.native_realization.runtime_provider_v2 import (
          write_qualified_runtime_provider_v2,
      )

      qualification = write_qualified_runtime_provider_v2(
          linked_semantic_module=inputs["linked_semantic_module"],
          behavioral_c_package=inputs["behavioral_c_package"],
          compiler=inputs["compiler"],
          nm=inputs["nm"],
          provider_id=${builtins.toJSON providerId},
          pinned_layout_authorities=tuple(
              json.loads(inputs[name].read_text(encoding="utf-8"))
              for name in sorted(inputs)
              if name.startswith("pinned_layout_authority_")
          ),
          recovered_executable_data=inputs.get("recovered_executable_data"),
          out=output.parent,
      )
      status = qualification.get("status")
      choices = output.parent / "implementation-choices.json"
      if (
          qualification.get("provider_kind") != "qualified_runtime"
          or status not in {"complete", "incomplete"}
          or not choices.is_file()
      ):
          raise SystemExit("qualified runtime V2 provider is malformed")
      if status == "complete" and (
          qualification.get("blockers") != []
          or not qualification.get("obligation_implementations")
          or not (output.parent / "native-realization-object-manifest.json").is_file()
          or not (output.parent / "native-ingress-plan.json").is_file()
      ):
          raise SystemExit("complete qualified runtime V2 provider is incomplete")
      if status == "incomplete" and (
          not qualification.get("blockers")
          or qualification.get("definition_materializations") != []
          or qualification.get("obligation_implementations") != []
          or (output.parent / "native-realization-object-manifest.json").exists()
      ):
          raise SystemExit("incomplete qualified runtime V2 provider materialized authority")
      if status == "incomplete":
          ingress = output.parent / "native-ingress-plan.json"
          runtime = output.parent / "shared-module-runtime-package.json"
          has_runtime_blocker = any(
              row.get("code") == "runtime_materialization_incomplete"
              for row in qualification["blockers"]
          )
          if ingress.exists() != runtime.exists() or (
              has_runtime_blocker != (ingress.is_file() and runtime.is_file())
          ):
              raise SystemExit(
                  "incomplete qualified runtime V2 diagnostics are inconsistent"
              )
    '';
  };
in
phase.derivation
