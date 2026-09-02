# spaghetti-extractor-python-role: authority
{
  pkgs,
  pythonEnv,
  semanticSlice,
  bindingIntent,
  interfacePackage,
  sourcePackage,
  transferPlan,
  resolvedExternalEnvironment,
  semanticObject,
  generatedChoices ? null,
  providerEntryUnits ? { },
  providerComponents ? { },
  provenanceArtifacts ? { },
  relationIntent ? null,
  inductionIntent ? null,
  interactionContractCatalog ? null,
  providerId,
  proofClassification,
  namePrefix,
  linkedSemanticModule ? null,
  compiler ? pkgs.pkgsCross.mingw32.stdenv.cc,
}:

assert builtins.isString providerId && providerId != "";
assert builtins.elem proofClassification [ "machine_overlay" "encapsulated_owned" ];

let
  providerIds = builtins.sort builtins.lessThan (
    builtins.attrNames providerComponents
  );
  provenanceIds = builtins.sort builtins.lessThan (
    builtins.attrNames provenanceArtifacts
  );
  providerInputs = builtins.foldl' (result: componentId:
    result // {
      "provider_interface_${componentId}" =
        providerComponents.${componentId}.interfacePackage;
      "provider_binding_intent_${componentId}" =
        providerComponents.${componentId}.bindingIntent;
      "provider_semantic_slice_${componentId}" =
        providerComponents.${componentId}.semanticSlice;
    }
  ) { } providerIds;
  provenanceInputs = builtins.foldl' (result: artifactId:
    result // {
      "provenance_${artifactId}" = provenanceArtifacts.${artifactId};
    }
  ) { } provenanceIds;
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-portable-c-work-package-provider-v2";
    kind = "semantic-provider-qualification";
    artifactName = "semantic-provider-qualification.json";
    expectedFormat =
      "spaghetti-extractor-semantic-provider-qualification-v2";
    allowedStatuses = [ "complete" "incomplete" ];
    pythonModules = [
      "spaghetti_extractor.semantic_providers.portable_c_work_package"
    ];
    phaseRole = "authority";
    extraNativeBuildInputs = [
      pkgs.cbmc
      pkgs.stdenv.cc
      compiler
    ];
    inputs = ({
      semantic_slice = semanticSlice;
      binding_intent = bindingIntent;
      interface_package = interfacePackage;
      source_package = sourcePackage;
      transfer_plan = transferPlan;
      resolved_external_environment = resolvedExternalEnvironment;
      machine_object_authority =
        "${semanticObject}/machine-object-authority.json";
    } // providerInputs // provenanceInputs)
    // pkgs.lib.optionalAttrs (linkedSemanticModule != null) {
      linked_semantic_module = linkedSemanticModule;
    }
    // pkgs.lib.optionalAttrs (generatedChoices != null) {
      generated_choices = generatedChoices;
    }
    // pkgs.lib.optionalAttrs (relationIntent != null) {
      relation_intent = relationIntent;
    }
    // pkgs.lib.optionalAttrs (inductionIntent != null) {
      induction_intent = inductionIntent;
    }
    // pkgs.lib.optionalAttrs (interactionContractCatalog != null) {
      interaction_contract_catalog = interactionContractCatalog;
    };
    program = ''
      from pathlib import Path

      from spaghetti_extractor.semantic_providers.portable_c_work_package import (
          write_portable_c_work_package_provider_v2,
      )

      result = write_portable_c_work_package_provider_v2(
          semantic_slice=inputs["semantic_slice"],
          binding_intent=inputs["binding_intent"],
          interface_package=inputs["interface_package"],
          source_package=inputs["source_package"],
          transfer_plan=inputs["transfer_plan"],
          resolved_external_environment=inputs[
              "resolved_external_environment"
          ],
          machine_object_authority=inputs["machine_object_authority"],
          host_compiler=Path(${builtins.toJSON "${pkgs.stdenv.cc}/bin/cc"}),
          pe32_compiler=Path(
              ${builtins.toJSON "${compiler}/bin/${compiler.targetPrefix}cc"}
          ),
          nm=Path(
              ${builtins.toJSON "${compiler}/bin/${compiler.targetPrefix}nm"}
          ),
          cbmc=Path(${builtins.toJSON "${pkgs.cbmc}/bin/cbmc"}),
          provider_id=${builtins.toJSON providerId},
          proof_classification=${builtins.toJSON proofClassification},
          out=output.parent,
          linked_semantic_module=inputs.get("linked_semantic_module"),
          generated_choices=inputs.get("generated_choices"),
          provider_entry_units=${builtins.toJSON providerEntryUnits},
          provider_components={
              component_id: {
                  "interface_package": inputs[
                      f"provider_interface_{component_id}"
                  ],
                  "binding_intent": inputs[
                      f"provider_binding_intent_{component_id}"
                  ],
                  "semantic_slice": inputs[
                      f"provider_semantic_slice_{component_id}"
                  ],
              }
              for component_id in ${builtins.toJSON providerIds}
          },
          provenance_artifacts={
              artifact_id: inputs[f"provenance_{artifact_id}"]
              for artifact_id in ${builtins.toJSON provenanceIds}
          },
          relation_intent=inputs.get("relation_intent"),
          induction_intent=inputs.get("induction_intent"),
          interaction_contract_catalog=inputs.get(
              "interaction_contract_catalog"
          ),
      )
      if (
          not result["object_manifest"].is_file()
          or not result["definition_choices"].is_file()
          or not result["implementation_choices"].is_file()
          or not result["contextual_refinement"].is_file()
          or not (output.parent / "objects").is_dir()
      ):
          raise SystemExit(
              "direct V6 portable provider omitted native materialization"
          )
    '';
  };
in
{
  inherit (phase) derivation manifest phasePythonSource;
  qualification = phase.artifact;
  definitionChoices = "${phase.derivation}/definition-choices.json";
  choices = "${phase.derivation}/implementation-choices.json";
  objectManifest = "${phase.derivation}/provider-object-manifest.json";
  contextualRefinement =
    "${phase.derivation}/contextual-refinement-result.json";
  inherit providerId;
}
