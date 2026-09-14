# spaghetti-extractor-python-role: authority
args@{
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
  bisimulationIntent ? null,
  exactCSlice ? null,
  previousQueryEvidence ? null,
  sharedSourceContract ? null,
  timeoutSeconds ? 300,
  sourceEntryTimeoutSeconds ? null,
  smtSolver ? null,
  runtimeAssurance ? null,
  conditionalTargetId ? null,
  selectedObligations ? null,
  interactionContractCatalog ? null,
  providerId,
  proofClassification,
  namePrefix,
  linkedSemanticModule ? null,
  compiler ? pkgs.pkgsCross.mingw32.stdenv.cc,
}:

assert builtins.isString providerId && providerId != "";
assert builtins.elem proofClassification [ "machine_overlay" "encapsulated_owned" ];
assert builtins.isInt timeoutSeconds && timeoutSeconds > 0;
assert sourceEntryTimeoutSeconds == null ||
  (builtins.isInt sourceEntryTimeoutSeconds && sourceEntryTimeoutSeconds > 0 && runtimeAssurance != null);
assert runtimeAssurance == null || (builtins.isString conditionalTargetId && conditionalTargetId != "");
assert selectedObligations == null || runtimeAssurance != null;

let
  conditional = runtimeAssurance != null;
  providerIds = builtins.sort builtins.lessThan (
    builtins.attrNames providerComponents
  );
  provenanceIds = builtins.sort builtins.lessThan (
    builtins.attrNames provenanceArtifacts
  );
  conditionalProviderIds = builtins.filter (id: providerComponents.${id} ? conditionalRefinement) providerIds;
  providerInputs = builtins.foldl' (result: componentId:
    result // {
      "provider_interface_${componentId}" =
        providerComponents.${componentId}.interfacePackage;
      "provider_binding_intent_${componentId}" =
        providerComponents.${componentId}.bindingIntent;
      "provider_semantic_slice_${componentId}" =
        providerComponents.${componentId}.semanticSlice;
      "provider_source_package_${componentId}" =
        providerComponents.${componentId}.sourcePackage;
    } // (if providerComponents.${componentId} ? conditionalRefinement then
      assert conditional && !(providerComponents.${componentId} ? qualification)
        && !(providerComponents.${componentId} ? contextualRefinement);
      { "provider_conditional_refinement_${componentId}" = providerComponents.${componentId}.conditionalRefinement; }
    else {
      "provider_qualification_${componentId}" = providerComponents.${componentId}.qualification;
      "provider_contextual_refinement_${componentId}" = providerComponents.${componentId}.contextualRefinement;
    })
  ) { } providerIds;
  provenanceInputs = builtins.foldl' (result: artifactId:
    result // {
      "provenance_${artifactId}" = provenanceArtifacts.${artifactId};
    }
  ) { } provenanceIds;
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-${if conditional then "conditional-contextual-check" else "portable-c-work-package-provider-v2"}";
    kind = if conditional then "component-conditional-check" else "semantic-provider-qualification";
    artifactName = if conditional then "conditional-engine-result.json" else "semantic-provider-qualification.json";
    expectedFormat = if conditional then "spaghetti-extractor-conditional-contextual-check-v1"
      else "spaghetti-extractor-semantic-provider-qualification-v2";
    allowedStatuses = if conditional then [ "satisfied" "incomplete" "violated" ] else [ "complete" "incomplete" ];
    pythonModules = [
      "spaghetti_extractor.semantic_providers.portable_c_work_package"
    ];
    phaseRole = "authority";
    extraNativeBuildInputs = [
      pkgs.cbmc
      pkgs.bubblewrap
      pkgs.stdenv.cc
      compiler
    ] ++ pkgs.lib.optional (smtSolver != null) smtSolver;
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
    // pkgs.lib.optionalAttrs conditional {
      runtime_assurance = pkgs.writeText "runtime-assurance.json" (builtins.toJSON runtimeAssurance);
    }
    // pkgs.lib.optionalAttrs (selectedObligations != null) {
      selected_obligations = pkgs.writeText "selected-obligations.json" (builtins.toJSON selectedObligations);
    }
    // pkgs.lib.optionalAttrs (previousQueryEvidence != null) {
      previous_query_evidence = previousQueryEvidence;
    }
    // pkgs.lib.optionalAttrs (sharedSourceContract != null) {
      shared_source_contract = sharedSourceContract;
    }
    // pkgs.lib.optionalAttrs (linkedSemanticModule != null) {
      linked_semantic_module = linkedSemanticModule;
    }
    // pkgs.lib.optionalAttrs (generatedChoices != null) {
      generated_choices = generatedChoices;
    }
    // pkgs.lib.optionalAttrs (relationIntent != null) {
      relation_intent = relationIntent;
    }
    // pkgs.lib.optionalAttrs (bisimulationIntent != null) {
      bisimulation_intent = bisimulationIntent;
    }
    // pkgs.lib.optionalAttrs (exactCSlice != null) {
      exact_c_slice = exactCSlice;
    }
    // pkgs.lib.optionalAttrs (interactionContractCatalog != null) {
      interaction_contract_catalog = interactionContractCatalog;
    };
    program = ''
      from pathlib import Path
      import json

      from spaghetti_extractor.semantic_providers.portable_c_work_package import (
          write_portable_c_work_package_provider_v2,
      )

      result = write_portable_c_work_package_provider_v2(
          selected_obligations=${if selectedObligations != null then "json.loads(inputs[\"selected_obligations\"].read_text())" else "None"},
          runtime_assurance=${if conditional then "json.loads(inputs[\"runtime_assurance\"].read_text())" else "None"},
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
          smt_solver=${if smtSolver == null then "None" else "Path(${builtins.toJSON "${smtSolver}/bin/z3"})"},
          provider_id=${builtins.toJSON providerId},
          proof_classification=${builtins.toJSON proofClassification},
          out=output.parent,
          source_summary_workspace=Path("source-summary-contract-work"),
          proof_workspace=Path("contextual-proof-work"),
          previous_query_evidence=inputs.get("previous_query_evidence"),
          shared_source_contract_artifacts=inputs.get("shared_source_contract"),
          timeout_seconds=${builtins.toJSON timeoutSeconds},
          source_entry_timeout_seconds=${if sourceEntryTimeoutSeconds == null then "None" else builtins.toJSON sourceEntryTimeoutSeconds},
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
                  "source_package": inputs[
                      f"provider_source_package_{component_id}"
                  ],
                  **({"conditional_refinement": inputs[f"provider_conditional_refinement_{component_id}"]}
                     if component_id in ${builtins.toJSON conditionalProviderIds} else {
                         "qualification": inputs[f"provider_qualification_{component_id}"],
                         "contextual_refinement": inputs[f"provider_contextual_refinement_{component_id}"],
                     }),
                  "proof_classification": ${builtins.toJSON
                    (builtins.listToAttrs (map (componentId: {
                      name = componentId;
                      value = providerComponents.${componentId}.proofClassification;
                    }) providerIds))}[component_id],
              }
              for component_id in ${builtins.toJSON providerIds}
          },
          provenance_artifacts={
              artifact_id: inputs[f"provenance_{artifact_id}"]
              for artifact_id in ${builtins.toJSON provenanceIds}
          },
          relation_intent=inputs.get("relation_intent"),
          bisimulation_intent=inputs.get("bisimulation_intent"),
          exact_c_slice=inputs.get("exact_c_slice"),
          interaction_contract_catalog=inputs.get(
              "interaction_contract_catalog"
          ),
      )
      ${if conditional then ''
      if any((output.parent / name).exists() for name in (
          "semantic-provider-qualification.json", "definition-choices.json", "implementation-choices.json")):
          raise SystemExit("conditional check emitted activation artifacts")
      '' else ''
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
      ''}
    '';
  };
  feedback = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-conditional-contextual-feedback";
    kind = "component-conditional-feedback";
    artifactName = "conditional-check.json";
    expectedFormat = "spaghetti-extractor-operator-work-status-v2";
    allowedStatuses = [ "complete" "incomplete" "violated" ];
    pythonModules = [ "spaghetti_extractor.operator.conditional_check" ];
    phaseRole = "operator";
    inputs = { engine_result = phase.artifact; };
    program = ''
      import json, shutil
      from spaghetti_extractor.operator.conditional_check import write_component_conditional_feedback
      packet = json.loads(inputs["engine_result"].read_text())
      destination = output.parent / "conditional-engine-result.json"
      shutil.copyfile(inputs["engine_result"], destination)
      write_component_conditional_feedback(target_id=${builtins.toJSON conditionalTargetId},
          component_id=packet["inputs"]["component_id"], packet_path=destination)
    '';
  };
  selected = if conditional then feedback else phase;
in
{
  inherit (selected) derivation manifest phasePythonSource;
  inherit providerId;
} // pkgs.lib.optionalAttrs conditional {
  conditionalCheckFor = { obligations ? null, queryTimeoutSeconds ? timeoutSeconds,
    entryQueryTimeoutSeconds ? sourceEntryTimeoutSeconds }:
    (import ./portable-c-work-package-provider-v2.nix (args // {
      selectedObligations = obligations;
      timeoutSeconds = queryTimeoutSeconds;
      sourceEntryTimeoutSeconds = entryQueryTimeoutSeconds;
    })).derivation;
  conditionalCheck = feedback.artifact;
  conditionalEngineResult = phase.artifact;
  conditionalRefinement = "${phase.derivation}/conditional-refinement-result.json";
  engineDerivation = phase.derivation;
} // pkgs.lib.optionalAttrs (!conditional) {
  qualification = phase.artifact;
  definitionChoices = "${phase.derivation}/definition-choices.json";
  choices = "${phase.derivation}/implementation-choices.json";
  objectManifest = "${phase.derivation}/provider-object-manifest.json";
  contextualRefinement = "${phase.derivation}/contextual-refinement-result.json";
}
