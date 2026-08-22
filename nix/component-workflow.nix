# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  reconstructionPlan,
  componentProposals,
  canonicalExternalSites ? null,
  callbackAuthority ? null,
  callBoundaryContracts ? null,
  intent,
  reviewRoot ? null,
  sourceRoot ? null,
  bindingRoot ? null,
  inductionRoot ? null,
  relationRoot ? null,
  namePrefix,
  interpreterPackage ? null,
  generatedLibraryComponents ? { },
  rootedBehavioralProjection,
  relationKernel ? null,
  interactionContractCatalog ? ../profiles/interaction-contracts-v1.json,
  compiler ? pkgs.pkgsCross.mingw32.stdenv.cc,
}:

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  intentPayload = builtins.fromJSON (builtins.readFile intent);
  liftUnits =
    (map (row: row // { kind = "component"; }) intentPayload.components)
    ++ (map (row: row // { kind = "group"; }) (intentPayload.groups or [ ]));
  sourceAssets = lib.concatMap (liftUnit:
    let source = liftUnit.source or null;
    in if source == null then [ ] else map (relative: {
      path = toString (sourceRoot + "/${lib.removePrefix "source/" relative}");
      role = "component_source";
      owner = liftUnit.id;
    }) (source.files ++ (source.shared_inputs or [ ]))) liftUnits;
  reviewAssets = map (liftUnit: {
    path = toString (reviewRoot + "/${lib.removePrefix "reviews/" liftUnit.interface_review}");
    role = "component_review";
    owner = liftUnit.id;
  }) (builtins.filter (liftUnit: (liftUnit.interface_review or null) != null)
    liftUnits);
  bindingAssets = map (liftUnit: {
    path = toString (bindingRoot + "/${lib.removePrefix "bindings/" liftUnit.machine_binding}");
    role = "component_machine_binding";
    owner = liftUnit.id;
  }) (builtins.filter (liftUnit: (liftUnit.machine_binding or null) != null)
    liftUnits);
  inductionAssets = map (liftUnit: {
    path = if inductionRoot == null then
      throw "${liftUnit.id} declares an induction declaration but inductionRoot is unset"
    else toString
      (inductionRoot + "/${lib.removePrefix "induction/" liftUnit.induction}");
    role = "component_induction";
    owner = liftUnit.id;
  }) (builtins.filter (liftUnit: (liftUnit.induction or null) != null)
    liftUnits);
  relationAssets = map (liftUnit: {
    path = if relationRoot == null then
      throw "${liftUnit.id} declares a relation but relationRoot is unset"
    else toString
      (relationRoot + "/${lib.removePrefix "relations/" liftUnit.relation}");
    role = "component_relation";
    owner = liftUnit.id;
  }) (builtins.filter (liftUnit: (liftUnit.relation or null) != null)
    liftUnits);
  assetInventory = [ {
    path = toString intent;
    role = "component_intent";
    owner = "component-workflow";
  } ] ++ sourceAssets ++ reviewAssets ++ bindingAssets ++ inductionAssets
    ++ relationAssets;
  mkPhaseSource = phase: modules: import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs modules;
    name = "${namePrefix}-components-${phase}-python-closure";
  };
  resolutionSource = mkPhaseSource "resolution" [
    "spaghetti_extractor.components.resolution"
  ];
  contractSource = mkPhaseSource "contract" [
    "spaghetti_extractor.components.contracts"
  ];
  developmentContractSource = mkPhaseSource "development-contract" [
    "spaghetti_extractor.components.development_contract"
  ];
  externalSiteSource = mkPhaseSource "external-sites" [
    "spaghetti_extractor.components.external_sites"
  ];
  sourcePackageSource = mkPhaseSource "source-package" [
    "spaghetti_extractor.components.source"
  ];
  evidenceSource = mkPhaseSource "evidence" [
    "spaghetti_extractor.components.evidence"
  ];
  adapterSource = mkPhaseSource "adapter" [
    "spaghetti_extractor.components.adapter"
  ];
  qualificationSource = mkPhaseSource "qualification" [
    "spaghetti_extractor.components.qualification"
  ];
  configurationSource = mkPhaseSource "configuration" [
    "spaghetti_extractor.components.configuration"
  ];
  statusSource = mkPhaseSource "status" [
    "spaghetti_extractor.components.status"
  ];
  machineBindingSource = mkPhaseSource "machine-binding" [
    "spaghetti_extractor.components.machine_binding"
    "spaghetti_extractor.util"
  ];
  compileReceiptSource = mkPhaseSource "compile-receipt" [
    "spaghetti_extractor.components.compile_receipt"
  ];
  sourceProfileSource = mkPhaseSource "source-profile" [
    "spaghetti_extractor.components.source_profile"
    "spaghetti_extractor.util"
  ];
  semanticContractSource = mkPhaseSource "semantic-contract" [
    "spaghetti_extractor.components.semantic_contract"
    "spaghetti_extractor.util"
  ];
  universalContractSource = mkPhaseSource "universal-contract" [
    "spaghetti_extractor.components.universal_contract"
    "spaghetti_extractor.components.universal_binding"
  ];
  relationSource = mkPhaseSource "component-relation" [
    "spaghetti_extractor.components.boundary_plan"
    "spaghetti_extractor.components.boundary_primitives"
    "spaghetti_extractor.components.interaction_contract"
    "spaghetti_extractor.components.interaction_inventory"
    "spaghetti_extractor.components.object_authority"
    "spaghetti_extractor.components.relation_checker"
    "spaghetti_extractor.components.relation_declaration"
    "spaghetti_extractor.components.relation_ir"
    "spaghetti_extractor.components.relation_lean"
    "spaghetti_extractor.components.relation_projection"
    "spaghetti_extractor.components.relation_proposal"
    "spaghetti_extractor.components.relation_receipt"
    "spaghetti_extractor.components.relation_solver"
    "spaghetti_extractor.util"
  ];
  componentImplementationSource = mkPhaseSource "universal-implementation" [
    "spaghetti_extractor.components.implementation"
  ];
  componentDependencySource = mkPhaseSource "universal-dependencies" [
    "spaghetti_extractor.candidate.authority.rooted_projection"
    "spaghetti_extractor.components.dependency_graph"
    "spaghetti_extractor.components.retirement"
  ];
  inductionPackageSource = mkPhaseSource "induction-package" [
    "spaghetti_extractor.components.inductive_package"
    "spaghetti_extractor.util"
  ];
  inductionCertificateSource = mkPhaseSource "induction-certificate" [
    "spaghetti_extractor.components.inductive_certificate"
    "spaghetti_extractor.components.inductive_contract"
    "spaghetti_extractor.util"
  ];
  inductionRefinementSource = mkPhaseSource "induction-refinement" [
    "spaghetti_extractor.components.inductive_refinement"
    "spaghetti_extractor.util"
  ];
  inductionFinalizationSource = mkPhaseSource "induction-finalization" [
    "spaghetti_extractor.components.inductive_certificate"
    "spaghetti_extractor.components.inductive_contract"
    "spaghetti_extractor.components.inductive_receipts"
    "spaghetti_extractor.util"
  ];
  refinementSource = mkPhaseSource "semantic-refinement" [
    "spaghetti_extractor.components.refinement"
    "spaghetti_extractor.util"
  ];
  serviceGraphSource = mkPhaseSource "service-graph" [
    "spaghetti_extractor.components.service_graph"
    "spaghetti_extractor.components.machine_binding"
    "spaghetti_extractor.util"
  ];
  activationReceiptSource = mkPhaseSource "activation-receipt" [
    "spaghetti_extractor.components.activation_receipt"
    "spaghetti_extractor.util"
  ];
  ownershipSource = mkPhaseSource "ownership" [
    "spaghetti_extractor.components.ownership"
  ];
  proposalInput = import ./component-proposal-input.nix {
    inherit pkgs pythonEnv componentProposals intent namePrefix;
  };
  common = {
    nativeBuildInputs = [ pythonEnv pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  };
  pinInputFile = name: path: builtins.path {
    inherit path;
    name = "${namePrefix}-${name}";
  };
  resolveRootFile = name: root: relative:
    if lib.isDerivation root
    then "${root}/${relative}"
    else if builtins.isString root
    then "${root}/${relative}"
    else pinInputFile name (root + "/${relative}");
  environment = phaseSource: ''
    export PYTHONHASHSEED=0
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export PYTHONPATH=${phaseSource}/src
  '';
  resolution = pkgs.runCommand "${namePrefix}-component-resolution-v2" common ''
    set -euo pipefail
    ${environment resolutionSource}
    mkdir -p "$out"
    ${python} - \
      ${proposalInput.selectedProposals} \
      ${intent} \
      "$out/component-resolution.json" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.components.resolution import (
        resolve_component_catalog_from_selection,
    )

    resolve_component_catalog_from_selection(
        selection=pathlib.Path(sys.argv[1]),
        intent=pathlib.Path(sys.argv[2]),
        out=pathlib.Path(sys.argv[3]),
    )
    PY
    jq -e '
      .format == "spaghetti-extractor-component-resolution-v2" and
      .status == "checked" and (.executes_original_binary | not) and
      (.components | length) > 0 and
      (.configurations | all(.status == "checked"))
    ' "$out/component-resolution.json" >/dev/null
  '';
  selectedProposalPayload = builtins.fromJSON
    (builtins.readFile proposalInput.selectedProposals);
  selectedRowsByComponent = builtins.listToAttrs (map (row: {
    name = row.component_id;
    value = row;
  }) selectedProposalPayload.selections);
  intentComponentsById = builtins.listToAttrs (map (component: {
    name = component.id;
    value = component;
  }) intentPayload.components);
  componentIds = map (component: component.id) intentPayload.components;
  directComponentDependencies = componentId:
    let
      proposal = selectedRowsByComponent.${componentId}.proposal;
      providerFor = dependency:
        let
          candidates = builtins.filter
            (candidateId:
              candidateId != componentId
              && builtins.elem dependency.target_unit_id
                selectedRowsByComponent.${candidateId}.proposal.membership.unit_ids)
            componentIds;
        # Keep every candidate in the isolated input closure.  A unique owner
        # becomes a component call; multiple owners must remain present so the
        # resolver preserves the exact ambiguity evidence instead of degrading
        # it to a missing-owner result.
        in candidates;
    in lib.unique (lib.concatMap providerFor
      (proposal.component_call_dependencies or [ ]));
  componentClosure = componentId: map (row: row.key) (lib.genericClosure {
    startSet = [ { key = componentId; } ];
    operator = row: map (dependencyId: { key = dependencyId; })
      (directComponentDependencies row.key);
  });
  mkComponentResolutionInputs = liftUnit:
    let
      closureIds = lib.sort builtins.lessThan (componentClosure liftUnit.id);
      intentCore = {
        format = intentPayload.format;
        program_id = intentPayload.program_id;
        permitted_activation_profiles = intentPayload.permitted_activation_profiles;
        components = map (componentId: intentComponentsById.${componentId}) closureIds;
        groups = [ ];
        configurations = [ ];
      };
      selectionCore = (builtins.removeAttrs selectedProposalPayload
        [ "selection_sha256" ]) // {
        selections = map (componentId: selectedRowsByComponent.${componentId})
          closureIds;
      };
      selection = selectionCore // {
        selection_sha256 = builtins.hashString "sha256"
          (builtins.toJSON selectionCore);
      };
    in {
      intent = builtins.toFile
        "${namePrefix}-${liftUnit.id}-component-intent-closure-v1.json"
        (builtins.toJSON intentCore + "\n");
      selection = builtins.toFile
        "${namePrefix}-${liftUnit.id}-selected-proposal-closure-v1.json"
        (builtins.toJSON selection + "\n");
    };
  mkComponentResolutionSlice = liftUnit:
    let inputs = mkComponentResolutionInputs liftUnit;
    in pkgs.runCommand "${namePrefix}-${liftUnit.id}-component-resolution-slice-v1" common ''
      set -euo pipefail
      ${environment resolutionSource}
      mkdir -p "$out"
      ${python} - \
        ${inputs.selection} \
        ${inputs.intent} \
        ${lib.escapeShellArg liftUnit.id} \
        "$out/component-resolution.json" <<'PY'
      import json
      import pathlib
      import sys
      from tempfile import TemporaryDirectory
      from spaghetti_extractor.components.resolution import (
          resolve_component_catalog_from_selection,
          slice_component_resolution,
      )

      selection, intent = map(pathlib.Path, sys.argv[1:3])
      with TemporaryDirectory() as temporary:
          resolved = pathlib.Path(temporary) / "component-resolution.json"
          resolve_component_catalog_from_selection(
              selection=selection,
              intent=intent,
              out=resolved,
          )
          slice_component_resolution(
              resolution=resolved,
              lift_unit_id=sys.argv[3],
              out=pathlib.Path(sys.argv[4]),
          )
      PY
      jq -e --arg id ${lib.escapeShellArg liftUnit.id} '
        .format == "spaghetti-extractor-component-resolution-slice-v1" and
        .status == "checked" and
        (.executes_original_binary | not) and
        (.components | map(.id) | index($id)) != null and
        (.groups | length) == 0 and
        (.configurations | length) == 0
      ' "$out/component-resolution.json" >/dev/null
    '';
  mkGroupResolutionSlice = liftUnit:
    pkgs.runCommand "${namePrefix}-${liftUnit.id}-component-resolution-slice-v1" common ''
      set -euo pipefail
      ${environment resolutionSource}
      mkdir -p "$out"
      ${python} - \
        ${resolution}/component-resolution.json \
        ${lib.escapeShellArg liftUnit.id} \
        "$out/component-resolution.json" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.components.resolution import slice_component_resolution

      slice_component_resolution(
          resolution=pathlib.Path(sys.argv[1]),
          lift_unit_id=sys.argv[2],
          out=pathlib.Path(sys.argv[3]),
      )
      PY
      jq -e --arg id ${lib.escapeShellArg liftUnit.id} '
        .format == "spaghetti-extractor-component-resolution-slice-v1" and
        .status == "checked" and
        (.executes_original_binary | not) and
        ((.components + .groups) | map(.id) | index($id)) != null and
        (.configurations | length) == 0
      ' "$out/component-resolution.json" >/dev/null
    '';
  resolutionSlices = builtins.listToAttrs (map (liftUnit: {
    name = liftUnit.id;
    value = if liftUnit.kind == "component"
      then mkComponentResolutionSlice liftUnit
      else mkGroupResolutionSlice liftUnit;
  }) liftUnits);
  mkExternalSiteSlice = liftUnit:
    pkgs.runCommand "${namePrefix}-${liftUnit.id}-component-external-sites-v1" common ''
      set -euo pipefail
      ${environment externalSiteSource}
      mkdir -p "$out"
      ${python} - \
        ${canonicalExternalSites} \
        ${resolutionSlices.${liftUnit.id}}/component-resolution.json \
        ${lib.escapeShellArg liftUnit.id} \
        "$out/external-sites.json" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.components.external_sites import (
          project_component_external_sites,
      )

      project_component_external_sites(
          canonical_external_sites=pathlib.Path(sys.argv[1]),
          resolution=pathlib.Path(sys.argv[2]),
          lift_unit_id=sys.argv[3],
          out=pathlib.Path(sys.argv[4]),
      )
      PY
      jq -e --arg id ${lib.escapeShellArg liftUnit.id} '
        .format == "spaghetti-extractor-component-external-site-slice-v1" and
        .lift_unit_id == $id and
        (.status == "checked" or .status == "incomplete" or .status == "violated") and
        (.executes_original_binary | not) and
        (.authority.can_authorize_candidate_runtime | not)
      ' "$out/external-sites.json" >/dev/null
    '';
  # Keep the canonical site artifact lazy. Merely asking for a pure component
  # contract must not force target-wide external-site analysis because some
  # other component declares an external service.
  externalSiteSlices = builtins.listToAttrs (map (liftUnit: {
      name = liftUnit.id;
      value =
        if canonicalExternalSites == null then
          throw "${liftUnit.id} requires canonical external sites"
        else
          mkExternalSiteSlice liftUnit;
    }) (builtins.filter (liftUnit:
      (liftUnit.machine_binding or null) != null
      && liftUnitUsesExternalSites liftUnit
    ) liftUnits));
  mkContract = liftUnit:
    let
      review = liftUnit.interface_review or null;
      reviewPath =
        if review == null then "-"
        else if reviewRoot == null then
          throw "${liftUnit.id} declares an interface review but reviewRoot is unset"
        else pinInputFile "${liftUnit.id}-boundary-review.json"
          (reviewRoot + "/${lib.removePrefix "reviews/" review}");
    in
    pkgs.runCommand "${namePrefix}-${liftUnit.id}-component-contract-v2" common ''
      set -euo pipefail
      ${environment contractSource}
      mkdir -p "$out"
      ${python} - \
        ${machineIr} \
        ${reconstructionPlan}/reconstruction-plan.json \
        ${resolutionSlices.${liftUnit.id}}/component-resolution.json \
        ${lib.escapeShellArg liftUnit.id} \
        ${lib.escapeShellArg (toString reviewPath)} \
        ${lib.escapeShellArg (if builtins.hasAttr liftUnit.id externalSiteSlices
          then toString externalSiteSlices.${liftUnit.id}
          else "-")} \
        "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.components.contracts import build_lift_unit_contract

      review = None if sys.argv[5] == "-" else pathlib.Path(sys.argv[5])
      external_sites = None if sys.argv[6] == "-" else pathlib.Path(sys.argv[6])
      build_lift_unit_contract(
          machine_ir=pathlib.Path(sys.argv[1]),
          reconstruction_plan=pathlib.Path(sys.argv[2]),
          resolution=pathlib.Path(sys.argv[3]),
          lift_unit_id=sys.argv[4],
          review=review,
          external_sites=external_sites,
          out_dir=pathlib.Path(sys.argv[7]),
      )
      PY
      jq -e '
        .format == "spaghetti-extractor-component-contract-package-v2" and
        (.status == "checked" or .status == "incomplete" or .status == "violated") and
        (.authority.activation_authorized | not) and
        .authority.activation_requires_separate_behavioral_evidence
      ' "$out/contract.json" >/dev/null
    '';
  contracts = builtins.listToAttrs (map (liftUnit: {
    name = liftUnit.id;
    value = mkContract liftUnit;
  }) liftUnits);
  mkDevelopmentDeclaration = liftUnit:
    builtins.toFile
      "${namePrefix}-${liftUnit.id}-component-development-declaration-v1.json"
      (builtins.toJSON {
        format = "spaghetti-extractor-component-development-declaration-v1";
        program_id = intentPayload.program_id;
        kind = liftUnit.kind;
        id = liftUnit.id;
        label = liftUnit.label;
        boundary = if liftUnit.kind == "component"
          then { selector = liftUnit.selector; }
          else { members = liftUnit.members; };
        evidence_profile = liftUnit.evidence_profile;
        source = liftUnit.source;
      });
  developmentLiftUnits = builtins.filter (liftUnit:
    (liftUnit.source or null) != null &&
    (liftUnit.source.operations or null) != null &&
    (liftUnit.interface_review or null) != null &&
    liftUnit.evidence_profile == "portable-component-v2"
  ) liftUnits;
  developmentDeclarations = builtins.listToAttrs (map (liftUnit: {
    name = liftUnit.id;
    value = mkDevelopmentDeclaration liftUnit;
  }) developmentLiftUnits);
  mkDevelopmentContract = liftUnit:
    let
      review = liftUnit.interface_review or null;
      reviewPath =
        if review == null then
          throw "${liftUnit.id} declares a portable source without an interface review"
        else if reviewRoot == null then
          throw "${liftUnit.id} declares an interface review but reviewRoot is unset"
        else pinInputFile "${liftUnit.id}-boundary-review.json"
          (reviewRoot + "/${lib.removePrefix "reviews/" review}");
    in
    pkgs.runCommand "${namePrefix}-${liftUnit.id}-component-development-contract-v1" common ''
      set -euo pipefail
      ${environment developmentContractSource}
      mkdir -p "$out"
      ${python} - \
        ${developmentDeclarations.${liftUnit.id}} \
        ${reviewPath} \
        "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.components.development_contract import (
          build_component_development_contract,
      )

      build_component_development_contract(
          declaration=pathlib.Path(sys.argv[1]),
          review=pathlib.Path(sys.argv[2]),
          out_dir=pathlib.Path(sys.argv[3]),
      )
      PY
      jq -e '
        .format == "spaghetti-extractor-component-development-contract-v1" and
        .status == "checked" and
        (.executes_original_binary | not) and
        (.authority.activation_authorized | not) and
        (.authority.candidate_runtime_authorized | not)
      ' "$out/contract.json" >/dev/null
    '';
  developmentContracts = builtins.listToAttrs (
    map (liftUnit: {
      name = liftUnit.id;
      value = mkDevelopmentContract liftUnit;
    }) developmentLiftUnits
  );
  mkSourcePaths = liftUnit: paths:
    builtins.listToAttrs (map (relative: {
      name = relative;
      value = toString (pinInputFile
        "${liftUnit.id}-${lib.replaceStrings [ "/" ] [ "-" ] relative}"
        (if sourceRoot == null then
          throw "${liftUnit.id} declares source but sourceRoot is unset"
        else sourceRoot + "/${lib.removePrefix "source/" relative}"));
    }) paths);
  mkSourcePackage = liftUnit:
    let
      source = liftUnit.source;
      files = mkSourcePaths liftUnit source.files;
      sharedInputs = mkSourcePaths liftUnit (source.shared_inputs or [ ]);
    in pkgs.runCommand "${namePrefix}-${liftUnit.id}-component-source-package-v2" common ''
      set -euo pipefail
      ${environment sourcePackageSource}
      mkdir -p "$out"
      ${python} - \
        ${lib.escapeShellArg liftUnit.id} \
        ${lib.escapeShellArg (builtins.toJSON files)} \
        ${lib.escapeShellArg (builtins.toJSON sharedInputs)} \
        ${lib.escapeShellArg (builtins.toJSON (source.entry or null))} \
        ${lib.escapeShellArg (builtins.toJSON (source.operations or null))} \
        "$out" <<'PY'
      import json
      import pathlib
      import sys
      from spaghetti_extractor.components.source import build_component_source_package

      build_component_source_package(
          lift_unit_id=sys.argv[1],
          files={key: pathlib.Path(value) for key, value in json.loads(sys.argv[2]).items()},
          shared_inputs={key: pathlib.Path(value) for key, value in json.loads(sys.argv[3]).items()},
          entry=json.loads(sys.argv[4]),
          operation_symbols=json.loads(sys.argv[5]),
          out_dir=pathlib.Path(sys.argv[6]),
      )
      PY
      jq -e --arg id ${lib.escapeShellArg liftUnit.id} '
        (.format == "spaghetti-extractor-component-source-package-v2" or
         .format == "spaghetti-extractor-component-source-package-v3") and
        .lift_unit_id == $id and
        (.files | length) > 0 and
        (.implementation_sha256 | length) == 64
      ' "$out/source-package.json" >/dev/null
    '';
  sourcePackages = builtins.listToAttrs (
    map (liftUnit: {
      name = liftUnit.id;
      value = mkSourcePackage liftUnit;
    }) (builtins.filter (liftUnit: (liftUnit.source or null) != null) liftUnits)
  );
  portableV2LiftUnits = builtins.filter (liftUnit:
    (liftUnit.source or null) != null &&
    (liftUnit.source.operations or null) != null &&
    liftUnit.evidence_profile == "portable-component-v2" &&
    builtins.hasAttr liftUnit.id developmentContracts
  ) liftUnits;
  mkCompileReceipt = liftUnit:
    pkgs.runCommand "${namePrefix}-${liftUnit.id}-component-compile-v1"
      (common // {
        nativeBuildInputs = common.nativeBuildInputs ++ [
          pkgs.stdenv.cc
          compiler
        ];
      }) ''
      set -euo pipefail
      ${environment compileReceiptSource}
      mkdir -p "$out"
      ${python} - \
        ${developmentContracts.${liftUnit.id}}/portable-interface.json \
        ${sourcePackages.${liftUnit.id}} \
        ${pkgs.stdenv.cc}/bin/cc \
        ${compiler}/bin/i686-w64-mingw32-gcc \
        ${lib.escapeShellArg (if builtins.hasAttr liftUnit.id inductionPackages
          then "${inductionPackages.${liftUnit.id}}/source-plan.json"
          else "-")} \
        "$out" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.components.compile_receipt import (
          build_component_compile_receipt,
      )

      interface, source, host_cc, pe32_cc = map(pathlib.Path, sys.argv[1:5])
      induction = [] if sys.argv[5] == "-" else [pathlib.Path(sys.argv[5])]
      output = pathlib.Path(sys.argv[6])
      build_component_compile_receipt(
          interface=interface,
          source_package=source,
          host_compiler=host_cc,
          pe32_compiler=pe32_cc,
          out_dir=output,
          inductive_source_plans=induction,
      )
      PY
      jq -e '
        .format == "spaghetti-extractor-component-compile-receipt-v1" and
        .status == "checked" and
        .policy.host_and_pe32_abi_checked and
        .policy.framework_managed_state and
        .policy.component_mutable_globals_forbidden
      ' "$out/compile-receipt.json" >/dev/null
    '';
  compileReceipts = builtins.listToAttrs (map (liftUnit: {
    name = liftUnit.id;
    value = mkCompileReceipt liftUnit;
  }) portableV2LiftUnits);
  sourceProfiles = builtins.listToAttrs (map (liftUnit: {
    name = liftUnit.id;
    value = pkgs.runCommand
      "${namePrefix}-${liftUnit.id}-component-source-profile-v1" common ''
      set -euo pipefail
      ${environment sourceProfileSource}
      mkdir -p "$out"
      ${python} - ${sourcePackages.${liftUnit.id}} "$out/source-profile.json" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.components.source_profile import (
          check_component_source_profile,
      )
      from spaghetti_extractor.util import write_json

      write_json(
          pathlib.Path(sys.argv[2]),
          check_component_source_profile(package=pathlib.Path(sys.argv[1])),
      )
      PY
      jq -e '
        .format == "spaghetti-extractor-component-source-profile-v1" and
        (.status == "satisfied" or .status == "incomplete" or .status == "violated") and
        (.policy.operator_behavior_examples_used | not)
      ' "$out/source-profile.json" >/dev/null
    '';
  }) portableV2LiftUnits);
  machineBindingLiftUnits = builtins.filter (liftUnit:
    (liftUnit.machine_binding or null) != null &&
    liftUnit.evidence_profile == "portable-component-v2" &&
    builtins.hasAttr liftUnit.id developmentContracts
  ) liftUnits;
  liftUnitUsesExternalSites = liftUnit:
    let
      bindingPath =
        if bindingRoot == null then
          throw "${liftUnit.id} declares a machine binding but bindingRoot is unset"
        else resolveRootFile "${liftUnit.id}-machine-binding.json" bindingRoot
          (lib.removePrefix "bindings/" liftUnit.machine_binding);
      declaration = builtins.fromJSON (builtins.readFile bindingPath);
    in builtins.any
      (service: (service.provider.kind or null) == "external_site")
      (declaration.services or [ ]);
  mkMachineBindingReceipt = liftUnit:
    let
      binding = liftUnit.machine_binding;
      bindingPath =
        if bindingRoot == null then
          throw "${liftUnit.id} declares a machine binding but bindingRoot is unset"
        else resolveRootFile "${liftUnit.id}-machine-binding.json" bindingRoot
          (lib.removePrefix "bindings/" binding);
      requiresExternalSites = liftUnitUsesExternalSites liftUnit;
      externalSites =
        if canonicalExternalSites == null || !requiresExternalSites then "-"
        else toString canonicalExternalSites;
      callbacks =
        if callbackAuthority == null then "-" else toString callbackAuthority;
    in pkgs.runCommand
      "${namePrefix}-${liftUnit.id}-component-machine-binding-v1" common ''
      set -euo pipefail
      ${environment machineBindingSource}
      mkdir -p "$out"
      ${python} - \
        ${bindingPath} \
        ${developmentContracts.${liftUnit.id}}/portable-interface.json \
        ${machineIr}/machine-ir.jsonl \
        ${machineIr}/machine-ir-manifest.json \
        ${lib.escapeShellArg externalSites} \
        ${lib.escapeShellArg callbacks} \
        ${resolutionSlices.${liftUnit.id}}/component-resolution.json \
        ${contracts.${liftUnit.id}}/semantic-component-catalog.json \
        "$out/machine-binding.json" \
        "$out/machine-binding-receipt.json" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.components.machine_binding import (
          check_component_machine_binding,
          materialize_component_machine_binding,
      )
      from spaghetti_extractor.util import write_json

      declaration, interface, machine_ir, manifest = map(pathlib.Path, sys.argv[1:5])
      sites = None if sys.argv[5] == "-" else pathlib.Path(sys.argv[5])
      callbacks = None if sys.argv[6] == "-" else pathlib.Path(sys.argv[6])
      resolution = pathlib.Path(sys.argv[7])
      catalog = pathlib.Path(sys.argv[8])
      binding = pathlib.Path(sys.argv[9])
      output = pathlib.Path(sys.argv[10])
      write_json(binding, materialize_component_machine_binding(
          declaration=declaration,
          interface=interface,
          machine_ir=machine_ir,
          machine_ir_manifest=manifest,
          semantic_component_catalog=catalog,
      ))
      receipt = check_component_machine_binding(
          binding=binding,
          interface=interface,
          machine_ir=machine_ir,
          machine_ir_manifest=manifest,
          canonical_external_sites=sites,
          callback_authority=callbacks,
          component_resolution=resolution,
          semantic_component_catalog=catalog,
      )
      write_json(output, receipt)
      PY
      jq -e '
        .format == "spaghetti-extractor-component-machine-binding-receipt-v1" and
        (.status == "checked" or .status == "incomplete" or .status == "violated") and
        (.activation_authorized == (.status == "checked"))
      ' "$out/machine-binding-receipt.json" >/dev/null
    '';
  machineBindingReceipts = builtins.listToAttrs (map (liftUnit: {
    name = liftUnit.id;
    value = mkMachineBindingReceipt liftUnit;
  }) machineBindingLiftUnits);
  semanticContracts = lib.mapAttrs (liftUnitId: bindingReceipt:
    let
      liftUnit = liftUnitsById.${liftUnitId};
      externalSites =
        if canonicalExternalSites == null || !(liftUnitUsesExternalSites liftUnit)
        then "-"
        else toString canonicalExternalSites;
    in pkgs.runCommand
      "${namePrefix}-${liftUnitId}-component-semantic-contract-v1" common ''
      set -euo pipefail
      ${environment semanticContractSource}
      mkdir -p "$out"
      ${python} - \
        ${developmentContracts.${liftUnitId}}/portable-interface.json \
        ${bindingReceipt}/machine-binding.json \
        ${machineIr}/machine-ir.jsonl \
        ${machineIr}/machine-ir-manifest.json \
        ${lib.escapeShellArg externalSites} \
        ${resolutionSlices.${liftUnitId}}/component-resolution.json \
        ${lib.escapeShellArg (if callBoundaryContracts == null then "-" else toString callBoundaryContracts)} \
        "$out/semantic-contract.json" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.components.semantic_contract import (
          build_component_semantic_contract,
      )
      from spaghetti_extractor.util import write_json

      interface, binding, machine_ir, manifest = map(pathlib.Path, sys.argv[1:5])
      external_sites = None if sys.argv[5] == "-" else pathlib.Path(sys.argv[5])
      resolution = pathlib.Path(sys.argv[6])
      call_boundaries = None if sys.argv[7] == "-" else pathlib.Path(sys.argv[7])
      output = pathlib.Path(sys.argv[8])
      write_json(output, build_component_semantic_contract(
          interface=interface,
          binding=binding,
          machine_ir=machine_ir,
          machine_ir_manifest=manifest,
          canonical_external_sites=external_sites,
          component_resolution=resolution,
          call_boundary_contracts=call_boundaries,
      ))
      PY
      jq -e '
        .format == "spaghetti-extractor-component-semantic-contract-v1" and
        (.status == "satisfied" or .status == "incomplete" or .status == "violated") and
        .policy.behavior_is_machine_derived and
        (.policy.operator_expected_outputs_accepted | not)
      ' "$out/semantic-contract.json" >/dev/null
    '') machineBindingReceipts;
  universalContracts = lib.mapAttrs (liftUnitId: semanticContract:
    pkgs.runCommand
      "${namePrefix}-${liftUnitId}-universal-component-contract-v3" common ''
      set -euo pipefail
      ${environment universalContractSource}
      mkdir -p "$out"
      ${python} - \
        ${developmentContracts.${liftUnitId}}/portable-interface.json \
        ${machineBindingReceipts.${liftUnitId}}/machine-binding.json \
        ${machineBindingReceipts.${liftUnitId}}/machine-binding-receipt.json \
        ${semanticContract}/semantic-contract.json \
        "$out" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.components.universal_contract import (
          build_component_contract_v3,
      )

      build_component_contract_v3(
          interface=pathlib.Path(sys.argv[1]),
          machine_binding=pathlib.Path(sys.argv[2]),
          machine_binding_receipt=pathlib.Path(sys.argv[3]),
          semantic_contract=pathlib.Path(sys.argv[4]),
          out=pathlib.Path(sys.argv[5]),
      )
      PY
      jq -e '
        .format == "spaghetti-extractor-component-contract-v3" and
        (.status == "checked" or .status == "incomplete" or .status == "violated") and
        .policy.implementation_independent and
        (.policy.original_binary_executed | not)
      ' "$out/component-contract-v3.json" >/dev/null
    '') semanticContracts;
  relationArtifacts = if relationKernel == null then { } else
    lib.mapAttrs (liftUnitId: semanticContract:
      let
        liftUnit = liftUnitsById.${liftUnitId};
        relationDeclaration = liftUnit.relation or null;
        relationDeclarationPath =
          if relationDeclaration == null then "-"
          else if relationRoot == null then
            throw "${liftUnitId} declares a relation but relationRoot is unset"
          else pinInputFile "${liftUnitId}-relation-declaration.json"
            (relationRoot + "/${lib.removePrefix "relations/" relationDeclaration}");
      in
      pkgs.runCommand
        "${namePrefix}-${liftUnitId}-component-relation-v3"
        (common // {
          nativeBuildInputs = common.nativeBuildInputs ++ [ pkgs.lean4 pkgs.coreutils ];
        }) ''
        set -euo pipefail
        ${environment relationSource}
        relation_work="$PWD/relation-work"
        mkdir -p "$relation_work"
        ${python} - \
          ${developmentContracts.${liftUnitId}}/portable-interface.json \
          ${machineBindingReceipts.${liftUnitId}}/machine-binding.json \
          ${semanticContract}/semantic-contract.json \
          ${pinInputFile "interaction-contracts-v1.json" interactionContractCatalog} \
          ${lib.escapeShellArg (toString relationDeclarationPath)} \
          "$relation_work" <<'PY'
        import json
        import pathlib
        import sys

        from spaghetti_extractor.components.interface_ir import (
            PortableComponentInterfaceV2,
        )
        from spaghetti_extractor.components.machine_binding import (
            ComponentMachineBindingV1,
        )
        from spaghetti_extractor.components.interaction_contract import (
            InteractionContractCatalogV1,
        )
        from spaghetti_extractor.components.interaction_inventory import (
            build_component_interaction_inventory,
        )
        from spaghetti_extractor.components.object_authority import (
            derive_machine_object_authority,
        )
        from spaghetti_extractor.components.relation_lean import (
            RelationLeanError,
            render_relation_certificate,
        )
        from spaghetti_extractor.components.relation_declaration import (
            ComponentRelationDeclarationError,
            ComponentRelationDeclarationV2,
        )
        from spaghetti_extractor.components.relation_proposal import (
            ComponentRelationProposalError,
            build_component_relation_proposal,
            build_component_relation_proposal_package,
        )
        from spaghetti_extractor.util import write_json

        interface_path, binding_path, semantic_path, catalog_path = map(pathlib.Path, sys.argv[1:5])
        declaration_path = None if sys.argv[5] == "-" else pathlib.Path(sys.argv[5])
        output = pathlib.Path(sys.argv[6])
        interface = PortableComponentInterfaceV2.parse(
            json.loads(interface_path.read_text(encoding="utf-8"))
        )
        binding = ComponentMachineBindingV1.parse(
            json.loads(binding_path.read_text(encoding="utf-8"))
        )
        semantic = json.loads(semantic_path.read_text(encoding="utf-8"))
        catalog = InteractionContractCatalogV1.parse(
            json.loads(catalog_path.read_text(encoding="utf-8"))
        )
        try:
            authority = derive_machine_object_authority(
                interface=interface,
                machine_binding=binding,
            )
            inventory = build_component_interaction_inventory(
                interface=interface,
                machine_binding=binding,
                semantic_contract=semantic,
                contract_catalog=catalog,
            )
            declaration = (
                None if declaration_path is None else ComponentRelationDeclarationV2.parse(
                    json.loads(declaration_path.read_text(encoding="utf-8"))
                )
            )
            selections = {} if declaration is None else declaration.selections_for(inventory)
            write_json(output / "object-authority.json", authority.to_payload())
            write_json(output / "interaction-inventory.json", inventory.to_payload())
            write_json(
                output / "relation-proposal.json",
                build_component_relation_proposal_package(
                    interaction_inventory=inventory,
                    contract_selections=selections,
                ),
            )
            relation = build_component_relation_proposal(
                interface=interface,
                machine_binding=binding,
                semantic_contract_sha256=str(semantic["contract_sha256"]),
                object_authority_sha256=authority.authority_sha256,
                interaction_inventory=inventory,
                contract_catalog=catalog,
                contract_selections=selections,
            )
            certificate = render_relation_certificate(
                relation=relation,
                interface=interface,
                interaction_inventory=inventory,
                contract_catalog=catalog,
            )
        except (
            ComponentRelationDeclarationError,
            ComponentRelationProposalError,
            RelationLeanError,
        ) as exc:
            write_json(output / "relation-status.json", {
                "format": "spaghetti-extractor-component-relation-status-v1",
                "status": "incomplete",
                "component_id": binding.identity,
                "code": "interaction_relation_incomplete",
                "detail": str(exc),
            })
        else:
            write_json(output / "relation-ir.json", relation.to_payload())
            (output / "RelationCertificate.lean").write_text(
                certificate, encoding="utf-8"
            )
        PY
        if [ -f "$relation_work/relation-ir.json" ]; then
          export LEAN_PATH=${relationKernel}
          lean --trust=0 \
            -o "$relation_work/RelationCertificate.olean" \
            "$relation_work/RelationCertificate.lean" \
            > "$relation_work/lean-audit.txt"
          if grep -q 'sorryAx\|Classical.choice\|native_decide[.]ax' "$relation_work/lean-audit.txt"; then
            cat "$relation_work/lean-audit.txt" >&2
            exit 1
          fi
          lean_sha256="$(sha256sum "$relation_work/RelationCertificate.olean" | cut -d ' ' -f 1)"
          ${python} - \
            ${developmentContracts.${liftUnitId}}/portable-interface.json \
            "$relation_work/relation-ir.json" \
            "$relation_work/interaction-inventory.json" \
            ${pinInputFile "interaction-contracts-v1.json" interactionContractCatalog} \
            "$lean_sha256" \
            "$relation_work/relation-receipt.json" \
            "$relation_work/relation-status.json" <<'PY'
        import json
        import pathlib
        import sys

        from spaghetti_extractor.components.interface_ir import (
            PortableComponentInterfaceV2,
        )
        from spaghetti_extractor.components.interaction_contract import (
            InteractionContractCatalogV1,
        )
        from spaghetti_extractor.components.interaction_inventory import (
            ComponentInteractionInventoryV1,
        )
        from spaghetti_extractor.components.relation_checker import (
            check_component_relation,
        )
        from spaghetti_extractor.components.boundary_plan import (
            compile_component_boundary_plan,
        )
        from spaghetti_extractor.components.object_authority import (
            MachineObjectAuthorityV1,
        )
        from spaghetti_extractor.components.relation_ir import (
            ComponentRelationIRV1,
        )
        from spaghetti_extractor.util import write_json

        interface_path, relation_path, inventory_path, catalog_path = map(pathlib.Path, sys.argv[1:5])
        interface = PortableComponentInterfaceV2.parse(
            json.loads(interface_path.read_text(encoding="utf-8"))
        )
        relation = ComponentRelationIRV1.parse(
            json.loads(relation_path.read_text(encoding="utf-8"))
        )
        inventory = ComponentInteractionInventoryV1.parse(
            json.loads(inventory_path.read_text(encoding="utf-8"))
        )
        catalog = InteractionContractCatalogV1.parse(
            json.loads(catalog_path.read_text(encoding="utf-8"))
        )
        authority = MachineObjectAuthorityV1.parse(
            json.loads((relation_path.parent / "object-authority.json").read_text(encoding="utf-8"))
        )
        if relation.bindings.get("object_authority_sha256") != authority.authority_sha256:
            raise ValueError("relation object authority binding is stale")
        receipt = check_component_relation(
            relation=relation,
            interface=interface,
            interaction_inventory=inventory,
            contract_catalog=catalog,
            lean_artifact_sha256=sys.argv[5],
        )
        write_json(pathlib.Path(sys.argv[6]), receipt.to_payload())
        if receipt.authorizing:
            plan, plan_receipt = compile_component_boundary_plan(
                relation=relation,
                relation_receipt=receipt,
                object_authority_sha256=authority.authority_sha256,
            )
            write_json(relation_path.parent / "boundary-plan.json", plan.to_payload())
            write_json(
                relation_path.parent / "boundary-plan-receipt.json",
                plan_receipt.to_payload(),
            )
        write_json(pathlib.Path(sys.argv[7]), {
            "format": "spaghetti-extractor-component-relation-status-v1",
            "status": receipt.status,
            "component_id": relation.component_id,
            "code": "relation_checked" if receipt.authorizing else "relation_unchecked",
            "detail": None,
        })
        PY
        fi
        mkdir -p "$out"
        cp -r "$relation_work/." "$out/"
        jq -e '
          .format == "spaghetti-extractor-component-relation-status-v1" and
          (.status == "checked" or .status == "incomplete" or .status == "violated")
        ' "$out/relation-status.json" >/dev/null
        if jq -e '.status == "checked"' "$out/relation-status.json" >/dev/null; then
          jq -e '
            .format == "spaghetti-extractor-component-boundary-plan-receipt-v3" and
            .status == "checked"
          ' "$out/boundary-plan-receipt.json" >/dev/null
        fi
      '') semanticContracts;
  relationCheckGates = lib.mapAttrs (liftUnitId: relation:
    pkgs.runCommand
      "${namePrefix}-${liftUnitId}-component-relation-check-v1" common ''
      set -euo pipefail
      if [ ! -f ${relation}/relation-receipt.json ]; then
        cat ${relation}/relation-status.json >&2
        exit 1
      fi
      jq -e '
        .format == "spaghetti-extractor-component-relation-receipt-v2" and
        .status == "checked"
      ' ${relation}/relation-receipt.json >/dev/null || {
        cat ${relation}/relation-receipt.json >&2
        exit 1
      }
      mkdir -p "$out"
      cp ${relation}/relation-ir.json "$out/relation-ir.json"
      cp ${relation}/relation-receipt.json "$out/relation-receipt.json"
      cp ${relation}/object-authority.json "$out/object-authority.json"
      cp ${relation}/interaction-inventory.json "$out/interaction-inventory.json"
      cp ${relation}/relation-proposal.json "$out/relation-proposal.json"
      cp ${relation}/boundary-plan.json "$out/boundary-plan.json"
      cp ${relation}/boundary-plan-receipt.json "$out/boundary-plan-receipt.json"
    '') relationArtifacts;
  universalMachineBindings = lib.mapAttrs (liftUnitId: contract:
    pkgs.runCommand
      "${namePrefix}-${liftUnitId}-universal-machine-binding-v3" common ''
      set -euo pipefail
      ${environment universalContractSource}
      mkdir -p "$out"
      ${python} - \
        ${contract}/component-contract-v3.json \
        ${machineBindingReceipts.${liftUnitId}}/machine-binding.json \
        ${machineBindingReceipts.${liftUnitId}}/machine-binding-receipt.json \
        ${semanticContracts.${liftUnitId}}/semantic-contract.json \
        ${if builtins.hasAttr liftUnitId relationArtifacts then relationArtifacts.${liftUnitId} else "-"} \
        "$out" <<'PY'
      import json
      import pathlib
      import sys

      from spaghetti_extractor.components.universal_binding import (
          build_component_machine_binding_v3,
          build_component_machine_binding_v4,
      )

      output = pathlib.Path(sys.argv[6])
      base = build_component_machine_binding_v3(
          contract=pathlib.Path(sys.argv[1]),
          machine_binding=pathlib.Path(sys.argv[2]),
          machine_binding_receipt=pathlib.Path(sys.argv[3]),
          semantic_contract=pathlib.Path(sys.argv[4]),
      )
      relation_root = None if sys.argv[5] == "-" else pathlib.Path(sys.argv[5])
      if relation_root is not None and (relation_root / "relation-ir.json").is_file():
          build_component_machine_binding_v4(
              binding=base,
              relation=relation_root / "relation-ir.json",
              relation_receipt=relation_root / "relation-receipt.json",
              out=output,
          )
      else:
          output.mkdir(parents=True, exist_ok=True)
          (output / "machine-binding-v3.json").write_text(
              json.dumps(base.to_payload(), indent=2, sort_keys=True) + "\n",
              encoding="utf-8",
          )
      PY
      jq -e '
        (.format == "spaghetti-extractor-component-machine-binding-v3" or
         .format == "spaghetti-extractor-component-machine-binding-v4") and
        (.status == "checked" or .status == "incomplete" or .status == "violated") and
        (.policy.original_binary_executed | not)
      ' "$out/machine-binding-v3.json" >/dev/null
    '') universalContracts;
  machineImplementations = lib.mapAttrs (liftUnitId: binding:
    pkgs.runCommand
      "${namePrefix}-${liftUnitId}-machine-ir-component-implementation-v3" common ''
      set -euo pipefail
      ${environment componentImplementationSource}
      mkdir -p "$out"
      ${python} - \
        ${lib.escapeShellArg "${liftUnitId}_machine_ir"} \
        ${universalContracts.${liftUnitId}}/component-contract-v3.json \
        ${binding}/machine-binding-v3.json \
        "$out" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.components.implementation import (
          adapt_machine_ir_implementation_v3,
      )

      adapt_machine_ir_implementation_v3(
          implementation_id=sys.argv[1],
          contract=pathlib.Path(sys.argv[2]),
          machine_binding=pathlib.Path(sys.argv[3]),
          out=pathlib.Path(sys.argv[4]),
      )
      PY
      jq -e '
        .format == "spaghetti-extractor-component-implementation-v3" and
        .kind == "machine_ir" and
        (.status == "checked" or .status == "incomplete" or .status == "violated")
      ' "$out/implementation-v3.json" >/dev/null
    '') universalMachineBindings;
  inductiveLiftUnits = builtins.filter
    (liftUnit: (liftUnit.induction or null) != null)
    liftUnits;
  mkInductionDeclarationInputs = liftUnit:
    let
      declarationPath =
        if inductionRoot == null then
          throw "${liftUnit.id} declares an induction declaration but inductionRoot is unset"
        else resolveRootFile "${liftUnit.id}-induction.json" inductionRoot
          (lib.removePrefix "induction/" liftUnit.induction);
      declaration = builtins.fromJSON (builtins.readFile declarationPath);
      combined =
        if (declaration.format or null) !=
            "spaghetti-extractor-inductive-component-declaration-v1" ||
           !(builtins.isAttrs (declaration.source or null)) ||
           !(builtins.isAttrs (declaration.proof or null))
        then throw
          "${liftUnit.id} induction must use the combined source/proof declaration V1"
        else declaration;
    in {
      original = declarationPath;
      source = builtins.toFile
        "${namePrefix}-${liftUnit.id}-inductive-source-declaration-v1.json"
        (builtins.toJSON ({
          format = "spaghetti-extractor-inductive-declaration-v1";
        } // combined.source));
      proof = builtins.toFile
        "${namePrefix}-${liftUnit.id}-inductive-proof-declaration-v1.json"
        (builtins.toJSON ({
          format = "spaghetti-extractor-inductive-proof-declaration-v1";
        } // combined.proof));
    };
  inductionDeclarations = builtins.listToAttrs (map (liftUnit: {
    name = liftUnit.id;
    value = mkInductionDeclarationInputs liftUnit;
  }) inductiveLiftUnits);
  mkInductionPackage = liftUnit:
    let
      declarationPath = inductionDeclarations.${liftUnit.id}.source;
      semanticContract =
        if builtins.hasAttr liftUnit.id semanticContracts then
          semanticContracts.${liftUnit.id}
        else throw
          "${liftUnit.id} declares induction but has no exact semantic contract";
      portableInterface =
        if builtins.hasAttr liftUnit.id developmentContracts then
          "${developmentContracts.${liftUnit.id}}/portable-interface.json"
        else throw
          "${liftUnit.id} declares induction but has no portable component V2 interface";
    in pkgs.runCommand
      "${namePrefix}-${liftUnit.id}-component-induction-package-v1" common ''
      set -euo pipefail
      ${environment inductionPackageSource}
      mkdir -p "$out"
      ${python} - \
        ${declarationPath} \
        ${portableInterface} \
        ${semanticContract}/semantic-contract.json \
        "$out" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.components.inductive_package import (
          write_inductive_package,
      )

      declaration, interface, semantic_contract, output = map(
          pathlib.Path, sys.argv[1:]
      )
      write_inductive_package(
          declaration=declaration,
          interface=interface,
          semantic_contract=semantic_contract,
          out_dir=output,
      )
      PY
      jq -e --arg id ${lib.escapeShellArg liftUnit.id} '
        .format == "spaghetti-extractor-inductive-package-v1" and
        .status == "checked" and
        .component_id == $id and
        (.policy.original_binary_executed | not) and
        (.policy.operator_behavior_examples_accepted | not) and
        .policy.exact_machine_inventory_replayed and
        (.artifacts | keys) == [
          "cutpoint_relation", "machine_receipt", "source_plan"
        ]
      ' "$out/induction-package.json" >/dev/null
      test -s "$out/source-plan.json"
      test -s "$out/machine-receipt.json"
      test -s "$out/cutpoint-relation.json"
    '';
  inductionPackages = builtins.listToAttrs (map (liftUnit: {
    name = liftUnit.id;
    value = mkInductionPackage liftUnit;
  }) inductiveLiftUnits);
  mkInductionDraftCertificate = liftUnit:
    pkgs.runCommand
      "${namePrefix}-${liftUnit.id}-component-induction-certificate-draft-v1"
      common ''
      set -euo pipefail
      ${environment inductionCertificateSource}
      mkdir -p "$out"
      ${python} - \
        ${inductionDeclarations.${liftUnit.id}.proof} \
        ${semanticContracts.${liftUnit.id}}/semantic-contract.json \
        ${developmentContracts.${liftUnit.id}}/portable-interface.json \
        ${sourcePackages.${liftUnit.id}} \
        ${inductionPackages.${liftUnit.id}}/source-plan.json \
        ${inductionPackages.${liftUnit.id}}/machine-receipt.json \
        ${inductionPackages.${liftUnit.id}}/cutpoint-relation.json \
        "$out/certificate.json" \
        "$out/certificate-check.json" <<'PY'
      import json
      import pathlib
      import sys

      from spaghetti_extractor.components.inductive_certificate import (
          materialize_inductive_certificate,
      )
      from spaghetti_extractor.components.inductive_contract import (
          check_inductive_operation_certificate,
      )
      from spaghetti_extractor.components.inductive_receipts import (
          CheckedInductiveMachineReceiptV1,
      )
      from spaghetti_extractor.util import write_json

      proof, semantic, interface, source, plan, machine_path, relation, certificate_out, check_out = (
          map(pathlib.Path, sys.argv[1:])
      )
      certificate = materialize_inductive_certificate(
          proof_declaration=proof,
          semantic_contract=semantic,
          interface=interface,
          source_package=source,
          source_plan=plan,
          machine_receipt=machine_path,
          cutpoint_relation=relation,
      )
      machine = CheckedInductiveMachineReceiptV1.parse(
          json.loads(machine_path.read_text(encoding="utf-8"))
      )
      machine_references = {
          item.receipt_id: machine.to_payload()
          for item in certificate.receipts
          if item.kind == "machine_semantics"
      }
      check = check_inductive_operation_certificate(
          certificate, receipt_payloads=machine_references
      )
      write_json(certificate_out, certificate.to_payload())
      write_json(check_out, check.to_payload())
      PY
      jq -e '
        .format == "spaghetti-extractor-portable-inductive-operation-certificate-v1"
      ' "$out/certificate.json" >/dev/null
      jq -e '
        .format == "spaghetti-extractor-portable-inductive-operation-check-v1" and
        .status == "incomplete"
      ' "$out/certificate-check.json" >/dev/null
    '';
  inductionDraftCertificates = builtins.listToAttrs (map (liftUnit: {
    name = liftUnit.id;
    value = mkInductionDraftCertificate liftUnit;
  }) inductiveLiftUnits);
  mkInductionSourceReceipt = liftUnit:
    let
      bindingDeclaration = builtins.fromJSON (builtins.readFile
        (resolveRootFile
          "${liftUnit.id}-machine-binding-declaration"
          bindingRoot
          (lib.removePrefix "bindings/" liftUnit.machine_binding)));
      componentServiceContracts = builtins.listToAttrs (map (service: {
        name = service.service_id;
        value = {
          component_id = service.provider.component_id;
          operation_id = service.provider.operation_id;
          semantic_contract =
            "${semanticContracts.${service.provider.component_id}}/semantic-contract.json";
          interface =
            "${developmentContracts.${service.provider.component_id}}/portable-interface.json";
        };
      }) (builtins.filter
        (service: service.provider.kind == "component_operation")
        bindingDeclaration.services));
    in
    pkgs.runCommand
      "${namePrefix}-${liftUnit.id}-component-induction-source-refinement-v1"
      (common // {
        nativeBuildInputs = common.nativeBuildInputs ++ [ pkgs.cbmc pkgs.stdenv.cc ];
      }) ''
      set -euo pipefail
      ${environment inductionRefinementSource}
      mkdir -p "$out"
      ${python} - \
        ${semanticContracts.${liftUnit.id}}/semantic-contract.json \
        ${developmentContracts.${liftUnit.id}}/portable-interface.json \
        ${sourcePackages.${liftUnit.id}} \
        ${sourceProfiles.${liftUnit.id}}/source-profile.json \
        ${inductionPackages.${liftUnit.id}}/source-plan.json \
        ${inductionPackages.${liftUnit.id}}/machine-receipt.json \
        ${inductionPackages.${liftUnit.id}}/cutpoint-relation.json \
        ${inductionDraftCertificates.${liftUnit.id}}/certificate.json \
        ${lib.escapeShellArg (builtins.toJSON componentServiceContracts)} \
        ${pkgs.cbmc}/bin/cbmc \
        "$out/source-receipt.json" <<'PY'
      import json
      import pathlib
      import sys

      from spaghetti_extractor.components.inductive_refinement import (
          check_inductive_source_refinement_artifacts,
      )
      from spaghetti_extractor.util import write_json

      semantic, interface, source, profile, plan, machine, relation, certificate = (
          map(pathlib.Path, sys.argv[1:9])
      )
      component_service_contracts = json.loads(sys.argv[9])
      cbmc, output = map(pathlib.Path, sys.argv[10:])
      write_json(output, check_inductive_source_refinement_artifacts(
          semantic_contract=semantic,
          interface=interface,
          source_package=source,
          source_profile=profile,
          source_plan=plan,
          machine_receipt=machine,
          cutpoint_relation=relation,
          certificate=certificate,
          component_service_contracts=component_service_contracts,
          cbmc=cbmc,
      ))
      PY
      jq -e '
        .format == "spaghetti-extractor-inductive-source-refinement-receipt-v1" and
        (.status == "satisfied" or .status == "incomplete" or .status == "violated") and
        (.policy.original_binary_executed | not) and
        (.policy.behavior_examples_used | not) and
        (.policy.bounded_unwinding_used | not)
      ' "$out/source-receipt.json" >/dev/null
    '';
  inductionSourceReceipts = builtins.listToAttrs (map (liftUnit: {
    name = liftUnit.id;
    value = mkInductionSourceReceipt liftUnit;
  }) inductiveLiftUnits);
  mkInductionRefinement = liftUnit:
    pkgs.runCommand
      "${namePrefix}-${liftUnit.id}-component-induction-refinement-v1"
      common ''
      set -euo pipefail
      ${environment inductionFinalizationSource}
      mkdir -p "$out"
      ${python} - \
        ${inductionDeclarations.${liftUnit.id}.proof} \
        ${semanticContracts.${liftUnit.id}}/semantic-contract.json \
        ${developmentContracts.${liftUnit.id}}/portable-interface.json \
        ${sourcePackages.${liftUnit.id}} \
        ${inductionPackages.${liftUnit.id}}/source-plan.json \
        ${inductionPackages.${liftUnit.id}}/machine-receipt.json \
        ${inductionPackages.${liftUnit.id}}/cutpoint-relation.json \
        ${inductionDraftCertificates.${liftUnit.id}}/certificate.json \
        ${inductionDraftCertificates.${liftUnit.id}}/certificate-check.json \
        ${inductionSourceReceipts.${liftUnit.id}}/source-receipt.json \
        "$out" <<'PY'
      import json
      import pathlib
      import sys

      from spaghetti_extractor.components.inductive_certificate import (
          materialize_inductive_certificate,
      )
      from spaghetti_extractor.components.inductive_contract import (
          InductiveOperationCertificateV1,
          InductiveOperationCheckV1,
          check_inductive_operation_certificate,
      )
      from spaghetti_extractor.components.inductive_receipts import (
          CheckedInductiveMachineReceiptV1,
          finalize_inductive_refinement_receipt,
      )
      from spaghetti_extractor.util import write_json

      proof, semantic, interface, source, plan, machine_path, relation, draft_path, draft_check_path, source_receipt_path, output = (
          map(pathlib.Path, sys.argv[1:])
      )
      source_receipt = json.loads(source_receipt_path.read_text(encoding="utf-8"))
      machine = CheckedInductiveMachineReceiptV1.parse(
          json.loads(machine_path.read_text(encoding="utf-8"))
      )
      if source_receipt.get("status") == "satisfied":
          certificate = materialize_inductive_certificate(
              proof_declaration=proof,
              semantic_contract=semantic,
              interface=interface,
              source_package=source,
              source_plan=plan,
              machine_receipt=machine_path,
              cutpoint_relation=relation,
              source_receipt=source_receipt,
          )
          receipts = {
              item.receipt_id: (
                  machine.to_payload()
                  if item.kind == "machine_semantics"
                  else source_receipt
              )
              for item in certificate.receipts
          }
          check = check_inductive_operation_certificate(
              certificate, receipt_payloads=receipts
          )
      else:
          certificate = InductiveOperationCertificateV1.parse(
              json.loads(draft_path.read_text(encoding="utf-8"))
          )
          check = InductiveOperationCheckV1.parse(
              json.loads(draft_check_path.read_text(encoding="utf-8"))
          )
      receipt = finalize_inductive_refinement_receipt(
          certificate=certificate,
          certificate_check=check,
          machine_receipt=machine,
          source_receipt=source_receipt,
      )
      write_json(output / "certificate.json", certificate.to_payload())
      write_json(output / "certificate-check.json", check.to_payload())
      write_json(output / "refinement-receipt.json", receipt)
      PY
      jq -e '
        .format == "spaghetti-extractor-inductive-refinement-receipt-v1" and
        (.status == "satisfied" or .status == "incomplete" or .status == "violated") and
        (.activation_authorized == (.status == "satisfied")) and
        (.policy.original_binary_executed | not) and
        (.policy.behavior_examples_used | not) and
        (.policy.bounded_unwinding_used | not)
      ' "$out/refinement-receipt.json" >/dev/null
    '';
  inductionRefinementArtifacts = builtins.listToAttrs (map (liftUnit: {
    name = liftUnit.id;
    value = mkInductionRefinement liftUnit;
  }) inductiveLiftUnits);
  finiteRefinementContracts = builtins.removeAttrs semanticContracts
    (map (liftUnit: liftUnit.id) inductiveLiftUnits);
  finiteRefinementReceipts = lib.mapAttrs (liftUnitId: semanticContract:
    pkgs.runCommand
      "${namePrefix}-${liftUnitId}-component-semantic-refinement-v1"
      (common // {
        nativeBuildInputs = common.nativeBuildInputs ++ [ pkgs.cbmc pkgs.stdenv.cc ];
      }) ''
      set -euo pipefail
      ${environment refinementSource}
      mkdir -p "$out"
      ${python} - \
        ${semanticContract}/semantic-contract.json \
        ${developmentContracts.${liftUnitId}}/portable-interface.json \
        ${sourcePackages.${liftUnitId}} \
        ${sourceProfiles.${liftUnitId}}/source-profile.json \
        ${pkgs.cbmc}/bin/cbmc \
        ${if builtins.hasAttr liftUnitId relationCheckGates then "${relationCheckGates.${liftUnitId}}/boundary-plan.json" else "-"} \
        ${if builtins.hasAttr liftUnitId relationCheckGates then "${relationCheckGates.${liftUnitId}}/boundary-plan-receipt.json" else "-"} \
        "$out/refinement-receipt.json" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.components.refinement import check_component_refinement
      from spaghetti_extractor.util import write_json

      semantic, interface, source, profile, cbmc = map(pathlib.Path, sys.argv[1:6])
      plan = None if sys.argv[6] == "-" else pathlib.Path(sys.argv[6])
      plan_receipt = None if sys.argv[7] == "-" else pathlib.Path(sys.argv[7])
      output = pathlib.Path(sys.argv[8])
      write_json(output, check_component_refinement(
          semantic_contract=semantic,
          interface=interface,
          source_package=source,
          source_profile=profile,
          cbmc=cbmc,
          boundary_plan=plan,
          boundary_plan_receipt=plan_receipt,
      ))
      PY
      jq -e '
        .format == "spaghetti-extractor-component-refinement-receipt-v1" and
        (.status == "satisfied" or .status == "incomplete" or .status == "violated") and
        (.activation_authorized == (.status == "satisfied")) and
        (.policy.original_binary_executed | not) and
        (.policy.operator_behavior_examples_used | not)
      ' "$out/refinement-receipt.json" >/dev/null
    '') finiteRefinementContracts;
  refinementReceipts = finiteRefinementReceipts // inductionRefinementArtifacts;
  mkServiceGraph = liftUnit:
    let
      knownInterfacePaths = builtins.listToAttrs (map (unit: {
        name = unit.id;
        value = "${developmentContracts.${unit.id}}/portable-interface.json";
      }) portableV2LiftUnits);
      knownBindingPaths = builtins.listToAttrs (map (unit: {
        name = unit.id;
        value = "${machineBindingReceipts.${unit.id}}/machine-binding.json";
      }) machineBindingLiftUnits);
    in pkgs.runCommand
      "${namePrefix}-${liftUnit.id}-component-service-graph-v1" common ''
      set -euo pipefail
      ${environment serviceGraphSource}
      mkdir -p "$out"
      ${python} - \
        ${lib.escapeShellArg liftUnit.id} \
        ${lib.escapeShellArg (builtins.toJSON knownInterfacePaths)} \
        ${lib.escapeShellArg (builtins.toJSON knownBindingPaths)} \
        "$out/service-graph.json" <<'PY'
      import json
      import pathlib
      import sys

      from spaghetti_extractor.components.interface_ir import (
          PortableComponentInterfaceV2,
      )
      from spaghetti_extractor.components.machine_binding import (
          ComponentMachineBindingV1,
      )
      from spaghetti_extractor.components.service_graph import (
          ServiceGraphConfigurationV1,
          build_service_graph,
      )
      from spaghetti_extractor.util import write_json

      root_lift_unit_id = sys.argv[1]
      interface_paths = json.loads(sys.argv[2])
      binding_paths = json.loads(sys.argv[3])
      output = pathlib.Path(sys.argv[4])
      interfaces_by_lift_unit = {
          lift_unit_id: PortableComponentInterfaceV2.parse(
              json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
          )
          for lift_unit_id, path in interface_paths.items()
      }
      machines_by_lift_unit = {
          lift_unit_id: ComponentMachineBindingV1.parse(
              json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
          )
          for lift_unit_id, path in binding_paths.items()
      }
      enabled_lift_unit_ids = set()
      pending = [root_lift_unit_id]
      while pending:
          lift_unit_id = pending.pop()
          if lift_unit_id in enabled_lift_unit_ids:
              continue
          enabled_lift_unit_ids.add(lift_unit_id)
          machine = machines_by_lift_unit.get(lift_unit_id)
          if machine is None:
              continue
          pending.extend(
              str(row.provider["component_id"])
              for row in machine.services
              if row.provider["kind"] == "component_operation"
          )
      interfaces = {
          interface.identity: interface
          for lift_unit_id, interface in interfaces_by_lift_unit.items()
          if lift_unit_id in enabled_lift_unit_ids
      }
      bindings = []
      for lift_unit_id in sorted(enabled_lift_unit_ids):
          machine = machines_by_lift_unit.get(lift_unit_id)
          interface = interfaces_by_lift_unit.get(lift_unit_id)
          if machine is None or interface is None:
              continue
          service_index = {row.identity: row for row in interface.services}
          for row in machine.services:
              service = service_index[row.service_id]
              provider = dict(row.provider)
              if provider["kind"] == "external_site":
                  provider = {
                      "kind": "external_site",
                      "site_id": provider["site_id"],
                      "parameter_type_ids": list(service.parameter_type_ids),
                      "result_type_id": service.result_type_id,
                      "effect_ids": list(service.effect_ids),
                  }
              elif provider["kind"] == "machine_events":
                  provider = {
                      "kind": "machine_events",
                      "event_ids": sorted(
                          f"{event['unit_id']}:{event['event_index']}:{event['event_sha256']}"
                          for event in provider["events"]
                      ),
                      "parameter_type_ids": list(service.parameter_type_ids),
                      "result_type_id": service.result_type_id,
                      "effect_ids": list(service.effect_ids),
                  }
              elif provider["kind"] == "component_operation":
                  provider.pop("events", None)
                  provider_lift_unit_id = provider["component_id"]
                  if provider_lift_unit_id in interfaces_by_lift_unit:
                      provider["component_id"] = (
                          interfaces_by_lift_unit[provider_lift_unit_id].identity
                      )
              bindings.append({
                  "component_id": interface.identity,
                  "service_id": row.service_id,
                  "provider": provider,
                  "mediation": row.mediation,
              })
      configuration = ServiceGraphConfigurationV1.create(
          identity=interfaces_by_lift_unit[root_lift_unit_id].identity,
          bindings=bindings,
      )
      graph = build_service_graph(
          interfaces=interfaces,
          configuration=configuration,
      )
      write_json(output, graph.to_payload())
      PY
      jq -e '
        .format == "spaghetti-extractor-component-service-graph-v1" and
        (.status == "checked" or .status == "incomplete" or .status == "violated") and
        (.activation_authorized == (.status == "checked"))
      ' "$out/service-graph.json" >/dev/null
    '';
  serviceGraphs = builtins.listToAttrs (map (liftUnit: {
    name = liftUnit.id;
    value = mkServiceGraph liftUnit;
  }) portableV2LiftUnits);
  ownershipReceipts = builtins.listToAttrs (map (liftUnit: {
    name = liftUnit.id;
    value = pkgs.runCommand
      "${namePrefix}-${liftUnit.id}-component-ownership-v1" common ''
      set -euo pipefail
      ${environment ownershipSource}
      mkdir -p "$out"
      ${python} - \
        ${machineBindingReceipts.${liftUnit.id}}/machine-binding.json \
        ${resolutionSlices.${liftUnit.id}} \
        "$out/ownership-receipt.json" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.components.ownership import (
          build_component_ownership_receipt,
      )

      build_component_ownership_receipt(
          machine_binding=pathlib.Path(sys.argv[1]),
          resolution_slice=pathlib.Path(sys.argv[2]),
          out=pathlib.Path(sys.argv[3]),
      )
      PY
      jq -e '
        .format == "spaghetti-extractor-component-ownership-receipt-v1" and
        (.status == "checked" or .status == "incomplete" or .status == "violated") and
        (.activation_authorized == (.status == "checked"))
      ' "$out/ownership-receipt.json" >/dev/null
    '';
  }) machineBindingLiftUnits);
  mkAdapterPlan = liftUnit:
    pkgs.runCommand "${namePrefix}-${liftUnit.id}-component-adapter-plan-v1" common ''
      set -euo pipefail
      ${environment adapterSource}
      mkdir -p "$out"
      ${python} - \
        ${contracts.${liftUnit.id}} \
        ${sourcePackages.${liftUnit.id}} \
        ${machineIr} \
        "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.components.adapter import build_component_adapter_plan

      build_component_adapter_plan(
          contract=pathlib.Path(sys.argv[1]),
          implementation=pathlib.Path(sys.argv[2]),
          machine_ir=pathlib.Path(sys.argv[3]),
          out_dir=pathlib.Path(sys.argv[4]),
      )
      PY
      jq -e '
        .format == "spaghetti-extractor-component-adapter-plan-v1" and
        (.status == "checked" or .status == "incomplete" or .status == "violated") and
        (.executes_original_binary | not) and
        (.policy.machine_ir_fallback_used | not) and
        (.policy.runtime_completion == "checked-machine-projection-v1" or
         .policy.runtime_completion == "explicit-reviewed-completion-v1" or
         .policy.runtime_completion == null) and
        (.policy.raw_machine_addresses_exposed | not)
      ' "$out/adapter-plan.json" >/dev/null
      test -s "$out/spaghetti-component-abi.h"
    '';
  adapterPlans = builtins.listToAttrs (
    map (liftUnit: {
      name = liftUnit.id;
      value = mkAdapterPlan liftUnit;
    }) (builtins.filter (liftUnit:
      (liftUnit.source or null) != null &&
      (liftUnit.source.entry or null) != null
    ) liftUnits)
  );
  mkEvidence = liftUnit:
    pkgs.runCommand "${namePrefix}-${liftUnit.id}-component-evidence-v3"
      (common // { nativeBuildInputs = common.nativeBuildInputs ++ [ pkgs.stdenv.cc ]; }) ''
      set -euo pipefail
      ${environment evidenceSource}
      mkdir -p "$out"
      ${python} - \
        ${contracts.${liftUnit.id}} \
        ${sourcePackages.${liftUnit.id}} \
        ${adapterPlans.${liftUnit.id}} \
        ${machineIr} \
        ${lib.escapeShellArg (builtins.toJSON liftUnit.verification)} \
        ${pkgs.stdenv.cc}/bin/cc \
        "$out/evidence.json" <<'PY'
      import json
      import pathlib
      import sys
      from spaghetti_extractor.components.evidence import produce_component_evidence

      produce_component_evidence(
          contract=pathlib.Path(sys.argv[1]),
          implementation=pathlib.Path(sys.argv[2]),
          adapter_plan=pathlib.Path(sys.argv[3]),
          machine_ir=pathlib.Path(sys.argv[4]),
          verification=json.loads(sys.argv[5]),
          compiler=pathlib.Path(sys.argv[6]),
          out=pathlib.Path(sys.argv[7]),
      )
      PY
      jq -e '
        .format == "spaghetti-extractor-component-evidence-v3" and
        (.status == "satisfied" or .status == "incomplete" or .status == "violated") and
        (.executes_original_binary | not)
      ' "$out/evidence.json" >/dev/null
    '';
  evidences = builtins.listToAttrs (
    map (liftUnit: {
      name = liftUnit.id;
      value = mkEvidence liftUnit;
    }) (builtins.filter (liftUnit:
      (liftUnit.source or null) != null &&
      builtins.hasAttr liftUnit.id adapterPlans &&
      (liftUnit.verification or null) != null &&
      (liftUnit.verification.producer or null) == "exhaustive-finite-domain-v1"
    ) liftUnits)
  );
  mkQualification = liftUnit:
    pkgs.runCommand "${namePrefix}-${liftUnit.id}-component-qualification-v3" common ''
      set -euo pipefail
      ${environment qualificationSource}
      mkdir -p "$out"
      ${python} - \
        ${contracts.${liftUnit.id}}/contract.json \
        ${sourcePackages.${liftUnit.id}} \
        ${evidences.${liftUnit.id}}/evidence.json \
        ${adapterPlans.${liftUnit.id}} \
        ${machineIr} \
        ${lib.escapeShellArg (builtins.toJSON liftUnit.verification)} \
        "$out/qualification.json" <<'PY'
      import json
      import pathlib
      import sys
      from spaghetti_extractor.components.qualification import qualify_lift_unit

      qualify_lift_unit(
          contract=pathlib.Path(sys.argv[1]),
          implementation=pathlib.Path(sys.argv[2]),
          evidence=pathlib.Path(sys.argv[3]),
          adapter_plan=pathlib.Path(sys.argv[4]),
          machine_ir=pathlib.Path(sys.argv[5]),
          verification=json.loads(sys.argv[6]),
          out=pathlib.Path(sys.argv[7]),
      )
      PY
      jq -e '
        .format == "spaghetti-extractor-component-qualification-v3" and
        (.status == "qualified" or .status == "incomplete" or .status == "violated") and
        (.assurance.original_binary_executed | not)
      ' "$out/qualification.json" >/dev/null
    '';
  qualifications = builtins.listToAttrs (
    map (liftUnit: {
      name = liftUnit.id;
      value = mkQualification liftUnit;
    }) (builtins.filter (liftUnit: builtins.hasAttr liftUnit.id evidences) liftUnits)
  );
  mkActivationReceiptWithGraph = scope: liftUnit: serviceGraph:
    let
      machineBinding = if builtins.hasAttr liftUnit.id universalMachineBindings
        then "${universalMachineBindings.${liftUnit.id}}/machine-binding-v3.json"
        else "-";
      refinement = if builtins.hasAttr liftUnit.id refinementReceipts
        then "${refinementReceipts.${liftUnit.id}}/refinement-receipt.json"
        else "-";
      ownership = if builtins.hasAttr liftUnit.id ownershipReceipts
        then "${ownershipReceipts.${liftUnit.id}}/ownership-receipt.json"
        else "-";
      relation = if builtins.hasAttr liftUnit.id relationCheckGates
        then "${relationCheckGates.${liftUnit.id}}/relation-receipt.json"
        else "-";
      boundaryPlan = if builtins.hasAttr liftUnit.id relationCheckGates
        then "${relationCheckGates.${liftUnit.id}}/boundary-plan-receipt.json"
        else "-";
      activationReceiptVersion = if builtins.hasAttr liftUnit.id relationCheckGates
        then "v3" else "v2";
    in pkgs.runCommand
      "${namePrefix}-${scope}-${liftUnit.id}-component-activation-receipt-${activationReceiptVersion}" common ''
      set -euo pipefail
      ${environment activationReceiptSource}
      mkdir -p "$out"
      ${python} - \
        ${developmentContracts.${liftUnit.id}}/portable-interface.json \
        ${sourceProfiles.${liftUnit.id}}/source-profile.json \
        ${compileReceipts.${liftUnit.id}}/compile-receipt.json \
        ${lib.escapeShellArg machineBinding} \
        ${lib.escapeShellArg refinement} \
        ${serviceGraph}/service-graph.json \
        ${lib.escapeShellArg ownership} \
        ${lib.escapeShellArg relation} \
        ${lib.escapeShellArg boundaryPlan} \
        ${lib.escapeShellArg liftUnit.id} \
        "$out/activation-receipt.json" <<'PY'
      import json
      import pathlib
      import sys

      from spaghetti_extractor.components.activation_receipt import (
          ActivationReceiptV1,
      )
      from spaghetti_extractor.util import write_json

      def load(path):
          if path == "-":
              return None
          return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))

      interface, source_profile, compile_receipt, machine, refinement, services, ownership, relation, boundary_plan, component_id, output = (
          sys.argv[1:]
      )
      receipt = ActivationReceiptV1.from_receipts(
          interface=load(interface),
          source_profile=load(source_profile),
          source_compile=load(compile_receipt),
          machine_binding=load(machine),
          semantic_refinement=load(refinement),
          service_graph=load(services),
          ownership=load(ownership),
          relation=load(relation),
          boundary_plan=load(boundary_plan),
          component_id=component_id,
      )
      write_json(pathlib.Path(output), receipt.to_payload())
      PY
      jq -e '
        ((.format == "spaghetti-extractor-component-activation-receipt-v3" and
          (.facets | length) == 9) or
         (.format == "spaghetti-extractor-component-activation-receipt-v2" and
          (.facets | length) == 7)) and
        (.status == "checked" or .status == "incomplete" or .status == "violated") and
        (.activation_authorized == (.status == "checked"))
      ' "$out/activation-receipt.json" >/dev/null
    '';
  mkActivationReceipt = liftUnit:
    mkActivationReceiptWithGraph "standalone" liftUnit serviceGraphs.${liftUnit.id};
  activationReceipts = builtins.listToAttrs (map (liftUnit: {
    name = liftUnit.id;
    value = mkActivationReceipt liftUnit;
  }) (builtins.filter (liftUnit:
    builtins.hasAttr liftUnit.id compileReceipts
  ) portableV2LiftUnits));
  activationCheckGates = lib.mapAttrs (liftUnitId: receipt:
    pkgs.runCommand "${namePrefix}-${liftUnitId}-component-activation-check-v1" common ''
      set -euo pipefail
      jq -e '
        (.format == "spaghetti-extractor-component-activation-receipt-v3" or
         .format == "spaghetti-extractor-component-activation-receipt-v2") and
        .status == "checked" and .activation_authorized
      ' ${receipt}/activation-receipt.json >/dev/null || {
        jq '{status, facets, next_actions}' \
          ${receipt}/activation-receipt.json >&2
        exit 1
      }
      mkdir -p "$out"
      cp ${receipt}/activation-receipt.json "$out/activation-receipt.json"
    '') activationReceipts;
  activationStatusReports = lib.mapAttrs (liftUnitId: receipt:
    pkgs.runCommand "${namePrefix}-${liftUnitId}-component-activation-status-v1" common ''
      set -euo pipefail
      mkdir -p "$out"
      cp ${receipt}/activation-receipt.json "$out/status.json"
    '') activationReceipts;
  liftUnitsById = builtins.listToAttrs (map (row: {
    name = row.id;
    value = row;
  }) liftUnits);
  enabledPortableV2Ids = configuration:
    map (selection: selection.id) (builtins.filter (selection:
      selection.activation == "enabled" &&
      builtins.hasAttr selection.id compileReceipts
    ) configuration.selections);
  selectedPortableV2Ids = configuration:
    map (selection: selection.id) (builtins.filter (selection:
      builtins.hasAttr selection.id machineBindingReceipts
    ) configuration.selections);
  mkConfigurationServiceGraph = configuration:
    let
      enabledIds = selectedPortableV2Ids configuration;
      enabledInterfacePaths = builtins.listToAttrs (map (id: {
        name = id;
        value = "${developmentContracts.${id}}/portable-interface.json";
      }) enabledIds);
      knownInterfacePaths = builtins.listToAttrs (map (liftUnit: {
        name = liftUnit.id;
        value = "${developmentContracts.${liftUnit.id}}/portable-interface.json";
      }) portableV2LiftUnits);
      bindingPaths = builtins.listToAttrs (map (id: {
        name = id;
        value = "${machineBindingReceipts.${id}}/machine-binding.json";
      }) (builtins.filter (id: builtins.hasAttr id machineBindingReceipts) enabledIds));
      graphId = "configuration_${builtins.substring 0 20
        (builtins.hashString "sha256" configuration.id)}";
    in pkgs.runCommand
      "${namePrefix}-${configuration.id}-component-service-graph-v1" common ''
      set -euo pipefail
      ${environment serviceGraphSource}
      mkdir -p "$out"
      ${python} - \
        ${lib.escapeShellArg graphId} \
        ${lib.escapeShellArg (builtins.toJSON enabledInterfacePaths)} \
        ${lib.escapeShellArg (builtins.toJSON knownInterfacePaths)} \
        ${lib.escapeShellArg (builtins.toJSON bindingPaths)} \
        "$out/service-graph.json" <<'PY'
      import json
      import pathlib
      import sys

      from spaghetti_extractor.components.interface_ir import (
          PortableComponentInterfaceV2,
      )
      from spaghetti_extractor.components.machine_binding import (
          ComponentMachineBindingV1,
      )
      from spaghetti_extractor.components.service_graph import (
          ServiceGraphConfigurationV1,
          build_service_graph,
      )
      from spaghetti_extractor.util import write_json

      graph_id, raw_enabled_interfaces, raw_known_interfaces, raw_bindings, output = sys.argv[1:]
      interfaces_by_lift_unit = {
          lift_unit_id: PortableComponentInterfaceV2.parse(
              json.loads(pathlib.Path(value).read_text(encoding="utf-8"))
          )
          for lift_unit_id, value in json.loads(raw_known_interfaces).items()
      }
      enabled_lift_unit_ids = set(json.loads(raw_enabled_interfaces))
      interfaces = {
          interface.identity: interface
          for lift_unit_id, interface in interfaces_by_lift_unit.items()
          if lift_unit_id in enabled_lift_unit_ids
      }
      bindings = []
      for lift_unit_id, value in json.loads(raw_bindings).items():
          machine = ComponentMachineBindingV1.parse(
              json.loads(pathlib.Path(value).read_text(encoding="utf-8"))
          )
          consumer = interfaces_by_lift_unit[lift_unit_id]
          services = {row.identity: row for row in consumer.services}
          for row in machine.services:
              service = services[row.service_id]
              provider = dict(row.provider)
              if provider["kind"] == "external_site":
                  provider = {
                      "kind": "external_site",
                      "site_id": provider["site_id"],
                      "parameter_type_ids": list(service.parameter_type_ids),
                      "result_type_id": service.result_type_id,
                      "effect_ids": list(service.effect_ids),
                  }
              elif provider["kind"] == "machine_events":
                  provider = {
                      "kind": "machine_events",
                      "event_ids": sorted(
                          f"{event['unit_id']}:{event['event_index']}:{event['event_sha256']}"
                          for event in provider["events"]
                      ),
                      "parameter_type_ids": list(service.parameter_type_ids),
                      "result_type_id": service.result_type_id,
                      "effect_ids": list(service.effect_ids),
                  }
              elif provider["kind"] == "component_operation":
                  provider.pop("events", None)
                  provider_lift_unit_id = provider["component_id"]
                  if provider_lift_unit_id in interfaces_by_lift_unit:
                      provider["component_id"] = (
                          interfaces_by_lift_unit[provider_lift_unit_id].identity
                      )
              bindings.append({
                  "component_id": consumer.identity,
                  "service_id": row.service_id,
                  "provider": provider,
                  "mediation": row.mediation,
              })
      graph = build_service_graph(
          interfaces=interfaces,
          configuration=ServiceGraphConfigurationV1.create(
              identity=graph_id,
              bindings=bindings,
          ),
      )
      write_json(pathlib.Path(output), graph.to_payload())
      PY
      jq -e '
        .format == "spaghetti-extractor-component-service-graph-v1" and
        (.status == "checked" or .status == "incomplete" or .status == "violated") and
        (.activation_authorized == (.status == "checked"))
      ' "$out/service-graph.json" >/dev/null
    '';
  serviceConfigurations = builtins.filter (configuration:
    selectedPortableV2Ids configuration != [ ]) intentPayload.configurations;
  configurationServiceGraphs = builtins.listToAttrs (map (configuration: {
    name = configuration.id;
    value = mkConfigurationServiceGraph configuration;
  }) serviceConfigurations);
  configurationActivationReceipts = builtins.listToAttrs (map (configuration:
    let
      ids = builtins.filter (id:
        builtins.hasAttr id compileReceipts &&
        builtins.hasAttr id machineBindingReceipts &&
        builtins.hasAttr id refinementReceipts &&
        builtins.hasAttr id ownershipReceipts
      ) (enabledPortableV2Ids configuration);
    in {
      name = configuration.id;
      value = builtins.listToAttrs (map (id: {
        name = id;
        value = mkActivationReceiptWithGraph configuration.id liftUnitsById.${id}
          configurationServiceGraphs.${configuration.id};
      }) ids);
    }) serviceConfigurations);
  mkPortableImplementation = configurationId: liftUnitId: receipt:
    pkgs.runCommand
      "${namePrefix}-${configurationId}-${liftUnitId}-portable-component-implementation-v3"
      common ''
      set -euo pipefail
      ${environment componentImplementationSource}
      mkdir -p "$out"
      ${python} - \
        ${lib.escapeShellArg "${liftUnitId}_portable_c"} \
        ${universalContracts.${liftUnitId}}/component-contract-v3.json \
        ${universalMachineBindings.${liftUnitId}}/machine-binding-v3.json \
        ${sourcePackages.${liftUnitId}} \
        ${receipt}/activation-receipt.json \
        "$out" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.components.implementation import (
          adapt_portable_c_implementation_v3,
      )

      adapt_portable_c_implementation_v3(
          implementation_id=sys.argv[1],
          contract=pathlib.Path(sys.argv[2]),
          machine_binding=pathlib.Path(sys.argv[3]),
          source_package=pathlib.Path(sys.argv[4]),
          activation_receipt=pathlib.Path(sys.argv[5]),
          out=pathlib.Path(sys.argv[6]),
      )
      PY
      jq -e '
        .format == "spaghetti-extractor-component-implementation-v3" and
        .kind == "portable_c" and
        (.status == "checked" or .status == "incomplete" or .status == "violated")
      ' "$out/implementation-v3.json" >/dev/null
    '';
  portableImplementationsByConfiguration = lib.mapAttrs
    (configurationId: receipts:
      lib.mapAttrs (liftUnitId: receipt:
        mkPortableImplementation configurationId liftUnitId receipt
      ) receipts
    ) configurationActivationReceipts;
  developmentPackages = lib.mapAttrs (liftUnitId: developmentContract:
    pkgs.linkFarm "${namePrefix}-${liftUnitId}-component-development-package-v1" [
      { name = "declaration"; path = developmentDeclarations.${liftUnitId}; }
      { name = "contract"; path = developmentContract; }
      { name = "source"; path = sourcePackages.${liftUnitId}; }
    ]) developmentContracts;
  mkActivationPlan = configuration:
    let
      selectedIds = map (selection: selection.id) configuration.selections;
      selectedContractPaths = builtins.listToAttrs (map (id: {
        name = id;
        value = toString contracts.${id};
      }) (builtins.filter (id: !(builtins.hasAttr id machineBindingReceipts)) selectedIds));
      selectedPortableInterfacePaths = builtins.listToAttrs (map (id: {
        name = id;
        value = "${developmentContracts.${id}}/portable-interface.json";
      }) (builtins.filter (id: builtins.hasAttr id machineBindingReceipts) selectedIds));
      selectedMachineBindingPaths = builtins.listToAttrs (map (id: {
        name = id;
        value = "${machineBindingReceipts.${id}}/machine-binding.json";
      }) (builtins.filter (id: builtins.hasAttr id machineBindingReceipts) selectedIds));
      selectedImplementationPaths = builtins.listToAttrs (map (id: {
        name = id;
        value = toString sourcePackages.${id};
      }) (builtins.filter (id: builtins.hasAttr id sourcePackages) selectedIds));
      selectedQualificationPaths = builtins.listToAttrs (map (id: {
        name = id;
        value = toString qualifications.${id};
      }) (builtins.filter (id: builtins.hasAttr id qualifications) selectedIds));
      selectedAdapterPlanPaths = builtins.listToAttrs (map (id: {
        name = id;
        value = toString adapterPlans.${id};
      }) (builtins.filter (id: builtins.hasAttr id adapterPlans) selectedIds));
      configurationReceipts = configurationActivationReceipts.${configuration.id} or { };
      selectedActivationReceiptPaths = builtins.listToAttrs (map (id: {
        name = id;
        value = "${configurationReceipts.${id}}/activation-receipt.json";
      }) (builtins.filter (id: builtins.hasAttr id configurationReceipts) selectedIds));
      selectedLibraryComponentPaths = lib.mapAttrs
        (_id: value: toString value) generatedLibraryComponents;
    in pkgs.runCommand "${namePrefix}-${configuration.id}-component-activation-plan-v3" common ''
      set -euo pipefail
      ${environment configurationSource}
      mkdir -p "$out"
      ${python} - \
        ${machineIr} \
        ${resolution}/component-resolution.json \
        ${lib.escapeShellArg configuration.id} \
        ${lib.escapeShellArg (builtins.toJSON selectedContractPaths)} \
        ${lib.escapeShellArg (builtins.toJSON selectedPortableInterfacePaths)} \
        ${lib.escapeShellArg (builtins.toJSON selectedMachineBindingPaths)} \
        ${lib.escapeShellArg (builtins.toJSON selectedImplementationPaths)} \
        ${lib.escapeShellArg (builtins.toJSON selectedQualificationPaths)} \
        ${lib.escapeShellArg (builtins.toJSON selectedAdapterPlanPaths)} \
        ${lib.escapeShellArg (builtins.toJSON selectedActivationReceiptPaths)} \
        ${lib.escapeShellArg (builtins.toJSON selectedLibraryComponentPaths)} \
        "$out/activation-plan.json" <<'PY'
      import json
      import pathlib
      import sys
      from spaghetti_extractor.components.configuration import compose_component_configuration

      compose_component_configuration(
          machine_ir=pathlib.Path(sys.argv[1]),
          resolution=pathlib.Path(sys.argv[2]),
          configuration_id=sys.argv[3],
          contracts={key: pathlib.Path(value) for key, value in json.loads(sys.argv[4]).items()},
          portable_interfaces={key: pathlib.Path(value) for key, value in json.loads(sys.argv[5]).items()},
          machine_bindings={key: pathlib.Path(value) for key, value in json.loads(sys.argv[6]).items()},
          implementations={key: pathlib.Path(value) for key, value in json.loads(sys.argv[7]).items()},
          qualifications={key: pathlib.Path(value) for key, value in json.loads(sys.argv[8]).items()},
          adapter_plans={key: pathlib.Path(value) for key, value in json.loads(sys.argv[9]).items()},
          activation_receipts={key: pathlib.Path(value) for key, value in json.loads(sys.argv[10]).items()},
          generated_library_components={key: pathlib.Path(value) for key, value in json.loads(sys.argv[11]).items()},
          out=pathlib.Path(sys.argv[12]),
      )
      PY
      jq -e '
        .format == "spaghetti-extractor-component-activation-plan-v3" and
        (.status == "checked" or .status == "incomplete" or .status == "violated") and
        .ownership.complete and .ownership.exclusive and
        (.hybrid.release_ready | not) and
        (.policy.runtime_package_is_sole_candidate_authority) and
        .policy.one_implementation_per_structural_unit and
        (.entries | all(
          .implementation_kind == "portable_replacement" or
          .implementation_kind == "machine_ir_fallback" or
          .implementation_kind == "blocked"
        )) and
        (.selections | all(
          .ownership_state == "portable_replacement" or
          .ownership_state == "machine_ir_fallback" or
          .ownership_state == "blocked"
        )) and
        ((.counts.blocked == 0 and .status == "checked") or
          (.counts.blocked > 0 and (.status == "incomplete" or .status == "violated"))) and
        .counts.structural_units ==
          (.counts.portable_replacement + .counts.machine_ir_fallback + .counts.blocked)
      ' "$out/activation-plan.json" >/dev/null
    '';
  activationPlans = builtins.listToAttrs (map (configuration: {
    name = configuration.id;
    value = mkActivationPlan configuration;
  }) intentPayload.configurations);
  selectedUniversalImplementations = configuration:
    let
      portable = portableImplementationsByConfiguration.${configuration.id} or { };
      selectedRows = builtins.filter
        (selection: builtins.hasAttr selection.id universalContracts)
        configuration.selections;
    in builtins.listToAttrs (map (selection: {
      name = selection.id;
      value =
        if selection.activation == "enabled" && builtins.hasAttr selection.id portable
        then portable.${selection.id}
        else machineImplementations.${selection.id};
    }) selectedRows);
  mkUniversalDependencyGraph = configuration:
    let
      selectedContracts = builtins.listToAttrs (map (selection: {
        name = selection.id;
        value = universalContracts.${selection.id};
      }) (builtins.filter
        (selection: builtins.hasAttr selection.id universalContracts)
        configuration.selections));
      selectedImplementations = selectedUniversalImplementations configuration;
      serviceGraph = configurationServiceGraphs.${configuration.id} or null;
      asPaths = values: lib.mapAttrs (_id: value: toString value) values;
      libraryPaths = asPaths generatedLibraryComponents;
    in pkgs.runCommand
      "${namePrefix}-${configuration.id}-component-dependency-graph-v3" common ''
      set -euo pipefail
      ${environment componentDependencySource}
      mkdir -p "$out"
      ${python} - \
        ${lib.escapeShellArg (builtins.toJSON (asPaths selectedContracts))} \
        ${lib.escapeShellArg (builtins.toJSON (asPaths selectedImplementations))} \
        ${lib.escapeShellArg (builtins.toJSON libraryPaths)} \
        ${lib.escapeShellArg (if serviceGraph == null then "-" else "${serviceGraph}/service-graph.json")} \
        "$out" <<'PY'
      import json
      import pathlib
      import sys

      from spaghetti_extractor.components.dependency_graph import (
          build_component_dependency_graph_from_service_graph_v3,
          build_component_dependency_graph_v3,
      )
      from spaghetti_extractor.components.implementation import (
          read_component_implementation_v3,
      )
      from spaghetti_extractor.components.universal_contract import (
          read_component_contract_v3,
      )

      def paths(raw):
          return {key: pathlib.Path(value) for key, value in json.loads(raw).items()}

      contract_paths = paths(sys.argv[1])
      implementation_paths = paths(sys.argv[2])
      for selection_id, root in paths(sys.argv[3]).items():
          contract_paths[f"library:{selection_id}"] = root / "component-contract-v3.json"
          implementation_paths[f"library:{selection_id}"] = root / "implementation-v3.json"
      contracts = {}
      for value in contract_paths.values():
          contract = read_component_contract_v3(value)
          contracts[contract.component_id] = contract
      implementations = {}
      for value in implementation_paths.values():
          implementation = read_component_implementation_v3(value)
          implementations[implementation.component_id] = implementation
      service_graph = None if sys.argv[4] == "-" else pathlib.Path(sys.argv[4])
      if service_graph is None:
          build_component_dependency_graph_v3(
              contracts=contracts,
              implementations=implementations,
              bindings=[],
              out=pathlib.Path(sys.argv[5]),
          )
      else:
          build_component_dependency_graph_from_service_graph_v3(
              contracts=contracts,
              implementations=implementations,
              service_graph=service_graph,
              out=pathlib.Path(sys.argv[5]),
          )
      PY
      jq -e '
        .format == "spaghetti-extractor-component-dependency-graph-v3" and
        (.status == "checked" or .status == "incomplete" or .status == "violated") and
        (.policy.original_binary_executed | not)
      ' "$out/component-dependency-graph-v3.json" >/dev/null
    '';
  dependencyGraphs = builtins.listToAttrs (map (configuration: {
    name = configuration.id;
    value = mkUniversalDependencyGraph configuration;
  }) intentPayload.configurations);
  mkComponentReleaseGate = configurationId: mode:
    pkgs.runCommand
      "${namePrefix}-${configurationId}-component-${mode}-release-gate-v1" common ''
      set -euo pipefail
      ${environment componentDependencySource}
      mkdir -p "$out"
      ${python} - \
        ${dependencyGraphs.${configurationId}}/component-dependency-graph-v3.json \
        ${activationPlans.${configurationId}}/activation-plan.json \
        ${rootedBehavioralProjection}/rooted-behavioral-projection-v1.json \
        ${lib.escapeShellArg mode} \
        "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.components.dependency_graph import (
          build_component_release_gate_v1,
      )
      from spaghetti_extractor.candidate.authority.rooted_projection import (
          load_rooted_behavioral_projection_v1,
      )

      build_component_release_gate_v1(
          graph=pathlib.Path(sys.argv[1]),
          activation_plan=pathlib.Path(sys.argv[2]),
          rooted_projection=load_rooted_behavioral_projection_v1(
              pathlib.Path(sys.argv[3])
          ),
          mode=sys.argv[4],
          out=pathlib.Path(sys.argv[5]),
      )
      PY
    '';
  hybridGates = lib.mapAttrs
    (configurationId: _graph: mkComponentReleaseGate configurationId "hybrid")
    dependencyGraphs;
  portableGates = lib.mapAttrs
    (configurationId: _graph: mkComponentReleaseGate configurationId "portable")
    dependencyGraphs;
  mkComponentReleaseCheck = configurationId: mode: gate:
    pkgs.runCommand
      "${namePrefix}-${configurationId}-component-${mode}-release-check-v1"
      (common // { nativeBuildInputs = common.nativeBuildInputs ++ [ pkgs.jq ]; }) ''
      set -euo pipefail
      jq -e --arg mode ${lib.escapeShellArg mode} '
        .format == "spaghetti-extractor-component-release-gate-v1" and
        .mode == $mode and .status == "ready" and .ready
      ' ${gate}/component-${mode}-release-gate-v1.json >/dev/null || {
        jq '{mode, status, counts, issues}' \
          ${gate}/component-${mode}-release-gate-v1.json >&2
        exit 1
      }
      mkdir -p "$out"
      cp ${gate}/component-${mode}-release-gate-v1.json \
        "$out/component-${mode}-release-gate-v1.json"
    '';
  hybridCheckGates = lib.mapAttrs
    (configurationId: gate:
      mkComponentReleaseCheck configurationId "hybrid" gate)
    hybridGates;
  portableCheckGates = lib.mapAttrs
    (configurationId: gate:
      mkComponentReleaseCheck configurationId "portable" gate)
    portableGates;
  mkRetirementReport = configuration:
    let
      selectedBindings = builtins.listToAttrs (map (selection: {
        name = selection.id;
        value = universalMachineBindings.${selection.id};
      }) (builtins.filter
        (selection: builtins.hasAttr selection.id universalMachineBindings)
        configuration.selections));
      asPaths = values: lib.mapAttrs (_id: value: toString value) values;
      roots = map (selection: selection.id) (builtins.filter
        (selection: selection.activation == "enabled" &&
          builtins.hasAttr selection.id universalContracts)
        configuration.selections);
    in pkgs.runCommand
      "${namePrefix}-${configuration.id}-component-retirement-report-v1" common ''
      set -euo pipefail
      ${environment componentDependencySource}
      mkdir -p "$out"
      ${python} - \
        ${dependencyGraphs.${configuration.id}}/component-dependency-graph-v3.json \
        ${lib.escapeShellArg (builtins.toJSON (asPaths selectedBindings))} \
        ${lib.escapeShellArg (builtins.toJSON (asPaths generatedLibraryComponents))} \
        ${lib.escapeShellArg (builtins.toJSON roots)} \
        "$out" <<'PY'
      import json
      import pathlib
      import sys
      from spaghetti_extractor.components.retirement import (
          build_component_retirement_report_v1,
      )

      bindings = {
          key: pathlib.Path(value)
          for key, value in json.loads(sys.argv[2]).items()
      }
      for root in json.loads(sys.argv[3]).values():
          path = pathlib.Path(root) / "machine-binding-v3.json"
          from spaghetti_extractor.components.universal_binding import (
              read_component_machine_binding_v3,
          )
          binding = read_component_machine_binding_v3(path)
          bindings[binding.component_id] = binding
      build_component_retirement_report_v1(
          graph=pathlib.Path(sys.argv[1]),
          machine_bindings=bindings,
          root_component_ids=json.loads(sys.argv[4]),
          out=pathlib.Path(sys.argv[5]),
      )
      PY
    '';
  retirementReports = builtins.listToAttrs (map (configuration: {
    name = configuration.id;
    value = mkRetirementReport configuration;
  }) intentPayload.configurations);
  mkSourceBundle = configuration:
    let
      selected = map (selection: liftUnitsById.${selection.id})
        (builtins.filter (selection: selection.activation == "enabled")
          configuration.selections);
      copyOne = liftUnit:
        let
          source = liftUnit.source or null;
          package = if source == null then null else sourcePackages.${liftUnit.id};
        in lib.optionalString (source != null) ''
          if jq -e --arg id ${lib.escapeShellArg liftUnit.id} \
              '.selections[] | select(.id == $id) | .ownership_state == "portable_replacement"' \
              ${activationPlans.${configuration.id}}/activation-plan.json >/dev/null; then
            mkdir -p "$out/components/${liftUnit.id}"
            cp -R ${package}/sources/. "$out/components/${liftUnit.id}/"
            cp ${package}/source-package.json \
              "$out/components/${liftUnit.id}/source-package.json"
          fi
        '';
    in pkgs.runCommand "${namePrefix}-${configuration.id}-component-sources-v3"
      (common // { nativeBuildInputs = common.nativeBuildInputs ++ [ pkgs.coreutils ]; }) ''
        set -euo pipefail
        mkdir -p "$out/components"
        ${lib.concatMapStringsSep "\n" copyOne selected}
        cp ${activationPlans.${configuration.id}}/activation-plan.json "$out/activation-plan.json"
        (cd "$out"; find components -type f -print0 | sort -z | xargs -0 -r sha256sum) \
          > "$out/source-files.sha256"
      '';
  sourceBundles = builtins.listToAttrs (map (configuration: {
    name = configuration.id;
    value = mkSourceBundle configuration;
  }) intentPayload.configurations);
  mkRuntimeConfiguration = configuration:
    let
      selectedIds = map (selection: selection.id) configuration.selections;
      enabledIds = map (selection: selection.id)
        (builtins.filter (selection: selection.activation == "enabled")
          configuration.selections);
      selected = ids: values: builtins.listToAttrs (map (id: {
        name = id;
        value = values.${id};
      }) (builtins.filter (id: builtins.hasAttr id values) ids));
    in {
      activationPlan = activationPlans.${configuration.id};
      contracts = selected
        (builtins.filter (id: !(builtins.hasAttr id machineBindingReceipts)) selectedIds)
        contracts;
      portableInterfaces = selected selectedIds developmentContracts;
      semanticContracts = selected enabledIds semanticContracts;
      implementations = selected enabledIds sourcePackages;
      qualifications = selected enabledIds qualifications;
      adapterPlans = selected enabledIds adapterPlans;
      activationReceipts =
        if builtins.hasAttr configuration.id configurationActivationReceipts
        then configurationActivationReceipts.${configuration.id}
        else { };
      machineBindings = selected enabledIds machineBindingReceipts;
      boundaryPlans = selected enabledIds relationCheckGates;
      libraryComponents = generatedLibraryComponents;
      universalContracts = selected selectedIds universalContracts;
      universalMachineBindings = selected selectedIds universalMachineBindings;
      universalImplementations = selectedUniversalImplementations configuration;
      dependencyGraph = dependencyGraphs.${configuration.id};
      hybridGate = hybridGates.${configuration.id};
      portableGate = portableGates.${configuration.id};
      retirementReport = retirementReports.${configuration.id};
      inherit enabledIds;
    };
  runtimeConfigurations = builtins.listToAttrs (map (configuration: {
    name = configuration.id;
    value = mkRuntimeConfiguration configuration;
  }) intentPayload.configurations);
  mkRuntime = {
    configurationId,
    runtimeCompiler ? compiler,
  }:
    assert lib.assertMsg (interpreterPackage != null)
      "component runtime construction requires interpreterPackage";
    assert lib.assertMsg (builtins.hasAttr configurationId runtimeConfigurations)
      "unknown component configuration: ${configurationId}";
    import ./component-runtime-package.nix {
      inherit pkgs pythonEnv pythonSource machineIr interpreterPackage;
      componentConfiguration = runtimeConfigurations.${configurationId};
      namePrefix = "${namePrefix}-${configurationId}";
      compiler = runtimeCompiler;
    };
  runtimeFor = configurationId: mkRuntime { inherit configurationId; };
  runtimePackages =
    if interpreterPackage == null then { }
    else lib.mapAttrs (configurationId: _configuration:
      runtimeFor configurationId) runtimeConfigurations;
  mkLiftUnitStatus = liftUnit:
    let
      source = if builtins.hasAttr liftUnit.id sourcePackages
        then toString sourcePackages.${liftUnit.id} else "-";
      evidence = if builtins.hasAttr liftUnit.id evidences
        then toString evidences.${liftUnit.id} else "-";
      adapter = if builtins.hasAttr liftUnit.id adapterPlans
        then toString adapterPlans.${liftUnit.id} else "-";
      qualification = if builtins.hasAttr liftUnit.id qualifications
        then toString qualifications.${liftUnit.id} else "-";
    in pkgs.runCommand "${namePrefix}-${liftUnit.id}-component-work-status-v1" common ''
      set -euo pipefail
      ${environment statusSource}
      mkdir -p "$out"
      ${python} - \
        ${contracts.${liftUnit.id}} \
        ${lib.escapeShellArg source} \
        ${lib.escapeShellArg adapter} \
        ${lib.escapeShellArg evidence} \
        ${lib.escapeShellArg qualification} \
        "$out/status.json" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.components.status import build_lift_unit_status

      optional = lambda value: None if value == "-" else pathlib.Path(value)
      build_lift_unit_status(
          contract=pathlib.Path(sys.argv[1]),
          source=optional(sys.argv[2]),
          adapter_plan=optional(sys.argv[3]),
          evidence=optional(sys.argv[4]),
          qualification=optional(sys.argv[5]),
          out=pathlib.Path(sys.argv[6]),
      )
      PY
      jq -e --arg id ${lib.escapeShellArg liftUnit.id} '
        .format == "spaghetti-extractor-component-work-status-v1" and
        .lift_unit_id == $id and
        (.status == "qualified" or .status == "incomplete" or .status == "violated") and
        (.policy.authorizes_runtime | not) and
        (.policy.executes_original_binary | not)
      ' "$out/status.json" >/dev/null
    '';
  statusReports = builtins.listToAttrs (map (liftUnit: {
    name = liftUnit.id;
    value = mkLiftUnitStatus liftUnit;
  }) liftUnits);
  mkWorkPackage = liftUnit:
    let
      canonicalStatus = if builtins.hasAttr liftUnit.id activationStatusReports
        then activationStatusReports.${liftUnit.id}
        else statusReports.${liftUnit.id};
      canonicalContract = if builtins.hasAttr liftUnit.id developmentContracts
        then developmentContracts.${liftUnit.id}
        else contracts.${liftUnit.id};
      optionalLink = values: name:
        lib.optionalString (builtins.hasAttr liftUnit.id values) ''
          ln -s ${values.${liftUnit.id}} "$out/${name}"
        '';
      manifest = pkgs.writeText "${namePrefix}-${liftUnit.id}-work-package.json"
        (builtins.toJSON {
          format = "spaghetti-extractor-component-work-package-v1";
          kind = liftUnit.kind;
          lift_unit_id = liftUnit.id;
          label = liftUnit.label;
          contents = {
            resolution = "resolution";
            external_sites = if builtins.hasAttr liftUnit.id externalSiteSlices
              then "external-sites" else null;
            contract = "contract";
            status = "status";
            source = if builtins.hasAttr liftUnit.id sourcePackages then "source" else null;
            adapter_plan = if builtins.hasAttr liftUnit.id adapterPlans then "adapter-plan" else null;
            evidence = if builtins.hasAttr liftUnit.id evidences then "evidence" else null;
            qualification = if builtins.hasAttr liftUnit.id qualifications then "qualification" else null;
            compile_receipt = if builtins.hasAttr liftUnit.id compileReceipts then "compile-receipt" else null;
            machine_binding = if builtins.hasAttr liftUnit.id machineBindingReceipts then "machine-binding" else null;
            semantic_contract = if builtins.hasAttr liftUnit.id semanticContracts then "semantic-contract" else null;
            induction_package = if builtins.hasAttr liftUnit.id inductionPackages then "induction-package" else null;
            induction_draft_certificate = if builtins.hasAttr liftUnit.id inductionDraftCertificates then "induction-draft-certificate" else null;
            induction_source_receipt = if builtins.hasAttr liftUnit.id inductionSourceReceipts then "induction-source-receipt" else null;
            refinement_receipt = if builtins.hasAttr liftUnit.id refinementReceipts then "refinement-receipt" else null;
            service_graph = if builtins.hasAttr liftUnit.id serviceGraphs then "service-graph" else null;
            ownership = if builtins.hasAttr liftUnit.id ownershipReceipts then "ownership" else null;
            activation_receipt = if builtins.hasAttr liftUnit.id activationReceipts then "activation-receipt" else null;
          };
          policy = {
            authorizes_runtime = false;
            executes_original_binary = false;
            independently_buildable = true;
          };
        });
    in pkgs.runCommand "${namePrefix}-${liftUnit.id}-component-work-package-v1"
      (common // { nativeBuildInputs = common.nativeBuildInputs ++ [ pkgs.coreutils ]; }) ''
        set -euo pipefail
        mkdir -p "$out"
        ln -s ${resolution} "$out/resolution"
        ${optionalLink externalSiteSlices "external-sites"}
        ln -s ${canonicalContract} "$out/contract"
        ln -s ${canonicalStatus} "$out/status"
        ${optionalLink sourcePackages "source"}
        ${optionalLink adapterPlans "adapter-plan"}
        ${optionalLink evidences "evidence"}
        ${optionalLink qualifications "qualification"}
        ${optionalLink compileReceipts "compile-receipt"}
        ${optionalLink machineBindingReceipts "machine-binding"}
        ${optionalLink semanticContracts "semantic-contract"}
        ${optionalLink inductionPackages "induction-package"}
        ${optionalLink inductionDraftCertificates "induction-draft-certificate"}
        ${optionalLink inductionSourceReceipts "induction-source-receipt"}
        ${optionalLink refinementReceipts "refinement-receipt"}
        ${optionalLink serviceGraphs "service-graph"}
        ${optionalLink ownershipReceipts "ownership"}
        ${optionalLink activationReceipts "activation-receipt"}
        cp ${manifest} "$out/work-package.json"
      '';
  workPackages = builtins.listToAttrs (map (liftUnit: {
    name = liftUnit.id;
    value = mkWorkPackage liftUnit;
  }) liftUnits);
  checkGates = lib.mapAttrs (liftUnitId: statusReport:
    pkgs.runCommand "${namePrefix}-${liftUnitId}-component-check-v1" common ''
      set -euo pipefail
      jq -e '.status == "qualified"' ${statusReport}/status.json >/dev/null || {
        jq '{status, lift_unit_id, next_action, blockers}' ${statusReport}/status.json >&2
        exit 1
      }
      mkdir -p "$out"
      cp ${statusReport}/status.json "$out/status.json"
    '') statusReports;
  mkConfigurationStatus = configuration:
    pkgs.runCommand "${namePrefix}-${configuration.id}-configuration-status-v1" common ''
      set -euo pipefail
      ${environment statusSource}
      mkdir -p "$out"
      ${python} - \
        ${activationPlans.${configuration.id}} \
        "$out/status.json" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.components.status import build_configuration_status

      build_configuration_status(
          activation_plan=pathlib.Path(sys.argv[1]),
          out=pathlib.Path(sys.argv[2]),
      )
      PY
      jq -e --arg id ${lib.escapeShellArg configuration.id} '
        .format == "spaghetti-extractor-component-configuration-status-v1" and
        .configuration_id == $id and
        (.status == "ready" or .status == "incomplete" or .status == "violated")
      ' "$out/status.json" >/dev/null
    '';
  configurationStatusReports = builtins.listToAttrs (map (configuration: {
    name = configuration.id;
    value = mkConfigurationStatus configuration;
  }) intentPayload.configurations);
  configurationCheckGates = lib.mapAttrs (configurationId: statusReport:
    pkgs.runCommand "${namePrefix}-${configurationId}-configuration-check-v1" common ''
      set -euo pipefail
      jq -e '.status == "ready"' ${statusReport}/status.json >/dev/null || {
        jq '{status, configuration_id, next_action, blockers}' ${statusReport}/status.json >&2
        exit 1
      }
      mkdir -p "$out"
      cp ${statusReport}/status.json "$out/status.json"
    '') configurationStatusReports;
  liftUnitIndex = builtins.listToAttrs (map (liftUnit: {
    name = liftUnit.id;
    value = {
      kind = liftUnit.kind;
      label = liftUnit.label;
      members = liftUnit.members or [ ];
      hasSource = builtins.hasAttr liftUnit.id sourcePackages;
      hasEvidence = builtins.hasAttr liftUnit.id evidences;
      hasAdapterPlan = builtins.hasAttr liftUnit.id adapterPlans;
      hasQualification = builtins.hasAttr liftUnit.id qualifications;
      hasPortableV2 = builtins.hasAttr liftUnit.id compileReceipts;
      hasSourceProfile = builtins.hasAttr liftUnit.id sourceProfiles;
      hasMachineBinding = builtins.hasAttr liftUnit.id machineBindingReceipts;
      hasSemanticContract = builtins.hasAttr liftUnit.id semanticContracts;
      hasInduction = builtins.hasAttr liftUnit.id inductionPackages;
      hasSemanticRefinement = builtins.hasAttr liftUnit.id refinementReceipts;
      hasActivationReceipt = builtins.hasAttr liftUnit.id activationReceipts;
    };
  }) liftUnits);
  configurationIndex = builtins.listToAttrs (map (configuration: {
    name = configuration.id;
    value = {
      kind = "configuration";
      label = configuration.label;
      selections = configuration.selections;
      hasRuntime = builtins.hasAttr configuration.id runtimePackages;
    };
  }) intentPayload.configurations);
  bundle = pkgs.linkFarm "${namePrefix}-component-contracts-v3" (
    [ { name = "resolution"; path = resolution; } ]
    ++ lib.mapAttrsToList (name: path: { name = "external-sites-${name}"; inherit path; }) externalSiteSlices
    ++ lib.mapAttrsToList (name: path: { inherit name path; }) contracts
    ++ lib.mapAttrsToList (name: path: { name = "source-${name}"; inherit path; }) sourcePackages
    ++ lib.mapAttrsToList (name: path: { name = "adapter-${name}"; inherit path; }) adapterPlans
    ++ lib.mapAttrsToList (name: path: { name = "evidence-${name}"; inherit path; }) evidences
    ++ lib.mapAttrsToList (name: path: { name = "qualification-${name}"; inherit path; }) qualifications
    ++ lib.mapAttrsToList (name: path: { name = "compile-${name}"; inherit path; }) compileReceipts
    ++ lib.mapAttrsToList (name: path: { name = "source-profile-${name}"; inherit path; }) sourceProfiles
    ++ lib.mapAttrsToList (name: path: { name = "machine-binding-${name}"; inherit path; }) machineBindingReceipts
    ++ lib.mapAttrsToList (name: path: { name = "semantic-contract-${name}"; inherit path; }) semanticContracts
    ++ lib.mapAttrsToList (name: path: { name = "induction-${name}"; inherit path; }) inductionPackages
    ++ lib.mapAttrsToList (name: path: { name = "induction-draft-${name}"; inherit path; }) inductionDraftCertificates
    ++ lib.mapAttrsToList (name: path: { name = "induction-source-${name}"; inherit path; }) inductionSourceReceipts
    ++ lib.mapAttrsToList (name: path: { name = "semantic-refinement-${name}"; inherit path; }) refinementReceipts
    ++ lib.mapAttrsToList (name: path: { name = "service-graph-${name}"; inherit path; }) serviceGraphs
    ++ lib.mapAttrsToList (name: path: { name = "ownership-${name}"; inherit path; }) ownershipReceipts
    ++ lib.mapAttrsToList (name: path: { name = "activation-${name}"; inherit path; }) activationReceipts
    ++ lib.mapAttrsToList (name: path: { name = "configuration-${name}"; inherit path; }) activationPlans
  );
in
{
  inherit proposalInput resolution resolutionSlices externalSiteSlices contracts developmentDeclarations developmentContracts developmentPackages sourcePackages adapterPlans evidences qualifications compileReceipts sourceProfiles machineBindingReceipts semanticContracts universalContracts relationArtifacts relationCheckGates universalMachineBindings machineImplementations portableImplementationsByConfiguration dependencyGraphs hybridGates portableGates hybridCheckGates portableCheckGates retirementReports inductionDeclarations inductionPackages inductionDraftCertificates inductionSourceReceipts inductionRefinementArtifacts finiteRefinementReceipts refinementReceipts serviceGraphs configurationServiceGraphs ownershipReceipts activationReceipts configurationActivationReceipts activationCheckGates activationStatusReports
    activationPlans sourceBundles runtimeConfigurations mkRuntime runtimeFor
    runtimePackages statusReports workPackages checkGates
    configurationStatusReports configurationCheckGates liftUnitIndex
    configurationIndex bundle assetInventory;
  contractIds = map (row: row.id) liftUnits;
  format = "spaghetti-extractor-component-dag-v3";
}
