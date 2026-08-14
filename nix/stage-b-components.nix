# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  reconstructionPlan,
  componentProposals,
  intent,
  reviewRoot ? null,
  sourceRoot ? null,
  namePrefix,
  interpreterPackage ? null,
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
  assetInventory = [ {
    path = toString intent;
    role = "component_intent";
    owner = "component-workflow";
  } ] ++ sourceAssets ++ reviewAssets;
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
  sourcePackageSource = mkPhaseSource "source-package" [
    "spaghetti_extractor.components.source"
  ];
  evidenceSource = mkPhaseSource "evidence" [
    "spaghetti_extractor.components.evidence"
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
      ${componentProposals}/component-proposals.json \
      ${intent} \
      "$out/component-resolution.json" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.components.resolution import resolve_component_catalog

    resolve_component_catalog(
        proposals=pathlib.Path(sys.argv[1]),
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
        ${resolution}/component-resolution.json \
        ${lib.escapeShellArg liftUnit.id} \
        ${lib.escapeShellArg (toString reviewPath)} \
        "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.components.contracts import build_lift_unit_contract

      review = None if sys.argv[5] == "-" else pathlib.Path(sys.argv[5])
      build_lift_unit_contract(
          machine_ir=pathlib.Path(sys.argv[1]),
          reconstruction_plan=pathlib.Path(sys.argv[2]),
          resolution=pathlib.Path(sys.argv[3]),
          lift_unit_id=sys.argv[4],
          review=review,
          out_dir=pathlib.Path(sys.argv[6]),
      )
      PY
      jq -e '
        .format == "spaghetti-extractor-component-contract-package-v2" and
        (.status == "checked" or .status == "incomplete") and
        (.authority.activation_authorized | not) and
        .authority.activation_requires_separate_behavioral_evidence
      ' "$out/contract.json" >/dev/null
    '';
  contracts = builtins.listToAttrs (map (liftUnit: {
    name = liftUnit.id;
    value = mkContract liftUnit;
  }) liftUnits);
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
        "$out" <<'PY'
      import json
      import pathlib
      import sys
      from spaghetti_extractor.components.source import build_component_source_package

      build_component_source_package(
          lift_unit_id=sys.argv[1],
          files={key: pathlib.Path(value) for key, value in json.loads(sys.argv[2]).items()},
          shared_inputs={key: pathlib.Path(value) for key, value in json.loads(sys.argv[3]).items()},
          entry=json.loads(${builtins.toJSON (builtins.toJSON source.entry)}),
          out_dir=pathlib.Path(sys.argv[4]),
      )
      PY
      jq -e --arg id ${lib.escapeShellArg liftUnit.id} '
        .format == "spaghetti-extractor-component-source-package-v2" and
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
  mkEvidence = liftUnit:
    pkgs.runCommand "${namePrefix}-${liftUnit.id}-component-evidence-v3"
      (common // { nativeBuildInputs = common.nativeBuildInputs ++ [ pkgs.stdenv.cc ]; }) ''
      set -euo pipefail
      ${environment evidenceSource}
      mkdir -p "$out"
      ${python} - \
        ${contracts.${liftUnit.id}} \
        ${sourcePackages.${liftUnit.id}} \
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
          machine_ir=pathlib.Path(sys.argv[3]),
          verification=json.loads(sys.argv[4]),
          compiler=pathlib.Path(sys.argv[5]),
          out=pathlib.Path(sys.argv[6]),
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
      (liftUnit.verification or null) != null &&
      builtins.elem (liftUnit.verification.producer or null) [
        "exhaustive-finite-domain-v1"
        "candidate-only-functional-suite-v1"
      ]
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
          machine_ir=pathlib.Path(sys.argv[4]),
          verification=json.loads(sys.argv[5]),
          out=pathlib.Path(sys.argv[6]),
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
  mkActivationPlan = configuration:
    let
      selectedIds = map (selection: selection.id) configuration.selections;
      selectedContractPaths = builtins.listToAttrs (map (id: {
        name = id;
        value = toString contracts.${id};
      }) selectedIds);
      selectedImplementationPaths = builtins.listToAttrs (map (id: {
        name = id;
        value = toString sourcePackages.${id};
      }) (builtins.filter (id: builtins.hasAttr id sourcePackages) selectedIds));
      selectedQualificationPaths = builtins.listToAttrs (map (id: {
        name = id;
        value = toString qualifications.${id};
      }) (builtins.filter (id: builtins.hasAttr id qualifications) selectedIds));
    in pkgs.runCommand "${namePrefix}-${configuration.id}-component-activation-plan-v3" common ''
      set -euo pipefail
      ${environment configurationSource}
      mkdir -p "$out"
      ${python} - \
        ${machineIr} \
        ${resolution}/component-resolution.json \
        ${lib.escapeShellArg configuration.id} \
        ${lib.escapeShellArg (builtins.toJSON selectedContractPaths)} \
        ${lib.escapeShellArg (builtins.toJSON selectedImplementationPaths)} \
        ${lib.escapeShellArg (builtins.toJSON selectedQualificationPaths)} \
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
          implementations={key: pathlib.Path(value) for key, value in json.loads(sys.argv[5]).items()},
          qualifications={key: pathlib.Path(value) for key, value in json.loads(sys.argv[6]).items()},
          out=pathlib.Path(sys.argv[7]),
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
  liftUnitsById = builtins.listToAttrs (map (row: { name = row.id; value = row; }) liftUnits);
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
      contracts = selected selectedIds contracts;
      implementations = selected enabledIds sourcePackages;
      qualifications = selected enabledIds qualifications;
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
    import ./stage-b-component-runtime-package.nix {
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
      qualification = if builtins.hasAttr liftUnit.id qualifications
        then toString qualifications.${liftUnit.id} else "-";
    in pkgs.runCommand "${namePrefix}-${liftUnit.id}-component-work-status-v1" common ''
      set -euo pipefail
      ${environment statusSource}
      mkdir -p "$out"
      ${python} - \
        ${contracts.${liftUnit.id}} \
        ${lib.escapeShellArg source} \
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
          evidence=optional(sys.argv[3]),
          qualification=optional(sys.argv[4]),
          out=pathlib.Path(sys.argv[5]),
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
            contract = "contract";
            status = "status";
            source = if builtins.hasAttr liftUnit.id sourcePackages then "source" else null;
            evidence = if builtins.hasAttr liftUnit.id evidences then "evidence" else null;
            qualification = if builtins.hasAttr liftUnit.id qualifications then "qualification" else null;
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
        ln -s ${contracts.${liftUnit.id}} "$out/contract"
        ln -s ${statusReports.${liftUnit.id}} "$out/status"
        ${optionalLink sourcePackages "source"}
        ${optionalLink evidences "evidence"}
        ${optionalLink qualifications "qualification"}
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
      hasQualification = builtins.hasAttr liftUnit.id qualifications;
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
    ++ lib.mapAttrsToList (name: path: { inherit name path; }) contracts
    ++ lib.mapAttrsToList (name: path: { name = "source-${name}"; inherit path; }) sourcePackages
    ++ lib.mapAttrsToList (name: path: { name = "evidence-${name}"; inherit path; }) evidences
    ++ lib.mapAttrsToList (name: path: { name = "qualification-${name}"; inherit path; }) qualifications
    ++ lib.mapAttrsToList (name: path: { name = "configuration-${name}"; inherit path; }) activationPlans
  );
in
{
  inherit resolution contracts sourcePackages evidences qualifications
    activationPlans sourceBundles runtimeConfigurations mkRuntime runtimeFor
    runtimePackages statusReports workPackages checkGates
    configurationStatusReports configurationCheckGates liftUnitIndex
    configurationIndex bundle assetInventory;
  contractIds = map (row: row.id) liftUnits;
  format = "spaghetti-extractor-component-dag-v3";
}
