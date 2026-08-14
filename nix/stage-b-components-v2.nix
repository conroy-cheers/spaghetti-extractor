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
  evidenceById ? { },
}:

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  intentPayload = builtins.fromJSON (builtins.readFile intent);
  liftUnits = intentPayload.components ++ (intentPayload.groups or [ ]);
  mkPhaseSource = phase: modules: import ./python-module-closure.nix {
    inherit pkgs modules;
    source = pythonSource;
    name = "${namePrefix}-components-v2-${phase}-python-closure";
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
  qualificationSource = mkPhaseSource "qualification" [
    "spaghetti_extractor.components.qualification"
  ];
  configurationSource = mkPhaseSource "configuration" [
    "spaghetti_extractor.components.configuration"
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
    from spaghetti_extractor.components.resolution import resolve_component_catalog_v2

    resolve_component_catalog_v2(
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
      from spaghetti_extractor.components.contracts import build_lift_unit_contract_v2

      review = None if sys.argv[5] == "-" else pathlib.Path(sys.argv[5])
      build_lift_unit_contract_v2(
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
      from spaghetti_extractor.components.source import build_component_source_package_v2

      build_component_source_package_v2(
          lift_unit_id=sys.argv[1],
          files={key: pathlib.Path(value) for key, value in json.loads(sys.argv[2]).items()},
          shared_inputs={key: pathlib.Path(value) for key, value in json.loads(sys.argv[3]).items()},
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
  mkQualification = liftUnit:
    if !builtins.hasAttr liftUnit.id sourcePackages then
      throw "${liftUnit.id} has qualification evidence but no portable source"
    else
    pkgs.runCommand "${namePrefix}-${liftUnit.id}-component-qualification-v2" common ''
      set -euo pipefail
      ${environment qualificationSource}
      mkdir -p "$out"
      ${python} - \
        ${contracts.${liftUnit.id}}/contract.json \
        ${sourcePackages.${liftUnit.id}}/source-package.json \
        ${lib.escapeShellArg (toString evidenceById.${liftUnit.id})} \
        "$out/qualification.json" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.components.qualification import qualify_lift_unit_v2

      qualify_lift_unit_v2(
          contract=pathlib.Path(sys.argv[1]),
          implementation=pathlib.Path(sys.argv[2]),
          evidence=pathlib.Path(sys.argv[3]),
          out=pathlib.Path(sys.argv[4]),
      )
      PY
      jq -e '
        .format == "spaghetti-extractor-component-qualification-v2" and
        (.status == "qualified" or .status == "incomplete" or .status == "violated") and
        (.assurance.original_binary_executed | not)
      ' "$out/qualification.json" >/dev/null
    '';
  qualifications = builtins.listToAttrs (
    map (liftUnit: {
      name = liftUnit.id;
      value = mkQualification liftUnit;
    }) (builtins.filter (liftUnit: builtins.hasAttr liftUnit.id evidenceById) liftUnits)
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
    in pkgs.runCommand "${namePrefix}-${configuration.id}-component-activation-plan-v2" common ''
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
      from spaghetti_extractor.components.configuration import compose_component_configuration_v2

      compose_component_configuration_v2(
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
        .format == "spaghetti-extractor-component-activation-plan-v2" and
        (.status == "checked" or .status == "incomplete" or .status == "violated") and
        .ownership.complete and .ownership.exclusive and
        (.hybrid.structurally_executable | not) and
        (.hybrid.release_ready | not) and
        .policy.one_implementation_per_structural_unit and
        .counts.structural_units ==
          (.counts.portable_replacements + .counts.machine_ir_fallback)
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
              '.selections[] | select(.id == $id) | .effective_implementation == "portable_replacement"' \
              ${activationPlans.${configuration.id}}/activation-plan.json >/dev/null; then
            mkdir -p "$out/components/${liftUnit.id}"
            cp -R ${package}/sources/. "$out/components/${liftUnit.id}/"
            cp ${package}/source-package.json \
              "$out/components/${liftUnit.id}/source-package.json"
          fi
        '';
    in pkgs.runCommand "${namePrefix}-${configuration.id}-component-sources-v2"
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
  bundle = pkgs.linkFarm "${namePrefix}-component-contracts-v2" (
    [ { name = "resolution"; path = resolution; } ]
    ++ lib.mapAttrsToList (name: path: { inherit name path; }) contracts
    ++ lib.mapAttrsToList (name: path: { name = "source-${name}"; inherit path; }) sourcePackages
    ++ lib.mapAttrsToList (name: path: { name = "qualification-${name}"; inherit path; }) qualifications
    ++ lib.mapAttrsToList (name: path: { name = "configuration-${name}"; inherit path; }) activationPlans
  );
in
{
  inherit resolution contracts sourcePackages qualifications activationPlans sourceBundles bundle;
  contractIds = map (row: row.id) liftUnits;
  format = "spaghetti-extractor-component-dag-v2";
}
