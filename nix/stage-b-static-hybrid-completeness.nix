{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  original,
  loadImageContract,
  behavioralRoots,
  machineImportProfiles,
  externalInterfaceProfiles ? [ ],
  namePrefix,
}:

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  checkerSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.stage_b_hybrid_completeness" ];
    name = "${namePrefix}-static-hybrid-completeness-python-closure";
  };
  profileArgs = lib.concatMapStringsSep " "
    (profile: lib.escapeShellArg (toString profile)) machineImportProfiles;
  interfaceArgs = lib.concatMapStringsSep " "
    (profile: lib.escapeShellArg (toString profile)) externalInterfaceProfiles;
  report = pkgs.runCommand "${namePrefix}-static-hybrid-completeness-v1" {
    nativeBuildInputs = [ pythonEnv pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  } ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export PYTHONPATH=${checkerSource}/src
    mkdir -p "$out"
    ${python} - \
      ${machineIr}/machine-ir.jsonl \
      ${machineIr}/machine-ir-manifest.json \
      ${original} \
      ${loadImageContract} \
      ${behavioralRoots} \
      "$out/static-hybrid-completeness.json" \
      ${toString (builtins.length machineImportProfiles)} \
      ${profileArgs} \
      ${interfaceArgs} <<'PY'
    import pathlib
    import sys

    from spaghetti_extractor.stage_b_hybrid_completeness import (
        write_static_hybrid_completeness_report,
    )

    (
        machine_ir,
        manifest,
        original,
        load_image,
        behavioral_roots,
        output,
        profile_count,
        *profiles,
    ) = sys.argv[1:]
    split = int(profile_count)
    write_static_hybrid_completeness_report(
        machine_ir=pathlib.Path(machine_ir),
        machine_ir_manifest=pathlib.Path(manifest),
        original_pe=pathlib.Path(original),
        load_image_contract=pathlib.Path(load_image),
        behavioral_roots=pathlib.Path(behavioral_roots),
        machine_import_profiles=tuple(
            pathlib.Path(value) for value in profiles[:split]
        ),
        external_interface_profiles=tuple(
            pathlib.Path(value) for value in profiles[split:]
        ),
        out=pathlib.Path(output),
    )
    PY
    jq -e '
      .format == "stage-b-static-hybrid-completeness-v1" and
      (.status == "complete" or .status == "incomplete" or .status == "violated") and
      .counts.units > 0 and .counts.reachable_units > 0 and
      .counts.blockers == (.blockers | length) and
      (.policy.potential_transfers_may_be_deferred | not) and
      (.policy.original_binary_executed | not) and
      (.authority | contains("legacy diagnostic and proposal inventory only"))
    ' "$out/static-hybrid-completeness.json" >/dev/null
  '';
in
{
  inherit report;
}
