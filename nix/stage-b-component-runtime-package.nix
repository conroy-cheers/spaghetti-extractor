{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  interpreterPackage,
  componentConfiguration,
  namePrefix,
  compiler ? pkgs.pkgsCross.mingw32.stdenv.cc,
}:

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  phaseSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.components.runtime" ];
    name = "${namePrefix}-component-runtime-v3-python-closure";
  };
  paths = values: lib.mapAttrs (_name: value: toString value) values;
in
pkgs.runCommand "${namePrefix}-component-runtime-package-v3" {
  nativeBuildInputs = [ pythonEnv pkgs.jq compiler pkgs.findutils ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export LC_ALL=C.UTF-8
  export SOURCE_DATE_EPOCH=1
  export PYTHONPATH=${phaseSource}/src
  jq -e '
    .format == "spaghetti-extractor-component-activation-plan-v3" and
    .status == "checked" and .counts.blocked == 0
  ' ${componentConfiguration.activationPlan}/activation-plan.json >/dev/null
  ${python} - \
    ${machineIr} \
    ${componentConfiguration.activationPlan}/activation-plan.json \
    ${lib.escapeShellArg (builtins.toJSON (paths componentConfiguration.contracts))} \
    ${lib.escapeShellArg (builtins.toJSON (paths componentConfiguration.implementations))} \
    ${lib.escapeShellArg (builtins.toJSON (paths componentConfiguration.qualifications))} \
    ${interpreterPackage} \
    "$out" <<'PY'
  import json
  import pathlib
  import sys

  from spaghetti_extractor.components.runtime import (
      build_component_runtime_package,
  )

  build_component_runtime_package(
      machine_ir=pathlib.Path(sys.argv[1]),
      activation_plan=pathlib.Path(sys.argv[2]),
      contracts={key: pathlib.Path(value) for key, value in json.loads(sys.argv[3]).items()},
      implementations={key: pathlib.Path(value) for key, value in json.loads(sys.argv[4]).items()},
      qualifications={key: pathlib.Path(value) for key, value in json.loads(sys.argv[5]).items()},
      interpreter_package=pathlib.Path(sys.argv[6]),
      out_dir=pathlib.Path(sys.argv[7]),
  )
  PY
  jq -e '
    .format == "spaghetti-extractor-component-runtime-package-v3" and
    .status == "ready" and
    (.executes_original_binary | not) and
    .policy.runtime_package_is_sole_candidate_authority and
    .policy.subsumed_members_may_not_fallback
  ' "$out/component-runtime-package.json" >/dev/null
  jq -e '
    .format == "spaghetti-extractor-component-runtime-completion-v3" and
    .status == "complete" and
    .ownership_complete and .ownership_exclusive and
    (.executes_original_binary | not)
  ' "$out/component-runtime-completion.json" >/dev/null
  jq -e '
    .format == "spaghetti-extractor-portable-selection-v3" and
    .status == "checked" and (.executes_original_binary | not)
  ' "$out/portable-component-selection.json" >/dev/null

  for adapter in "$out"/components/*/generated-adapter.c; do
    test -e "$adapter" || continue
    component_dir="$(dirname "$adapter")"
    mapfile -d $'\0' sources < <(
      find "$component_dir" -type f -name '*.c' ! -name 'generated-adapter.c' \
        -print0 | sort -z
    )
    ${compiler}/bin/i686-w64-mingw32-gcc \
      -std=c11 -Wall -Werror -fsyntax-only \
      -I${interpreterPackage} -I"$component_dir" \
      "$adapter" "''${sources[@]}"
  done
''
