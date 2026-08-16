# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  name,
  machineIr,
  releaseHypotheses,
  checkedIsland,
  behaviorPack,
  catalogSearchIndex,
  canonicalExternalSites,
}:

let
  lib = pkgs.lib;
  phaseSource = import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [ "spaghetti_extractor.libraries.v4_component" ];
    name = "${name}-python-closure";
  };
in
pkgs.runCommand name {
  nativeBuildInputs = [ pythonEnv pkgs.jq ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONDONTWRITEBYTECODE=1
  export LC_ALL=C.UTF-8
  export SOURCE_DATE_EPOCH=1
  export PYTHONPATH=${phaseSource}/src
  mkdir -p "$out"
  ${pythonEnv}/bin/python3 - \
    ${lib.escapeShellArg machineIr} \
    ${lib.escapeShellArg releaseHypotheses} \
    ${lib.escapeShellArg checkedIsland} \
    ${lib.escapeShellArg behaviorPack} \
    ${lib.escapeShellArg catalogSearchIndex} \
    ${lib.escapeShellArg canonicalExternalSites} \
    "$out" <<'PY'
  import pathlib
  import sys

  from spaghetti_extractor.libraries.v4_component import (
      build_checked_library_component_v1,
  )

  build_checked_library_component_v1(
      machine_ir=pathlib.Path(sys.argv[1]),
      release_hypotheses=pathlib.Path(sys.argv[2]),
      checked_island=pathlib.Path(sys.argv[3]),
      behavior_pack=pathlib.Path(sys.argv[4]),
      catalog_search_index=pathlib.Path(sys.argv[5]),
      canonical_external_sites=pathlib.Path(sys.argv[6]),
      out_dir=pathlib.Path(sys.argv[7]),
  )
  PY
  jq -e '
    .format == "spaghetti-extractor-generated-library-component-v1" and
    (.status == "complete" or .status == "incomplete") and
    (.policy.original_binary_executed | not) and
    (.policy.handwritten_behavior_tests_used | not)
  ' "$out/library-component.json" >/dev/null
  jq -e '
    .format == "spaghetti-extractor-component-contract-v3" and
    .status == "checked"
  ' "$out/component-contract-v3.json" >/dev/null
  jq -e '
    .format == "spaghetti-extractor-component-machine-binding-v3" and
    .status == "checked"
  ' "$out/machine-binding-v3.json" >/dev/null
  jq -e '
    .format == "spaghetti-extractor-component-implementation-v3" and
    .status == "checked" and .kind == "portable_c"
  ' "$out/implementation-v3.json" >/dev/null
''
