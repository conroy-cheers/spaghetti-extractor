# spaghetti-extractor-python-role: authority
{
  pkgs,
  pythonEnv,
  name,
  targetId,
  machineIr,
  releaseHypotheses,
  islandId,
  adoptionIntent,
  behaviorPack,
  catalogSearchIndex,
  abiMatchResolution ? null,
  canonicalExternalSites,
  targetCertificates,
}:

let
  lib = pkgs.lib;
  phaseSource = import ./python-module-closure.nix {
    phaseRole = "authority";
    inherit pkgs;
    modules = [ "spaghetti_extractor.libraries.v4_activation" ];
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
    ${lib.escapeShellArg targetId} \
    ${lib.escapeShellArg machineIr} \
    ${lib.escapeShellArg releaseHypotheses} \
    ${lib.escapeShellArg islandId} \
    ${lib.escapeShellArg adoptionIntent} \
    ${lib.escapeShellArg behaviorPack} \
    ${lib.escapeShellArg catalogSearchIndex} \
    ${lib.escapeShellArg (if abiMatchResolution == null then "" else abiMatchResolution)} \
    ${lib.escapeShellArg canonicalExternalSites} \
    ${lib.escapeShellArg targetCertificates} \
    "$out/checked-library-island.json" <<'PY'
  import pathlib
  import sys

  from spaghetti_extractor.libraries.v4_activation import check_library_island_v1

  check_library_island_v1(
      target_id=sys.argv[1],
      machine_ir=pathlib.Path(sys.argv[2]),
      release_hypotheses=pathlib.Path(sys.argv[3]),
      island_id=sys.argv[4],
      adoption_intent=pathlib.Path(sys.argv[5]),
      implementation=pathlib.Path(sys.argv[6]),
      catalog_search_index=pathlib.Path(sys.argv[7]),
      abi_match_resolution=(None if not sys.argv[8] else pathlib.Path(sys.argv[8])),
      canonical_external_sites=pathlib.Path(sys.argv[9]),
      target_certificates=pathlib.Path(sys.argv[10]),
      out=pathlib.Path(sys.argv[11]),
  )
  PY
  jq -e '
    .format == "spaghetti-extractor-checked-library-island-v1" and
    (.status == "complete" or .status == "incomplete" or .status == "violated")
  ' "$out/checked-library-island.json" >/dev/null
''
