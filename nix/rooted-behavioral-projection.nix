# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  namePrefix,
  rootClosure,
  semanticIndex,
}:

let
  pythonClosure = import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [
      "spaghetti_extractor.candidate.authority.rooted_projection"
    ];
    name = "${namePrefix}-rooted-behavioral-projection-python-closure";
  };
in
pkgs.runCommand "${namePrefix}-rooted-behavioral-projection-v1" {
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
  export SPAGHETTI_ORIGINAL_EXECUTION_FORBIDDEN=1
  export PYTHONPATH=${pythonClosure}/src
  mkdir -p "$out"
  ${pythonEnv}/bin/python3 - \
    ${rootClosure} \
    ${semanticIndex} \
    "$out/rooted-behavioral-projection-v1.json" <<'PY'
  import pathlib
  import sys

  from spaghetti_extractor.candidate.authority.rooted_projection import (
      derive_rooted_behavioral_projection_v1,
      write_rooted_behavioral_projection_v1,
  )

  root_closure, semantic_index, output = map(pathlib.Path, sys.argv[1:])
  projection = derive_rooted_behavioral_projection_v1(
      root_closure=root_closure,
      semantic_index=semantic_index,
  )
  write_rooted_behavioral_projection_v1(output, projection)
  PY
  jq -e '
    .format == "spaghetti-extractor-rooted-behavioral-projection-v1" and
    (.root_unit_ids | length) > 0 and
    (.reachable_unit_ids | length) > 0 and
    .structural_unit_count >= (.reachable_unit_ids | length) and
    (.projection_sha256 | test("^[0-9a-f]{64}$"))
  ' "$out/rooted-behavioral-projection-v1.json" >/dev/null
''
