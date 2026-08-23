# spaghetti-extractor-python-role: candidate
{ pkgs, pythonEnv, original, staticExport ? null, loadImageContract ? null
, imageId, namePrefix }:

let
  pythonSource = import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [ "spaghetti_extractor.candidate.project" ];
    name = "${namePrefix}-module-interface-python-closure";
  };
in
pkgs.runCommand "${namePrefix}-module-interface-v2" {
  nativeBuildInputs = [ pythonEnv pkgs.jq ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONPATH=${pythonSource}/src
  ${pythonEnv}/bin/python3 - ${original} \
    ${if loadImageContract != null then loadImageContract else "${staticExport}/load-image-contract.json"} \
    "$out" <<'PY'
  import pathlib
  import sys
  from spaghetti_extractor.candidate.project import write_pe32_module_interface

  write_pe32_module_interface(
      image_id=${builtins.toJSON imageId},
      original_pe=pathlib.Path(sys.argv[1]),
      load_image_contract=pathlib.Path(sys.argv[2]),
      out=pathlib.Path(sys.argv[3]),
  )
  PY
  jq -e '
    .format == "spaghetti-extractor-pe32-module-interface-v2" and
    .status == "complete" and .image_id == ${builtins.toJSON imageId} and
    (.export_directory.slot_count >= 0) and
    (.directories | length == 16) and
    .policy.layout_compatibility == "not_promised"
  ' "$out/module-interface.json" >/dev/null
''
