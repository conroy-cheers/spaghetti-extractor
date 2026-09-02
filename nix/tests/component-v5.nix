{ pkgs, pythonEnv }:

let
  package = import ../component-v5-interface-package.nix {
    inherit pkgs pythonEnv;
    namePrefix = "spaghetti-extractor-component-v5-fixture";
    componentId = "ascii-to-lower";
    intent = ../../targets/gnu-hello/intent/interfaces-v5/ascii-to-lower.json;
  };
in
pkgs.runCommand "spaghetti-extractor-component-v5-check" {
  nativeBuildInputs = [ pkgs.jq ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  jq -e '
    .format == "spaghetti-extractor-portable-component-interface-v5" and
    .id == "ascii-to-lower" and
    (.operations | length) == 1
  ' ${package.interface} >/dev/null
  test -s ${package.schema}
  test -s ${package.manifest}
  mkdir -p "$out"
  ln -s ${package.derivation} "$out/interface-package"
''
