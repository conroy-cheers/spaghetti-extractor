{
  pkgs,
  pythonEnv,
  pythonSource,
  spec,
  sdkHeaders ? pkgs.pkgsCross.mingw32.windows.mingw_w64_headers,
  name ? null,
}:

let
  lib = pkgs.lib;
  specification = builtins.fromJSON (builtins.readFile spec);
  profileName =
    if name != null then name
    else "spaghetti-extractor-${specification.id}-interface-profile-v1";
  phasePythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.external_interface_ast" ];
    name = "${profileName}-python-closure";
  };
  headers = map (
    binding: "${sdkHeaders}/include/${binding.include}"
  ) specification.headers;
  includes = lib.concatMapStringsSep "\n" (
    binding: "#include <${binding.include}>"
  ) specification.headers;
  headerArguments = lib.concatMapStringsSep " " lib.escapeShellArg headers;
in
pkgs.runCommand profileName {
  nativeBuildInputs = [ pythonEnv pkgs.llvmPackages.clang-unwrapped pkgs.jq ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export LC_ALL=C.UTF-8
  export PYTHONPATH=${phasePythonSource}/src
  mkdir -p "$out"

  cat > translation.c <<'EOF'
  #define CINTERFACE 1
  #define COBJMACROS 1
  ${includes}
  EOF
  clang \
    --target=i686-w64-windows-gnu \
    -fms-extensions \
    -fdeclspec \
    -Wno-everything \
    -I${sdkHeaders}/include \
    -Xclang -ast-dump=json \
    -fsyntax-only translation.c \
    > ast.json
  cp ${spec} spec.json

  ${pythonEnv}/bin/python3 - \
    ast.json spec.json \
    "$out/interface-profile.json" ${headerArguments} <<'PY'
  import pathlib
  import sys
  from spaghetti_extractor.external_interface_ast import (
      extract_external_interface_profile,
  )

  ast, spec, output, *headers = map(pathlib.Path, sys.argv[1:])
  extract_external_interface_profile(
      ast_json=ast,
      spec=spec,
      headers=headers,
      out=output,
  )
  PY
  jq -e --arg id ${lib.escapeShellArg specification.id} '
    .format == "stage-a-external-interface-profile-v1" and
    .id == $id and .model == "x86-pe32" and .status == "complete" and
    .counts.factories > 0 and .counts.interfaces > 0 and .counts.methods > 0
  ' "$out/interface-profile.json" >/dev/null
''
