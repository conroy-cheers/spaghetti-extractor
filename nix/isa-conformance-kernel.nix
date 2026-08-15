{
  pkgs,
  leanSource,
}:

let
  modules = [
    "X87"
    "Bytes"
    "PE32"
    "Machine"
    "Decode"
    "Semantics"
    "ISAQualification"
    "ISAInventory"
    "ISAConformance"
    "ISAConformanceRunner"
  ];
  modulesJson = builtins.toJSON modules;
in
pkgs.runCommand "spaghetti-extractor-isa-conformance-kernel" {
  nativeBuildInputs = [ pkgs.lean4 pkgs.jq ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export LC_ALL=C.UTF-8
  export SOURCE_DATE_EPOCH=1
  mkdir -p SpaghettiExtractor "$out/SpaghettiExtractor/ISA"
  cp -r ${leanSource}/SpaghettiExtractor/ISA SpaghettiExtractor/
  chmod -R u+w SpaghettiExtractor/ISA
  export LEAN_PATH="$out:$PWD"

  for module in ${builtins.concatStringsSep " " modules}; do
    cp "SpaghettiExtractor/ISA/$module.lean" "$out/SpaghettiExtractor/ISA/$module.lean"
    lean --trust=0 \
      -o "$out/SpaghettiExtractor/ISA/$module.olean" \
      -c "$out/SpaghettiExtractor/ISA/$module.c" \
      "SpaghettiExtractor/ISA/$module.lean"
    leanc -c -o "$out/SpaghettiExtractor/ISA/$module.o" \
      "$out/SpaghettiExtractor/ISA/$module.c"
  done

  jq -n \
    --argjson modules ${pkgs.lib.escapeShellArg modulesJson} \
    --arg lean_version "$(lean --version | head -n1)" \
    '{
      format: "spaghetti-extractor-isa-conformance-kernel-v1",
      modules: $modules,
      lean_version: $lean_version,
      usage: {
        environment: "SPAGHETTI_LEAN_KERNEL_CACHE",
        supported_command: "nix run .#test -- affected"
      }
    }' > "$out/kernel-manifest.json"
''
