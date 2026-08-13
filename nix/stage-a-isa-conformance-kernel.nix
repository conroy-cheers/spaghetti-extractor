{
  pkgs,
  leanSource,
}:

let
  modules = [
    "X87"
    "Formal"
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
  cp -r ${leanSource}/StageA .
  chmod -R u+w StageA
  mkdir -p "$out/StageA"
  export LEAN_PATH="$out:$PWD"

  for module in ${builtins.concatStringsSep " " modules}; do
    cp "StageA/$module.lean" "$out/StageA/$module.lean"
    lean --trust=0 \
      -o "$out/StageA/$module.olean" \
      -c "$out/StageA/$module.c" \
      "StageA/$module.lean"
    leanc -c -o "$out/StageA/$module.o" \
      "$out/StageA/$module.c"
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
