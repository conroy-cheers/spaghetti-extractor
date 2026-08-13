{
  pkgs,
  namePrefix,
  source,
  sourceFiles,
  compileSources,
  cFlags ? [ "-std=c11" ],
  includeDirectories ? [ "." ],
  clang ? pkgs.clang,
}:

let
  lib = pkgs.lib;
  flags = lib.escapeShellArgs cFlags;
  includes = lib.concatMapStringsSep " " (
    path: "-I${lib.escapeShellArg "${source}/${path}"}"
  ) includeDirectories;
  sourceRows = lib.concatMapStringsSep "\n" (relative: ''
    source_relative=${lib.escapeShellArg relative}
    ast_path="$TMPDIR/ast-$index.json"
    ${clang}/bin/clang ${flags} ${includes} \
      -fsyntax-only -Xclang -ast-dump=json \
      "$source_root/$source_relative" > "$ast_path"
    source_sha256="$(sha256sum "$source_root/$source_relative" | cut -d ' ' -f 1)"
    ${pkgs.jq}/bin/jq -n \
      --arg path "$source_relative" \
      --arg source_sha256 "$source_sha256" \
      --slurpfile ast "$ast_path" \
      '{path: $path, source_sha256: $source_sha256, ast: $ast[0]}' \
      >> "$TMPDIR/translation-units.ndjson"
    index=$((index + 1))
  '') compileSources;
in
assert builtins.isString namePrefix && namePrefix != "";
assert builtins.isList sourceFiles && sourceFiles != [ ];
assert builtins.isList compileSources && compileSources != [ ];
assert builtins.all (path: builtins.elem path sourceFiles) compileSources;
pkgs.runCommand "${namePrefix}-clang-ast-bundle-v1" {
  nativeBuildInputs = [ clang pkgs.coreutils pkgs.jq ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export LC_ALL=C.UTF-8
  export SOURCE_DATE_EPOCH=1
  source_root=${lib.escapeShellArg (toString source)}
  : > "$TMPDIR/translation-units.ndjson"
  index=0
  ${sourceRows}
  mkdir -p "$out"
  ${pkgs.jq}/bin/jq -s '
    {
      format: "spaghetti-extractor-clang-ast-bundle-v1",
      translation_units: sort_by(.path)
    }
  ' "$TMPDIR/translation-units.ndjson" > "$out/clang-ast-bundle.json"
''
