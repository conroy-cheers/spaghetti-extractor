{
  pkgs,
  mingw32,
  namePrefix,
  version,
  source,
  sourceFiles,
  compileSources ? sourceFiles,
  specification,
  sourceBinding,
  runtimeLock,
  executableName,
  cFlags ? [ "-std=c11" "-O2" "-Wall" "-Wextra" "-Werror" ],
  ldFlags ? [ ],
  portableStdenv ? pkgs.pkgsCross.aarch64-multiplatform.stdenv,
}:

let
  lib = pkgs.lib;
  compileInputs = lib.concatStringsSep " " (
    map (path: lib.escapeShellArg path) compileSources
  );
  compileFlags = lib.concatStringsSep " " (map lib.escapeShellArg cFlags);
  linkFlags = lib.concatStringsSep " " (map lib.escapeShellArg ldFlags);
  mkCandidate = {
    stdenv,
    platform,
    architecture,
    targetTriple,
    outputName,
    requirePe32 ? false,
  }:
    stdenv.mkDerivation {
      pname = "${namePrefix}-${platform}";
      inherit version;
      src = source;
      dontConfigure = true;
      dontFixup = true;
      strictDeps = true;
      __contentAddressed = true;
      nativeBuildInputs = [ pkgs.file pkgs.jq ];
      buildPhase = ''
        runHook preBuild
        $CC ${compileFlags} \
          -ffile-prefix-map=${source}=portable-source \
          ${compileInputs} ${linkFlags} -Wl,-Map,candidate.map \
          -o ${lib.escapeShellArg outputName}
        runHook postBuild
      '';
      installPhase = ''
        runHook preInstall
        mkdir -p "$out/bin" "$out/share/spaghetti-extractor/source"
        cp ${lib.escapeShellArg outputName} "$out/bin/${executableName}"
        cp candidate.map "$out/share/spaghetti-extractor/candidate.map"
        ${lib.concatMapStringsSep "\n" (path: ''
          target_relative=${lib.escapeShellArg path}
          mkdir -p \
            "$out/share/spaghetti-extractor/source/$(dirname "$target_relative")"
          cp ${lib.escapeShellArg path} \
            "$out/share/spaghetti-extractor/source/$target_relative"
        '') sourceFiles}
        cp ${specification} "$out/share/spaghetti-extractor/source-project.json"
        cp ${sourceBinding}/source-project-binding.json \
          "$out/share/spaghetti-extractor/source-project-binding.json"
        cp ${runtimeLock}/runtime-lock-v1.json \
          "$out/share/spaghetti-extractor/runtime-lock-v1.json"
        ${lib.optionalString requirePe32 ''
          ${pkgs.file}/bin/file "$out/bin/${executableName}" \
            | grep -q 'PE32 executable'
        ''}

        binary_sha256="$(sha256sum "$out/bin/${executableName}" | cut -d ' ' -f 1)"
        binary_size="$(stat -c %s "$out/bin/${executableName}")"
        source_project_specification_sha256="$(${pkgs.jq}/bin/jq -er \
          .specification_sha256 \
          "$out/share/spaghetti-extractor/source-project.json")"
        source_project_binding_sha256="$(${pkgs.jq}/bin/jq -er \
          .binding_sha256 \
          "$out/share/spaghetti-extractor/source-project-binding.json")"
        source_project_sha256="$(sha256sum \
          "$out/share/spaghetti-extractor/source-project-binding.json" | cut -d ' ' -f 1)"
        runtime_lock_sha256="$(sha256sum \
          "$out/share/spaghetti-extractor/runtime-lock-v1.json" | cut -d ' ' -f 1)"
        map_sha256="$(sha256sum \
          "$out/share/spaghetti-extractor/candidate.map" | cut -d ' ' -f 1)"
        ${pkgs.jq}/bin/jq -n \
          --arg platform ${lib.escapeShellArg platform} \
          --arg architecture ${lib.escapeShellArg architecture} \
          --arg target_triple ${lib.escapeShellArg targetTriple} \
          --arg executable ${lib.escapeShellArg "bin/${executableName}"} \
          --arg binary_sha256 "$binary_sha256" \
          --argjson binary_size "$binary_size" \
          --arg source_project_sha256 "$source_project_sha256" \
          --arg source_project_binding_sha256 "$source_project_binding_sha256" \
          --arg source_project_specification_sha256 "$source_project_specification_sha256" \
          --arg runtime_lock_sha256 "$runtime_lock_sha256" \
          --arg map_sha256 "$map_sha256" '
          {
            format: "spaghetti-extractor-portable-c-candidate-v1",
            schema_version: 1,
            status: "candidate-generated",
            platform: $platform,
            architecture: $architecture,
            target_triple: $target_triple,
            executes_original_binary: false,
            source_project_sha256: $source_project_sha256,
            source_project_binding_sha256: $source_project_binding_sha256,
            source_project_specification_sha256: $source_project_specification_sha256,
            runtime_lock_sha256: $runtime_lock_sha256,
            output: {
              path: $executable,
              sha256: $binary_sha256,
              bytes: $binary_size
            },
            linker_map: {
              path: "share/spaghetti-extractor/candidate.map",
              sha256: $map_sha256
            }
          }
        ' > "$out/portable-c-candidate-v1.json"

        : > candidate-sources.ndjson
        ${lib.concatMapStringsSep "\n" (path: ''
          source_relative=${lib.escapeShellArg path}
          installed_source="$out/share/spaghetti-extractor/source/$source_relative"
          ${pkgs.jq}/bin/jq -n \
            --arg path ${lib.escapeShellArg path} \
            --arg sha256 "$(sha256sum "$installed_source" | cut -d ' ' -f 1)" \
            '{path: $path, sha256: $sha256}' >> candidate-sources.ndjson
        '') sourceFiles}
        sources_json="$(${pkgs.jq}/bin/jq -s 'sort_by(.path)' candidate-sources.ndjson)"
        binding_sources="$(${pkgs.jq}/bin/jq -c \
          '.sources | map({path, sha256}) | sort_by(.path)' \
          "$out/share/spaghetti-extractor/source-project-binding.json")"
        test "$(${pkgs.jq}/bin/jq -c . <<<"$sources_json")" = "$binding_sources"
        ${pkgs.jq}/bin/jq -n \
          --arg platform ${lib.escapeShellArg platform} \
          --arg architecture ${lib.escapeShellArg architecture} \
          --arg target_triple ${lib.escapeShellArg targetTriple} \
          --arg executable ${lib.escapeShellArg "bin/${executableName}"} \
          --arg binary_sha256 "$binary_sha256" \
          --argjson binary_size "$binary_size" \
          --arg specification_sha256 "$source_project_specification_sha256" \
          --arg source_project_binding_sha256 "$source_project_binding_sha256" \
          --arg source_project_binding_artifact_sha256 "$source_project_sha256" \
          --arg runtime_lock_sha256 "$runtime_lock_sha256" \
          --arg map_sha256 "$map_sha256" \
          --argjson sources "$sources_json" '
          {
            format: "stage-b-source-project-build-v1",
            status: "candidate-generated",
            candidate_kind: "portable-c-source-project",
            platform: $platform,
            architecture: $architecture,
            target_triple: $target_triple,
            executes_original_binary: false,
            inputs: {
              source_project_specification_sha256: $specification_sha256,
              source_project_binding_sha256: $source_project_binding_sha256,
              source_project_binding_artifact_sha256: $source_project_binding_artifact_sha256,
              runtime_lock_sha256: $runtime_lock_sha256,
              sources: $sources
            },
            outputs: {
              candidate: {
                path: $executable,
                sha256: $binary_sha256,
                bytes: $binary_size
              },
              linker_map: {
                path: "share/spaghetti-extractor/candidate.map",
                sha256: $map_sha256
              }
            },
            authority: {
              proof_authority: false,
              stage_a_pass_authorized: false,
              whole_program_equivalence_claim: false
            }
          }
        ' > "$out/source-project-build.json"
        runHook postInstall
      '';
    };
  pe32 = mkCandidate {
    stdenv = mingw32.stdenv;
    platform = "pe32";
    architecture = "i686";
    targetTriple = "i686-w64-mingw32";
    outputName = "candidate.exe";
    requirePe32 = true;
  };
  native = mkCandidate {
    stdenv = portableStdenv;
    platform = "non_x86";
    architecture = portableStdenv.hostPlatform.parsed.cpu.name;
    targetTriple = portableStdenv.hostPlatform.config;
    outputName = "candidate";
  };
in
assert builtins.isList sourceFiles && sourceFiles != [ ];
assert builtins.isList compileSources && compileSources != [ ];
assert builtins.all (path: builtins.elem path sourceFiles) compileSources;
{
  inherit pe32 native;
}
