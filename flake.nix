{
  description = "Spaghetti Extractor binary reimplementation and equivalence-proof tooling";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          mingw32 = pkgs.pkgsCross.mingw32;
          mingw32Oniguruma = mingw32.oniguruma.overrideAttrs (old: {
            meta = (old.meta or { }) // {
              platforms = (old.meta.platforms or [ ]) ++ [ "i686-windows" ];
            };
          });
          pythonEnv = pkgs.python3.withPackages (
            ps: with ps; [
              capstone
              pefile
              z3-solver
            ]
          );
          spaghetti-extractor = pkgs.python3Packages.buildPythonApplication {
            pname = "spaghetti-extractor";
            version = "0.1.0";
            src = ./.;
            pyproject = true;

            build-system = with pkgs.python3Packages; [
              setuptools
            ];

            dependencies = with pkgs.python3Packages; [
              capstone
              pefile
              z3-solver
            ];

            doCheck = false;
            pythonImportsCheck = [ "spaghetti_extractor" ];
          };
          stageAJqCommonCflags = "-g0 -fno-asynchronous-unwind-tables -fno-ident -fno-inline -fno-inline-functions -fno-inline-small-functions -fno-ipa-cp -fno-ipa-sra -fno-ipa-icf";
          stageAJqOriginalCflags = "-O2 -fno-align-functions -fno-align-labels -fno-align-loops -fno-align-jumps ${stageAJqCommonCflags}";
          stageAJqCandidateCflags = "-O2 -falign-functions=32 -falign-labels=16 -falign-loops=16 -falign-jumps=16 ${stageAJqCommonCflags}";
          mkStageAJq =
            label: cflags:
            (mingw32.jq.override {
              oniguruma = mingw32Oniguruma;
            }).overrideAttrs
              (old: {
                pname = "stage-a-jq-${label}";
                doCheck = false;
                doInstallCheck = false;
                dontStrip = true;
                outputs = [ "out" ];
                buildInputs = (old.buildInputs or [ ]) ++ [ mingw32.windows.pthreads ];
                configureFlags = [
                  "--prefix=${builtins.placeholder "out"}"
                  "--bindir=${builtins.placeholder "out"}/bin"
                  "--sbindir=${builtins.placeholder "out"}/bin"
                  "--datadir=${builtins.placeholder "out"}/share"
                  "--mandir=${builtins.placeholder "out"}/share/man"
                ];
                CFLAGS = cflags;
                LDFLAGS = "-Wl,-Map,jq-${label}.map";
                postFixup = "";
                postInstall =
                  (old.postInstall or "")
                  + ''
                    map_path="$(find . -name 'jq-${label}.map' -print -quit)"
                    if [ -z "$map_path" ]; then
                      echo "missing jq-${label}.map" >&2
                      exit 1
                    fi
                    mkdir -p "$out/share/spaghetti-extractor/stage-a-jq-fixtures/${label}"
                    cp "$map_path" "$out/share/spaghetti-extractor/stage-a-jq-fixtures/${label}/jq.map"
                    cp "$out/bin/jq.exe" "$out/share/spaghetti-extractor/stage-a-jq-fixtures/${label}/jq.exe"
                  '';
                meta = (old.meta or { }) // {
                  platforms = (old.meta.platforms or [ ]) ++ [ "i686-windows" ];
                };
              });
          stage-a-jq-original = mkStageAJq "original" stageAJqOriginalCflags;
          stage-a-jq-candidate = mkStageAJq "candidate" stageAJqCandidateCflags;
          stage-a-fixtures = mingw32.stdenv.mkDerivation {
            pname = "stage-a-fixtures";
            version = "0.2.0";
            src = ./tools/stage-a-fixtures;

            dontConfigure = true;

            buildPhase = ''
              runHook preBuild
              common_flags=(
                -g0
                -fno-asynchronous-unwind-tables
                -fno-exceptions
                -fno-ident
                -nostdlib
                -Wl,--exclude-all-symbols
                -Wl,--subsystem,console
                -Wl,-e,_mainCRTStartup
                -Wl,--image-base,0x400000
                -Wl,--section-alignment,0x1000
                -Wl,--file-alignment,0x200
              )
              $CC -O0 "''${common_flags[@]}" -o stage-a-loop-original.exe stage_a_loop.S
              $CC -O2 "''${common_flags[@]}" -o stage-a-loop-candidate.exe stage_a_loop.S
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall
              fixture_dir="$out/share/spaghetti-extractor/stage-a-fixtures/relational-v3"
              mkdir -p "$fixture_dir"
              cp stage-a-loop-original.exe stage-a-loop-candidate.exe "$fixture_dir/"
              cat > "$fixture_dir/block-map-loop.json" <<'JSON'
              {
                "blocks": [
                  {
                    "id": "entry-loop",
                    "kind": "code",
                    "reachable": true,
                    "root": { "kind": "pe_entrypoint", "checked": true },
                    "original": { "rva": "0x1000", "size": 2 },
                    "candidate": { "rva": "0x1000", "size": 2 },
                    "source": {
                      "kind": "fixture",
                      "function": "entry_loop",
                      "function_block_index": 0
                    }
                  }
                ],
                "waivers": [
                  { "id": "loop-linker-padding", "binary": "both", "rva": "0x1002", "size": 2, "reason": "verified post-jump NOP alignment emitted by the PE linker" }
                ]
              }
              JSON
              cat > "$fixture_dir/layout-contract.json" <<'JSON'
              {
                "format": "stage-a-layout-contract-v1",
                "required_facts": [
                  "matching_architecture",
                  "matching_section_rvas",
                  "matching_section_permissions",
                  "matching_imports",
                  "all_executable_bytes_classified",
                  "matching_normalized_executable_section_spans"
                ],
                "facts": {
                  "matching_architecture": true,
                  "matching_section_rvas": true,
                  "matching_section_permissions": true,
                  "matching_imports": true,
                  "all_executable_bytes_classified": true,
                  "matching_normalized_executable_section_spans": true
                }
              }
              JSON
              runHook postInstall
            '';
          };
          stage-a-fixtures-check = pkgs.runCommand "stage-a-fixtures-check"
            {
              nativeBuildInputs = [
                spaghetti-extractor
                pkgs.jq
                pkgs.lean4
              ];
            }
            ''
              fixture_dir="${stage-a-fixtures}/share/spaghetti-extractor/stage-a-fixtures/relational-v3"
              work="$TMPDIR/stage-a-v3"
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$TMPDIR/stage-a-relational-cache"
              mkdir -p "$work"
              spaghetti-extractor stage-a-generate-relation-contract \
                --original "$fixture_dir/stage-a-loop-original.exe" \
                --candidate "$fixture_dir/stage-a-loop-candidate.exe" \
                --mapping "$fixture_dir/block-map-loop.json" \
                --out "$work/relation-contract.json"
              spaghetti-extractor stage-a-prove \
                --original "$fixture_dir/stage-a-loop-original.exe" \
                --candidate "$fixture_dir/stage-a-loop-candidate.exe" \
                --relation-contract "$work/relation-contract.json" \
                --out "$work/proof"
              spaghetti-extractor stage-a-check-proof \
                --report "$work/proof" \
                --out "$work/proof-check.json"
              spaghetti-extractor stage-a-export-reference-contract \
                --original "$fixture_dir/stage-a-loop-original.exe" \
                --candidate "$fixture_dir/stage-a-loop-candidate.exe" \
                --mapping "$fixture_dir/block-map-loop.json" \
                --validation-report "$work/proof" \
                --layout-contract "$fixture_dir/layout-contract.json" \
                --sidecar-dir "$work/contract" \
                --unit-contract-dir "$work/contract" \
                --out "$work/contract/reference-contract.json"
              jq -e '
                .constraints.validation_report_artifact_binding.status == "satisfied" and
                .constraints.proof_obligation_inventory.status == "satisfied"
              ' "$work/contract/reference-contract.json" >/dev/null
              spaghetti-extractor stage-a-smoke-contract \
                --reference-contract "$work/contract/reference-contract.json" \
                --out "$work/contract-smoke.json"
              jq -e '.status == "pass"' "$work/contract-smoke.json" >/dev/null
              mkdir -p "$out"
              cp -R "$work/." "$out/"
            '';
          stage-a-fixtures-root = pkgs.writeShellApplication {
            name = "stage-a-fixtures-root";
            text = ''
              printf '%s\n' "${stage-a-fixtures}"
            '';
          };
          stage-a-jq-fixtures = pkgs.runCommand "stage-a-jq-fixtures"
            {
              nativeBuildInputs = [ pkgs.jq ];
            }
            ''
              fixture_dir="$out/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment"
              mkdir -p "$fixture_dir"
              cp "${stage-a-jq-original}/share/spaghetti-extractor/stage-a-jq-fixtures/original/jq.exe" "$fixture_dir/jq-original.exe"
              cp "${stage-a-jq-candidate}/share/spaghetti-extractor/stage-a-jq-fixtures/candidate/jq.exe" "$fixture_dir/jq-candidate.exe"
              cp "${stage-a-jq-original}/share/spaghetti-extractor/stage-a-jq-fixtures/original/jq.map" "$fixture_dir/jq-original.map"
              cp "${stage-a-jq-candidate}/share/spaghetti-extractor/stage-a-jq-fixtures/candidate/jq.map" "$fixture_dir/jq-candidate.map"
              for path in "${stage-a-jq-original}"/bin/*.dll "${stage-a-jq-candidate}"/bin/*.dll; do
                [ -e "$path" ] || continue
                name="$(basename "$path")"
                if [ ! -e "$fixture_dir/$name" ]; then
                  cp -L "$path" "$fixture_dir/"
                  chmod u+w "$fixture_dir/$name"
                fi
              done
              jq -n \
                --arg original_flags "${stageAJqOriginalCflags}" \
                --arg candidate_flags "${stageAJqCandidateCflags}" \
                --arg compiler "$(${mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc -dumpmachine)" \
                --arg compiler_version "$(${mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc -dumpfullversion -dumpversion)" \
                '{
                  format: "stage-a-jq-fixture-build-metadata-v1",
                  source: "jq from nixpkgs",
                  target: "i686-w64-mingw32",
                  original: { file: "jq-original.exe", linker_map: "jq-original.map", flags: $original_flags },
                  candidate: { file: "jq-candidate.exe", linker_map: "jq-candidate.map", flags: $candidate_flags },
                  compiler: { target: $compiler, version: $compiler_version }
                }' > "$fixture_dir/build-metadata.json"
            '';
          stage-a-jq-fixtures-check = pkgs.runCommand "stage-a-jq-fixtures-check"
            {
              nativeBuildInputs = [
                spaghetti-extractor
                pkgs.jq
                pkgs.lean4
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment"
              work="$TMPDIR/stage-a-jq"
              mkdir -p "$work"
              spaghetti-extractor stage-a-generate-map \
                --original "$fixture_dir/jq-original.exe" \
                --candidate "$fixture_dir/jq-candidate.exe" \
                --linker-map-original "$fixture_dir/jq-original.map" \
                --linker-map-candidate "$fixture_dir/jq-candidate.map" \
                --original-flags "${stageAJqOriginalCflags}" \
                --candidate-flags "${stageAJqCandidateCflags}" \
                --out "$work/jq-block-map.json" \
                --layout-contract-out "$work/jq-layout-contract.json" \
                > "$work/generate-map.stdout"
              spaghetti-extractor stage-a-generate-relation-contract \
                --original "$fixture_dir/jq-original.exe" \
                --candidate "$fixture_dir/jq-candidate.exe" \
                --mapping "$work/jq-block-map.json" \
                --external-profile "${./profiles/pe32-kernel32-lockstep-v1.json}" \
                --out "$work/jq-relation-contract.json" \
                > "$work/generate-relation.stdout"
              SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$work/relational-cache" \
                spaghetti-extractor stage-a-prepare-relational \
                  --original "$fixture_dir/jq-original.exe" \
                  --candidate "$fixture_dir/jq-candidate.exe" \
                  --relation-contract "$work/jq-relation-contract.json" \
                  --out "$work/relational-v3" \
                  > "$work/relational-v3.stdout"
              jq -e '
                .status == "prepared" and
                .acceptance.status == "incomplete" and
                .acceptance.theorem == null and
                .composition_progress.status == "incomplete" and
                .composition_progress.counts.rooted_reachable_nodes > 0 and
                .composition_progress.counts.rooted_reachable_feasible_edges > 0 and
                .composition_progress.counts.rooted_external_refinement_candidates == 9 and
                .composition_progress.counts.rooted_external_contract_gap_edges == 3 and
                .composition_progress.counts.rooted_refined_segments == 52 and
                .composition_progress.counts.unsupported_instructions == 0
              ' "$work/relational-v3/prepared-proof.json" >/dev/null
              jq -e '.status == "supported" and .counts.issues == 0' \
                "$work/relational-v3/semantic-gaps.json" >/dev/null
              mkdir -p "$out/generated" "$out/report"
              cp "$work/jq-block-map.json" "$work/jq-layout-contract.json" "$work/jq-relation-contract.json" "$out/report/"
              cp -R "$work/relational-v3" "$out/report/relational-v3"
              cp "$work/relational-v3/semantic-gaps.json" "$out/generated/jq-formal-gaps.json"
              if spaghetti-extractor stage-a-export-reference-contract \
                  --original "$fixture_dir/jq-original.exe" \
                  --candidate "$fixture_dir/jq-candidate.exe" \
                  --mapping "$out/report/jq-block-map.json" \
                  --validation-report "$out/report/relational-v3" \
                  --layout-contract "$out/report/jq-layout-contract.json" \
                  --sidecar-dir "$out/generated" \
                  --unit-contract-dir "$out/generated" \
                  --out "$out/generated/jq-reference-contract.json" \
                  > "$work/reference-contract.stdout"; then
                echo "jq reference contract unexpectedly claimed formal completion" >&2
                exit 1
              fi
              jq -e '.status == "incomplete"' "$out/generated/jq-reference-contract.json" >/dev/null
              spaghetti-extractor stage-a-smoke-contract \
                --reference-contract "$out/generated/jq-reference-contract.json" \
                --out "$out/generated/contract-smoke.json" \
                > "$work/smoke.stdout"
              jq -e '.status == "pass"' "$out/generated/contract-smoke.json" >/dev/null
            '';
          stage-a-jq-fixtures-root = pkgs.writeShellApplication {
            name = "stage-a-jq-fixtures-root";
            text = ''
              printf '%s\n' "${stage-a-jq-fixtures}"
            '';
          };
          stage-b-jq-skeleton = pkgs.runCommand "stage-b-jq-skeleton"
            {
              nativeBuildInputs = [ spaghetti-extractor ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment"
              work="$TMPDIR/stage-b-jq-skeleton"
              mkdir -p "$work"
              spaghetti-extractor stage-b-generate-skeleton \
                --original "$fixture_dir/jq-original.exe" \
                --reference-contract "${stage-a-jq-fixtures-check}/generated/jq-reference-contract.json" \
                --target-name jq \
                --source-language c \
                --implementation-mode contract-guided-c \
                --out-dir "$work/skeleton" \
                > "$work/skeleton.stdout"
              out_dir="$out/share/spaghetti-extractor/stage-b/jq/skeleton"
              mkdir -p "$out_dir"
              cp -R "$work/skeleton/." "$out_dir/"
            '';
          stage-b-jq-skeleton-root = pkgs.writeShellApplication {
            name = "stage-b-jq-skeleton-root";
            text = ''
              printf '%s\n' "${stage-b-jq-skeleton}/share/spaghetti-extractor/stage-b/jq/skeleton"
            '';
          };
        in
        {
          default = spaghetti-extractor;
          inherit
            spaghetti-extractor
            stage-a-fixtures
            stage-a-fixtures-check
            stage-a-fixtures-root
            stage-a-jq-fixtures
            stage-a-jq-fixtures-check
            stage-a-jq-fixtures-root
            stage-b-jq-skeleton
            stage-b-jq-skeleton-root
            ;
        }
      );

      apps = forAllSystems (
        system:
        let
          packages = self.packages.${system};
        in
        {
          default = {
            type = "app";
            program = "${packages.spaghetti-extractor}/bin/spaghetti-extractor";
          };
          spaghetti-extractor = {
            type = "app";
            program = "${packages.spaghetti-extractor}/bin/spaghetti-extractor";
          };
          spaghetti-extractor-slice = {
            type = "app";
            program = "${packages.spaghetti-extractor}/bin/spaghetti-extractor-slice";
          };
          stage-a-fixtures-root = {
            type = "app";
            program = "${packages.stage-a-fixtures-root}/bin/stage-a-fixtures-root";
          };
          stage-a-jq-fixtures-root = {
            type = "app";
            program = "${packages.stage-a-jq-fixtures-root}/bin/stage-a-jq-fixtures-root";
          };
          stage-b-jq-skeleton-root = {
            type = "app";
            program = "${packages.stage-b-jq-skeleton-root}/bin/stage-b-jq-skeleton-root";
          };
        }
      );

      checks = forAllSystems (
        system:
        let
          packages = self.packages.${system};
        in
        {
          inherit (packages)
            spaghetti-extractor
            stage-a-fixtures-check
            stage-a-jq-fixtures-check
            stage-b-jq-skeleton
            ;
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          packages = self.packages.${system};
          pythonEnv = pkgs.python3.withPackages (
            ps: with ps; [
              capstone
              pefile
              pytest
              z3-solver
            ]
          );
        in
        {
          default = pkgs.mkShell {
            packages = [
              pythonEnv
              packages.spaghetti-extractor
              pkgs.jq
              pkgs.lean4
              pkgs.nix
              pkgs.pkgsCross.mingw32.stdenv.cc
              pkgs.llvm
            ];
            shellHook = ''
              export PYTHONPATH="$PWD/src''${PYTHONPATH:+:$PYTHONPATH}"
            '';
          };
        }
      );
    };
}
