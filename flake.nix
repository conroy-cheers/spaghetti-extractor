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
              unicorn
              z3-solver
            ]
          );
          bochs-conformance = pkgs.callPackage ./nix/bochs-conformance.nix {
            instrumentationSrc = ./tools/bochs-conformance;
          };
          spaghettiExtractorCoreSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./pyproject.toml
              ./src
              ./nix/stage-a-lean-graph.nix
            ];
          };
          spaghetti-extractor-core = pkgs.python3Packages.buildPythonApplication {
            pname = "spaghetti-extractor";
            version = "0.1.0";
            src = spaghettiExtractorCoreSource;
            pyproject = true;

            postPatch = ''
              sed -i '/share\/spaghetti-extractor\/profiles/d' pyproject.toml
            '';

            build-system = with pkgs.python3Packages; [
              setuptools
            ];

            dependencies = with pkgs.python3Packages; [
              capstone
              pefile
              unicorn
              z3-solver
            ];

            doCheck = false;
            pythonImportsCheck = [ "spaghetti_extractor" ];
          };
          spaghetti-extractor-profiles = pkgs.runCommand
            "spaghetti-extractor-profiles"
            { }
            ''
              mkdir -p "$out/share/spaghetti-extractor/profiles"
              cp ${./profiles}/*.json "$out/share/spaghetti-extractor/profiles/"
            '';
          spaghetti-extractor = pkgs.symlinkJoin {
            name = "spaghetti-extractor-0.1.0";
            paths = [
              spaghetti-extractor-core
              spaghetti-extractor-profiles
            ];
            meta.mainProgram = "spaghetti-extractor";
          };
          singlestep-80386-conformance =
            pkgs.callPackage ./nix/singlestep-80386-conformance.nix {
              inherit spaghetti-extractor;
            };
          stageABochs80386ShardIndices = pkgs.lib.range 0 15;
          stageABochs80386Opcodes = [
            "6601"
            "6605"
            "6629"
            "6631"
            "6639"
            "6685"
            "6689"
            "668B"
            "66B8"
          ];
          stageABochs80386Shards = pkgs.lib.concatMap
            (opcode:
              map
                (shardIndex:
                  let
                    imported =
                      singlestep-80386-conformance.importDerivations.${opcode}.${toString shardIndex};
                    shardName = "${pkgs.lib.toLower opcode}-${toString shardIndex}-of-16";
                  in
                  pkgs.runCommand "stage-a-bochs-80386-${shardName}"
                    {
                      nativeBuildInputs = [
                        bochs-conformance
                        pkgs.jq
                        pkgs.lean4
                        spaghetti-extractor
                      ];
                      preferLocalBuild = false;
                      allowSubstitutes = true;
                    }
                    ''
                      shard_out="$out/${opcode}/shard-${toString shardIndex}-of-16"
                      mkdir -p "$shard_out"
                      export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-isa-kernel-cache}"
                      spaghetti-extractor stage-a-check-isa-conformance \
                        --corpus ${imported}/corpus.json \
                        --backend bochs \
                        --bochs-runner ${bochs-conformance}/bin/spaghetti-bochs-conformance-runner \
                        --out "$shard_out/report.json" \
                        > "$shard_out/check.stdout"
                      jq -e \
                        '.status == "pass"
                         and .qualification == "qualified"
                         and .counts.cases > 0
                         and .counts.matched == .counts.cases
                         and .counts.mismatched == 0
                         and .counts.unsupported == 0
                         and .counts.errors == 0
                         and .proof_authority == false
                        and .closes_stage_a_proof == false' \
                        "$shard_out/check.stdout" > /dev/null
                      spaghetti-extractor stage-a-check-isa-conformance \
                        --corpus ${imported}/corpus.json \
                        --backend unicorn \
                        --out "$shard_out/unicorn-report.json" \
                        > "$shard_out/unicorn-check.stdout"
                      jq -e \
                        '.status == "pass"
                         and .qualification == "qualified"
                         and .counts.cases > 0
                         and .counts.matched == .counts.cases
                         and .counts.mismatched == 0
                         and .counts.unsupported == 0
                         and .counts.errors == 0
                         and .proof_authority == false
                         and .closes_stage_a_proof == false' \
                        "$shard_out/unicorn-check.stdout" > /dev/null
                      spaghetti-extractor stage-a-check-isa-conformance \
                        --corpus ${imported}/corpus.json \
                        --backend lean \
                        --out "$shard_out/lean-report.json" \
                        --forms-out "$shard_out/lean-forms.json" \
                        > "$shard_out/lean-check.stdout"
                      jq -e \
                        '.status == "pass"
                         and .qualification == "qualified"
                         and .counts.cases > 0
                         and .counts.matched == .counts.cases
                         and .counts.mismatched == 0
                         and .counts.unsupported == 0
                         and .counts.errors == 0
                         and .proof_authority == false
                         and .closes_stage_a_proof == false' \
                        "$shard_out/lean-check.stdout" > /dev/null
                      corpus_sha256="$(sha256sum ${imported}/corpus.json | cut -d ' ' -f 1)"
                      report_sha256="$(sha256sum "$shard_out/report.json" | cut -d ' ' -f 1)"
                      unicorn_report_sha256="$(sha256sum "$shard_out/unicorn-report.json" | cut -d ' ' -f 1)"
                      lean_report_sha256="$(sha256sum "$shard_out/lean-report.json" | cut -d ' ' -f 1)"
                      lean_forms_sha256="$(sha256sum "$shard_out/lean-forms.json" | cut -d ' ' -f 1)"
                      import_manifest_sha256="$(sha256sum ${imported}/manifest.json | cut -d ' ' -f 1)"
                      runner_sha256="$(sha256sum ${bochs-conformance}/bin/spaghetti-bochs-conformance-runner | cut -d ' ' -f 1)"
                      guest_sha256="$(sha256sum ${bochs-conformance}/libexec/spaghetti-extractor/bochs-conformance/guest.img | cut -d ' ' -f 1)"
                      bochs_sha256="$(sha256sum ${bochs-conformance}/libexec/spaghetti-extractor/bochs-conformance/bochs-raw | cut -d ' ' -f 1)"
                      jq -n \
                        --arg opcode ${pkgs.lib.escapeShellArg opcode} \
                        --argjson shard_index ${toString shardIndex} \
                        --argjson shard_count 16 \
                        --arg bochs_store_path ${pkgs.lib.escapeShellArg (toString bochs-conformance)} \
                        --arg corpus_store_path ${pkgs.lib.escapeShellArg (toString imported)} \
                        --arg corpus_sha256 "$corpus_sha256" \
                        --arg report_sha256 "$report_sha256" \
                        --arg unicorn_report_sha256 "$unicorn_report_sha256" \
                        --arg lean_report_sha256 "$lean_report_sha256" \
                        --arg lean_forms_sha256 "$lean_forms_sha256" \
                        --arg import_manifest_sha256 "$import_manifest_sha256" \
                        --arg runner_sha256 "$runner_sha256" \
                        --arg guest_sha256 "$guest_sha256" \
                        --arg bochs_sha256 "$bochs_sha256" \
                        --slurpfile package_metadata ${bochs-conformance}/share/spaghetti-extractor/bochs-conformance/package-metadata.json \
                        '{
                          format: "stage-a-bochs-conformance-execution-v1",
                          source: {
                            opcode: $opcode,
                            shard_index: $shard_index,
                            shard_count: $shard_count,
                            corpus_store_path: $corpus_store_path,
                            corpus_sha256: $corpus_sha256,
                            import_manifest_sha256: $import_manifest_sha256
                          },
                          backend: {
                            store_path: $bochs_store_path,
                            runner_sha256: $runner_sha256,
                            guest_sha256: $guest_sha256,
                            bochs_binary_sha256: $bochs_sha256,
                            package: $package_metadata[0]
                          },
                          report: {
                            path: "report.json",
                            sha256: $report_sha256
                          },
                          unicorn_report: {
                            path: "unicorn-report.json",
                            sha256: $unicorn_report_sha256
                          },
                          lean_report: {
                            path: "lean-report.json",
                            sha256: $lean_report_sha256
                          },
                          lean_forms: {
                            path: "lean-forms.json",
                            sha256: $lean_forms_sha256
                          },
                          trust: {
                            role: "isa_conformance_evidence_only",
                            proof_authority: false,
                            closes_stage_a_proof: false
                          }
                        }' > "$shard_out/execution-manifest.json"
                      ln -s ${imported}/manifest.json "$shard_out/import-manifest.json"
                      ln -s ${imported}/corpus.json "$shard_out/corpus.json"
                    '')
                stageABochs80386ShardIndices)
            stageABochs80386Opcodes;
          stageABochs80386EvidenceIndex = pkgs.lib.concatMap
            (opcode:
              map
                (shardIndex: {
                  inherit opcode;
                  shard_index = shardIndex;
                  shard_count = 16;
                  path = "${opcode}/shard-${toString shardIndex}-of-16/execution-manifest.json";
                })
                stageABochs80386ShardIndices)
            stageABochs80386Opcodes;
          stage-a-isa-conformance-bochs-80386 = pkgs.runCommand
            "stage-a-isa-conformance-bochs-80386"
            { }
            ''
              mkdir -p "$out"
              ${pkgs.lib.concatMapStringsSep "\n"
                (opcode:
                  pkgs.lib.concatMapStringsSep "\n"
                    (shardIndex:
                      let
                        shard = builtins.elemAt stageABochs80386Shards (
                          (pkgs.lib.lists.findFirstIndex
                            (value: value == opcode) 0 stageABochs80386Opcodes)
                          * builtins.length stageABochs80386ShardIndices
                          + shardIndex
                        );
                        relative = "${opcode}/shard-${toString shardIndex}-of-16";
                      in ''
                        mkdir -p "$out/${opcode}"
                        ln -s "${shard}/${relative}" "$out/${relative}"
                      '')
                    stageABochs80386ShardIndices)
                stageABochs80386Opcodes}
              cat > "$out/index.json" <<'JSON'
              ${builtins.toJSON {
                format = "stage-a-isa-conformance-evidence-set-v1";
                suite = "SingleStepTests-80386-Bochs-Unicorn-Lean";
                shards = stageABochs80386EvidenceIndex;
                trust = {
                  role = "isa_conformance_evidence_only";
                  proof_authority = false;
                  closes_stage_a_proof = false;
                };
              }}
              JSON
            '';
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
          stageAGnuHelloCommonCflags = "-g0 -fno-asynchronous-unwind-tables -fno-ident -fno-inline -fno-inline-functions -fno-inline-small-functions -fno-ipa-cp -fno-ipa-sra -fno-ipa-icf";
          stageAGnuHelloOriginalCflags = "-O2 -fno-align-functions -fno-align-labels -fno-align-loops -fno-align-jumps ${stageAGnuHelloCommonCflags}";
          stageAGnuHelloCandidateCflags = "-O2 -falign-functions=32 -falign-labels=16 -falign-loops=16 -falign-jumps=16 ${stageAGnuHelloCommonCflags}";
          stageAGnuHelloLayoutLdflags = pkgs.lib.concatStringsSep " " [
            "-Wl,--section-start=.data=0x420000"
            "-Wl,--section-start=.rdata=0x421000"
            "-Wl,--section-start=.bss=0x430000"
            "-Wl,--section-start=.edata=0x431000"
            "-Wl,--section-start=.idata=0x432000"
            "-Wl,--section-start=.tls=0x433000"
            "-Wl,--section-start=.reloc=0x434000"
          ];
          mkStageAGnuHello =
            label: cflags:
            mingw32.hello.overrideAttrs (old: {
              pname = "stage-a-gnu-hello-${label}";
              doCheck = false;
              doInstallCheck = false;
              dontStrip = true;
              outputs = [ "out" ];
              env = (old.env or { }) // {
                CFLAGS = cflags;
                LDFLAGS = "${stageAGnuHelloLayoutLdflags} -Wl,-Map,hello-${label}.map";
              };
              postFixup = "";
              postInstall =
                (old.postInstall or "")
                + ''
                  map_path="$(find . -name 'hello-${label}.map' -print -quit)"
                  if [ -z "$map_path" ]; then
                    echo "missing hello-${label}.map" >&2
                    exit 1
                  fi
                  fixture_dir="$out/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/${label}"
                  mkdir -p "$fixture_dir"
                  cp "$map_path" "$fixture_dir/hello.map"
                  cp "$out/bin/hello.exe" "$fixture_dir/hello.exe"
                '';
              meta = (old.meta or { }) // {
                platforms = (old.meta.platforms or [ ]) ++ [ "i686-windows" ];
              };
            });
          stage-a-gnu-hello-original = mkStageAGnuHello "original" stageAGnuHelloOriginalCflags;
          stage-a-gnu-hello-candidate = mkStageAGnuHello "candidate" stageAGnuHelloCandidateCflags;
          stageAMinimalHelloCommonCflags = "-g0 -fno-asynchronous-unwind-tables -fno-ident";
          stageAMinimalHelloOriginalCflags = "-O2 -fno-align-functions -fno-align-labels -fno-align-loops -fno-align-jumps ${stageAMinimalHelloCommonCflags}";
          stageAMinimalHelloCandidateCflags = "-O2 -falign-functions=32 -falign-labels=16 -falign-loops=16 -falign-jumps=16 ${stageAMinimalHelloCommonCflags}";
          stageAMinimalHelloLayoutLdflags = stageAGnuHelloLayoutLdflags;
          mkStageAMinimalHello =
            label: cflags:
            mingw32.stdenv.mkDerivation {
              pname = "stage-a-minimal-hello-${label}";
              version = "1";
              src = ./tools/stage-a-fixtures;
              dontConfigure = true;
              dontStrip = true;

              buildPhase = ''
                runHook preBuild
                $CC ${cflags} ${stageAMinimalHelloLayoutLdflags} \
                  -Wl,-Map,hello-${label}.map \
                  -o hello.exe stage_a_hello.c
                runHook postBuild
              '';

              installPhase = ''
                runHook preInstall
                fixture_dir="$out/share/spaghetti-extractor/stage-a-minimal-hello-fixtures/${label}"
                mkdir -p "$fixture_dir"
                cp hello.exe "$fixture_dir/hello.exe"
                cp "hello-${label}.map" "$fixture_dir/hello.map"
                runHook postInstall
              '';
            };
          stage-a-minimal-hello-original =
            mkStageAMinimalHello "original" stageAMinimalHelloOriginalCflags;
          stage-a-minimal-hello-candidate =
            mkStageAMinimalHello "candidate" stageAMinimalHelloCandidateCflags;
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
          stage-a-gnu-hello-fixtures = pkgs.runCommand "stage-a-gnu-hello-fixtures"
            {
              nativeBuildInputs = [ pkgs.jq ];
            }
            ''
              fixture_dir="$out/share/spaghetti-extractor/stage-a-fixtures/gnu-hello-o2-alignment"
              mkdir -p "$fixture_dir"
              cp "${stage-a-gnu-hello-original}/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/original/hello.exe" "$fixture_dir/hello-original.exe"
              cp "${stage-a-gnu-hello-candidate}/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/candidate/hello.exe" "$fixture_dir/hello-candidate.exe"
              cp "${stage-a-gnu-hello-original}/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/original/hello.map" "$fixture_dir/hello-original.map"
              cp "${stage-a-gnu-hello-candidate}/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/candidate/hello.map" "$fixture_dir/hello-candidate.map"
              jq -n \
                --arg original_flags "${stageAGnuHelloOriginalCflags}" \
                --arg candidate_flags "${stageAGnuHelloCandidateCflags}" \
                --arg linker_flags "${stageAGnuHelloLayoutLdflags}" \
                --arg compiler "$(${mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc -dumpmachine)" \
                --arg compiler_version "$(${mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc -dumpfullversion -dumpversion)" \
                '{
                  format: "stage-a-gnu-hello-fixture-build-metadata-v1",
                  source: "GNU hello from pinned nixpkgs",
                  target: "i686-w64-mingw32",
                  original: { file: "hello-original.exe", linker_map: "hello-original.map", flags: $original_flags },
                  candidate: { file: "hello-candidate.exe", linker_map: "hello-candidate.map", flags: $candidate_flags },
                  linker_flags: $linker_flags,
                  compiler: { target: $compiler, version: $compiler_version }
                }' > "$fixture_dir/build-metadata.json"
            '';
          stage-a-gnu-hello-static-map = pkgs.runCommand "stage-a-gnu-hello-static-map"
            {
              nativeBuildInputs = [ spaghetti-extractor-core ];
            }
            ''
              fixture_dir="${stage-a-gnu-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/gnu-hello-o2-alignment"
              mkdir -p "$out"
              spaghetti-extractor stage-a-generate-map \
                --original "$fixture_dir/hello-original.exe" \
                --candidate "$fixture_dir/hello-candidate.exe" \
                --linker-map-original "$fixture_dir/hello-original.map" \
                --linker-map-candidate "$fixture_dir/hello-candidate.map" \
                --original-flags "${stageAGnuHelloOriginalCflags}" \
                --candidate-flags "${stageAGnuHelloCandidateCflags}" \
                --out "$out/hello-block-map.json" \
                --layout-contract-out "$out/hello-layout-contract.json" \
                > "$out/generate-map.stdout"
            '';
          stage-a-gnu-hello-relation-contract = pkgs.runCommand "stage-a-gnu-hello-relation-contract"
            {
              nativeBuildInputs = [ spaghetti-extractor-core ];
            }
            ''
              fixture_dir="${stage-a-gnu-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/gnu-hello-o2-alignment"
              mkdir -p "$out"
              spaghetti-extractor stage-a-generate-relation-contract \
                --original "$fixture_dir/hello-original.exe" \
                --candidate "$fixture_dir/hello-candidate.exe" \
                --mapping "${stage-a-gnu-hello-static-map}/hello-block-map.json" \
                --external-profile "${./profiles/pe32-kernel32-lockstep-v1.json}" \
                --external-profile "${./profiles/pe32-msvcrt-lockstep-v1.json}" \
                --out "$out/hello-relation-contract.json" \
                > "$out/generate-relation.stdout"
            '';
          stage-a-gnu-hello-preflight = pkgs.runCommand "stage-a-gnu-hello-preflight"
            {
              nativeBuildInputs = [
                spaghetti-extractor-core
                pkgs.lean4
                pkgs.jq
              ];
            }
            ''
              fixture_dir="${stage-a-gnu-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/gnu-hello-o2-alignment"
              work="$TMPDIR/stage-a-gnu-hello"
              mkdir -p "$work"
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-relational-kernel-cache}"
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_JOBS=16
              set +e
              SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$work/relational-cache" \
                spaghetti-extractor stage-a-prepare-relational \
                  --original "$fixture_dir/hello-original.exe" \
                  --candidate "$fixture_dir/hello-candidate.exe" \
                  --relation-contract "${stage-a-gnu-hello-relation-contract}/hello-relation-contract.json" \
                  --out "$work/relational-v3" \
                  > "$work/relational-v3.stdout" \
                  2> "$work/relational-v3.stderr"
              prepare_status=$?
              set -e
              if [ "$prepare_status" -eq 0 ]; then
                echo "GNU hello unexpectedly passed semantic preflight" >&2
                exit 1
              fi
              jq -e '
                .status == "incomplete" and
                (.issues | length) > 0 and
                ([.issues[].category] | unique) == ["formal_instruction_unsupported"]
              ' "$work/relational-v3/semantic-gaps.json" >/dev/null
              mkdir -p "$out/report"
              cp "${stage-a-gnu-hello-static-map}/hello-block-map.json" \
                "${stage-a-gnu-hello-static-map}/hello-layout-contract.json" \
                "${stage-a-gnu-hello-relation-contract}/hello-relation-contract.json" \
                "$out/report/"
              cp -R "$work/relational-v3" "$out/report/relational-v3"
              cp "$work/relational-v3.stdout" "$work/relational-v3.stderr" "$out/report/"
            '';
          stage-a-minimal-hello-fixtures = pkgs.runCommand "stage-a-minimal-hello-fixtures"
            {
              nativeBuildInputs = [ pkgs.jq ];
            }
            ''
              fixture_dir="$out/share/spaghetti-extractor/stage-a-fixtures/minimal-hello-o2-alignment"
              mkdir -p "$fixture_dir"
              cp "${stage-a-minimal-hello-original}/share/spaghetti-extractor/stage-a-minimal-hello-fixtures/original/hello.exe" "$fixture_dir/hello-original.exe"
              cp "${stage-a-minimal-hello-candidate}/share/spaghetti-extractor/stage-a-minimal-hello-fixtures/candidate/hello.exe" "$fixture_dir/hello-candidate.exe"
              cp "${stage-a-minimal-hello-original}/share/spaghetti-extractor/stage-a-minimal-hello-fixtures/original/hello.map" "$fixture_dir/hello-original.map"
              cp "${stage-a-minimal-hello-candidate}/share/spaghetti-extractor/stage-a-minimal-hello-fixtures/candidate/hello.map" "$fixture_dir/hello-candidate.map"
              jq -n \
                --arg original_flags "${stageAMinimalHelloOriginalCflags}" \
                --arg candidate_flags "${stageAMinimalHelloCandidateCflags}" \
                --arg linker_flags "${stageAMinimalHelloLayoutLdflags}" \
                --arg compiler "$(${mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc -dumpmachine)" \
                --arg compiler_version "$(${mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc -dumpfullversion -dumpversion)" \
                '{
                  format: "stage-a-minimal-hello-fixture-build-metadata-v1",
                  source: "tools/stage-a-fixtures/stage_a_hello.c",
                  target: "i686-w64-mingw32",
                  original: { file: "hello-original.exe", linker_map: "hello-original.map", flags: $original_flags },
                  candidate: { file: "hello-candidate.exe", linker_map: "hello-candidate.map", flags: $candidate_flags },
                  linker_flags: $linker_flags,
                  compiler: { target: $compiler, version: $compiler_version }
                }' > "$fixture_dir/build-metadata.json"
            '';
          stage-a-minimal-hello-static-map = pkgs.runCommand "stage-a-minimal-hello-static-map"
            {
              nativeBuildInputs = [ spaghetti-extractor-core ];
            }
            ''
              fixture_dir="${stage-a-minimal-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/minimal-hello-o2-alignment"
              mkdir -p "$out"
              spaghetti-extractor stage-a-generate-map \
                --original "$fixture_dir/hello-original.exe" \
                --candidate "$fixture_dir/hello-candidate.exe" \
                --linker-map-original "$fixture_dir/hello-original.map" \
                --linker-map-candidate "$fixture_dir/hello-candidate.map" \
                --original-flags "${stageAMinimalHelloOriginalCflags}" \
                --candidate-flags "${stageAMinimalHelloCandidateCflags}" \
                --out "$out/hello-block-map.json" \
                --layout-contract-out "$out/hello-layout-contract.json" \
                > "$out/generate-map.stdout"
            '';
          stage-a-minimal-hello-relation-contract = pkgs.runCommand "stage-a-minimal-hello-relation-contract"
            {
              nativeBuildInputs = [ spaghetti-extractor-core ];
            }
            ''
              fixture_dir="${stage-a-minimal-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/minimal-hello-o2-alignment"
              mkdir -p "$out"
              spaghetti-extractor stage-a-generate-relation-contract \
                --original "$fixture_dir/hello-original.exe" \
                --candidate "$fixture_dir/hello-candidate.exe" \
                --mapping "${stage-a-minimal-hello-static-map}/hello-block-map.json" \
                --external-profile "${./profiles/pe32-kernel32-lockstep-v1.json}" \
                --external-profile "${./profiles/pe32-msvcrt-lockstep-v1.json}" \
                --out "$out/hello-relation-contract.json" \
                > "$out/generate-relation.stdout"
            '';
          stage-a-minimal-hello-prepared-proof = pkgs.runCommand "stage-a-minimal-hello-prepared-proof"
            {
              nativeBuildInputs = [
                spaghetti-extractor-core
                pkgs.lean4
              ];
            }
            ''
              fixture_dir="${stage-a-minimal-hello-fixtures}/share/spaghetti-extractor/stage-a-fixtures/minimal-hello-o2-alignment"
              work="$TMPDIR/stage-a-minimal-hello"
              mkdir -p "$work"
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-relational-kernel-cache}"
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_JOBS=16
              SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$work/relational-cache" \
                spaghetti-extractor stage-a-prepare-relational \
                  --original "$fixture_dir/hello-original.exe" \
                  --candidate "$fixture_dir/hello-candidate.exe" \
                  --relation-contract "${stage-a-minimal-hello-relation-contract}/hello-relation-contract.json" \
                  --out "$work/relational-v3" \
                  > "$work/relational-v3.stdout"
              mkdir -p "$out/report"
              cp "${stage-a-minimal-hello-static-map}/hello-block-map.json" \
                "${stage-a-minimal-hello-static-map}/hello-layout-contract.json" \
                "${stage-a-minimal-hello-relation-contract}/hello-relation-contract.json" \
                "$out/report/"
              cp -R "$work/relational-v3" "$out/report/relational-v3"
              cp "$work/relational-v3.stdout" "$out/report/"
            '';
          stage-a-minimal-hello-proof-smoke =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              prepared = stage-a-minimal-hello-prepared-proof + "/report/relational-v3";
              targetNodes = [ "local-proof-pack-005" ];
              targetBundle = true;
            };
          stage-a-minimal-hello-check = pkgs.runCommand "stage-a-minimal-hello-check"
            {
              nativeBuildInputs = [ pkgs.jq ];
            }
            ''
              prepared="${stage-a-minimal-hello-prepared-proof}/report/relational-v3"
              jq -e '
                .status == "prepared" and
                .acceptance.status == "incomplete" and
                .acceptance.theorem == null and
                .composition_progress.status == "incomplete" and
                .composition_progress.counts.unsupported_instructions == 0 and
                .composition_progress.counts.rooted_reachable_nodes > 0 and
                .composition_progress.counts.rooted_reachable_feasible_edges > 0 and
                .composition_progress.counts.rooted_refined_segments > 0 and
                .composition_progress.counts.rooted_refined_segments <
                  .composition_progress.counts.rooted_reachable_feasible_edges
              ' "$prepared/prepared-proof.json" >/dev/null
              jq -e '.status == "supported" and (.issues | length) == 0' \
                "$prepared/semantic-gaps.json" >/dev/null
              jq -e '
                .format == "stage-a-lean-target-bundle-v1" and
                .lean_trust == 0 and
                ([.nodes[].id] | index("local-proof-pack-005")) != null
              ' "${stage-a-minimal-hello-proof-smoke}/bundle.json" >/dev/null
              mkdir -p "$out"
              cp "$prepared/prepared-proof.json" "$prepared/semantic-gaps.json" "$out/"
              cp "${stage-a-minimal-hello-proof-smoke}/bundle.json" "$out/proof-smoke-bundle.json"
            '';
          stage-a-jq-static-map = pkgs.runCommand "stage-a-jq-static-map"
            {
              nativeBuildInputs = [
                spaghetti-extractor-core
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment"
              mkdir -p "$out"
              spaghetti-extractor stage-a-generate-map \
                --original "$fixture_dir/jq-original.exe" \
                --candidate "$fixture_dir/jq-candidate.exe" \
                --linker-map-original "$fixture_dir/jq-original.map" \
                --linker-map-candidate "$fixture_dir/jq-candidate.map" \
                --original-flags "${stageAJqOriginalCflags}" \
                --candidate-flags "${stageAJqCandidateCflags}" \
                --out "$out/jq-block-map.json" \
                --layout-contract-out "$out/jq-layout-contract.json" \
                > "$out/generate-map.stdout"
            '';
          stage-a-jq-relation-contract = pkgs.runCommand "stage-a-jq-relation-contract"
            {
              nativeBuildInputs = [
                spaghetti-extractor-core
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment"
              mkdir -p "$out"
              spaghetti-extractor stage-a-generate-relation-contract \
                --original "$fixture_dir/jq-original.exe" \
                --candidate "$fixture_dir/jq-candidate.exe" \
                --mapping "${stage-a-jq-static-map}/jq-block-map.json" \
                --external-profile "${./profiles/pe32-kernel32-lockstep-v1.json}" \
                --external-profile "${./profiles/pe32-msvcrt-lockstep-v1.json}" \
                --out "$out/jq-relation-contract.json" \
                > "$out/generate-relation.stdout"
            '';
          stage-a-jq-prepared-proof = pkgs.runCommand "stage-a-jq-prepared-proof"
            {
              nativeBuildInputs = [
                spaghetti-extractor-core
                pkgs.lean4
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment"
              work="$TMPDIR/stage-a-jq"
              mkdir -p "$work"
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-relational-kernel-cache}"
              export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_JOBS=16
              SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$work/relational-cache" \
                spaghetti-extractor stage-a-prepare-relational \
                  --original "$fixture_dir/jq-original.exe" \
                  --candidate "$fixture_dir/jq-candidate.exe" \
                  --relation-contract "${stage-a-jq-relation-contract}/jq-relation-contract.json" \
                  --out "$work/relational-v3" \
                  > "$work/relational-v3.stdout"
              mkdir -p "$out/report"
              cp "${stage-a-jq-static-map}/jq-block-map.json" \
                "${stage-a-jq-static-map}/jq-layout-contract.json" \
                "${stage-a-jq-relation-contract}/jq-relation-contract.json" \
                "$out/report/"
              cp -R "$work/relational-v3" "$out/report/relational-v3"
            '';
          stage-a-jq-reference-contract = pkgs.runCommand "stage-a-jq-reference-contract"
            {
              nativeBuildInputs = [
                spaghetti-extractor
                pkgs.jq
              ];
            }
            ''
              fixture_dir="${stage-a-jq-fixtures}/share/spaghetti-extractor/stage-a-fixtures/jq-o2-alignment"
              prepared="${stage-a-jq-prepared-proof}/report"
              work="$TMPDIR/stage-a-jq-reference"
              mkdir -p "$work" "$out/generated"
              cp "$prepared/relational-v3/semantic-gaps.json" \
                "$out/generated/jq-formal-gaps.json"
              if spaghetti-extractor stage-a-export-reference-contract \
                  --original "$fixture_dir/jq-original.exe" \
                  --candidate "$fixture_dir/jq-candidate.exe" \
                  --mapping "$prepared/jq-block-map.json" \
                  --validation-report "$prepared/relational-v3" \
                  --layout-contract "$prepared/jq-layout-contract.json" \
                  --sidecar-dir "$out/generated" \
                  --unit-contract-dir "$out/generated" \
                  --out "$out/generated/jq-reference-contract.json" \
                  > "$work/reference-contract.stdout"; then
                echo "jq reference contract unexpectedly claimed formal completion" >&2
                exit 1
              fi
              jq -e '.status == "incomplete"' \
                "$out/generated/jq-reference-contract.json" >/dev/null
              spaghetti-extractor stage-a-smoke-contract \
                --reference-contract "$out/generated/jq-reference-contract.json" \
                --out "$out/generated/contract-smoke.json" \
                > "$work/smoke.stdout"
              jq -e '.status == "pass"' \
                "$out/generated/contract-smoke.json" >/dev/null
            '';
          stage-a-jq-fixtures-check = pkgs.runCommand "stage-a-jq-fixtures-check"
            {
              nativeBuildInputs = [ pkgs.jq ];
            }
            ''
              prepared="${stage-a-jq-prepared-proof}/report"
              generated="${stage-a-jq-reference-contract}/generated"
              jq -e '
                .status == "prepared" and
                .acceptance.status == "incomplete" and
                .acceptance.theorem == null and
                .composition_progress.status == "incomplete" and
                .composition_progress.counts.rooted_reachable_nodes > 0 and
                .composition_progress.counts.rooted_reachable_feasible_edges > 0 and
                .composition_progress.counts.rooted_external_refinement_candidates > 0 and
                .composition_progress.counts.rooted_refined_segments > 0 and
                .composition_progress.counts.rooted_refined_segments <
                  .composition_progress.counts.rooted_reachable_feasible_edges and
                .composition_progress.counts.unsupported_instructions == 0 and
                .composition_progress.reachability_assurance.status == "incomplete" and
                (.composition_progress.reachability_assurance.blocker_totals.coverage_bearing | not) and
                (.composition_progress.reachability_assurance.blocker_totals.comparable | not) and
                .composition_progress.reachability_assurance.conservative_potential_reachability.node_count ==
                  .composition_progress.counts.potential_reachable_nodes and
                .composition_progress.reachability_assurance.represented_rooted_reachability.node_count ==
                  .composition_progress.counts.rooted_reachable_nodes and
                .composition_progress.reachability_assurance.conservative_potential_reachability.node_count >
                  .composition_progress.reachability_assurance.represented_rooted_reachability.node_count
              ' "$prepared/relational-v3/prepared-proof.json" >/dev/null
              jq -e '
                (.launch.original_is_dll | not) and
                (.launch.candidate_is_dll | not) and
                .launch.original_exports == [] and
                .launch.candidate_exports == [] and
                (.launch.original_tls_callback_rvas | length) == 2 and
                (.launch.candidate_tls_callback_rvas | length) == 2 and
                (.launch.tls_callback_target_ids | length) == 2 and
                (.machine_import_call_contracts | any(
                  .import.dll == "kernel32.dll" and
                  .import.symbol == "TlsGetValue" and
                  .world_effect == "tlsState")) and
                (.machine_import_call_contracts | any(
                  .import.dll == "msvcrt.dll" and
                  .import.symbol == "free" and
                  .world_effect == "dynamicRangeRelease")) and
                (.machine_import_call_contracts | any(
                  .import.dll == "msvcrt.dll" and
                  .import.symbol == "atexit" and
                  .world_effect == "callbackRegistration")) and
                (.machine_import_call_contracts | any(
                  .import.dll == "msvcrt.dll" and
                  .import.symbol == "exit" and
                  .disposition == "protocol"))
              ' "$prepared/relational-v3/relation-contract.json" >/dev/null
              jq -e '.format == "stage-a-interface-manifest-v1"' \
                "$prepared/relational-v3/stage-a-interface-manifest.json" >/dev/null
              jq -e '.status == "supported" and .counts.issues == 0' \
                "$prepared/relational-v3/semantic-gaps.json" >/dev/null
              jq -e '.status == "incomplete"' \
                "$generated/jq-reference-contract.json" >/dev/null
              jq -e '.status == "pass"' \
                "$generated/contract-smoke.json" >/dev/null
              mkdir -p "$out"
              ln -s "$prepared" "$out/report"
              ln -s "$generated" "$out/generated"
            '';
          relationalLeanSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = ./src/spaghetti_extractor/lean/StageA;
          };
          relationalKernelModules = [
            "Formal"
            "ISAQualification"
            "ISAConformance"
            "ISAConformanceRunner"
            "RelationalDecode"
            "RelationalLoader"
            "RelationalMachine"
            "RelationalPEExecution"
            "RelationalISAQualification"
            "Relational"
            "RelationalInvariant"
            "RelationalExecution"
            "RelationalImage"
            "RelationalSegment"
            "RelationalComposition"
            "RelationalLinkedFrames"
            "RelationalEnvironment"
            "RelationalCallbacks"
            "RelationalCertificates"
            "RelationalPEWorldExecution"
            "RelationalStaticTree"
          ];
          isaKernelModules = [
            "Formal"
            "ISAQualification"
            "ISAConformance"
            "ISAConformanceRunner"
          ];
          stage-a-isa-kernel-cache =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              standaloneSourceRoot =
                relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
              standaloneModules = isaKernelModules;
              targetNodes = isaKernelModules;
              targetBundle = true;
            };
          stage-a-relational-kernel-cache =
            import ./nix/stage-a-lean-graph.nix {
              inherit pkgs;
              standaloneSourceRoot =
                relationalLeanSource + "/src/spaghetti_extractor/lean/StageA";
              standaloneModules = relationalKernelModules;
              targetNodes = relationalKernelModules;
              targetBundle = true;
            };
          mkStageARelationalTest = name: module: testFiles:
            let
              usesLean =
                builtins.elem name [ "state" "lean" "pipeline" ]
                || pkgs.lib.hasPrefix "state-" name
                || pkgs.lib.hasPrefix "lean-" name
                || pkgs.lib.hasPrefix "pipeline-" name
                || pkgs.lib.hasPrefix "contract" name
                || pkgs.lib.hasPrefix "acceptance" name;
              testSource = pkgs.lib.fileset.toSource {
                root = ./.;
                fileset = pkgs.lib.fileset.unions (
                  [
                    ./tests/stage_a_relational_support.py
                  ]
                  ++ testFiles
                  ++ pkgs.lib.optionals usesLean
                    [ ./src/spaghetti_extractor/lean/StageA ]
                  ++ pkgs.lib.optionals (pkgs.lib.hasPrefix "contract" name)
                    [ ./nix/stage-a-lean-graph.nix ]
                );
              };
            in
            pkgs.runCommand "stage-a-relational-tests-${name}"
              {
                nativeBuildInputs = [
                  spaghetti-extractor
                  pythonEnv
                  pkgs.lean4
                ];
              }
              ''
                export HOME="$TMPDIR/home"
                export XDG_CACHE_HOME="$TMPDIR/xdg-cache"
                export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$TMPDIR/relational-cache"
                ${pkgs.lib.optionalString usesLean ''
                  export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${stage-a-relational-kernel-cache}"
                ''}
                export PYTHONPATH="${spaghetti-extractor}/${pkgs.python3.sitePackages}:${pythonEnv}/${pkgs.python3.sitePackages}:${testSource}:${testSource}/tests"
                mkdir -p "$HOME" "$XDG_CACHE_HOME" "$SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE"
                cd "$TMPDIR"
                python -m unittest -v ${module}
                mkdir -p "$out/${name}"
                printf '%s\n' '${module}' > "$out/${name}/test-module.txt"
              '';
          mkStageARelationalTestSuite = name: module: className: testFile:
            let
              testMethods = builtins.filter (method: method != null) (
                map
                  (line:
                    let
                      matched = builtins.match
                        "^    def (test_[A-Za-z0-9_]+)\\(self.*$" line;
                    in
                    if matched == null then null else builtins.head matched)
                  (pkgs.lib.splitString "\n" (builtins.readFile testFile))
              );
              cases = builtins.listToAttrs (
                map
                  (method:
                    let caseName = pkgs.lib.removePrefix "test_" method;
                    in {
                      name = caseName;
                      value = mkStageARelationalTest
                        "${name}-${caseName}"
                        "${module}.${className}.${method}"
                        [ testFile ];
                    })
                  testMethods
              );
            in
            {
              inherit cases;
              aggregate = pkgs.symlinkJoin {
                name = "stage-a-relational-tests-${name}";
                paths = builtins.attrValues cases;
              };
            };
          stage-a-relational-tests-schema = mkStageARelationalTest
            "schema"
            "tests.test_relational_schema tests.test_contract_tools.ContractToolTests.test_cli_exposes_one_stage_a_authority_and_candidate_only_stage_b_tools"
            [
              ./tests/test_relational_schema.py
              ./tests/test_contract_tools.py
              ./tests/contract_fixtures.py
              ./tests/pe_fixtures.py
            ];
          stage-a-relational-tests-build-graph = mkStageARelationalTest
            "build-graph"
            "tests.test_stage_a_build_graph"
            [
              ./tests/test_stage_a_build_graph.py
              ./flake.lock
            ];
          stage-a-relational-tests-static-word-relations = mkStageARelationalTest
            "acceptance-static-word-relations"
            "tests.test_stage_a_static_word_relations"
            [ ./tests/test_stage_a_static_word_relations.py ];
          stage-a-relational-tests-external-protocol = mkStageARelationalTest
            "external-protocol"
            "tests.test_stage_a_external_protocol"
            [
              ./tests/test_stage_a_external_protocol.py
              ./profiles/pe32-msvcrt-lockstep-v1.json
            ];
          stage-a-relational-tests-external-contract-selection =
            mkStageARelationalTest
              "external-contract-selection"
              "tests.test_stage_a_external_contract_selection"
              [ ./tests/test_stage_a_external_contract_selection.py ];
          stage-a-relational-tests-external-stateful-memory =
            mkStageARelationalTest
              "external-stateful-memory"
              "tests.test_stage_a_external_stateful_memory"
              [
                ./tests/test_stage_a_external_stateful_memory.py
                ./profiles/pe32-msvcrt-lockstep-v1.json
              ];
          stage-a-relational-tests-external-stateful-memory-kernel =
            mkStageARelationalTest
              "lean-external-stateful-memory"
              "tests.test_stage_a_external_stateful_memory_kernel"
              [ ./tests/test_stage_a_external_stateful_memory_kernel.py ];
          stage-a-relational-tests-reachable-acceptance =
            mkStageARelationalTest
              "reachable-acceptance"
              "tests.test_stage_a_reachable_acceptance"
              [ ./tests/test_stage_a_reachable_acceptance.py ];
          stage-a-relational-tests-pe-entry-surface =
            mkStageARelationalTest
              "pe-entry-surface"
              "tests.test_stage_a_pe_entry_surface"
              [
                ./tests/test_stage_a_pe_entry_surface.py
                ./tests/pe_fixtures.py
              ];
          stage-a-relational-tests-formal-pe-entry-surface =
            mkStageARelationalTest
              "lean-formal-pe-entry-surface"
              "tests.test_stage_a_formal_pe_entry_surface"
              [ ./tests/test_stage_a_formal_pe_entry_surface.py ];
          stage-a-relational-tests-proof-blocked =
            mkStageARelationalTest
              "lean-proof-blocked"
              "tests.test_stage_a_proof_blocked"
              [ ./tests/test_stage_a_proof_blocked.py ];
          stage-a-relational-tests-loader-image-diagnostics =
            mkStageARelationalTest
              "loader-image-diagnostics"
              "tests.test_stage_a_loader_image_diagnostics"
              [
                ./tests/test_stage_a_loader_image_diagnostics.py
                ./tests/pe_fixtures.py
              ];
          stage-a-relational-tests-loader-image-valid =
            mkStageARelationalTest
              "lean-loader-image-valid"
              "tests.test_stage_a_loader_image_valid"
              [ ./tests/test_stage_a_loader_image_valid.py ];
          stage-a-relational-tests-raw-eip-execution =
            mkStageARelationalTest
              "lean-raw-eip-execution"
              "tests.test_stage_a_raw_eip_execution"
              [
                ./tests/test_stage_a_raw_eip_execution.py
                ./tests/pe_fixtures.py
              ];
          stage-a-relational-tests-indirect-control = mkStageARelationalTest
            "indirect-control"
            "tests.test_stage_a_indirect_control tests.test_stage_a_initial_static_code_pointers"
            [
              ./tests/test_stage_a_indirect_control.py
              ./tests/test_stage_a_initial_static_code_pointers.py
            ];
          stage-a-relational-tests-control-provenance = mkStageARelationalTest
            "control-provenance"
            "tests.test_stage_a_control_provenance"
            [ ./tests/test_stage_a_control_provenance.py ];
          stage-a-relational-tests-isa-conformance = mkStageARelationalTest
            "isa-conformance"
            "tests.test_stage_a_isa_conformance"
            [ ./tests/test_stage_a_isa_conformance.py ];
          stage-a-relational-tests-isa-conformance-kernel =
            mkStageARelationalTest
              "lean-isa-conformance-kernel"
              "tests.test_stage_a_isa_conformance_kernel"
              [ ./tests/test_stage_a_isa_conformance_kernel.py ];
          stage-a-relational-tests-isa-conformance-lean =
            mkStageARelationalTest
              "lean-isa-conformance-runner"
              "tests.test_stage_a_isa_conformance_lean"
              [
                ./tests/test_stage_a_isa_conformance.py
                ./tests/test_stage_a_isa_conformance_lean.py
              ];
          stage-a-relational-tests-isa-conformance-unicorn =
            mkStageARelationalTest
              "isa-conformance-unicorn"
              "tests.test_stage_a_isa_conformance_unicorn"
              [ ./tests/test_stage_a_isa_conformance_unicorn.py ];
          stage-a-relational-tests-isa-conformance-bochs =
            mkStageARelationalTest
              "isa-conformance-bochs"
              "tests.test_stage_a_isa_conformance_bochs"
              [ ./tests/test_stage_a_isa_conformance_bochs.py ];
          stage-a-relational-tests-isa-conformance-differential =
            mkStageARelationalTest
              "lean-isa-conformance-differential"
              "tests.test_stage_a_isa_conformance_differential"
              [
                ./tests/test_stage_a_isa_conformance_differential.py
                ./tests/test_stage_a_isa_conformance_unicorn.py
              ];
          stage-a-relational-tests-isa-conformance-80386 =
            mkStageARelationalTest
              "isa-conformance-80386-import"
              "tests.test_stage_a_isa_conformance_80386"
              [ ./tests/test_stage_a_isa_conformance_80386.py ];
          stage-a-relational-tests-isa-conformance-80386-differential =
            mkStageARelationalTest
              "lean-isa-conformance-80386-differential"
              "tests.test_stage_a_isa_conformance_80386_differential"
              [
                ./tests/test_stage_a_isa_conformance_80386.py
                ./tests/test_stage_a_isa_conformance_80386_differential.py
              ];
          stage-a-relational-tests-bounded-table-call-generation =
            mkStageARelationalTest
              "bounded-table-call-generation"
              "tests.test_stage_a_bounded_table_call_generation"
              [ ./tests/test_stage_a_bounded_table_call_generation.py ];
          stage-a-relational-tests-bounded-table-call-kernel =
            mkStageARelationalTest
              "lean-bounded-table-call-kernel"
              "tests.test_stage_a_bounded_table_call_kernel"
              [ ./tests/test_stage_a_bounded_table_call_kernel.py ];
          stage-a-relational-tests-reverse-sentinel-scanner-integration =
            mkStageARelationalTest
              "lean-reverse-sentinel-scanner-integration"
              "tests.test_stage_a_reverse_sentinel_scanner_integration"
              [ ./tests/test_stage_a_reverse_sentinel_scanner_integration.py ];
          stage-a-relational-tests-callsite-preservation = mkStageARelationalTest
            "callsite-preservation"
            "tests.test_stage_a_callsite_preservation"
            [ ./tests/test_stage_a_callsite_preservation.py ];
          stage-a-relational-tests-callsite-summary-generation =
            mkStageARelationalTest
              "callsite-summary-generation"
              "tests.test_stage_a_callsite_summary_generation"
              [ ./tests/test_stage_a_callsite_summary_generation.py ];
          stage-a-relational-tests-call-return-summary =
            mkStageARelationalTest
              "call-return-summary"
              "tests.test_stage_a_call_return_summary"
              [ ./tests/test_stage_a_call_return_summary.py ];
          stage-a-relational-tests-callsite-preservation-schema =
            mkStageARelationalTest
              "callsite-preservation-schema"
              "tests.test_stage_a_callsite_preservation_schema"
              [ ./tests/test_stage_a_callsite_preservation_schema.py ];
          stage-a-relational-tests-register-analysis =
            mkStageARelationalTest
              "register-analysis"
              "tests.test_stage_a_register_analysis"
              [ ./tests/test_stage_a_register_analysis.py ];
          stage-a-relational-tests-lean-runtime-frame-import-environment =
            mkStageARelationalTest
              "lean-runtime-frame-import-environment"
              "tests.test_stage_a_runtime_frame_import_environment"
              [ ./tests/test_stage_a_runtime_frame_import_environment.py ];
          stage-a-relational-tests-acceptance-runtime-frame-import =
            mkStageARelationalTest
              "acceptance-runtime-frame-import"
              "tests.test_stage_a_runtime_frame_import_acceptance"
              [ ./tests/test_stage_a_runtime_frame_import_acceptance.py ];
          stage-a-relational-tests-acceptance-runtime-frame-register =
            mkStageARelationalTest
              "acceptance-runtime-frame-register"
              "tests.test_stage_a_runtime_frame_register_acceptance"
              [ ./tests/test_stage_a_runtime_frame_register_acceptance.py ];
          stageARelationalContractSuite = mkStageARelationalTestSuite
            "contract" "tests.test_stage_a_relational_contract"
            "StageARelationalContractTests" ./tests/test_stage_a_relational_contract.py;
          stageARelationalStateSuite = mkStageARelationalTestSuite
            "state" "tests.test_stage_a_relational_state"
            "StageARelationalStateTests" ./tests/test_stage_a_relational_state.py;
          stageARelationalPipelineSuite = mkStageARelationalTestSuite
            "pipeline" "tests.test_stage_a_relational_pipeline"
            "StageARelationalPipelineTests" ./tests/test_stage_a_relational_pipeline.py;
          stageARelationalLeanSuite = mkStageARelationalTestSuite
            "lean" "tests.test_stage_a_relational_lean"
            "StageARelationalLeanTests" ./tests/test_stage_a_relational_lean.py;
          stageARelationalAcceptanceSuite = mkStageARelationalTestSuite
            "acceptance" "tests.test_stage_a_relational_acceptance"
            "StageARelationalAcceptanceTests" ./tests/test_stage_a_relational_acceptance.py;
          stage-a-relational-tests-contract = stageARelationalContractSuite.aggregate;
          stage-a-relational-tests-state = stageARelationalStateSuite.aggregate;
          stage-a-relational-tests-pipeline = stageARelationalPipelineSuite.aggregate;
          stage-a-relational-tests-pipeline-cmov-general-composition =
            stageARelationalPipelineSuite.cases.cmov_expression_emits_general_compositional_components;
          stage-a-relational-tests-lean = stageARelationalLeanSuite.aggregate;
          stage-a-relational-tests-lean-return-slot-inventory =
            stageARelationalLeanSuite.cases.import_register_indirect_call_witness_is_checked_by_lean;
          stage-a-relational-tests-lean-dynamic-range-result =
            stageARelationalLeanSuite.cases.dynamic_range_result_relation_is_checked_by_lean;
          stage-a-relational-tests-lean-linked-frames =
            stageARelationalLeanSuite.cases.linked_runtime_frames_support_an_arbitrary_dormant_tail;
          stage-a-relational-tests-contract-machine-import =
            stageARelationalContractSuite.cases.machine_import_call_contract_validation_fails_closed;
          stage-a-relational-tests-acceptance = stageARelationalAcceptanceSuite.aggregate;
          stage-a-relational-tests-acceptance-whole-program-kernel =
            stageARelationalAcceptanceSuite.cases.whole_program_equivalence_kernel_checks_without_sorry;
          stage-a-relational-tests-acceptance-instruction-adequacy =
            stageARelationalAcceptanceSuite.cases.instruction_semantics_adequacy_rejects_ambiguous_pe_fetch;
          stage-a-relational-tests-acceptance-instruction-adequacy-tamper =
            stageARelationalAcceptanceSuite.cases.instruction_adequacy_aggregate_rejects_tampered_region_span;
          stage-a-relational-tests-acceptance-instruction-adequacy-multi-chunk =
            stageARelationalAcceptanceSuite.cases.instruction_adequacy_aggregate_composes_multiple_chunks;
          stage-a-relational-tests-acceptance-entry-surface =
            stageARelationalAcceptanceSuite.cases.console_launch_rejects_dll_and_export_entry_surfaces;
          stage-a-relational-tests-acceptance-direct-loop =
            stageARelationalAcceptanceSuite.cases.direct_loop_emits_and_checks_closed_whole_program_theorem;
          stage-a-relational-tests-acceptance-canonical-region =
            stageARelationalAcceptanceSuite.cases.whole_program_theorem_rejects_noncanonical_reachable_region;
          stage-a-relational-tests-acceptance-executable-coverage =
            stageARelationalAcceptanceSuite.cases.whole_program_theorem_rejects_tampered_executable_partition;
          stage-a-relational-tests-acceptance-semantic-code-aliases =
            stageARelationalAcceptanceSuite.cases.whole_program_theorem_requires_semantic_code_alias_bridges;
          stage-a-relational-tests-acceptance-tls-launch =
            stageARelationalAcceptanceSuite.cases.tls_directory_is_parsed_and_rejected_by_console_launch_v1;
          stage-a-relational-tests-acceptance-tls-parsing =
            stageARelationalAcceptanceSuite.cases.formal_tls_directory_and_callback_parsing;
          stage-a-relational-tests-acceptance-tls-roots =
            stageARelationalAcceptanceSuite.cases.tls_callbacks_become_lean_checked_launch_roots;
          stage-a-relational-tests-acceptance-control-frontier =
            stageARelationalAcceptanceSuite.cases.control_frontier_does_not_hide_independent_reachable_branch;
          stage-a-relational-tests-acceptance-nested-external =
            stageARelationalAcceptanceSuite.cases.nested_external_call_preserves_internal_runtime_frame_end_to_end;
          stage-a-relational-tests-acceptance-protocol-callback =
            stageARelationalAcceptanceSuite.cases.protocol_call_and_callback_return_close_whole_program_theorem;
          stage-a-relational-tests-acceptance-import-register-return =
            stageARelationalAcceptanceSuite.cases.import_register_survives_checked_internal_call_and_return;
          stage-a-relational-tests-acceptance-direct-stack-read =
            stageARelationalAcceptanceSuite.cases.direct_paired_stack_read_loop_closes_whole_program_theorem;
          stage-a-relational-tests-acceptance-below-frame-stack-read =
            stageARelationalAcceptanceSuite.cases.below_frame_stack_read_closes_only_for_same_checked_location;
          stage-a-relational-tests-acceptance-below-frame-stack-guard =
            stageARelationalAcceptanceSuite.cases.below_frame_zero_guard_closes_only_for_same_checked_location;
          stage-a-relational-tests-acceptance-stack-base-related-word =
            stageARelationalAcceptanceSuite.cases.preserved_stack_base_becomes_related_word_at_successor;
          stage-a-relational-tests-state-dynamic-flow-call-boundary =
            stageARelationalStateSuite.cases.dynamic_range_flow_does_not_cross_call_frames;
          stage-a-relational-tests-acceptance-representative =
            stageARelationalAcceptanceSuite.cases.representative_control_slice_closes_whole_program_theorem;
          stage-a-relational-tests-acceptance-terminal-return =
            stageARelationalAcceptanceSuite.cases.top_level_return_checks_terminal_invariant_end_to_end;
          stage-a-relational-tests-acceptance-external-loop =
            stageARelationalAcceptanceSuite.cases.external_call_loop_checks_paired_environment_end_to_end;
          stage-a-relational-tests-acceptance-external-allocation =
            stageARelationalAcceptanceSuite.cases.external_allocation_and_dynamic_write_close_whole_program_theorem;
          stage-a-relational-tests-acceptance-input-flag-guard =
            stageARelationalAcceptanceSuite.cases.input_flag_guard_closes_only_for_the_same_checked_flag;
          stage-a-relational-tests-acceptance-exact-pure-guard =
            stageARelationalAcceptanceSuite.cases.exact_pure_guard_uses_derived_register_exactness;
          stage-a-relational-tests-acceptance-exact-to-related =
            stageARelationalAcceptanceSuite.cases.exact_register_output_weakens_to_related_successor;
          stage-a-relational-tests-acceptance-exact-register-transfer =
            stageARelationalAcceptanceSuite.cases.exact_register_transfer_and_cfg_edge_are_checked_by_lean;
          stage-a-relational-tests-acceptance-immutable-image-word =
            stageARelationalAcceptanceSuite.cases.immutable_image_word_load_closes_register_transfer;
          stage-a-relational-tests-acceptance-fixed-immutable-expression =
            stageARelationalAcceptanceSuite.cases.fixed_immutable_expression_chain_closes_whole_program_theorem;
          stage-a-relational-tests-acceptance-static-word-slot =
            stageARelationalAcceptanceSuite.cases.static_word_slot_load_closes_register_transfer;
          stage-a-relational-tests-acceptance-paired-static-word-guard =
            stageARelationalAcceptanceSuite.cases.paired_static_word_guard_closes_whole_program_theorem;
          stage-a-relational-tests-acceptance-immutable-pe-pointer-chain =
            stageARelationalAcceptanceSuite.cases.immutable_pe_pointer_chain_guard_closes_whole_program_theorem;
          stage-a-relational-tests-acceptance-immutable-pe-header =
            stageARelationalAcceptanceSuite.cases.immutable_mapped_pe_header_read8_closes_exact_guard;
          stage-a-relational-tests-acceptance-direct-call-stack-writes =
            stageARelationalAcceptanceSuite.cases.direct_call_with_prepared_stack_word_checks_whole_program_theorem;
          stage-a-relational-tests-acceptance-dynamic-spill =
            stageARelationalAcceptanceSuite.cases.dynamic_base_spill_with_field_write_is_checked_by_lean;
          stage-a-relational-tests-acceptance-direct-call-static-writes =
            stageARelationalAcceptanceSuite.cases.direct_call_with_prepared_static_word_checks_whole_program_theorem;
          stage-a-relational-tests = pkgs.symlinkJoin {
            name = "stage-a-relational-tests";
            paths = [
              stage-a-relational-tests-schema
              stage-a-relational-tests-build-graph
              stage-a-relational-tests-static-word-relations
              stage-a-relational-tests-external-protocol
              stage-a-relational-tests-external-contract-selection
              stage-a-relational-tests-external-stateful-memory
              stage-a-relational-tests-external-stateful-memory-kernel
              stage-a-relational-tests-reachable-acceptance
              stage-a-relational-tests-pe-entry-surface
              stage-a-relational-tests-formal-pe-entry-surface
              stage-a-relational-tests-proof-blocked
              stage-a-relational-tests-loader-image-diagnostics
              stage-a-relational-tests-loader-image-valid
              stage-a-relational-tests-raw-eip-execution
              stage-a-relational-tests-indirect-control
              stage-a-relational-tests-control-provenance
              stage-a-relational-tests-isa-conformance
              stage-a-relational-tests-isa-conformance-kernel
              stage-a-relational-tests-isa-conformance-lean
              stage-a-relational-tests-isa-conformance-unicorn
              stage-a-relational-tests-isa-conformance-bochs
              stage-a-relational-tests-isa-conformance-differential
              stage-a-relational-tests-isa-conformance-80386
              stage-a-relational-tests-isa-conformance-80386-differential
              stage-a-relational-tests-bounded-table-call-generation
              stage-a-relational-tests-bounded-table-call-kernel
              stage-a-relational-tests-callsite-preservation
              stage-a-relational-tests-callsite-summary-generation
              stage-a-relational-tests-call-return-summary
              stage-a-relational-tests-callsite-preservation-schema
              stage-a-relational-tests-register-analysis
              stage-a-relational-tests-lean-runtime-frame-import-environment
              stage-a-relational-tests-acceptance-runtime-frame-import
              stage-a-relational-tests-acceptance-runtime-frame-register
              stage-a-relational-tests-contract
              stage-a-relational-tests-state
              stage-a-relational-tests-pipeline
              stage-a-relational-tests-lean
              stage-a-relational-tests-acceptance
            ];
          };
          stage-a-jq-fixtures-root = pkgs.writeShellApplication {
            name = "stage-a-jq-fixtures-root";
            text = ''
              printf '%s\n' "${stage-a-jq-fixtures}"
            '';
          };
          stage-a-gnu-hello-fixtures-root = pkgs.writeShellApplication {
            name = "stage-a-gnu-hello-fixtures-root";
            text = ''
              printf '%s\n' "${stage-a-gnu-hello-fixtures}"
            '';
          };
          stage-a-minimal-hello-fixtures-root = pkgs.writeShellApplication {
            name = "stage-a-minimal-hello-fixtures-root";
            text = ''
              printf '%s\n' "${stage-a-minimal-hello-fixtures}"
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
            bochs-conformance
            singlestep-80386-conformance
            spaghetti-extractor
            stage-a-isa-conformance-bochs-80386
            stage-a-isa-kernel-cache
            stage-a-fixtures
            stage-a-fixtures-check
            stage-a-fixtures-root
            stage-a-gnu-hello-fixtures
            stage-a-gnu-hello-static-map
            stage-a-gnu-hello-relation-contract
            stage-a-gnu-hello-preflight
            stage-a-gnu-hello-fixtures-root
            stage-a-minimal-hello-fixtures
            stage-a-minimal-hello-static-map
            stage-a-minimal-hello-relation-contract
            stage-a-minimal-hello-prepared-proof
            stage-a-minimal-hello-proof-smoke
            stage-a-minimal-hello-check
            stage-a-minimal-hello-fixtures-root
            stage-a-jq-fixtures
            stage-a-jq-static-map
            stage-a-jq-relation-contract
            stage-a-jq-prepared-proof
            stage-a-jq-reference-contract
            stage-a-jq-fixtures-check
            stage-a-jq-fixtures-root
            stage-a-relational-kernel-cache
            stage-a-relational-tests
            stage-a-relational-tests-schema
            stage-a-relational-tests-build-graph
            stage-a-relational-tests-static-word-relations
            stage-a-relational-tests-external-protocol
            stage-a-relational-tests-external-contract-selection
            stage-a-relational-tests-external-stateful-memory
            stage-a-relational-tests-external-stateful-memory-kernel
            stage-a-relational-tests-reachable-acceptance
            stage-a-relational-tests-pe-entry-surface
            stage-a-relational-tests-formal-pe-entry-surface
            stage-a-relational-tests-proof-blocked
            stage-a-relational-tests-loader-image-diagnostics
            stage-a-relational-tests-loader-image-valid
            stage-a-relational-tests-raw-eip-execution
            stage-a-relational-tests-indirect-control
            stage-a-relational-tests-control-provenance
            stage-a-relational-tests-isa-conformance
            stage-a-relational-tests-isa-conformance-kernel
            stage-a-relational-tests-isa-conformance-lean
            stage-a-relational-tests-isa-conformance-unicorn
            stage-a-relational-tests-isa-conformance-bochs
            stage-a-relational-tests-isa-conformance-differential
            stage-a-relational-tests-isa-conformance-80386
            stage-a-relational-tests-isa-conformance-80386-differential
            stage-a-relational-tests-bounded-table-call-generation
            stage-a-relational-tests-bounded-table-call-kernel
            stage-a-relational-tests-reverse-sentinel-scanner-integration
            stage-a-relational-tests-callsite-preservation
            stage-a-relational-tests-callsite-summary-generation
            stage-a-relational-tests-call-return-summary
            stage-a-relational-tests-callsite-preservation-schema
            stage-a-relational-tests-register-analysis
            stage-a-relational-tests-lean-runtime-frame-import-environment
            stage-a-relational-tests-acceptance-runtime-frame-import
            stage-a-relational-tests-acceptance-runtime-frame-register
            stage-a-relational-tests-contract
            stage-a-relational-tests-state
            stage-a-relational-tests-pipeline
            stage-a-relational-tests-pipeline-cmov-general-composition
            stage-a-relational-tests-lean
            stage-a-relational-tests-lean-return-slot-inventory
            stage-a-relational-tests-lean-dynamic-range-result
            stage-a-relational-tests-lean-linked-frames
            stage-a-relational-tests-contract-machine-import
            stage-a-relational-tests-acceptance
            stage-a-relational-tests-acceptance-whole-program-kernel
            stage-a-relational-tests-acceptance-instruction-adequacy
            stage-a-relational-tests-acceptance-instruction-adequacy-tamper
            stage-a-relational-tests-acceptance-instruction-adequacy-multi-chunk
            stage-a-relational-tests-acceptance-entry-surface
            stage-a-relational-tests-acceptance-direct-loop
            stage-a-relational-tests-acceptance-canonical-region
            stage-a-relational-tests-acceptance-executable-coverage
            stage-a-relational-tests-acceptance-semantic-code-aliases
            stage-a-relational-tests-acceptance-tls-launch
            stage-a-relational-tests-acceptance-tls-parsing
            stage-a-relational-tests-acceptance-tls-roots
            stage-a-relational-tests-acceptance-control-frontier
            stage-a-relational-tests-acceptance-nested-external
            stage-a-relational-tests-acceptance-protocol-callback
            stage-a-relational-tests-acceptance-import-register-return
            stage-a-relational-tests-acceptance-direct-stack-read
            stage-a-relational-tests-acceptance-below-frame-stack-read
            stage-a-relational-tests-acceptance-below-frame-stack-guard
            stage-a-relational-tests-acceptance-stack-base-related-word
            stage-a-relational-tests-state-dynamic-flow-call-boundary
            stage-a-relational-tests-acceptance-representative
            stage-a-relational-tests-acceptance-terminal-return
            stage-a-relational-tests-acceptance-external-loop
            stage-a-relational-tests-acceptance-external-allocation
            stage-a-relational-tests-acceptance-input-flag-guard
            stage-a-relational-tests-acceptance-exact-pure-guard
            stage-a-relational-tests-acceptance-exact-to-related
            stage-a-relational-tests-acceptance-exact-register-transfer
              stage-a-relational-tests-acceptance-immutable-image-word
              stage-a-relational-tests-acceptance-fixed-immutable-expression
              stage-a-relational-tests-acceptance-static-word-slot
            stage-a-relational-tests-acceptance-paired-static-word-guard
            stage-a-relational-tests-acceptance-immutable-pe-pointer-chain
            stage-a-relational-tests-acceptance-immutable-pe-header
            stage-a-relational-tests-acceptance-direct-call-stack-writes
            stage-a-relational-tests-acceptance-dynamic-spill
            stage-a-relational-tests-acceptance-direct-call-static-writes
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
          stage-a-gnu-hello-fixtures-root = {
            type = "app";
            program = "${packages.stage-a-gnu-hello-fixtures-root}/bin/stage-a-gnu-hello-fixtures-root";
          };
          stage-a-minimal-hello-fixtures-root = {
            type = "app";
            program = "${packages.stage-a-minimal-hello-fixtures-root}/bin/stage-a-minimal-hello-fixtures-root";
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
            stage-a-isa-conformance-bochs-80386
            stage-a-fixtures-check
            stage-a-gnu-hello-preflight
            stage-a-minimal-hello-check
            stage-a-jq-fixtures-check
            stage-a-relational-tests
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
              unicorn
              z3-solver
            ]
          );
        in
        {
          default = pkgs.mkShell {
            packages = [
              pythonEnv
              packages.bochs-conformance
              packages.spaghetti-extractor
              pkgs.jq
              pkgs.lean4
              pkgs.nix
              pkgs.pkgsCross.mingw32.stdenv.cc
              pkgs.llvm
              pkgs.xed
            ];
            shellHook = ''
              export PYTHONPATH="$PWD/src''${PYTHONPATH:+:$PYTHONPATH}"
            '';
          };
        }
      );
    };
}
