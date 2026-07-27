# Reproducible Nix orchestration for a Stage A round-trip qualification corpus.
#
# Expected flake arguments:
#
#   import ./nix/stage-a-roundtrip-corpus.nix {
#     inherit pkgs;
#     spaghettiExtractor = self.packages.${system}.spaghetti-extractor;
#
#     # Supply exactly one of corpusRoot or generation.
#     corpusRoot = promotedCorpus;
#     # generation = {
#     #   externalProfile = ./profiles/pe32-kernel32-lockstep-v1.json;
#     #   seed = 0;
#     #   count = 1;
#     #   profile = "phase0-winapi-lockstep-v1";
#     #   toolchain = "llvm-msvc";
#     #   compiler = "${pkgs.llvmPackages_21.clang-unwrapped}/bin/clang-cl";
#     #   linker = "${pkgs.llvmPackages_21.lld}/bin/lld-link";
#     #   nativeBuildInputs = [
#     #     pkgs.llvmPackages_21.clang-unwrapped
#     #     pkgs.llvmPackages_21.lld.out
#     #     pkgs.pkgsCross.mingw32.stdenv.cc
#     #   ];
#     # };
#
#     # Measurements come from prior qualification reports.  Missing entries
#     # use conservative defaults and remain visible in pack-plan.json.
#     caseMeasurements = {
#       example = {
#         estimatedSeconds = 420;
#         estimatedMemoryMB = 4096;
#         resourceClass = "standard";
#       };
#     };
#
#     # These callbacks are the flake-specific bridge to Stage A.  They must
#     # return derivations and must not invoke Nix recursively.  Preparation is
#     # separated from the generated Lean graph, and final acceptance auditing
#     # is separated from both, so each semantic phase has its own store key.
#     mkCasePreparation = {
#       caseId, case, caseRoot, corpusRoot, staticPreflight, measurement, ...
#     }: ...;
#     mkCaseProofDag = args@{ preparation, preparationGraph, ... }:
#       import ./stage-a-lean-graph.nix {
#         inherit pkgs;
#         prepared = preparation;
#         targetNodes = [ args.case.proofNode ];
#         targetBundle = true;
#       };
#     mkCaseAudit = {
#       caseId, case, preparation, proofDag, ...
#     }: ...;
#   }
#
# The returned attrset exposes `corpus`, `smoke`, `packPlan`,
# `casePreparations`, `caseProofDags`, `caseAudits`, `proofPacks`,
# `aggregateReport`, and `check`.  The smoke output is in every preparation
# dependency path.  Pack and aggregate derivations only consume existing audit
# result files; they never invoke a proof runner or execute an opaque binary.
# A pack is a report target over independently cached case proof DAGs, so
# changing pack policy does not invalidate preparation or Lean work.  Ordinary
# Nix builder and substituter configuration selects local or remote execution.
{
  pkgs,
  spaghettiExtractor,
  name ? "stage-a-roundtrip",
  corpusRoot ? null,
  corpusManifest ? "corpus.json",
  generation ? null,
  caseMeasurements ? { },
  caseMeasurementDefaults ? { },
  packPolicy ? {
    maxEstimatedSeconds = 1200;
    maxCases = 4;
  },
  mkCasePreparation ? null,
  mkCaseProofDag ? null,
  mkCaseAudit ? null,
  contentAddressed ? true,
  caseResultFile ? "result.json",
}:

let
  lib = pkgs.lib;
  inherit (lib)
    concatMapStringsSep
    escapeShellArg
    foldl'
    imap0
    listToAttrs
    optionalString
    ;

  hasCorpus = corpusRoot != null;
  hasGeneration = generation != null;
  validRelativePath =
    value:
    builtins.isString value
    && value != ""
    && !lib.hasPrefix "/" value
    && builtins.all (component: component != "" && component != "." && component != "..") (
      lib.splitString "/" value
    );
  proofPipelineCallbacks = [
    mkCasePreparation
    mkCaseProofDag
    mkCaseAudit
  ];
  proofPipelineEnabled = builtins.all (callback: callback != null) proofPipelineCallbacks;
  proofPipelineDisabled = builtins.all (callback: callback == null) proofPipelineCallbacks;
  bundleFileName = caseId: "${builtins.hashString "sha256" caseId}.json";
  generatedCorpus =
    let
      seed = generation.seed or 0;
      count = generation.count or 1;
      profile = generation.profile or "phase0-winapi-lockstep-v1";
      toolchain = generation.toolchain or "gnu";
      compiler = generation.compiler or null;
      linker = generation.linker or null;
      checkDeterminism = generation.checkDeterminism or true;
      expectedCounts = generation.expectedCounts or null;
      extraInputs = generation.nativeBuildInputs or [ ];
      externalProfile =
        if generation ? externalProfile && generation.externalProfile != null then
          builtins.path {
            path = generation.externalProfile;
            name = "${name}-external-profile.json";
          }
        else
          null;
      optionalArgument =
        flag: value: optionalString (value != null) " ${flag} ${escapeShellArg (toString value)}";
      generatorCommand = output: ''
        ${spaghettiExtractor}/bin/spaghetti-extractor stage-a-fuzz-generate \
          --seed ${toString seed} \
          --count ${toString count} \
          --profile ${escapeShellArg profile} \
          --toolchain ${escapeShellArg toolchain} \
          --out "${output}" \
          --force${optionalArgument "--external-profile" externalProfile}${optionalArgument "--compiler" compiler}${optionalArgument "--linker" linker}
      '';
    in
    pkgs.runCommand "${name}-deterministic-corpus"
      {
        nativeBuildInputs = [
          spaghettiExtractor
          pkgs.coreutils
          pkgs.diffutils
          pkgs.findutils
          pkgs.jq
        ]
        ++ extraInputs;
        # This feeds the generated-manifest IFD boundary and therefore needs a
        # concrete output path during pure evaluation.
        preferLocalBuild = false;
        allowSubstitutes = true;
        passthru = {
          deterministicRegenerationChecked = true;
          executesOriginalBinary = false;
        };
      }
      ''
        export HOME="$TMPDIR/home"
        export LC_ALL=C
        export SOURCE_DATE_EPOCH=1
        export ZERO_AR_DATE=1
        mkdir -p "$HOME" "$TMPDIR/first"
        ${generatorCommand "$TMPDIR/first"} > "$TMPDIR/first-command.json"
        ${optionalString checkDeterminism ''
          mkdir -p "$TMPDIR/second"
          ${generatorCommand "$TMPDIR/second"} > "$TMPDIR/second-command.json"
          diff --recursive --no-dereference "$TMPDIR/first" "$TMPDIR/second"
        ''}
        mkdir -p "$out"
        cp -R --no-preserve=mode,ownership,timestamps "$TMPDIR/first"/. "$out/"
        find "$out" -type f -exec chmod a-x '{}' +
        jq -e '
          .format == "stage-a-roundtrip-corpus-v1" and
          (.cases | length) == ${toString count} and
          .shard_count > 0
        ' "$out/${corpusManifest}" >/dev/null
        ${optionalString (expectedCounts != null) ''
          jq -e --argjson expected ${escapeShellArg (builtins.toJSON expectedCounts)} \
            '.expected_counts == $expected' \
            "$out/${corpusManifest}" >/dev/null
        ''}
        second_manifest_sha256=""
        ${optionalString checkDeterminism ''
          second_manifest_sha256="$(sha256sum "$TMPDIR/second/${corpusManifest}" | cut -d" " -f1)"
        ''}
        jq -n \
          --arg first_sha256 "$(sha256sum "$TMPDIR/first/${corpusManifest}" | cut -d" " -f1)" \
          --arg second_sha256 "$second_manifest_sha256" \
          --argjson determinism_checked ${if checkDeterminism then "true" else "false"} \
          '{
            format: "stage-a-roundtrip-nix-generation-v1",
            status: (if $determinism_checked then "reproducible" else "generated" end),
            determinism_checked: $determinism_checked,
            byte_identical_regeneration: (if $determinism_checked then true else null end),
            first_manifest_sha256: $first_sha256,
            second_manifest_sha256: (if $determinism_checked then $second_sha256 else null end),
            executes_original_binary: false
          }
        ' > "$out/nix-generation.json"
      '';

  sourceCorpus = if hasGeneration then generatedCorpus else corpusRoot;
  sourceManifestPath = sourceCorpus + "/${corpusManifest}";
  manifest = builtins.fromJSON (builtins.readFile sourceManifestPath);
  caseRefs = manifest.cases;
  caseIds = map (case: case.id) caseRefs;
  uniqueCaseIds = lib.unique caseIds;

  caseManifestFor =
    reference: builtins.fromJSON (builtins.readFile (sourceCorpus + "/${reference.path}"));

  defaultMeasurement = {
    estimatedSeconds = 600;
    estimatedMemoryMB = 4096;
    resourceClass = "unmeasured";
    measured = false;
    measurementSource = "unmeasured-fallback-v1";
  };

  measuredCases = map (
    reference:
    let
      case = caseManifestFor reference;
      hasCaseMeasurement = builtins.hasAttr reference.id caseMeasurements;
      hasClassMeasurement = builtins.hasAttr case.expectation.disposition caseMeasurementDefaults;
      supplied =
        if hasCaseMeasurement then
          caseMeasurements.${reference.id}
        else if hasClassMeasurement then
          caseMeasurementDefaults.${case.expectation.disposition}
        else
          { };
      measurement =
        defaultMeasurement
        // supplied
        // {
          measured = hasCaseMeasurement || hasClassMeasurement;
        };
    in
    {
      inherit reference measurement;
      inherit case;
      group = "shard-${toString reference.shard}-${measurement.resourceClass}";
    }
  ) caseRefs;

  groupedCases = lib.groupBy (item: item.group) measuredCases;

  appendMeasuredPack =
    state: item:
    let
      current = state.current;
      exceeds =
        current != [ ]
        && (
          builtins.length current >= packPolicy.maxCases
          ||
            foldl' (total: member: total + member.measurement.estimatedSeconds) 0 current
            + item.measurement.estimatedSeconds > packPolicy.maxEstimatedSeconds
        );
    in
    if exceeds then
      {
        completed = state.completed ++ [ current ];
        current = [ item ];
      }
    else
      {
        inherit (state) completed;
        current = current ++ [ item ];
      };

  packGroup =
    items:
    let
      state = foldl' appendMeasuredPack {
        completed = [ ];
        current = [ ];
      } items;
    in
    state.completed ++ lib.optional (state.current != [ ]) state.current;

  rawPacks = lib.concatMap (group: packGroup groupedCases.${group}) (builtins.attrNames groupedCases);

  packs = imap0 (
    index: members:
    let
      estimatedSeconds = foldl' (total: member: total + member.measurement.estimatedSeconds) 0 members;
      estimatedMemoryMB = foldl' (
        maximum: member:
        if member.measurement.estimatedMemoryMB > maximum then
          member.measurement.estimatedMemoryMB
        else
          maximum
      ) 0 members;
      first = builtins.head members;
    in
    {
      id = "pack-${toString index}-${first.group}";
      inherit members estimatedSeconds estimatedMemoryMB;
      resourceClass = first.measurement.resourceClass;
      corpusShard = first.reference.shard;
    }
  ) rawPacks;

  packPlanPayload = {
    format = "stage-a-roundtrip-nix-pack-plan-v1";
    corpus = {
      format = manifest.format;
      generator_version = manifest.generator_version;
      case_ids = caseIds;
      manifest = "corpus-manifest.json";
    };
    policy = packPolicy;
    packs = map (pack: {
      inherit (pack)
        id
        estimatedSeconds
        estimatedMemoryMB
        resourceClass
        corpusShard
        ;
      cases = map (member: {
        id = member.reference.id;
        expected = member.case.expectation.disposition;
        inherit (member) measurement;
      }) pack.members;
    }) packs;
  };

  smoke = import ./stage-a-roundtrip-smoke.nix {
    inherit
      pkgs
      spaghettiExtractor
      name
      corpusManifest
      ;
    corpusRoot = sourceCorpus;
  };

  caseArguments = member: {
    caseId = member.reference.id;
    inherit (member) case measurement;
    caseRoot = "${smoke}/corpus/${builtins.dirOf member.reference.path}";
    caseManifest = "${smoke}/corpus/${member.reference.path}";
    corpusRoot = "${smoke}/corpus";
    corpusManifest = "${smoke}/corpus/${corpusManifest}";
    staticPreflight = "${smoke}/smoke/cases/${member.reference.id}/static-preflight.json";
    inherit smoke contentAddressed;
  };

  casePreparations =
    if !proofPipelineEnabled then
      { }
    else
      listToAttrs (
        map (member: {
          name = member.reference.id;
          value = mkCasePreparation (caseArguments member);
        }) measuredCases
      );

  # One IFD boundary realizes every preparation before graph-dependent proof
  # derivations are evaluated.  Reading each preparation independently would
  # serialize the corpus in the evaluator and hide all parallelism from Nix.
  preparationGraphBundle =
    if !proofPipelineEnabled then
      null
    else
      pkgs.runCommand "${name}-preparation-graph-bundle"
        {
          preferLocalBuild = false;
          allowSubstitutes = true;
        }
        (
          ''
            mkdir -p "$out"
          ''
          + concatMapStringsSep "\n" (
            member:
            let
              caseId = member.reference.id;
            in
            ''
              cp \
                ${escapeShellArg "${casePreparations.${caseId}}/module-graph.json"} \
                "$out/${bundleFileName caseId}"
            ''
          ) measuredCases
        );

  caseProofDags =
    if !proofPipelineEnabled then
      { }
    else
      listToAttrs (
        map (member: {
          name = member.reference.id;
          value = mkCaseProofDag (
            caseArguments member
            // {
              preparation = casePreparations.${member.reference.id};
              preparationGraph = "${preparationGraphBundle}/${bundleFileName member.reference.id}";
            }
          );
        }) measuredCases
      );

  caseAudits =
    if !proofPipelineEnabled then
      { }
    else
      listToAttrs (
        map (member: {
          name = member.reference.id;
          value = mkCaseAudit (
            caseArguments member
            // {
              preparation = casePreparations.${member.reference.id};
              proofDag = caseProofDags.${member.reference.id};
            }
          );
        }) measuredCases
      );

  mkPackReport =
    pack:
    let
      membersPayload = builtins.toJSON (
        map (
          member:
          let
            caseId = member.reference.id;
          in
          {
            id = caseId;
            expected = member.case.expectation.disposition;
            result = "${caseAudits.${caseId}}/${caseResultFile}";
            inherit (member) measurement;
          }
        ) pack.members
      );
    in
    pkgs.runCommand "${name}-${pack.id}-report"
      (
        {
          nativeBuildInputs = [ pkgs.python3 ];
        }
        // lib.optionalAttrs contentAddressed {
          __contentAddressed = true;
        }
        // {
          preferLocalBuild = true;
          allowSubstitutes = true;
          passthru = {
            inherit (pack) estimatedSeconds estimatedMemoryMB resourceClass;
            caseIds = map (member: member.reference.id) pack.members;
          };
        }
      )
      ''
        mkdir -p "$out/cases"
        MEMBERS=${escapeShellArg membersPayload} \
        PACK_ID=${escapeShellArg pack.id} \
        ESTIMATED_SECONDS=${escapeShellArg (toString pack.estimatedSeconds)} \
        ESTIMATED_MEMORY_MB=${escapeShellArg (toString pack.estimatedMemoryMB)} \
        RESOURCE_CLASS=${escapeShellArg pack.resourceClass} \
          python3 - "$out" <<'PY'
        import json
        import os
        import pathlib
        import shutil
        import sys

        out = pathlib.Path(sys.argv[1])
        members = json.loads(os.environ["MEMBERS"])
        results = []
        for member in members:
            source = pathlib.Path(member["result"])
            if not source.is_file():
                raise SystemExit(f"case proof omitted {source}")
            result = json.loads(source.read_text(encoding="utf-8"))
            if result.get("format") != "stage-a-roundtrip-case-result-v1":
                raise SystemExit(f"case {member['id']} has an unsupported result format")
            if result.get("case_id") != member["id"]:
                raise SystemExit(f"case {member['id']} result identity does not match")
            if result.get("expected_disposition") != member["expected"]:
                raise SystemExit(f"case {member['id']} expectation does not match")
            if result.get("mode") != "proof-core":
                raise SystemExit(f"case {member['id']} did not use proof-core mode")
            actual = result.get("actual_disposition")
            if actual not in {"pass", "violated", "incomplete"}:
                raise SystemExit(f"case {member['id']} has an invalid disposition")
            acceptance = result.get("acceptance")
            if actual == "pass" and not (
                isinstance(acceptance, dict)
                and acceptance.get("authority") == "whole_program_lean"
                and acceptance.get("theorem")
                    == "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked"
                and any(
                    phase.get("id") == "proof-build-and-audit"
                    and phase.get("status") == "pass"
                    for phase in result.get("phases", [])
                    if isinstance(phase, dict)
                )
            ):
                raise SystemExit(
                    f"case {member['id']} pass lacks whole-program Lean authority"
                )
            violation = result.get("violation")
            if actual == "violated" and not (
                isinstance(violation, dict)
                and violation.get("format")
                    == "stage-a-checked-violation-result-v1"
                and violation.get("status") == "violated"
                and isinstance(violation.get("checks"), dict)
                and violation["checks"]
                and all(value is True for value in violation["checks"].values())
                and violation.get("trust", {}).get("role")
                    == "checked_inequivalence_witness"
                and violation.get("trust", {}).get("can_authorize_pass") is False
                and any(
                    phase.get("id") == "checked-violation-replay"
                    and phase.get("status") == "violated"
                    for phase in result.get("phases", [])
                    if isinstance(phase, dict)
                )
            ):
                raise SystemExit(
                    f"case {member['id']} violation lacks checked evidence"
                )
            destination = out / "cases" / member["id"]
            destination.mkdir(parents=True)
            shutil.copyfile(source, destination / "result.json")
            results.append({
                "case_id": member["id"],
                "expected": member["expected"],
                "actual": actual,
                "expectation_matched": (
                    result.get("expectation_matched") is True
                    and actual == member["expected"]
                ),
                "measurement": member["measurement"],
                "result": result,
            })
        unexpected_passes = [
            item["case_id"] for item in results
            if item["expected"] != "pass" and item["actual"] == "pass"
        ]
        mismatches = [
            item["case_id"] for item in results
            if not item["expectation_matched"]
        ]
        payload = {
            "format": "stage-a-roundtrip-nix-pack-result-v1",
            "status": "pass" if not mismatches and not unexpected_passes else "incomplete",
            "pack_id": os.environ["PACK_ID"],
            "estimated_seconds": int(os.environ["ESTIMATED_SECONDS"]),
            "estimated_memory_mb": int(os.environ["ESTIMATED_MEMORY_MB"]),
            "resource_class": os.environ["RESOURCE_CLASS"],
            "case_ids": [item["case_id"] for item in results],
            "expectation_mismatch_case_ids": mismatches,
            "unexpected_pass_case_ids": unexpected_passes,
            "cases": results,
            "reran_proofs": False,
            "executes_original_binary": False,
        }
        (out / "pack-result.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        PY
      '';

  proofPacks =
    if !proofPipelineEnabled then
      { }
    else
      listToAttrs (
        map (pack: {
          name = pack.id;
          value = mkPackReport pack;
        }) packs
      );

  aggregateReport =
    if !proofPipelineEnabled then
      null
    else
      let
        packInputs = builtins.toJSON (
          map (pack: {
            id = pack.id;
            result = "${proofPacks.${pack.id}}/pack-result.json";
          }) packs
        );
        expectedCounts = builtins.toJSON manifest.expected_counts;
      in
      pkgs.runCommand "${name}-aggregate-report"
        (
          {
            nativeBuildInputs = [ pkgs.python3 ];
          }
          // lib.optionalAttrs contentAddressed {
            __contentAddressed = true;
          }
          // {
            preferLocalBuild = true;
            allowSubstitutes = true;
          }
        )
        ''
          mkdir -p "$out/packs"
          cp ${escapeShellArg "${smoke}/corpus/${corpusManifest}"} \
            "$out/corpus-manifest.json"
          PACKS=${escapeShellArg packInputs} \
          EXPECTED_COUNTS=${escapeShellArg expectedCounts} \
          EXPECTED_CASE_IDS=${escapeShellArg (builtins.toJSON caseIds)} \
            python3 - "$out" <<'PY'
          import json
          import os
          import pathlib
          import shutil
          import sys

          out = pathlib.Path(sys.argv[1])
          expected_counts = json.loads(os.environ["EXPECTED_COUNTS"])
          expected_case_ids = json.loads(os.environ["EXPECTED_CASE_IDS"])
          packs = []
          cases = []
          for entry in json.loads(os.environ["PACKS"]):
              source = pathlib.Path(entry["result"])
              payload = json.loads(source.read_text(encoding="utf-8"))
              if payload.get("format") != "stage-a-roundtrip-nix-pack-result-v1":
                  raise SystemExit(f"pack {entry['id']} has an unsupported result format")
              destination = out / "packs" / f"{entry['id']}.json"
              shutil.copyfile(source, destination)
              packs.append({
                  "id": entry["id"],
                  "status": payload.get("status"),
                  "result": f"packs/{entry['id']}.json",
              })
              cases.extend(payload.get("cases", []))
          observed_case_ids = [case["case_id"] for case in cases]
          if sorted(observed_case_ids) != sorted(expected_case_ids):
              raise SystemExit("aggregate case inventory does not match the corpus")
          actual_counts = {
              disposition: sum(case.get("actual") == disposition for case in cases)
              for disposition in ("pass", "violated", "incomplete")
          }
          declared_counts = {
              disposition: sum(case.get("expected") == disposition for case in cases)
              for disposition in ("pass", "violated", "incomplete")
          }
          expected_counts_match = declared_counts == expected_counts
          mismatches = [
              case["case_id"] for case in cases
              if not case.get("expectation_matched")
          ]
          unexpected_passes = [
              case["case_id"] for case in cases
              if case.get("expected") != "pass" and case.get("actual") == "pass"
          ]
          all_packs_pass = all(pack["status"] == "pass" for pack in packs)
          payload = {
              "format": "stage-a-roundtrip-nix-qualification-v1",
              "status": (
                  "pass" if (
                      all_packs_pass and expected_counts_match
                      and not mismatches and not unexpected_passes
                  )
                  else "incomplete"
              ),
              "corpus": {
                  "manifest": "corpus-manifest.json",
                  "generator_version": ${builtins.toJSON manifest.generator_version},
                  "expected_counts": expected_counts,
              },
              "counts": {
                  "cases": len(cases),
                  **actual_counts,
                  "declared_expectations_match_manifest": expected_counts_match,
                  "expectation_mismatches": len(mismatches),
                  "unexpected_passes": len(unexpected_passes),
              },
              "expectation_mismatch_case_ids": mismatches,
              "unexpected_pass_case_ids": unexpected_passes,
              "packs": packs,
              "cases": cases,
              "trust": {
                  "positive_pass_requires": "whole_program_lean",
                  "supported_acceptance_theorems": [
                      "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked",
                  ],
                  "negative_pass_is_fatal": True,
                  "aggregator_has_proof_authority": False,
              },
              "reran_proofs": False,
              "executes_original_binary": False,
          }
          (out / "run-result.json").write_text(
              json.dumps(payload, indent=2, sort_keys=True) + "\n",
              encoding="utf-8",
          )
          PY
          cat > "$out/pack-plan.json" <<'JSON'
          ${builtins.toJSON packPlanPayload}
          JSON
        '';

  check =
    if aggregateReport == null then
      null
    else
      pkgs.runCommand "${name}-qualification-check"
        (
          {
            nativeBuildInputs = [ pkgs.jq ];
          }
          // lib.optionalAttrs contentAddressed {
            __contentAddressed = true;
          }
          // {
            preferLocalBuild = true;
            allowSubstitutes = true;
          }
        )
        ''
          jq -e '
            .format == "stage-a-roundtrip-nix-qualification-v1" and
            .status == "pass" and
            .counts.expectation_mismatches == 0 and
            .counts.unexpected_passes == 0 and
            .counts.declared_expectations_match_manifest == true and
            .trust.aggregator_has_proof_authority == false and
            .trust.positive_pass_requires == "whole_program_lean" and
            .trust.supported_acceptance_theorems == [
              "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked"
            ] and
            .reran_proofs == false and
            .executes_original_binary == false
          ' ${aggregateReport}/run-result.json >/dev/null
          mkdir -p "$out"
          cp ${aggregateReport}/run-result.json "$out/run-result.json"
          cp ${aggregateReport}/pack-plan.json "$out/pack-plan.json"
          cp ${aggregateReport}/corpus-manifest.json "$out/corpus-manifest.json"
        '';
in
assert hasCorpus != hasGeneration;
assert proofPipelineEnabled || proofPipelineDisabled;
assert manifest.format == "stage-a-roundtrip-corpus-v1";
assert builtins.length caseRefs > 0;
assert validRelativePath corpusManifest;
assert builtins.all (
  reference:
  builtins.isString reference.id
  && builtins.match "[A-Za-z0-9][A-Za-z0-9._-]*" reference.id != null
  && validRelativePath reference.path
  && builtins.isInt reference.shard
  && reference.shard >= 0
) caseRefs;
assert builtins.length caseIds == builtins.length uniqueCaseIds;
assert builtins.all (caseId: builtins.elem caseId caseIds) (builtins.attrNames caseMeasurements);
assert builtins.all (
  disposition:
  builtins.elem disposition [
    "pass"
    "violated"
    "incomplete"
  ]
) (builtins.attrNames caseMeasurementDefaults);
assert packPolicy.maxCases > 0;
assert packPolicy.maxEstimatedSeconds > 0;
assert builtins.all (
  item:
  builtins.isInt item.measurement.estimatedSeconds
  && item.measurement.estimatedSeconds > 0
  && builtins.isInt item.measurement.estimatedMemoryMB
  && item.measurement.estimatedMemoryMB > 0
  && builtins.isString item.measurement.resourceClass
  && item.measurement.resourceClass != ""
  && builtins.match "[a-z0-9][a-z0-9-]*" item.measurement.resourceClass != null
  && builtins.isString item.measurement.measurementSource
  && item.measurement.measurementSource != ""
) measuredCases;
{
  corpus = sourceCorpus;
  inherit
    manifest
    smoke
    packPlanPayload
    casePreparations
    preparationGraphBundle
    caseProofDags
    caseAudits
    proofPacks
    aggregateReport
    check
    ;
  packPlan = pkgs.writeText "${name}-pack-plan.json" (builtins.toJSON packPlanPayload + "\n");
}
