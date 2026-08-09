{
  pkgs,
  name,
  spaghettiExtractor,
  kernelCache,
  semanticKernel,
  corpus,
  generatedCorpus ? null,
  bochsRunner,
  requirements ? null,
  xedCatalog ? null,
  contentAddressed ? true,
  pythonEnv ? pkgs.python3,
  pythonSource,
  leanShardCount ? 1,
}:

let
  caAttrs = pkgs.lib.optionalAttrs contentAddressed {
    __contentAddressed = true;
  };
  shardPythonSource =
    if leanShardCount == 1 then
      null
    else
      import ./python-module-closure.nix {
        inherit pkgs;
        source = pythonSource;
        modules = [ "spaghetti_extractor.isa_conformance_shards" ];
        extraPaths = [ "spaghetti_extractor/lean/StageA" ];
        name = "${name}-shard-python-closure";
      };
  qualificationPythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.isa_qualification_worker" ];
    name = "${name}-qualification-python-closure";
  };
  layeredArtifactSchemaPredicate = ''
    (
      .status == "qualified"
      or .status == "incomplete"
      or .status == "disputed"
      or .status == "vetoed"
    )
    and (
      .qualification_layers.structural.status == "complete"
      or .qualification_layers.structural.status == "incomplete"
    )
    and (
      [
        .qualification_layers.structural.counts.required_forms,
        .qualification_layers.structural.counts.complete,
        .qualification_layers.structural.counts.incomplete
      ]
      | all(.[]; type == "number" and . >= 0 and floor == .)
    )
    and (
      .qualification_layers.structural.counts.required_forms
      == (
        .qualification_layers.structural.counts.complete
        + .qualification_layers.structural.counts.incomplete
      )
    )
    and (
      .qualification_layers.structural.diagnostics
      | type == "array"
    )
    and (
      .qualification_layers.concrete_oracle.status == "qualified"
      or .qualification_layers.concrete_oracle.status == "incomplete"
      or .qualification_layers.concrete_oracle.status == "disputed"
      or .qualification_layers.concrete_oracle.status == "vetoed"
    )
    and (
      [
        .qualification_layers.concrete_oracle.counts.required_forms,
        .qualification_layers.concrete_oracle.counts.qualified,
        .qualification_layers.concrete_oracle.counts.incomplete,
        .qualification_layers.concrete_oracle.counts.disputed,
        .qualification_layers.concrete_oracle.counts.vetoed
      ]
      | all(.[]; type == "number" and . >= 0 and floor == .)
    )
    and (
      .qualification_layers.concrete_oracle.counts.required_forms
      == (
        .qualification_layers.concrete_oracle.counts.qualified
        + .qualification_layers.concrete_oracle.counts.incomplete
        + .qualification_layers.concrete_oracle.counts.disputed
        + .qualification_layers.concrete_oracle.counts.vetoed
      )
    )
    and (
      .qualification_layers.concrete_oracle.diagnostics
      | type == "array"
    )
  '';
  mkArtifactSchemaPredicate = legacyFormat: layeredFormat: ''
    (
      .format == "${legacyFormat}"
      or (
        .format == "${layeredFormat}"
        and (${layeredArtifactSchemaPredicate})
      )
    )
    and .trust.proof_authority == false
    and .trust.closes_stage_a_proof == false
  '';
  mkQualifiedArtifactPredicate = legacyFormat: layeredFormat: schemaPredicate: ''
    (${schemaPredicate})
    and (
      (
        .format == "${legacyFormat}"
        and .status == "qualified"
      )
      or (
        .format == "${layeredFormat}"
        and .status == "qualified"
        and .qualification_layers.structural.status == "complete"
        and (
          .qualification_layers.structural.counts.required_forms > 0
        )
        and (
          .qualification_layers.structural.counts.complete
          == .qualification_layers.structural.counts.required_forms
        )
        and .qualification_layers.structural.counts.incomplete == 0
        and .qualification_layers.structural.diagnostics == []
        and .qualification_layers.concrete_oracle.status == "qualified"
        and (
          .qualification_layers.concrete_oracle.counts.required_forms
          == .qualification_layers.structural.counts.required_forms
        )
        and (
          .qualification_layers.concrete_oracle.counts.qualified
          == .qualification_layers.concrete_oracle.counts.required_forms
        )
        and .qualification_layers.concrete_oracle.counts.incomplete == 0
        and .qualification_layers.concrete_oracle.counts.disputed == 0
        and .qualification_layers.concrete_oracle.counts.vetoed == 0
        and .qualification_layers.concrete_oracle.diagnostics == []
      )
    )
  '';
  mkUsableSelectionArtifactPredicate =
    legacyFormat: layeredFormat: schemaPredicate: ''
    (${schemaPredicate})
    and (
      (
        .format == "${legacyFormat}"
        and .status == "qualified"
        and .counts.disputed == 0
        and .counts.vetoed == 0
      )
      or (
        .format == "${layeredFormat}"
        and (
          .status == "qualified"
          or .status == "incomplete"
        )
        and .qualification_layers.structural.status == "complete"
        and (
          .qualification_layers.structural.counts.required_forms > 0
        )
        and (
          .qualification_layers.structural.counts.complete
          == .qualification_layers.structural.counts.required_forms
        )
        and .qualification_layers.structural.counts.incomplete == 0
        and .qualification_layers.structural.diagnostics == []
        and (
          .qualification_layers.concrete_oracle.status == "qualified"
          or .qualification_layers.concrete_oracle.status == "incomplete"
        )
        and (
          .qualification_layers.concrete_oracle.counts.required_forms
          == .qualification_layers.structural.counts.required_forms
        )
        and .qualification_layers.concrete_oracle.counts.disputed == 0
        and .qualification_layers.concrete_oracle.counts.vetoed == 0
      )
    )
  '';
  qualificationArtifactSchemaPredicate = mkArtifactSchemaPredicate
    "stage-a-isa-kernel-qualification-v1"
    "stage-a-isa-kernel-qualification-v2";
  qualifiedQualificationArtifactPredicate =
    mkQualifiedArtifactPredicate "stage-a-isa-kernel-qualification-v1"
      "stage-a-isa-kernel-qualification-v2"
      qualificationArtifactSchemaPredicate;
  selectionArtifactSchemaPredicate = mkArtifactSchemaPredicate
    "stage-a-isa-kernel-selection-v1"
    "stage-a-isa-kernel-selection-v2";
  qualifiedSelectionArtifactPredicate =
    mkQualifiedArtifactPredicate "stage-a-isa-kernel-selection-v1"
      "stage-a-isa-kernel-selection-v2"
      selectionArtifactSchemaPredicate;
  usableSelectionArtifactPredicate =
    mkUsableSelectionArtifactPredicate "stage-a-isa-kernel-selection-v1"
      "stage-a-isa-kernel-selection-v2"
      selectionArtifactSchemaPredicate;
  mkSingleConformance =
    { backend, corpusInput, suffix ? backend, withForms ? backend == "lean" }:
    import ./stage-a-isa-conformance.nix {
      inherit
        pkgs
        pythonEnv
        pythonSource
        spaghettiExtractor
        kernelCache
        bochsRunner
        contentAddressed
        ;
      corpus = corpusInput;
      name = "${name}-${suffix}";
      inherit backend;
      inherit withForms;
    };
  mkLeanCorpusShard =
    shardIndex:
    pkgs.runCommand "${name}-lean-corpus-shard-${toString shardIndex}" ({
      nativeBuildInputs = [ pythonEnv ];
      preferLocalBuild = false;
      allowSubstitutes = true;
    } // caAttrs) ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export PYTHONDONTWRITEBYTECODE=1
      export PYTHONPATH=${shardPythonSource}/src
      mkdir -p "$out"
      ${pythonEnv}/bin/python3 - \
          ${corpus} "$out/corpus.json" \
          ${toString shardIndex} ${toString leanShardCount} <<'PY'
      import json
      import pathlib
      import sys

      from spaghetti_extractor.isa_conformance import (
          parse_isa_conformance_corpus,
          serialize_isa_conformance_corpus,
      )
      from spaghetti_extractor.isa_conformance_shards import (
          partition_isa_conformance_corpus,
      )

      source = pathlib.Path(sys.argv[1])
      output = pathlib.Path(sys.argv[2])
      shard = partition_isa_conformance_corpus(
          parse_isa_conformance_corpus(
              json.loads(source.read_text(encoding="utf-8"))
          ),
          shard_index=int(sys.argv[3]),
          shard_count=int(sys.argv[4]),
      )
      output.write_text(
          json.dumps(
              serialize_isa_conformance_corpus(shard),
              indent=2,
              sort_keys=True,
          ) + "\n",
          encoding="utf-8",
      )
      PY
    '';
  leanShardCorpora =
    if leanShardCount == 1 then [ ]
    else pkgs.lib.genList mkLeanCorpusShard leanShardCount;
  leanShardReports = pkgs.lib.imap0
    (index: shard:
      mkSingleConformance {
        backend = "lean";
        corpusInput = "${shard}/corpus.json";
        suffix = "lean-shard-${toString index}";
        withForms = true;
      })
    leanShardCorpora;
  leanShardInputs = builtins.toJSON (pkgs.lib.imap0
    (index: shard: {
      corpus = "${shard}/corpus.json";
      report = "${builtins.elemAt leanShardReports index}/report.json";
      forms = "${builtins.elemAt leanShardReports index}/forms.json";
    })
    leanShardCorpora);
  mergedLean = pkgs.runCommand "${name}-lean-merged" ({
    nativeBuildInputs = [ pythonEnv ];
    preferLocalBuild = false;
    allowSubstitutes = true;
  } // caAttrs) ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export PYTHONDONTWRITEBYTECODE=1
    export PYTHONPATH=${shardPythonSource}/src
    mkdir -p "$out"
    ${pythonEnv}/bin/python3 - \
        ${corpus} "$out/report.json" "$out/forms.json" \
        ${pkgs.lib.escapeShellArg leanShardInputs} <<'PY'
    import json
    import pathlib
    import sys

    from spaghetti_extractor.isa_conformance import (
        parse_isa_conformance_corpus,
        serialize_isa_conformance_report,
    )
    from spaghetti_extractor.isa_conformance_shards import (
        merge_isa_conformance_shards,
        merge_lean_semantic_form_shards,
    )

    full_corpus = parse_isa_conformance_corpus(
        json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    )
    rows = json.loads(sys.argv[4])
    shard_corpora = [
        parse_isa_conformance_corpus(
            json.loads(pathlib.Path(row["corpus"]).read_text(encoding="utf-8"))
        )
        for row in rows
    ]
    reports = [
        json.loads(pathlib.Path(row["report"]).read_text(encoding="utf-8"))
        for row in rows
    ]
    forms = [
        json.loads(pathlib.Path(row["forms"]).read_text(encoding="utf-8"))
        for row in rows
    ]
    report = merge_isa_conformance_shards(
        full_corpus,
        shard_corpora=shard_corpora,
        shard_reports=reports,
    )
    pathlib.Path(sys.argv[2]).write_text(
        json.dumps(
            serialize_isa_conformance_report(report, corpus=full_corpus),
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )
    pathlib.Path(sys.argv[3]).write_text(
        json.dumps(
            merge_lean_semantic_form_shards(
                full_corpus,
                shard_corpora=shard_corpora,
                shard_payloads=forms,
            ),
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )
    PY
  '';
  lean =
    if leanShardCount == 1 then
      mkSingleConformance {
        backend = "lean";
        corpusInput = corpus;
      }
    else
      mergedLean;
  unicorn = mkSingleConformance {
    backend = "unicorn";
    corpusInput = corpus;
  };
  bochs = mkSingleConformance {
    backend = "bochs";
    corpusInput = corpus;
  };
  qualification = pkgs.runCommand "${name}-qualification"
    (
      {
        nativeBuildInputs = [
          pkgs.jq
          pythonEnv
        ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      // caAttrs
    )
    ''
      mkdir -p "$out"
      export PYTHONHASHSEED=0
      export PYTHONDONTWRITEBYTECODE=1
      export PYTHONPATH=${qualificationPythonSource}/src
      ${pythonEnv}/bin/python3 - \
        ${corpus} \
        ${lean}/forms.json \
        ${bochs}/report.json \
        ${unicorn}/report.json \
        ${lean}/report.json \
        ${semanticKernel} \
        "$out/qualification.json" \
        "$out/lean-form-crosswalk.json" \
        ${if generatedCorpus == null then "-" else generatedCorpus} \
        > "$out/result.json" <<'PY'
      import json
      import pathlib
      import sys

      from spaghetti_extractor.isa_qualification_worker import (
          build_isa_kernel_qualification,
      )

      generated = None if sys.argv[9] == "-" else pathlib.Path(sys.argv[9])
      result = build_isa_kernel_qualification(
          corpus=pathlib.Path(sys.argv[1]),
          lean_forms=pathlib.Path(sys.argv[2]),
          bochs_report=pathlib.Path(sys.argv[3]),
          unicorn_report=pathlib.Path(sys.argv[4]),
          lean_report=pathlib.Path(sys.argv[5]),
          semantic_kernel=pathlib.Path(sys.argv[6]),
          out=pathlib.Path(sys.argv[7]),
          crosswalk_out=pathlib.Path(sys.argv[8]),
          generated_corpus=generated,
      )
      print(json.dumps(result, indent=2, sort_keys=True))
      PY
      jq -e '
        .format == "stage-a-isa-kernel-qualification-result-v1"
        and .proof_authority == false
        and .closes_stage_a_proof == false
      ' "$out/result.json" > /dev/null
      jq -e '${qualificationArtifactSchemaPredicate}' \
        "$out/qualification.json" > /dev/null
    '';
  qualificationCheck = pkgs.runCommand "${name}-qualified"
    (
      {
        nativeBuildInputs = [ pkgs.jq ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      // caAttrs
    )
    ''
      jq -e '${qualifiedQualificationArtifactPredicate}' \
        ${qualification}/qualification.json > /dev/null
      mkdir -p "$out"
      ln -s ${qualification}/qualification.json "$out/qualification.json"
      ln -s ${qualification}/lean-form-crosswalk.json \
        "$out/lean-form-crosswalk.json"
    '';
  mkSelection =
    side:
    pkgs.runCommand "${name}-${side}-selection"
      (
        {
          nativeBuildInputs = [
            pkgs.jq
            spaghettiExtractor
          ];
          preferLocalBuild = false;
          allowSubstitutes = true;
        }
        // caAttrs
      )
      ''
        mkdir -p "$out"
        set +e
        spaghetti-extractor stage-a-select-isa-kernel-qualification \
          --requirements ${requirements} \
          --qualification ${qualification}/qualification.json \
          --semantic-kernel ${semanticKernel} \
          --side ${side} \
          --out "$out/selection.json" \
          > "$out/result.json"
        worker_status="$?"
        set -e
        if [ "$worker_status" -gt 1 ]; then
          echo "ISA selection worker failed with status $worker_status" >&2
          exit "$worker_status"
        fi
        jq -e '
          .format == "stage-a-isa-kernel-selection-result-v1"
          and .proof_authority == false
          and .closes_stage_a_proof == false
        ' "$out/result.json" > /dev/null
        jq -e '${selectionArtifactSchemaPredicate}' \
          "$out/selection.json" > /dev/null
      '';
  originalSelection =
    if requirements == null then null else mkSelection "original";
  candidateSelection =
    if requirements == null then null else mkSelection "candidate";
  selectionCheck =
    if requirements == null then
      null
    else
      pkgs.runCommand "${name}-selections-qualified"
        (
          {
            nativeBuildInputs = [ pkgs.jq ];
            preferLocalBuild = false;
            allowSubstitutes = true;
          }
          // caAttrs
        )
        ''
          for selection in \
            ${originalSelection}/selection.json \
            ${candidateSelection}/selection.json
          do
            jq -e '${qualifiedSelectionArtifactPredicate}' \
              "$selection" > /dev/null
          done
          mkdir -p "$out"
          ln -s ${originalSelection}/selection.json "$out/original.json"
          ln -s ${candidateSelection}/selection.json "$out/candidate.json"
        '';
  selectionEvidenceCheck =
    if requirements == null then
      null
    else
      pkgs.runCommand "${name}-selections-usable-evidence"
        (
          {
            nativeBuildInputs = [ pkgs.jq ];
            preferLocalBuild = false;
            allowSubstitutes = true;
          }
          // caAttrs
        )
        ''
          for selection in \
            ${originalSelection}/selection.json \
            ${candidateSelection}/selection.json
          do
            jq -e '${usableSelectionArtifactPredicate}' \
              "$selection" > /dev/null
          done
          mkdir -p "$out"
          ln -s ${originalSelection}/selection.json "$out/original.json"
          ln -s ${candidateSelection}/selection.json "$out/candidate.json"
          jq -n \
            --slurpfile original ${originalSelection}/selection.json \
            --slurpfile candidate ${candidateSelection}/selection.json '
            [$original[0], $candidate[0]] as $selections |
            {
              format: "stage-a-isa-selection-evidence-policy-v1",
              status: (
                if ([$selections[].status] | all(. == "qualified"))
                then "qualified"
                else "usable-incomplete"
                end
              ),
              policy: {
                structural_qualification_required: true,
                concrete_oracle_incomplete_allowed: true,
                concrete_oracle_disputes_allowed: false,
                concrete_oracle_vetoes_allowed: false
              },
              counts: {
                required_forms:
                  ([$selections[].counts.required_forms] | add),
                qualified:
                  ([$selections[].counts.qualified] | add),
                incomplete:
                  ([$selections[].counts.incomplete] | add),
                disputed:
                  ([$selections[].counts.disputed] | add),
                vetoed:
                  ([$selections[].counts.vetoed] | add)
              },
              trust: {
                role: "isa_conformance_evidence_only",
                proof_authority: false,
                closes_stage_a_proof: false
              }
            }
          ' > "$out/policy.json"
        '';
  campaign =
    if xedCatalog == null then
      null
    else
      pkgs.runCommand "${name}-campaign"
        (
          {
            nativeBuildInputs = [
              pkgs.jq
              spaghettiExtractor
            ];
            preferLocalBuild = false;
            allowSubstitutes = true;
          }
          // caAttrs
        )
        ''
          mkdir -p "$out"
          spaghetti-extractor stage-a-plan-isa-qualification \
            --catalog ${xedCatalog} \
            --qualification ${qualification}/qualification.json \
            --crosswalk ${qualification}/lean-form-crosswalk.json \
            --out "$out/campaign.json" \
            > "$out/result.json"
          jq -e '
            .format == "stage-a-isa-qualification-campaign-result-v1"
            and .status == "complete"
            and .proof_authority == false
            and .closes_stage_a_proof == false
          ' "$out/result.json" > /dev/null
          jq -e '
            .format == "stage-a-isa-qualification-campaign-v1"
            and .trust.proof_authority == false
            and .trust.closes_stage_a_proof == false
          ' "$out/campaign.json" > /dev/null
        '';
  bundle = pkgs.runCommand "${name}-bundle"
    (
      {
        nativeBuildInputs = [ pkgs.jq ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      // caAttrs
    )
    ''
      mkdir -p "$out"
      ln -s ${lean}/report.json "$out/lean-report.json"
      ln -s ${unicorn}/report.json "$out/unicorn-report.json"
      ln -s ${bochs}/report.json "$out/bochs-report.json"
      ln -s ${qualification}/qualification.json "$out/qualification.json"
      ln -s ${qualification}/lean-form-crosswalk.json \
        "$out/lean-form-crosswalk.json"
      ${pkgs.lib.optionalString (campaign != null) ''
        ln -s ${campaign}/campaign.json "$out/campaign.json"
      ''}
      ${pkgs.lib.optionalString (selectionEvidenceCheck != null) ''
        ln -s ${selectionEvidenceCheck}/original.json "$out/original-selection.json"
        ln -s ${selectionEvidenceCheck}/candidate.json "$out/candidate-selection.json"
        ln -s ${selectionEvidenceCheck}/policy.json "$out/selection-policy.json"
      ''}
      jq -n \
        --arg lean ${pkgs.lib.escapeShellArg (toString lean)} \
        --arg unicorn ${pkgs.lib.escapeShellArg (toString unicorn)} \
        --arg bochs ${pkgs.lib.escapeShellArg (toString bochs)} \
        --arg qualification ${pkgs.lib.escapeShellArg (toString qualification)} \
        '{
          format: "stage-a-isa-qualification-graph-v1",
          nodes: {
            lean: $lean,
            unicorn: $unicorn,
            bochs: $bochs,
            qualification: $qualification
          },
          selection_policy:
            "structural-complete-oracle-non-vetoed-v1",
          trust: {
            role: "isa_conformance_evidence_only",
            proof_authority: false,
            closes_stage_a_proof: false
          }
        }' > "$out/graph.json"
    '';
in
assert builtins.isInt leanShardCount && leanShardCount > 0;
assert leanShardCount == 1 || pythonSource != null;
{
  inherit
    lean
    unicorn
    bochs
    qualification
    qualificationCheck
    originalSelection
    candidateSelection
    selectionCheck
    selectionEvidenceCheck
    campaign
    bundle
    ;
}
