{
  pkgs,
  name,
  original,
  candidate,
  relationContract,
  analysisKernelCache,
  tools,
  extraReportArtifacts ? [ ],
  dataflowFineGrained ? true,
  dataflowContentAddressed ? true,
  extractionJobs ? 8,
  extractionBatch ? 4,
  normalizationJobs ? 8,
  normalizationBatch ? 128,
}:

let
  inherit (pkgs.lib) concatMapStringsSep optionalString;

  side = label: if label == "original" then original else candidate;

  linkerMapArgument =
    fixture:
    optionalString (fixture ? linkerMap && fixture.linkerMap != null) ''
      inventory_args+=(--linker-map "${fixture.linkerMap}")
    '';

  mkInventory =
    label:
    let
      fixture = side label;
    in
    pkgs.runCommand "${name}-${label}-inventory"
      {
        nativeBuildInputs = [
          tools.side
          pkgs.jq
        ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      ''
        mkdir -p "$out"
        inventory_args=(
          --binary "${fixture.binary}"
          --side "${label}"
          --out "$out/inventory.json"
        )
        ${linkerMapArgument fixture}
        spaghetti-extractor-side inventory-binary \
          "''${inventory_args[@]}" \
          > "$out/inventory.stdout"
        jq -e '
          .format == "stage-a-binary-cutpoint-inventory-v1" and
          .status == "pass" and
          .counts.issues == 0 and
          .counts.regions > 0 and
          .counts.extraction_regions >= .counts.regions
        ' "$out/inventory.json" >/dev/null
        spaghetti-extractor-side \
          project-inventory-extraction-request \
          --inventory "$out/inventory.json" \
          --scope base \
          --out "$out/request.json" \
          > "$out/request.stdout"
        jq -e '
          .format == "stage-a-relational-side-extraction-request-v1" and
          .side == "${label}" and
          (.regions | length) > 0
        ' "$out/request.json" >/dev/null
        spaghetti-extractor-side \
          project-inventory-extraction-request \
          --inventory "$out/inventory.json" \
          --scope superset \
          --out "$out/isa-request.json" \
          > "$out/isa-request.stdout"
        jq -e \
          --argjson base_count "$(jq '.regions | length' "$out/request.json")" '
          .format == "stage-a-relational-side-extraction-request-v1" and
          .side == "${label}" and
          (.regions | length) >= $base_count
        ' "$out/isa-request.json" >/dev/null
      '';

  mkSideExtraction =
    label: inventory:
    let
      fixture = side label;
    in
    pkgs.runCommand "${name}-${label}-extraction"
      {
        nativeBuildInputs = [
          tools.side
          pkgs.lean4
          pkgs.jq
        ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      ''
        export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${analysisKernelCache}"
        export SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_MEMORY_MB=8192
        export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_JOBS=${toString extractionJobs}
        export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_BATCH=${toString extractionBatch}
        export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$TMPDIR/relational-cache"
        mkdir -p "$out"
        spaghetti-extractor-side extract-side \
          --binary "${fixture.binary}" \
          --request "${inventory}/request.json" \
          --out "$out/extraction.json" \
          > "$out/extraction.stdout"
        jq -e '
          .format == "stage-a-relational-side-extraction-v1" and
          .side == "${label}" and
          (.regions | length) > 0
        ' "$out/extraction.json" >/dev/null
      '';

  mkSideIsa =
    label: request:
    let
      fixture = side label;
    in
    pkgs.runCommand "${name}-${label}-isa"
      {
        nativeBuildInputs = [
          tools.side
          pkgs.lean4
          pkgs.jq
        ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      ''
        export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${analysisKernelCache}"
        export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$TMPDIR/relational-cache"
        mkdir -p "$out"
        spaghetti-extractor-side extract-side-isa \
          --binary "${fixture.binary}" \
          --request "${request}" \
          --out "$out/isa.json" \
          > "$out/isa.stdout"
        jq -e '
          .format == "stage-a-relational-side-isa-v1" and
          .side == "${label}" and
          (.regions | length) > 0
        ' "$out/isa.json" >/dev/null
      '';

  mkMergedIsaRequest =
    label: inventory: supplement:
    pkgs.runCommand "${name}-${label}-merged-isa-request"
      {
        nativeBuildInputs = [
          tools.side
          pkgs.jq
        ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      ''
        mkdir -p "$out"
        spaghetti-extractor-side merge-side-extraction-requests \
          --input "${inventory}/isa-request.json" \
          --input "${supplement}/request.json" \
          --out "$out/request.json" \
          > "$out/request.stdout"
        jq -e '
          .format == "stage-a-relational-side-extraction-request-v1" and
          .side == "${label}" and
          (.regions | length) > 0
        ' "$out/request.json" >/dev/null
      '';

  mkSupplementRequest =
    label: inventory:
    let
      fixture = side label;
    in
    pkgs.runCommand "${name}-${label}-supplement-request"
      {
        nativeBuildInputs = [
          tools.side
          pkgs.jq
        ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      ''
        mkdir -p "$out"
        spaghetti-extractor-side \
          project-missing-side-extraction-request \
          --binary "${fixture.binary}" \
          --side "${label}" \
          --relation-contract "${relationContract}" \
          --inventory "${inventory}/inventory.json" \
          --out "$out/request.json" \
          > "$out/request.stdout"
        jq -e '
          .format == "stage-a-relational-side-extraction-request-v1" and
          .side == "${label}"
        ' "$out/request.json" >/dev/null
      '';

  mkSupplementExtraction =
    label: request:
    let
      fixture = side label;
    in
    pkgs.runCommand "${name}-${label}-supplement-extraction"
      {
        nativeBuildInputs = [
          tools.side
          pkgs.lean4
          pkgs.jq
        ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      ''
        export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${analysisKernelCache}"
        export SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_MEMORY_MB=8192
        export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_JOBS=2
        export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_BATCH=1
        export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$TMPDIR/relational-cache"
        mkdir -p "$out"
        spaghetti-extractor-side extract-side \
          --binary "${fixture.binary}" \
          --request "${request}/request.json" \
          --out "$out/extraction.json" \
          > "$out/extraction.stdout"
        jq -e '
          .format == "stage-a-relational-side-extraction-v1" and
          .side == "${label}"
        ' "$out/extraction.json" >/dev/null
      '';

  mkMergedExtraction =
    label: base: supplement:
    let
      fixture = side label;
    in
    pkgs.runCommand "${name}-${label}-merged-extraction"
      {
        nativeBuildInputs = [
          tools.side
          pkgs.jq
        ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      ''
        mkdir -p "$out"
        spaghetti-extractor-side merge-side-extractions \
          --binary "${fixture.binary}" \
          --side "${label}" \
          --input "${base}/extraction.json" \
          --input "${supplement}/extraction.json" \
          --out "$out/extraction.json" \
          > "$out/merge.stdout"
        jq -e '
          .format == "stage-a-relational-side-extraction-v1" and
          .side == "${label}" and
          (.regions | length) > 0
        ' "$out/extraction.json" >/dev/null
      '';
in
rec {
  originalInventory = mkInventory "original";
  candidateInventory = mkInventory "candidate";

  originalExtraction = mkSideExtraction "original" originalInventory;
  candidateExtraction = mkSideExtraction "candidate" candidateInventory;

  originalSupplementRequest = mkSupplementRequest "original" originalInventory;
  candidateSupplementRequest = mkSupplementRequest "candidate" candidateInventory;
  originalIsaRequest = mkMergedIsaRequest "original" originalInventory originalSupplementRequest;
  candidateIsaRequest = mkMergedIsaRequest "candidate" candidateInventory candidateSupplementRequest;
  originalIsa = mkSideIsa "original" "${originalIsaRequest}/request.json";
  candidateIsa = mkSideIsa "candidate" "${candidateIsaRequest}/request.json";
  originalSupplementExtraction = mkSupplementExtraction "original" originalSupplementRequest;
  candidateSupplementExtraction = mkSupplementExtraction "candidate" candidateSupplementRequest;
  originalMergedExtraction =
    mkMergedExtraction "original" originalExtraction
      originalSupplementExtraction;
  candidateMergedExtraction =
    mkMergedExtraction "candidate" candidateExtraction
      candidateSupplementExtraction;

  normalizedBehaviors =
    pkgs.runCommand "${name}-normalized-behaviors"
      {
        nativeBuildInputs = [
          tools.normalize
          pkgs.lean4
          pkgs.jq
        ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      ''
        export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${analysisKernelCache}"
        export SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_MEMORY_MB=8192
        export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_NORMALIZATION_JOBS=${toString normalizationJobs}
        export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_NORMALIZATION_BATCH=${toString normalizationBatch}
        mkdir -p "$out"
        spaghetti-extractor-normalize \
          --original "${original.binary}" \
          --candidate "${candidate.binary}" \
          --relation-contract "${relationContract}" \
          --original-extraction "${originalMergedExtraction}/extraction.json" \
          --candidate-extraction "${candidateMergedExtraction}/extraction.json" \
          --out "$out/normalized-behaviors.json" \
          > "$out/normalization.stdout"
        jq -e '
          .format == "stage-a-relational-pair-normalization-v1" and
          .status == "untrusted_proposal_requires_lean_normalization_replay" and
          (.regions | length) > 0
        ' "$out/normalized-behaviors.json" >/dev/null
      '';

  regionFacts =
    pkgs.runCommand "${name}-region-facts"
      {
        nativeBuildInputs = [
          tools.regionFacts
          pkgs.jq
        ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      ''
        mkdir -p "$out"
        if ! spaghetti-extractor-region-facts \
          --original "${original.binary}" \
          --candidate "${candidate.binary}" \
          --relation-contract "${relationContract}" \
          --original-extraction "${originalMergedExtraction}/extraction.json" \
          --candidate-extraction "${candidateMergedExtraction}/extraction.json" \
          --normalized-behaviors "${normalizedBehaviors}/normalized-behaviors.json" \
          --out "$out/region-facts.json" \
          > "$out/result.json"; then
          cat "$out/result.json" >&2
          exit 1
        fi
        jq -e '
          .format == "stage-a-relational-region-facts-v1" and
          .status == "untrusted_proposal_requires_global_analysis" and
          (.region_count > 0)
        ' "$out/region-facts.json" >/dev/null
      '';

  proposalRaw =
    pkgs.runCommand "${name}-proposal-raw"
      {
        nativeBuildInputs = [
          tools.proposal
          pkgs.lean4
          pkgs.jq
        ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      ''
        work="$TMPDIR/${name}-proposals"
        mkdir -p "$work"
        export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL="${analysisKernelCache}"
        export SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_MEMORY_MB=8192
        export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_JOBS=${toString extractionJobs}
        export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_NORMALIZATION_JOBS=${toString normalizationJobs}
        export SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_NORMALIZATION_BATCH=${toString normalizationBatch}
        set +e
        SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE="$work/relational-cache" \
          spaghetti-extractor-proposal discover-proposals \
            --original "${original.binary}" \
            --candidate "${candidate.binary}" \
            --relation-contract "${relationContract}" \
            --original-extraction "${originalMergedExtraction}/extraction.json" \
            --candidate-extraction "${candidateMergedExtraction}/extraction.json" \
            --normalized-behaviors "${normalizedBehaviors}/normalized-behaviors.json" \
            --region-facts "${regionFacts}/region-facts.json" \
            --out "$work/proposal" \
            > "$work/proposal.stdout" \
            2> "$work/proposal.stderr"
        proposal_status=$?
        set -e
        if [ "$proposal_status" -ne 0 ]; then
          cat "$work/proposal.stderr" >&2
          cat "$work/proposal.stdout" >&2
          exit "$proposal_status"
        fi
        mkdir -p "$out"
        cp -R "$work/proposal" "$out/proposal"
        cp "$work/proposal.stdout" "$work/proposal.stderr" "$out/"
      '';

  proposal =
    pkgs.runCommand "${name}-proposal"
      {
        nativeBuildInputs = [
          tools.proposal
          pkgs.jq
        ];
        preferLocalBuild = true;
        allowSubstitutes = true;
      }
      ''
        mkdir -p "$out"
        spaghetti-extractor-proposal validate-proposal \
          --proposal "${proposalRaw}/proposal" \
          > "$out/proposal-validation.json"
        jq -e '
          .format == "stage-a-relational-proposal-closure-v1" and
          .status == "untrusted_proposal_requires_lean_replay" and
          .acceptance_authority == false
        ' "${proposalRaw}/proposal/relational-proposal-manifest.json" >/dev/null
        test ! -e "${proposalRaw}/proposal/lean"
        test ! -e "${proposalRaw}/proposal/relational-product-graph.json"
        ln -s "${proposalRaw}/proposal" "$out/proposal"
      '';

  semanticProducts =
    pkgs.runCommand "${name}-semantic-products"
      {
        nativeBuildInputs = [
          tools.semanticProducts
          pkgs.jq
        ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      ''
        spaghetti-extractor-semantic-products \
          --proposal "${proposal}/proposal" \
          --out "$out" \
          > "$TMPDIR/semantic-products.json"
        jq -e '
          .format == "stage-a-relational-semantic-products-v1" and
          .status == "untrusted_proposal_requires_lean_replay" and
          .acceptance_authority == false and
          (.semantic_ir_sha256 | type == "string") and
          (.invariants_sha256 | type == "string")
        ' "$out/semantic-products-manifest.json" >/dev/null
      '';

  registerDataflowProblem =
    pkgs.runCommand "${name}-register-dataflow-problem"
      {
        nativeBuildInputs = [
          tools.registerDataflowProblem
          pkgs.jq
        ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      ''
        proposal_dir="${proposal}/proposal"
        mkdir -p "$out"
        spaghetti-extractor-register-dataflow-problem \
          --original "$proposal_dir/artifacts/original.pe" \
          --candidate "$proposal_dir/artifacts/candidate.pe" \
          --seed "$proposal_dir/relational-register-dataflow-problem-seed.json" \
          --contract "$proposal_dir/relation-contract.json" \
          --decoded-behaviors "$proposal_dir/relational-decoded-behaviors.json" \
          --out "$out/problem.json" \
          > "$out/result.json"
        jq -e '
          .format == "stage-a-register-dataflow-problem-v1" and
          .acceptance_authority == false and
          (.transfer_programs.region_count > 0)
        ' "$out/problem.json" >/dev/null
      '';

  registerDataflowPlan =
    pkgs.runCommand "${name}-register-dataflow-plan"
      {
        nativeBuildInputs = [
          tools.dataflowPlan
          pkgs.jq
        ];
        preferLocalBuild = true;
        allowSubstitutes = true;
      }
      ''
        spaghetti-extractor-dataflow-plan \
          --problem "${registerDataflowProblem}/problem.json" \
          --out-dir "$out" \
          > "$TMPDIR/plan.json"
        jq -e '
          .format == "stage-a-register-dataflow-pack-manifest-v1" and
          .acceptance_authority == false and
          (.transfer_context_sha256 | type == "string") and
          .pack_count == (.packs | length) and
          .pack_count > 0
        ' "$out/manifest.json" >/dev/null
        test -f "$out/transfer-context.json"
        jq -se '
          all(.[];
            all(.regions[];
              has("program") and (has("observations") | not)))
        ' "$out"/packs/*.json >/dev/null
      '';

  registerDataflow = import ./stage-a-register-dataflow-graph.nix {
    inherit pkgs;
    dataflowAggregator = tools.dataflowAggregate;
    dataflowSummary = tools.dataflowSummary;
    dataflowWorker = tools.dataflowWorker;
    planned = registerDataflowPlan;
    fineGrained = dataflowFineGrained;
    contentAddressed = dataflowContentAddressed;
  };

  registerReplay =
    pkgs.runCommand "${name}-register-replay"
      {
        nativeBuildInputs = [
          tools.registerReplay
          pkgs.jq
        ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      ''
        spaghetti-extractor-register-replay \
          --proposal "${proposal}/proposal" \
          --register-dataflow-aggregate "${registerDataflow}/aggregate.json" \
          --out "$out" \
          > "$TMPDIR/register-replay.json"
        jq -e '
          .format == "stage-a-relational-register-replay-v1" and
          .status == "untrusted_proposal_requires_lean_replay" and
          .acceptance_authority == false and
          (.proposal_closure_sha256 | type == "string") and
          (.aggregate_sha256 | type == "string")
        ' "$out/register-replay-manifest.json" >/dev/null
      '';

  memoryProducts =
    pkgs.runCommand "${name}-memory-products"
      {
        nativeBuildInputs = [
          tools.memoryProducts
          pkgs.jq
        ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      ''
        spaghetti-extractor-memory-products \
          --proposal "${proposal}/proposal" \
          --register-replay "${registerReplay}" \
          --out "$out" \
          > "$TMPDIR/memory-products.json"
        jq -e '
          .format == "stage-a-relational-memory-products-v1" and
          .status == "untrusted_proposal_requires_lean_replay" and
          .acceptance_authority == false and
          (.memory_contracts_sha256 | type == "string") and
          (.external_call_sites_sha256 | type == "string")
        ' "$out/memory-products-manifest.json" >/dev/null
      '';

  compositionProducts =
    pkgs.runCommand "${name}-composition-products"
      {
        nativeBuildInputs = [
          tools.compositionProducts
          pkgs.jq
        ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      ''
        spaghetti-extractor-composition-products \
          --proposal "${proposal}/proposal" \
          --register-replay "${registerReplay}" \
          --semantic-products "${semanticProducts}" \
          --memory-products "${memoryProducts}" \
          --original-isa "${originalIsa}/isa.json" \
          --candidate-isa "${candidateIsa}/isa.json" \
          --out "$out" \
          > "$TMPDIR/composition-products.json"
        jq -e '
          .format == "stage-a-relational-composition-products-v1" and
          .status == "untrusted_proposal_requires_lean_replay" and
          .acceptance_authority == false and
          .isa_mode == "side_artifacts" and
          (.products_sha256 | type == "string") and
          (.files | length) == 7
        ' "$out/composition-products-manifest.json" >/dev/null
      '';

  analysis =
    pkgs.runCommand "${name}-analysis"
      {
        nativeBuildInputs = [
          tools.analysis
          pkgs.jq
        ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      ''
        work="$TMPDIR/${name}-analysis"
        mkdir -p "$work"
        set +e
        spaghetti-extractor-analysis assemble-relational \
          --proposal "${proposal}/proposal" \
          --register-replay "${registerReplay}" \
          --semantic-products "${semanticProducts}" \
          --memory-products "${memoryProducts}" \
          --composition-products "${compositionProducts}" \
          --out "$work/analysis" \
          > "$work/analysis.stdout" \
          2> "$work/analysis.stderr"
        analysis_status=$?
        set -e
        if [ "$analysis_status" -ne 0 ]; then
          cat "$work/analysis.stderr" >&2
          cat "$work/analysis.stdout" >&2
          exit "$analysis_status"
        fi
        if ! spaghetti-extractor-analysis validate-analysis \
          --analysis "$work/analysis" \
          > "$work/analysis-validation.json"; then
          cat "$work/analysis-validation.json" >&2
          exit 1
        fi
        jq -e '
          .format == "stage-a-relational-analysis-v1" and
          .status == "analyzed" and
          (.files | length) > 20
        ' "$work/analysis/relational-analysis-manifest.json" >/dev/null
        if [ -e "$work/analysis/lean" ] || \
           [ -e "$work/analysis/certificates" ] || \
           [ -e "$work/analysis/relational-proposal-manifest.json" ]; then
          find "$work/analysis" -maxdepth 2 -print >&2
          echo "assembled analysis contains non-analysis products" >&2
          exit 1
        fi
        mkdir -p "$out"
        cp -R "$work/analysis" "$out/analysis"
        cp "$work/analysis.stdout" "$work/analysis.stderr" \
          "$work/analysis-validation.json" "$out/"
      '';

  registerDataflowCheck =
    pkgs.runCommand "${name}-register-dataflow-check"
      {
        nativeBuildInputs = [
          tools.dataflowCompare
          pkgs.jq
        ];
        preferLocalBuild = true;
        allowSubstitutes = true;
      }
      ''
        mkdir -p "$out"
        spaghetti-extractor-dataflow-compare \
          --aggregate "${registerDataflow}/aggregate.json" \
          --register-relations \
            "${analysis}/analysis/relational-register-relations.json" \
          --out "$out/comparison.json" \
          > "$out/compare-command.json"
        jq -e '
          .format == "stage-a-register-dataflow-comparison-v1" and
          .status == "match" and
          .acceptance_authority == false and
          .region_count > 0 and
          .mismatch_count == 0
        ' "$out/comparison.json" >/dev/null
      '';

  preparedProof =
    pkgs.runCommand "${name}-prepared-proof"
      {
        nativeBuildInputs = [
          tools.preparation
          pkgs.jq
        ];
        preferLocalBuild = false;
        allowSubstitutes = true;
      }
      ''
        work="$TMPDIR/${name}"
        mkdir -p "$work"
        set +e
        spaghetti-extractor-preparation generate-relational \
          --analysis "${analysis}/analysis" \
          --out "$work/relational-v3" \
          > "$work/relational-v3.stdout" \
          2> "$work/relational-v3.stderr"
        prepare_status=$?
        set -e
        if [ "$prepare_status" -ne 0 ]; then
          cat "$work/relational-v3.stderr" >&2
          cat "$work/relational-v3.stdout" >&2
          exit "$prepare_status"
        fi
        jq -e '
          .status == "supported" and
          (.issues | length) == 0
        ' "$work/relational-v3/semantic-gaps.json" >/dev/null
        jq -e '
          (
            .status == "incomplete" and
            .theorem == null and
            (.blockers | length) > 0 and
            all(.blockers[]; (.code | type) == "string" and (.code | length) > 0)
          ) or (
            .status == "ready" and
            .theorem ==
              "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked" and
            (.blockers | length) == 0
          )
        ' "$work/relational-v3/whole-program-acceptance.json" >/dev/null
        jq -e '
          .status == "prepared" and
          (
            (
              .acceptance.status == "incomplete" and
              .expected_final_theorem == null and
              (.acceptance.blockers | length) > 0
            ) or (
              .acceptance.status == "ready" and
              .expected_final_theorem ==
                "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked" and
              (.acceptance.blockers | length) == 0
            )
          )
        ' "$work/relational-v3/prepared-proof.json" >/dev/null
        mkdir -p "$out/report"
        ${concatMapStringsSep "\n" (artifact: ''
          cp "${artifact.source}" "$out/report/${artifact.target}"
        '') extraReportArtifacts}
        cp -R "$work/relational-v3" "$out/report/relational-v3"
        cp "$work/relational-v3.stdout" "$work/relational-v3.stderr" \
          "$out/report/"
      '';
}
