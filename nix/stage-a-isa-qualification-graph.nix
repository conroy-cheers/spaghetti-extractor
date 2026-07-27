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
}:

let
  caAttrs = pkgs.lib.optionalAttrs contentAddressed {
    __contentAddressed = true;
  };
  mkConformance =
    backend:
    import ./stage-a-isa-conformance.nix {
      inherit
        pkgs
        spaghettiExtractor
        kernelCache
        corpus
        bochsRunner
        contentAddressed
        ;
      name = "${name}-${backend}";
      inherit backend;
      withForms = backend == "lean";
    };
  lean = mkConformance "lean";
  unicorn = mkConformance "unicorn";
  bochs = mkConformance "bochs";
  qualification = pkgs.runCommand "${name}-qualification"
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
      spaghetti-extractor stage-a-build-isa-kernel-qualification \
        --corpus ${corpus} \
        --lean-forms ${lean}/forms.json \
        --bochs-report ${bochs}/report.json \
        --unicorn-report ${unicorn}/report.json \
        --lean-report ${lean}/report.json \
        --semantic-kernel ${semanticKernel} \
        ${pkgs.lib.optionalString (generatedCorpus != null) "--generated-corpus ${generatedCorpus}"} \
        --out "$out/qualification.json" \
        --crosswalk-out "$out/lean-form-crosswalk.json" \
        > "$out/result.json"
      worker_status="$?"
      set -e
      if [ "$worker_status" -gt 1 ]; then
        echo "ISA qualification worker failed with status $worker_status" >&2
        exit "$worker_status"
      fi
      jq -e '
        .format == "stage-a-isa-kernel-qualification-result-v1"
        and .proof_authority == false
        and .closes_stage_a_proof == false
      ' "$out/result.json" > /dev/null
      jq -e '
        .format == "stage-a-isa-kernel-qualification-v1"
        and .trust.proof_authority == false
        and .trust.closes_stage_a_proof == false
      ' "$out/qualification.json" > /dev/null
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
      jq -e '
        .format == "stage-a-isa-kernel-qualification-v1"
        and .status == "qualified"
        and .trust.proof_authority == false
        and .trust.closes_stage_a_proof == false
      ' ${qualification}/qualification.json > /dev/null
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
        jq -e '
          .format == "stage-a-isa-kernel-selection-v1"
          and .trust.proof_authority == false
          and .trust.closes_stage_a_proof == false
        ' "$out/selection.json" > /dev/null
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
            jq -e '
              .format == "stage-a-isa-kernel-selection-v1"
              and .status == "qualified"
              and .trust.proof_authority == false
              and .trust.closes_stage_a_proof == false
            ' "$selection" > /dev/null
          done
          mkdir -p "$out"
          ln -s ${originalSelection}/selection.json "$out/original.json"
          ln -s ${candidateSelection}/selection.json "$out/candidate.json"
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
      ${pkgs.lib.optionalString (selectionCheck != null) ''
        ln -s ${selectionCheck}/original.json "$out/original-selection.json"
        ln -s ${selectionCheck}/candidate.json "$out/candidate-selection.json"
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
          trust: {
            role: "isa_conformance_evidence_only",
            proof_authority: false,
            closes_stage_a_proof: false
          }
        }' > "$out/graph.json"
    '';
in
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
    campaign
    bundle
    ;
}
