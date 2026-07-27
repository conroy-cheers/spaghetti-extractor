{ pkgs
, dataflowAggregator
, dataflowSummary
, dataflowWorker
, planned
, manifestFile ? planned + "/manifest.json"
, packsRoot ? planned + "/packs"
, transferContextFile ? planned + "/transfer-context.json"
, fineGrained ? false
, contentAddressed ? true
}:

let
  lib = pkgs.lib;
  manifest = builtins.fromJSON (builtins.readFile manifestFile);
  caAttrs = lib.optionalAttrs contentAddressed {
    __contentAddressed = true;
  };
  transferContextInput =
    if manifest.transfer_context_sha256 != null then
      pkgs.runCommand "stage-a-register-dataflow-transfer-context"
        ({
          preferLocalBuild = true;
          allowSubstitutes = true;
        } // caAttrs)
        ''
          mkdir -p "$out"
          cp ${transferContextFile} "$out/transfer-context.json"
        ''
    else null;
  fineTransferContextArg = lib.optionalString
    (manifest.transfer_context_sha256 != null)
    "--transfer-context ${transferContextInput}/transfer-context.json";
  packRows = manifest.packs;
  packIds = map (pack: pack.id) packRows;
  packById = builtins.listToAttrs (map (pack: {
    name = pack.id;
    value = pack;
  }) packRows);
  manifestValid =
    manifest.format == "stage-a-register-dataflow-pack-manifest-v1"
    && manifest.acceptance_authority == false
    && manifest.pack_count == builtins.length packRows
    && manifest.topological_pack_ids == packIds
    && builtins.length packIds == builtins.length (lib.unique packIds)
    && builtins.all (pack:
      builtins.all (predecessor: builtins.hasAttr predecessor packById)
        pack.predecessor_ids
    ) packRows;
  # Project each IFD-generated pack through a cheap CA derivation. Nix 2.35
  # cannot use builtins.path on an output placeholder in pure evaluation.
  # The projection also gives unchanged pack content a stable identity when
  # another pack changes in the parent plan.
  packInputs = builtins.listToAttrs (map (pack: {
    name = pack.id;
    value = pkgs.runCommand
      (lib.strings.sanitizeDerivationName
        "stage-a-register-dataflow-input-${pack.id}")
      ({
        preferLocalBuild = true;
        allowSubstitutes = true;
      } // caAttrs)
      ''
        mkdir -p "$out"
        cp ${packsRoot}/${pack.id}.json "$out/pack.json"
      '';
  }) packRows);
  nodeDrvs = lib.fix (self: builtins.listToAttrs (map (pack:
    let
      dependencies = map (predecessor: self.${predecessor}.summary)
        pack.predecessor_ids;
      predecessorArgs = lib.escapeShellArgs (map
        (dependency: "${dependency}/summary.json") dependencies);
      node = pkgs.runCommand
        (lib.strings.sanitizeDerivationName
          "stage-a-register-dataflow-${pack.id}")
        ({
          outputs = [ "out" "solution" "audit" ];
          nativeBuildInputs = [
            dataflowSummary
            dataflowWorker
            pkgs.jq
          ];
          preferLocalBuild = false;
          allowSubstitutes = true;
        } // caAttrs)
        ''
          mkdir -p "$out" "$solution" "$audit"
          predecessor_args=()
          for predecessor in ${predecessorArgs}; do
            predecessor_args+=(--predecessor "$predecessor")
          done
          spaghetti-extractor-dataflow-worker \
            --pack ${packInputs.${pack.id}}/pack.json \
            ${fineTransferContextArg} \
            "''${predecessor_args[@]}" \
            --out "$solution/result.json" \
            > "$audit/solve.json"
          jq -e '
            .format == "stage-a-register-dataflow-pack-result-v1" and
            .pack_id == ${builtins.toJSON pack.id} and
            .acceptance_authority == false
          ' "$solution/result.json" >/dev/null
          spaghetti-extractor-dataflow-summary \
            --result "$solution/result.json" \
            --out "$out/summary.json" \
            > "$audit/project.json"
          jq -e '
            .format == "stage-a-register-dataflow-pack-summary-v1" and
            .pack_id == ${builtins.toJSON pack.id} and
            .acceptance_authority == false
          ' "$out/summary.json" >/dev/null
          ln -s "$out/summary.json" "$audit/summary.json"
          ln -s "$solution/result.json" "$audit/result.json"
        '';
    in {
      name = pack.id;
      value = {
        summary = node.out;
        solution = node.solution;
        audit = node.audit;
        derivation = node;
      };
    }
  ) packRows));
  solutionResultArgs = lib.escapeShellArgs (map
    (packId: "${nodeDrvs.${packId}.solution}/result.json") packIds);
  solutionArgs = lib.escapeShellArgs (map
    (packId: "${nodeDrvs.${packId}.solution}/result.json") packIds);
  summaryArgs = lib.escapeShellArgs (map
    (packId: "${nodeDrvs.${packId}.summary}/summary.json") packIds);
  fineAggregate = pkgs.runCommand "stage-a-register-dataflow-aggregate-fine"
    ({
      outputs = [ "out" "audit" ];
      nativeBuildInputs = [ dataflowAggregator pkgs.jq ];
      preferLocalBuild = true;
      allowSubstitutes = true;
    } // caAttrs)
    ''
      mkdir -p "$out" "$audit"
      result_args=()
      for result in ${solutionResultArgs}; do
        result_args+=(--result "$result")
      done
      spaghetti-extractor-dataflow-aggregate \
        --manifest ${manifestFile} \
        "''${result_args[@]}" \
        --out "$out/aggregate.json" \
        > "$audit/aggregate-command.json"
      jq -e '
        .format == "stage-a-register-dataflow-aggregate-v1" and
        .acceptance_authority == false
      ' "$out/aggregate.json" >/dev/null
      mkdir -p "$audit/summaries"
      summary_paths=(${summaryArgs})
      solution_paths=(${solutionArgs})
      pack_ids=(${lib.escapeShellArgs packIds})
      for index in "''${!pack_ids[@]}"; do
        ln -s "''${summary_paths[$index]}" \
          "$audit/summaries/''${pack_ids[$index]}.json"
      done
      mkdir -p "$audit/solutions"
      for index in "''${!pack_ids[@]}"; do
        ln -s "''${solution_paths[$index]}" \
          "$audit/solutions/''${pack_ids[$index]}.json"
      done
      ln -s ${planned} "$audit/planned"
    '';
  coarseAggregate = pkgs.runCommand "stage-a-register-dataflow-aggregate"
    ({
      nativeBuildInputs = [ dataflowAggregator dataflowWorker pkgs.jq ];
      preferLocalBuild = true;
      allowSubstitutes = true;
    } // caAttrs)
    ''
      mkdir -p "$out"
      transfer_context_args=()
      if jq -e '.transfer_context_sha256 != null' ${manifestFile} >/dev/null; then
        transfer_context_args+=(--transfer-context ${transferContextFile})
      fi
      spaghetti-extractor-dataflow-worker \
        --manifest ${manifestFile} \
        --packs-root ${packsRoot} \
        "''${transfer_context_args[@]}" \
        --out-dir "$out/results" \
        > "$out/solve.json"

      result_args=()
      while IFS= read -r pack_id; do
        result_args+=(--result "$out/results/$pack_id.json")
      done < <(jq -r '.topological_pack_ids[]' ${manifestFile})
      spaghetti-extractor-dataflow-aggregate \
        --manifest ${manifestFile} \
        "''${result_args[@]}" \
        --out "$out/aggregate.json" \
        > "$out/aggregate-command.json"
      jq -e '
        .format == "stage-a-register-dataflow-aggregate-v1" and
        .acceptance_authority == false
      ' "$out/aggregate.json" >/dev/null
      ln -s ${planned} "$out/planned"
    '';
in
if fineGrained then
  assert manifestValid;
  fineAggregate.overrideAttrs (old: {
    passthru = (old.passthru or { }) // {
      packNodes = nodeDrvs;
    };
  })
else
  coarseAggregate
