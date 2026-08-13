{
  pkgs,
  pythonEnv,
  pythonSource,
  binary,
  machineIr,
  machineIrManifest,
  semanticIndex,
  transitionSummaries,
  structuralTargets,
  name,
  targetHints ? null,
  targetEvidence ? null,
  contentAddressed ? true,
}:

let
  lib = pkgs.lib;
  phasePythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [
      "spaghetti_extractor.stage_a_indexed_target_evidence_v3"
    ];
    name = "${name}-python-closure";
  };
  caAttrs = lib.optionalAttrs contentAddressed { __contentAddressed = true; };
in
pkgs.runCommand name (
  {
    nativeBuildInputs = [ pythonEnv pkgs.jq ];
    preferLocalBuild = false;
    allowSubstitutes = true;
  }
  // caAttrs
) ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONDONTWRITEBYTECODE=1
  export LC_ALL=C.UTF-8
  export SOURCE_DATE_EPOCH=1
  export SPAGHETTI_ORIGINAL_EXECUTION_FORBIDDEN=1
  export PYTHONPATH=${phasePythonSource}/src

  args=(
    --binary ${binary}
    --machine-ir ${machineIr}
    --machine-ir-manifest ${machineIrManifest}
    --semantic-index ${semanticIndex}
    --transition-summaries ${transitionSummaries}
    --structural-targets ${structuralTargets}
    --out "$out"
  )
  ${lib.optionalString (targetHints != null) ''
    args+=(--target-hints ${targetHints})
  ''}
  ${lib.optionalString (targetEvidence != null) ''
    args+=(--target-evidence ${targetEvidence})
  ''}
  ${pythonEnv}/bin/python3 -m \
    spaghetti_extractor.stage_a_indexed_target_evidence_v3 \
    "''${args[@]}"

  # Incomplete and violated analyses are useful cached diagnostics.  The
  # derivation fails only when the provider cannot emit its typed artifact.
  jq -e '
    .format == "spaghetti-extractor-indexed-target-evidence-report-v3" and
    (.status == "complete" or .status == "incomplete" or .status == "violated") and
    .authorizing == false and
    (.counts.indirect_exits | type == "number") and
    (.counts.evidence_records | type == "number") and
    (.global_issues | type == "array") and
    (.exits | type == "array")
  ' "$out/indexed-target-evidence-report-v3.json" >/dev/null

  jq -S '{
    format: "spaghetti-extractor-indexed-target-evidence-metadata-v3",
    status: .status,
    artifact_id: .artifact_id,
    artifact_manifest_sha256: .artifact_manifest_sha256,
    record_ids: ([.exits[] | select(.status == "complete") | .exit_id] | sort)
  }' "$out/indexed-target-evidence-report-v3.json" \
    > "$out/metadata.json"
''
