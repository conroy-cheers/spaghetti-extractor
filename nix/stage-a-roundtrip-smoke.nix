# Cheap, static-only qualification gate for a round-trip corpus.
#
# Expected flake arguments:
#
#   import ./nix/stage-a-roundtrip-smoke.nix {
#     inherit pkgs;
#     name = "stage-a-roundtrip";
#     spaghettiExtractor = self.packages.${system}.spaghetti-extractor;
#     corpusRoot = generatedOrPinnedCorpus;
#     corpusManifest = "corpus.json"; # relative to corpusRoot
#     caseIds = [ ];                 # empty means every case
#   }
#
# This derivation invokes no Wine, emulator, or Windows runtime command.  It
# removes execute bits from the copied corpus and invokes only Stage A's static
# preflight.  Later Nix proof DAGs depend on its checked corpus and static-
# preflight report, then perform full proof preparation exactly once.
{
  pkgs,
  spaghettiExtractor,
  corpusRoot,
  name ? "stage-a-roundtrip",
  corpusManifest ? "corpus.json",
  caseIds ? [ ],
}:

let
  inherit (pkgs.lib)
    concatMapStringsSep
    escapeShellArg
    hasPrefix
    splitString
    unique
    ;
  validRelativePath =
    value:
    builtins.isString value
    && value != ""
    && !hasPrefix "/" value
    && builtins.all (component: component != "" && component != "." && component != "..") (
      splitString "/" value
    );
  validCaseId =
    value: builtins.isString value && builtins.match "[A-Za-z0-9][A-Za-z0-9._-]*" value != null;
  caseArguments = concatMapStringsSep "\n" (
    caseId: "smoke_args+=(--case ${escapeShellArg caseId})"
  ) caseIds;
in
assert validRelativePath corpusManifest;
assert builtins.all validCaseId caseIds;
assert builtins.length caseIds == builtins.length (unique caseIds);
pkgs.runCommand "${name}-static-preflight-smoke"
  {
    nativeBuildInputs = [
      spaghettiExtractor
      pkgs.coreutils
      pkgs.findutils
      pkgs.jq
    ];
    # This feeds proof preparation through IFD, so its output path must be
    # concrete during pure evaluation.
    preferLocalBuild = true;
    allowSubstitutes = true;
    passthru = {
      inherit corpusManifest caseIds;
      staticOnly = true;
      executesOriginalBinary = false;
    };
  }
  ''
    mkdir -p "$out/corpus" "$out/smoke"
    cp -R --no-preserve=mode,ownership,timestamps \
      ${escapeShellArg (toString corpusRoot)}/. "$out/corpus/"

    # A PE is evidence here, never a process.  No runtime launcher is invoked.
    find "$out/corpus" -type f -exec chmod a-x '{}' +

    jq -e '
      .format == "stage-a-roundtrip-corpus-v1" and
      (.cases | type) == "array" and
      (.cases | length) > 0 and
      all(.cases[];
        (.id | type) == "string" and
        (.path | type) == "string" and
        (.sha256 | test("^[0-9a-f]{64}$")))
    ' "$out/corpus/${corpusManifest}" >/dev/null
    cat > "$TMPDIR/requested-case-ids.json" <<'JSON'
    ${builtins.toJSON caseIds}
    JSON
    if jq -e 'length == 0' "$TMPDIR/requested-case-ids.json" >/dev/null; then
      jq '[.cases[].id]' "$out/corpus/${corpusManifest}" \
        > "$TMPDIR/expected-case-ids.json"
    else
      cp "$TMPDIR/requested-case-ids.json" "$TMPDIR/expected-case-ids.json"
    fi
    jq -e --slurpfile corpus "$out/corpus/${corpusManifest}" '
      length > 0 and
      length == (unique | length) and
      all(.[]; . as $id | any($corpus[0].cases[]; .id == $id))
    ' "$TMPDIR/expected-case-ids.json" >/dev/null

    smoke_args=(
      stage-a-fuzz-run
      --corpus "$out/corpus/${corpusManifest}"
      --mode proof-core
      --stop-after-static-preflight
      --out "$out/smoke"
    )
    ${caseArguments}
    set +e
    ${spaghettiExtractor}/bin/spaghetti-extractor \
      "''${smoke_args[@]}" > "$TMPDIR/smoke-command.json"
    smoke_status=$?
    set -e
    if [ "$smoke_status" -ne 0 ]; then
      cat "$TMPDIR/smoke-command.json" >&2
      exit "$smoke_status"
    fi
    cp "$TMPDIR/smoke-command.json" "$out/smoke-command.json"

    jq -e --slurpfile expected "$TMPDIR/expected-case-ids.json" '
      .format == "stage-a-roundtrip-run-result-v1" and
      .status == "pass" and
      .stopped_after == "static-preflight" and
      .expectations_evaluated == false and
      (.static_preflight_failure_case_ids | length) == 0 and
      .trust.runner_has_proof_authority == false and
      .trust.positive_pass_requires == "whole_program_lean" and
      ([.cases[].case_id] | sort) == ($expected[0] | sort) and
      ([.cases[].case_id] | length) == ([.cases[].case_id] | unique | length) and
      all(.cases[];
        .acceptance.authority == null and
        .actual_disposition == "incomplete" and
        any(.phases[];
          .id == "static-preflight" and .status == "ready") and
        all(.phases[];
          .id != "proof-preparation" and
          .id != "proof-build-and-audit"))
    ' "$out/smoke/run-result.json" >/dev/null

    while IFS= read -r case_id; do
      test -f "$out/smoke/cases/$case_id/static-preflight.json"
      jq -e '
        .format == "stage-a-relational-static-preflight-v1" and
        .status == "ready" and
        .acceptance_authority == false
      ' "$out/smoke/cases/$case_id/static-preflight.json" >/dev/null
    done < <(jq -r '.[]' "$TMPDIR/expected-case-ids.json")

    jq -n \
      --arg corpus "$out/corpus/${corpusManifest}" \
      --arg report "$out/smoke/run-result.json" \
      --slurpfile selected_cases "$TMPDIR/expected-case-ids.json" \
      '{
        format: "stage-a-roundtrip-nix-smoke-v1",
        status: "pass",
        static_only: true,
        executes_original_binary: false,
        corpus: $corpus,
        report: $report,
        selected_cases: $selected_cases[0]
      }
    ' > "$out/smoke.json"
  ''
