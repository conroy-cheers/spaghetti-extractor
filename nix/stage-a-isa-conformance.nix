{
  pkgs,
  name,
  spaghettiExtractor,
  kernelCache ? null,
  corpus,
  backend,
  bochsRunner ? null,
  withForms ? false,
  contentAddressed ? true,
}:

assert builtins.elem backend [
  "lean"
  "unicorn"
  "bochs"
];
assert backend != "bochs" || bochsRunner != null;
assert !withForms || backend == "lean";
assert backend != "lean" || kernelCache != null;

pkgs.runCommand name
  (
    {
      nativeBuildInputs = [
        pkgs.jq
        pkgs.lean4
        spaghettiExtractor
      ];
      preferLocalBuild = false;
      allowSubstitutes = true;
    }
    // pkgs.lib.optionalAttrs contentAddressed {
      __contentAddressed = true;
    }
  )
  ''
    mkdir -p "$out"
    set +e
    spaghetti-extractor stage-a-check-isa-conformance-worker \
      --corpus ${corpus} \
      --backend ${backend} \
      ${pkgs.lib.optionalString (backend == "bochs") "--bochs-runner ${bochsRunner}"} \
      --out "$out/report.json" \
      ${pkgs.lib.optionalString withForms ''--forms-out "$out/forms.json"''} \
      > "$out/result.json"
    worker_status="$?"
    set -e
    if [ "$worker_status" -gt 1 ]; then
      echo "ISA conformance worker failed with status $worker_status" >&2
      exit "$worker_status"
    fi
    jq -e '
      .format == "stage-a-isa-conformance-check-v1"
      and .proof_authority == false
      and .closes_stage_a_proof == false
    ' "$out/result.json" > /dev/null
  ''
