{
  pkgs,
  name,
  spaghettiExtractor ? null,
  pythonEnv ? null,
  pythonSource ? null,
  kernelCache ? null,
  corpus,
  backend,
  bochsRunner ? null,
  withForms ? false,
  contentAddressed ? true,
}:

let
  narrowWorker = pythonEnv != null && pythonSource != null;
  workerSource =
    if narrowWorker then
      import ./python-module-closure.nix {
        inherit pkgs;
        source = pythonSource;
        modules = [ "spaghetti_extractor.isa_conformance_worker" ];
        extraPaths = [ "spaghetti_extractor/lean/StageA" ];
        name = "${name}-python-closure";
      }
    else
      null;
  narrowWorkerCommand = ''
    export PYTHONHASHSEED=0
    export PYTHONDONTWRITEBYTECODE=1
    export PYTHONPATH=${workerSource}/src
    ${pythonEnv}/bin/python3 - \
        ${corpus} ${pkgs.lib.escapeShellArg backend} \
        "$out/report.json" \
        ${pkgs.lib.escapeShellArg (if backend == "bochs" then toString bochsRunner else "-")} \
        ${pkgs.lib.escapeShellArg (if backend == "lean" then toString kernelCache else "-")} \
        ${if withForms then ''"$out/forms.json"'' else "-"} \
        1800 > "$out/result.json" <<'PY'
    import json
    import pathlib
    import sys

    from spaghetti_extractor.isa_conformance_worker import (
        run_isa_conformance_worker,
    )

    optional = lambda value: None if value == "-" else pathlib.Path(value)
    result = run_isa_conformance_worker(
        corpus_path=pathlib.Path(sys.argv[1]),
        backend=sys.argv[2],
        out=pathlib.Path(sys.argv[3]),
        bochs_runner=optional(sys.argv[4]),
        lean_kernel_cache=optional(sys.argv[5]),
        forms_out=optional(sys.argv[6]),
        lean_timeout_seconds=int(sys.argv[7]),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    PY
  '';
  packageWorkerCommand = ''
    spaghetti-extractor stage-a-check-isa-conformance-worker \
      --corpus ${corpus} \
      --backend ${backend} \
      ${pkgs.lib.optionalString (backend == "bochs") "--bochs-runner ${bochsRunner}"} \
      ${pkgs.lib.optionalString (backend == "lean") "--lean-kernel-cache ${kernelCache}"} \
      ${pkgs.lib.optionalString (backend == "lean") "--lean-timeout-seconds 1800"} \
      --out "$out/report.json" \
      ${pkgs.lib.optionalString withForms ''--forms-out "$out/forms.json"''} \
      > "$out/result.json"
  '';
in
assert builtins.elem backend [
  "lean"
  "unicorn"
  "bochs"
];
assert backend != "bochs" || bochsRunner != null;
assert !withForms || backend == "lean";
assert backend != "lean" || kernelCache != null;
assert narrowWorker || spaghettiExtractor != null;

pkgs.runCommand name
  (
    {
      nativeBuildInputs = [ pkgs.jq pkgs.lean4 ]
        ++ pkgs.lib.optionals narrowWorker [ pythonEnv ]
        ++ pkgs.lib.optionals (!narrowWorker) [ spaghettiExtractor ];
      preferLocalBuild = false;
      allowSubstitutes = true;
    }
    // pkgs.lib.optionalAttrs contentAddressed {
      __contentAddressed = true;
    }
  )
  ''
    mkdir -p "$out"
    set -euo pipefail
    ${if narrowWorker then narrowWorkerCommand else packageWorkerCommand}
    jq -e '
      .format == "stage-a-isa-conformance-check-v1"
      and .proof_authority == false
      and .closes_stage_a_proof == false
    ' "$out/result.json" > /dev/null
  ''
