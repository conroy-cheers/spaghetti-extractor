# jq test runner through normal program execution

The `--run-tests` implementation is ordinary source-assisted C: test-file and
thread execution in `runner.c`, value checks in `values.c`. Both decimal-number
and pthread behavior remain enabled. See `BOUNDARY.md` for ownership, process
outcomes, shared input policy and practical assurance limits.

Use the retained lifting environment and an installed toolkit:

```sh
runner_tool="$PWD/build/component-assembly-update-2026-09-27/toolkit-final/bin/spaghetti-extractor"
python tests/fixtures/jq-test-runner/prepare.py \
  build/jq-runtime-contexts-lifting-2026-09-27/program build/my-tests "$runner_tool"
python tests/fixtures/jq-test-runner/compare.py \
  build/my-tests/authoring \
  build/jq-ir-lifting-2026-09-27/lifecycle/final/inputs ORIGINAL_BIN build/my-tests/package
spaghetti-headless-wayland "$runner_tool" component check jq test-runner \
  --comparison-package build/my-tests/package --output build/my-tests/checked
"$runner_tool" candidate apply jq --project build/my-jq \
  --comparison build/my-tests/checked --component test-runner \
  --accept-boundary-change test-runner \
  --assembly-command "python $PWD/tests/fixtures/jq-test-runner/assemble.py {project}" \
  --check-command 'make -j2 jq live-values'
```

`ORIGINAL_BIN` contains the pinned original jq executable and DLLs. Native
comparison checks actual arguments, stdout/stderr, exit status and successful
pthread creation/join counts. The whole original test-runner object is disabled;
an untouched-original run also checks observation transparency. Every Wine
execution uses a headless Wayland desktop. No allocation observer is shared
unsafely between the three concurrently active workers.

`assemble.py` records the exact choice of the existing non-MVS pthread spelling
before ordinary reversible function retirement. It does not add preprocessor
interpretation to the checker. `--bindings FILE` can combine this selection with
other reviewed component changes. The shared file provider and process stdin
decoder are reused; named files retain their original lifetime until process
termination. Add normal program checks to `candidate apply` for publication only
after those workloads succeed.

The retained `build/jq-final-support-lifting-2026-09-27/` experiment includes the
complete prepare/check/apply recipes and native comparison evidence. Editing C
uses the same public workflow and `--reuse-comparison` for eligible objects.
