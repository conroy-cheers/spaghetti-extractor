# jq CLI through the public component workflow

This fixture replaces jq's real process body with 622 lines of source-assisted
ordinary C. Native startup still converts wide arguments to UTF-8; small runtime
adapters supply stream modes, terminal handling, callback identity and process
exit. The original CLI body and its private helpers are trapped on the source
side. An untouched executable checks that the observer itself preserves behavior.
See [BOUNDARY.md](BOUNDARY.md) for ownership and runtime scope.

Run Python commands in the retained lifting environment. Set `toolkit` to an
installed `spaghetti-extractor`, `project` to the existing portable jq project,
`native` to a retained comparison's `inputs/` directory, and `original` to the
pinned original jq binary directory. Use fresh output paths:

```sh
python tests/fixtures/jq-cli/prepare.py "$project" "$work/cli" "$toolkit"
python tests/fixtures/jq-cli/compare.py "$work/cli/authoring" "$native" "$original" "$work/comparison"
spaghetti-headless-wayland "$toolkit" component check jq cli \
  --comparison-package "$work/comparison" --output "$work/checked"
```

The comparison uses `program_driver` from the existing tooling. Its 48 cases
exercise options and errors, text/binary output, Unicode arguments, JSON/raw
formatting, callbacks, exit policies and file consumers. stdout/stderr are compared
as bytes, without normalization. Both normal exit and the actual CRT abort exit
are observed. No Wine command runs outside the headless Wayland desktop.

Apply the checked component with the existing transaction workflow. Commands must
use absolute script paths because they run in the staged project:

```sh
"$toolkit" candidate apply jq --project "$project" --comparison "$work/checked" \
  --component cli --accept-boundary-change cli \
  --assembly-command "python $repo/tests/fixtures/jq-cli/assemble.py {project}"
```

Add the usual `--check-command` build and headless program-run commands before
publication. `assemble.py` retains and normalizes the backend's conditional
process-entry spelling, then calls the existing jq binding recipe. Source export,
retirement, rollback and dependency selection remain shared tooling. The standalone
entry calls the same component through an ordinary C adapter.

The common [Windows-output library](../portable-runtime/windows-output.c) supplies
one stdout/stderr policy for the CLI and all existing consumers. Windows uses the
original CRT; the Linux backend uses libc cookie streams. The library also carries
the exercised wide-ASCII assertion behavior in text and binary modes. The jq
recipe excludes the component that provides `main` from library-only consumers.
No compiler, checker or proof-engine changes are involved.

For the new file-based portable workloads, `jq-portable/run.py` accepts repeated
`--runtime-file NAME=PATH` arguments, retaining exact input hashes. `cases.py`
supplies the corresponding input bytes. Existing `values.json` is already supplied
by that runner; `text.txt` and `filter.jq` are additional inputs.

The completed experiment is retained at
`build/jq-cli-lifting-2026-09-27/`. `cli/final/` has 48 native matches;
`host-final-run/` and `arm-final-run/` each have 277 CLI plus 32 live-value matches.
All 38/39 prior component records and source files are unchanged. The report in
[docs/jq-cli-continuation.md](../../../docs/jq-cli-continuation.md) records costs,
diagnosed failures, limits and remaining full-program work.
