# jq multi-file input component

This groups the ten native entries sharing `jq_util_input_state` into nine
ordinary operations. Direct and callback reads use the same `next` operation.
Private C owns the parser, filenames, buffers, counters and returned values;
the boundary transports the actual state pointer without reconstructing it.
See [BOUNDARY.md](BOUNDARY.md) for ownership, callbacks and retained target quirks.

```sh
python tests/fixtures/jq-input-stream/prepare.py PROJECT INPUT-WORK TOOLKIT
python tests/fixtures/jq-input-stream/compare.py \
  INPUT-WORK/authoring NATIVE-INPUTS INPUT-WORK/comparison
spaghetti-headless-wayland spaghetti-extractor component check jq input-stream \
  --comparison-package INPUT-WORK/comparison --output INPUT-CHECK
```

Run in the lifting shell. `PROJECT` supplies pinned jq headers; `TOOLKIT` is the
`spaghetti-extractor` executable; `NATIVE-INPUTS` is a retained native comparison's
`inputs/` directory. The reviewed native-entry table pins the original image
through the existing hook generator. All public bodies and the private reader
are trapped on the source side. Eleven scenarios cover two jq contexts,
raw/JSON/slurp, repeated files, errors, early teardown, metadata and two input
states sharing stdin, including repeated `-` and Ctrl-Z EOF.

The same shared [file library](../portable-runtime/windows-files.h) is a native
comparison dependency and a portable application dependency. Native adapter C
supplies stdin and the callback entry's image-bound identity. The portable
adapter supplies process-owned stdin state and uses the existing import-identity
diagnostic backend. Do not replace that identity check with unconditional success:
the pinned CLI's import thunk triggers a real assertion in some error paths.

`portable-bindings.json` maps the operations to the existing source-assembly
facility. Select [file-input](../jq-file-input/README.md) once to supply the shared
library. In the portable CLI, declare `void spx_stdin_set_binary(int);` and call
`spx_stdin_set_binary(1)` in the existing `--binary` branch before input is read.
This is an ordinary platform startup binding; the component does not parse argv.
Default output modes are a separate runtime policy.

The checked handoff and conventional standalone projects are recorded in the
[continuation report](../../../docs/jq-file-runtime-continuation.md). For a local
edit, reopen its comparison result and use `--reuse-comparison`; use partial
`candidate export --update-components` and the existing jq binding refresh to
retain unrelated component work.
