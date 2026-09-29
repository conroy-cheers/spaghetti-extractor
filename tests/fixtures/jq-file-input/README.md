# jq file input and shared file runtime

This component replaces `jv_load_file` with ordinary C. The independently usable
[`windows-files` library](../portable-runtime/windows-files.h) supplies pathname
lookup and stream decoding. The parser, values and UTF-8 helpers remain explicit
dependencies. This is source-assisted lifting of the pinned jq configuration.

In the lifting shell, use an existing portable source project for its jq headers
and a retained native comparison's `inputs/` for the compiler, imports and DLLs:

```sh
python tests/fixtures/jq-file-input/prepare.py PROJECT FILE-WORK TOOLKIT
python tests/fixtures/jq-file-input/compare.py \
  FILE-WORK/authoring NATIVE-INPUTS FILE-WORK/comparison
spaghetti-headless-wayland spaghetti-extractor component check jq file-input \
  --comparison-package FILE-WORK/comparison --output FILE-CHECK
```

`TOOLKIT` is the `spaghetti-extractor` executable. Edit the generated authoring
workspace's C, or reopen `FILE-CHECK` through `component start --comparison-result`
for subsequent local edits. Nineteen cases exercise repeated raw/JSON loads,
CRLF, Ctrl-Z, embedded NUL, invalid and split UTF-8, case lookup and errors. Large
fixtures are generated in the C driver from short retained selectors; their exact
bytes are also recorded in `fixture-bytes.json`. The original body is trapped on
the source side, and returned values and remaining jq allocations are compared.

`portable-bindings.json` supplies the ordinary `jv_load_file` entry adapter for
the existing source export/refresh workflow. The file-input source package also
contains the shared library's implementation, linked once. The
[input-stream component](../jq-input-stream/README.md) and module loader use that
provider through its C header. They do not each compile another copy.

The [continuation report](../../../docs/jq-file-runtime-continuation.md) records
the combined assembly, runtime scope, retained failures and two-architecture
program comparisons. Native comparison is finite evidence, not qualification.
