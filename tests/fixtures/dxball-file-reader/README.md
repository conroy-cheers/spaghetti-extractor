# DX-Ball file reader

`reader.c` lifts `0x40d9f0..0x40db13` into ordinary C. The [boundary](BOUNDARY.md)
preserves the fallback path, ignored read count, both buffer ownership modes and
failure leaks. Win32 behavior comes from the [shared backend](../../../docs/shared-wine-test-environment.md),
with no DX-Ball-specific file API implementation.

Use a retained preceding comparison package for the existing compiler/Wine inputs:

```sh
python tests/fixtures/dxball-file-reader/prepare.py /path/to/DXBall.exe \
  /path/to/wave-check/inputs /tmp/reader
spaghetti-headless-wayland spaghetti-extractor component check dxball file-reader \
  --comparison-package /tmp/reader/file-reader --output /tmp/reader-check
```

The 22 cases cover allocated and supplied buffers, fallback/missing paths,
allocation failure, failed/short/empty reads, ignored close failure, invalid size,
positive BOOL results, long fallback names and repeated calls. They run the real
machine body without starting the game. The generic environment observes path and
flags, requested/transferred bytes, preserved output bytes and handle lifetimes.

To demonstrate a locally caught defect, copy `reader.c` and change the allocation-
failure branch to close the file before returning NULL. The original leaks that
handle. Use public `component start --comparison-package ... --source-file ...`
and `component check --case allocation-failure --reuse-comparison ...` to replay
it; no full-program run is needed.

Update a copy of the preceding WAV source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/reader-check --accept-boundary-change file-reader \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-file-reader/assemble.py {project} /tmp/reader-check' \
  --check-command 'make -C {project} file-reader audio audio-setup wave' \
  --check-command 'python {project}/check-reader.py' \
  --check-command 'python {project}/check-audio.py' \
  --check-command 'python {project}/check-audio-setup.py' \
  --check-command 'python {project}/check-wave.py'
```

For AArch64, set its `CC`/`AR` and add `--runner /path/to/qemu-aarch64` to each
check command. The affected sound/WAV adapters are rebuilt against the changed
shared backend; neighboring authored component C is reused. These standalone
consumers need neither Wine nor the original executable.

For normal execution:

```sh
python tests/fixtures/dxball-file-reader/prepare-normal.py /tmp/reader-check/inputs \
  /path/to/wave-normal-check/inputs /tmp/reader-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball file-reader \
  --comparison-package /tmp/reader-normal/package --output /tmp/reader-normal-check
```

The same backend observes actual Wine file calls from the importing module. That
includes CRT consumers as well as the selected reader, so their security and
handle inputs are platform requirements rather than per-target emulation. The
source reader's original body is trapped. Native allocation, music and other
unlifted services remain; a passing mixed run is not a standalone portable game.
Closes of resources acquired outside the observed file imports use the explicit
native forwarding option and retain `handle_known=0`. Their identity/lifetime is
outside this observation scope. Local controlled component cases remain strict.
