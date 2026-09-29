# DX-Ball WAV loading

`wave.c` implements sample loading and RIFF traversal in ordinary C. The
[boundary](BOUNDARY.md) preserves the original parser's partial outputs,
historical format pointer, allocation/disposal behavior and shared sound-bank
state. The pinned executable supplies the oracle; no original game source is used.

Run preparation inside the project's lifting environment, retaining the preceding
sound-bank comparison package:

```sh
python tests/fixtures/dxball-wave/prepare.py /path/to/DXBall.exe \
  /path/to/audio-local-check/inputs /tmp/dx-wave
spaghetti-headless-wayland spaghetti-extractor component check dxball wave-loader \
  --comparison-package /tmp/dx-wave/wave-loader --output /tmp/dx-wave-check
```

The 52 cases exercise parsing, actual bank disposal, allocation failure, file
failure, dangling slots, partial query outputs, positive error statuses, callbacks,
long names and a load/stop/release sequence. DirectSound scenarios and observations
come from the shared backend. The record allocator and input-file bytes are
explicit application boundary providers; their controlled behavior is not a claim
about arbitrary native heaps or invalid-memory accesses.

Export into a copy of the preceding sound-setup source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-wave-check --accept-boundary-change wave-loader \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-wave/assemble.py {project} /tmp/dx-wave-check' \
  --check-command 'make -C {project} wave' \
  --check-command 'python {project}/check-wave.py'
```

The standalone consumer runs without Wine or the original executable. With
AArch64 `CC`/`AR`, append `--runner /path/to/qemu-aarch64` to the check command.

For a local defect demonstration, copy `wave.c` and insert
`state->slots[slot]=NULL;` after the first `free_sample` call, in the missing-file
branch. That apparent cleanup changes the original behavior:

```sh
spaghetti-extractor component start dxball wave-loader \
  --comparison-package /tmp/dx-wave-check/inputs \
  --source-file source/wave.c=/tmp/wave-wrong.c --output /tmp/dx-wave-wrong
spaghetti-headless-wayland spaghetti-extractor component check dxball wave-loader \
  --comparison-package /tmp/dx-wave-wrong --case file-failure \
  --reuse-comparison /tmp/dx-wave-check --output /tmp/dx-wave-wrong-check
```

The differing slot appears at `$.wave.final.roots[6]`. Unchanged compiler objects
are reused. Restore the original authored file for subsequent integration.

Normal program integration is additional evidence:

```sh
python tests/fixtures/dxball-wave/prepare-normal.py /tmp/dx-wave-check/inputs \
  /path/to/setup-normal-check/inputs /tmp/dx-wave-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball wave-loader \
  --comparison-package /tmp/dx-wave-normal/package --output /tmp/dx-wave-normal-check
```

The adapter captures original entry history and maps sample records through the
existing owner. Native allocation/free events establish live and retired records;
an incoming pointer alone never makes a retired record live. The normal consumer
is single-threaded and requires nonrecursive loader invocations and live records
at ordinary typed bank accesses. It retains the native file reader, allocator,
other remaining functions and Wine platform implementations. The loader body,
parser and descriptor helper are trapped on the replacement side, preventing
fallback into their original instruction interiors. This is not a portable game.
