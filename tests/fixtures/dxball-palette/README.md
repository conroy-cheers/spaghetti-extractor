# Shared DX-Ball palette effects

`palette.c` closes the shared fade, left/right shift, rotating sequence and
single-color bodies used by the scenes. It borrows the existing image-loader
palette arrays and flow mode. See [BOUNDARY.md](BOUNDARY.md) for byte history,
callbacks, ranges and progress assumptions. No original source is used.

Inside the existing lifting development environment:

```sh
python tests/fixtures/dxball-palette/prepare.py /path/to/DXBall.exe \
  /path/to/mds-stream-normal-check/inputs /tmp/palette
spaghetti-headless-wayland spaghetti-extractor component check dxball palette-effects \
  --comparison-package /tmp/palette/palette-effects --output /tmp/palette-check
```

The 31 retained cases compare whole palettes and rotating buffers, guards,
ordered service calls and callback changes. A useful defect replay changes the
right shift's four-byte copy to three bytes: RGB still looks correct, but the
flag-byte difference is reported locally.

```sh
spaghetti-extractor component start dxball palette-effects \
  --comparison-package /tmp/palette-check/inputs \
  --source-file source/palette.c=/path/to/edit.c --output /tmp/palette-edit
spaghetti-headless-wayland spaghetti-extractor component check dxball palette-effects \
  --comparison-package /tmp/palette-edit --case right-wrap \
  --reuse-comparison /tmp/palette-check --output /tmp/palette-replay
```

Apply the matching selection to a copy of the preceding MDS source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/palette-check --accept-boundary-change palette-effects \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-palette/assemble.py {project} /tmp/palette-check' \
  --check-command 'make -C {project} palette' \
  --check-command 'python {project}/check-palette.py'
```

For AArch64, set its `CC` and `AR` in the make command and pass
`--runner /path/to/qemu-aarch64` to the check. The consumer is a source program
with declared callback services; it is not the full desktop game. The assembly
recipe needs no PE decoding library after the comparison is retained.

Exercise the new bodies through their real callers:

```sh
python tests/fixtures/dxball-palette/prepare-normal.py /tmp/palette-check/inputs \
  /path/to/mds-stream-normal-check/inputs /tmp/palette-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball music-control \
  --comparison-package /tmp/palette-normal/package \
  --reuse-comparison /path/to/mds-stream-normal-check --output /tmp/palette-normal-check
```

The enclosing comparison identity stays `music-control`; `palette-effects` is an
independent program entry. All retained shared backend sources are preserved.
Normal observations retain the preceding fields and add outer palette calls with
arguments and before/after palette hashes. Nested rotation calls to the RGB helper
are part of their caller, not extra synthetic production operations.

Continue with the [standalone worklist](../dxball-standalone/README.md). Its linker
census makes missing program bindings visible; it does not grant proof authority
or turn a subsystem export into a complete program.
