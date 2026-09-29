# DX-Ball music controller

The four controller bodies in [music.c](music.c) implement track replacement,
start/resume, pause and stop. The [boundary](BOUNDARY.md) exposes a shared current
record, opaque stream identities, allocation and the existing MDS library services.
Service callbacks may redirect the root; the C preserves the original reloads.
No WinMM implementation is embedded in this target fixture.

Prepare from retained inputs and compare without starting the game:

```sh
python tests/fixtures/dxball-music/prepare.py /path/to/DXBall.exe \
  /path/to/reader-check/inputs /tmp/music
spaghetti-headless-wayland spaghetti-extractor component check dxball music-control \
  --comparison-package /tmp/music/music-control --output /tmp/music-check
```

The 30 cases cover load/start failures, zero/nonzero status distinctions, allocation
failure, empty roots, ignored cleanup failures, incoming historical words,
callbacks that change the current record, and a play/pause/resume/stop sequence.
The original machine bodies execute over the same application service boundary;
these are not MIDI platform simulations.

For a local negative replay, copy `music.c` and cache `state->current` across the
resume service call, then write `playing` through the cached pointer. Public
`component start --comparison-package ... --source-file source/music.c=...`
creates the draft; `component check --case resume-root-redirection
--reuse-comparison ...` catches the wrong object write without game execution.

Update a copy of the preceding standalone source selection:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/music-check --accept-boundary-change music-control \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-music/assemble.py {project} /tmp/music-check' \
  --check-command 'make -C {project} music' \
  --check-command 'python {project}/check-music.py'
```

AArch64 uses its `CC`/`AR` and `check-music.py --runner /path/to/qemu-aarch64`.
Neighbors are retained. The source consumer uses the controlled application
library boundary; it is not a standalone MIDI player or complete game.

For normal integration, the adapter calls the actual retained MDS library:

```sh
python tests/fixtures/dxball-music/prepare-normal.py /tmp/music-check/inputs \
  /path/to/reader-normal-check/inputs /tmp/music-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball music-control \
  --comparison-package /tmp/music-normal/package --output /tmp/music-normal-check
```

The source side traps all four original controller bodies. Outer controller calls,
record identity, playing state and allocation/disposal counts add to the previous
program observations. Allocated record bytes are transported within each execution;
uninitialized record words are not used as cross-candidate identity evidence.
The MDS application bodies remain native below this boundary. Mapped files,
platform allocation and MIDI now use the shared candidate-neutral Wine backend.
The normal adapter declares the MDS callback identity and its allocation-backed
user values; all platform behavior, completions and observations stay shared.
See [the backend scope](../../../docs/shared-wine-test-environment.md#mapped-storage-and-queued-midi-2026-09-29)
before extending an independent MDS component boundary.
