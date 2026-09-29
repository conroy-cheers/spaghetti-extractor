# MDS event expansion

[events.c](events.c) expands compact MDS events into stream events, preserving
partial writes, padding and failed-call output history. The [boundary](BOUNDARY.md)
defines two independent byte-backed descriptors. The operation needs no platform
service or knowledge of the rest of the game.

Prepare from retained inputs and compare without game startup:

```sh
python tests/fixtures/dxball-mds-events/prepare.py /path/to/DXBall.exe \
  /path/to/music-normal-check/inputs /tmp/mds-events
spaghetti-headless-wayland spaghetti-extractor component check dxball mds-events \
  --comparison-package /tmp/mds-events/mds-events --output /tmp/mds-check
```

The environment package must retain the six bundled MDS files. The 34 cases
include all blocks in those files, generated streams, short buffers and payloads,
unaligned bytes, untouched descriptor fields and a successful call followed by
a failing call on the same destination. Full byte regions and guards are compared.

For a local defect replay, change the inserted stream word from zero to one.
Use `component start --comparison-package /tmp/mds-check/inputs --source-file
source/events.c=/path/to/edit.c`, then `component check --case one-short
--reuse-comparison /tmp/mds-check`. The output-byte mismatch is observable locally.

Apply the matching comparison to a copy of the preceding source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/mds-check --accept-boundary-change mds-events \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-mds-events/assemble.py {project} /tmp/mds-check' \
  --check-command 'make -C {project} mds-events' \
  --check-command 'python {project}/check-mds-events.py'
```

AArch64 uses its `CC`/`AR` and `check-mds-events.py --runner /path/to/qemu-aarch64`.
The consumer compiles from source and uses the retained music assets. This unit
does not implement the whole MDS parser, MIDI lifecycle or portable game runtime.

Exercise the replacement in its actual parser and game caller:

```sh
python tests/fixtures/dxball-mds-events/prepare-normal.py /tmp/mds-check/inputs \
  /path/to/music-normal-check/inputs /tmp/mds-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball music-control \
  --comparison-package /tmp/mds-normal/package \
  --reuse-comparison /path/to/music-normal-check --output /tmp/mds-normal-check
```

The program comparison keeps its existing `music-control` entry and adds
`mds-events` with `program_entry_packages`, preserving the preceding selection and
compiler cache. A new component's local comparison retains its own identity.
The source side replaces the entire native expander body. The shared Wine backend
continues to observe mapped storage, allocations, MIDI buffer bytes and callbacks
without distinguishing the candidates. The new normal observer adds expander
arguments, outputs and execution counts while preserving the prior observations.
