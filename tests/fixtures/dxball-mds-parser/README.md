# MDS container parsing

[parser.c](parser.c) parses the MDS container, allocates its buffer collection and
uses the independently lifted event expander. The [boundary](BOUNDARY.md) defines
shared info/header objects, readable backing, allocation history and cleanup.
The portable implementation uses typed views; the target adapter carries the
PE32 layout and pointer correspondence. The shared Wine backend supplies storage
semantics for either candidate.

Prepare and compare without starting the game:

```sh
python tests/fixtures/dxball-mds-parser/prepare.py /path/to/DXBall.exe \
  /path/to/mds-events-check/inputs /tmp/mds-parser
spaghetti-headless-wayland spaghetti-extractor component check dxball mds-parser \
  --comparison-package /tmp/mds-parser/mds-parser --output /tmp/mds-check
```

The event package must retain all six bundled MDS files. The 42 cases include
those files, malformed chunks, partial writes, unaligned backing, failed storage
operations and repeated parsing of the same info object. Observations retain
whole allocation bytes, partial info updates, live/lock history and platform
calls. Declared length and physically readable extent are separate inputs.

For a defect replay, add `info->buffers=NULL;` after the cleanup `free` call.
Use `component start --comparison-package /tmp/mds-check/inputs --source-file
source/parser.c=/path/to/edit.c`, then `component check --case delta-only
--reuse-comparison /tmp/mds-check`. The local comparison catches the changed
dangling pointer; no game run is needed.

Apply a matching comparison to a copy of the preceding source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/mds-check --accept-boundary-change mds-parser \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-mds-parser/assemble.py {project} /tmp/mds-check' \
  --check-command 'make -C {project} mds-parser' \
  --check-command 'python {project}/check-mds-parser.py'
```

The consumer links the existing event component and shared backend. AArch64 uses
its `CC`/`AR` and `check-mds-parser.py --runner /path/to/qemu-aarch64`. This
validates the source consumer; a production portable MIDI/game runtime remains
a separate obligation.

Exercise the replacement through its actual loader and MIDI consumer:

```sh
python tests/fixtures/dxball-mds-parser/prepare-normal.py /tmp/mds-check/inputs \
  /path/to/mds-events-normal-check/inputs /tmp/mds-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball music-control \
  --comparison-package /tmp/mds-normal/package \
  --reuse-comparison /path/to/mds-events-normal-check --output /tmp/mds-normal-check
```

The enclosing comparison keeps its `music-control` identity and adds the parser
using `program_entry_packages`. The parser's own local comparison is independent.
Normal observations preserve the preceding program fields and add parse results
and header metadata. Local finite evidence and executable C eligibility do not
grant formal activation authority; the optional formal source profile remains
incomplete for this unit.
