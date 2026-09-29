# MDS stream lifecycle

[stream.c](stream.c) implements start, pause, stop, completion and release over the
shared info and buffer types from the parser. [BOUNDARY.md](BOUNDARY.md) describes
historical flags/counts, callback requeue, publication and error-side lifetimes.
The loader, parser and event expander are reused to construct real input objects;
all WinMM and storage behavior comes from the shared environment.

Prepare and compare without starting the game:

```sh
python tests/fixtures/dxball-mds-stream/prepare.py /path/to/DXBall.exe \
  /path/to/mds-loader-check/inputs /tmp/mds-stream
spaghetti-headless-wayland spaghetti-extractor component check dxball mds-stream \
  --comparison-package /tmp/mds-stream/mds-stream --output /tmp/mds-check
```

The 50 cases include all six bundled MDS files, two live streams, partial startup,
failed open publication, resume, callback requeue, pending-count wraparound,
deferred completion, zero-length payloads and cleanup failures. The deliberate
reset-failure/release case enables controlled observation of invalid disposal;
later access to retired storage remains a capability error.

The shared transport keeps imported field baselines separate from byte snapshots
and publishes only actual C changes. `provider-linked-header` injects a provider
update to a private queue link between callback execution and state publication.
It reproduces the whole-header overwrite seen with Wine without starting the
game. Source C does not need to know or overwrite that provider-owned link.
`provider-read-interleave` changes that link between constructing the C view and
recording its write baseline. It reproduced another lost-link failure exposed
by normal execution. The baseline now comes from the same captured words as the
view; a second native read must not turn a provider update into an apparent C
write. Both cases run without the game or a native MIDI driver.

For a C defect replay, change `--info->pending;` to `info->pending-=2;`.
Use `component start --comparison-package /tmp/mds-check/inputs --source-file
source/stream.c=/path/to/edit.c`, then `component check --case nonloop-completion
--reuse-comparison /tmp/mds-check`. The pending-count mismatch is diagnosed locally.

Apply the matching comparison to a copy of the preceding source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/mds-check --accept-boundary-change mds-stream \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-mds-stream/assemble.py {project} /tmp/mds-check' \
  --check-command 'make -C {project} audio audio-setup wave file-reader mds-parser mds-loader mds-stream' \
  --check-command 'python {project}/check-audio.py' \
  --check-command 'python {project}/check-audio-setup.py' \
  --check-command 'python {project}/check-wave.py' \
  --check-command 'python {project}/check-reader.py' \
  --check-command 'python {project}/check-mds-parser.py' \
  --check-command 'python {project}/check-mds-loader.py' \
  --check-command 'python {project}/check-mds-stream.py'
```

These checks cover the affected consumers after updating the shared backend and
transport. AArch64 uses its `CC`/`AR` and each check accepts
`--runner /path/to/qemu-aarch64`. The preceding component implementations remain
unchanged; their evidence references bind the new consumer selection.

Exercise all MDS replacements through the actual music controller:

```sh
python tests/fixtures/dxball-mds-stream/prepare-normal.py /tmp/mds-check/inputs \
  /path/to/mds-loader-normal-check/inputs /tmp/mds-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball music-control \
  --comparison-package /tmp/mds-normal/package \
  --reuse-comparison /path/to/mds-loader-normal-check --output /tmp/mds-normal-check
```

The normal observer keeps the previous fields and adds lifecycle/callback state.
No synthetic production API or proof qualification is needed for these executable
comparisons. They do not grant strong activation authority or supply a production
portable music backend.
