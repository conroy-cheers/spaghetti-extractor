# MDS file and memory loading

[loader.c](loader.c) manages the outer MDS allocation and file mapping, invoking
the existing parser and event-expander components. The [boundary](BOUNDARY.md)
defines output publication, input modes and cleanup/lifetime behavior. Shared
Win32 services execute all allocation, file and mapping effects.

Prepare and compare without starting the game:

```sh
python tests/fixtures/dxball-mds-loader/prepare.py /path/to/DXBall.exe \
  /path/to/mds-parser-check/inputs /tmp/mds-loader
spaghetti-headless-wayland spaghetti-extractor component check dxball mds-loader \
  --comparison-package /tmp/mds-loader/mds-loader --output /tmp/mds-check
```

The parser package must retain the six bundled MDS files. The 41 cases cover file
and memory modes, every bundled asset through both paths, invalid flags, higher
flag bits, allocation/mapping failures, malformed input, cleanup failures and
repeated calls. The output slot and snapshots of info/buffer bytes remain visible
alongside the shared platform history. The parser and event expander are declared
component dependencies; their implementations are reused.

To replay a meaningful local defect, clear `output->value` in the failure cleanup.
Use `component start --comparison-package /tmp/mds-check/inputs --source-file
source/loader.c=/path/to/edit.c`, then `component check --case failed-output-history
--reuse-comparison /tmp/mds-check`. The preserved caller value exposes the error.

Apply the matching comparison to a copy of the preceding source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/mds-check --accept-boundary-change mds-loader \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-mds-loader/assemble.py {project} /tmp/mds-check' \
  --check-command 'make -C {project} mds-loader' \
  --check-command 'python {project}/check-mds-loader.py'
```

AArch64 uses its `CC`/`AR` and `check-mds-loader.py --runner /path/to/qemu-aarch64`.
This consumer links the previous parser and event objects with the shared backend.

Exercise the replacement through the actual music controller and MIDI consumer:

```sh
python tests/fixtures/dxball-mds-loader/prepare-normal.py /tmp/mds-check/inputs \
  /path/to/mds-parser-normal-check/inputs /tmp/mds-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball music-control \
  --comparison-package /tmp/mds-normal/package \
  --reuse-comparison /path/to/mds-parser-normal-check --output /tmp/mds-normal-check
```

The enclosing program comparison retains its identity and prior observations.
It adds the loader through `program_entry_packages`; the loader's own local
comparison remains independently editable. These finite comparisons and portable
source executions grant experimental evidence, not formal activation authority.
