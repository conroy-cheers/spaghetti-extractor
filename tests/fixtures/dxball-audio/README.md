# DX-Ball sound bank control

`audio.c` implements playback, looping, stopping, lost-buffer recovery, record
disposal, suspension and shutdown over one shared bank. The [boundary](BOUNDARY.md)
defines retained bytes, identity, lifetime, callback reloads and status history.
Native device creation and sample loading remain neighboring services.

The platform binding comes from the installed
[shared Wine backend](../../../docs/shared-wine-test-environment.md), retained once
in the comparison consumer. Target code supplies application mappings and scenario
data. Both candidate binaries enter the same SDK-typed COM proxy methods. Normal
execution calls Wine; standalone exports compile the same controlled backend.
The backend API surface and lifetime/concurrency limits are explicit in the guide.

Use the existing development environment and pinned original executable:

```sh
python tests/fixtures/dxball-audio/prepare.py /path/to/DXBall.exe /tmp/dx-audio
spaghetti-headless-wayland spaghetti-extractor component check dxball audio-bank \
  --comparison-package /tmp/dx-audio/audio-bank --output /tmp/dx-audio-check
```

The 36 independent cases need neither game startup nor an audio device. They
execute original entries with controlled providers, including a sequence through
all nine operations. Recovery invokes a loader provider which calls the actual
release operation before publishing a new record. Observations retain every slot,
sample byte, resource lifetime and ordered interaction. The provider overwrites
disposed record storage, exposing accidental use of an uncopied saved name.

Add this component to a copy of the preceding display source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-audio-check --accept-boundary-change audio-bank \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-audio/assemble.py {project} /tmp/dx-audio-check' \
  --check-command 'make -j2' --check-command 'python check-audio.py'
```

The standalone consumer needs neither Wine nor the original executable. With
AArch64 `CC`/`AR`, use `python check-audio.py --runner /path/to/qemu-aarch64`.
Unchanged neighboring component records, compiled objects and consumers are reused.

For a local defect demonstration, copy `audio.c` and change release-one to cache
the selected sample before `release_buffer`, then clear the cached sample's buffer
after that call. The provider in `release-redirected-record` redirects the slot;
the original clears the current sample. Start a workspace using the public command
so unchanged source files and headers are retained:

```sh
spaghetti-extractor component start dxball audio-bank \
  --comparison-package /tmp/dx-audio-check/inputs \
  --source-file source/audio.c=/tmp/audio-wrong.c --output /tmp/dx-audio-wrong
spaghetti-headless-wayland spaghetti-extractor component check dxball audio-bank \
  --comparison-package /tmp/dx-audio-wrong --case release-redirected-record \
  --reuse-comparison /tmp/dx-audio-check --output /tmp/dx-audio-wrong-check
```

Normal integration uses the retained display/application comparison package:

```sh
python tests/fixtures/dxball-audio/prepare-normal.py /tmp/dx-audio-check/inputs \
  /path/to/display-normal-check/inputs /tmp/dx-audio-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball audio-bank \
  --comparison-package /tmp/dx-audio-normal/package --output /tmp/dx-audio-normal-check
```

The normal backend requires live incoming sample records and successful complete
GetStatus outputs. It stops explicitly on query failure; original-caller restore
history transport remains unfinished there. Its placeholders are not original
stack history. The local cases independently check unwritten outputs and history
carried between slots. Sample-loader failure/lifetime behavior and general
other platform families require further lifting; a passing normal workload cannot
discharge these obligations.
