# DX-Ball sound device setup

`setup.c` implements initialization and focus/reload over the existing sound bank
and application owner. The [boundary](BOUNDARY.md) records the native entries,
shared state, callbacks, error results, exact dialogs and nonlocal termination.
The original PE32 instructions provide the oracle; no game source is used.

The platform binding comes from the installed
[shared Wine backend](../../../docs/shared-wine-test-environment.md), retained once
in the comparison consumer. Target code supplies application mappings and scenario
data. Both candidate binaries enter the same SDK-typed COM proxy methods. Normal
execution calls Wine; standalone exports compile the same controlled backend.
The backend API surface and lifetime/concurrency limits are explicit in the guide.

Prepare from the preceding local sound-bank and normal application packages in
the repository development environment:

```sh
python tests/fixtures/dxball-audio-setup/prepare.py /path/to/DXBall.exe \
  /path/to/audio-local-check/inputs /path/to/audio-normal-check/inputs /tmp/dx-setup
spaghetti-headless-wayland spaghetti-extractor component check dxball audio-setup \
  --comparison-package /tmp/dx-setup/audio-setup --output /tmp/dx-setup-check
```

The 36 cases need neither game startup nor a sound device. They cover creation,
positive failure results, retries, dialogs, termination, partial publication,
callback redirection and a focus/suspend/refocus/initialize sequence. Release and
reload use the actual sound-bank C. Providers overwrite disposed record storage
so name copying and lifetime effects are observable independently.

Add the component to a copy of the preceding sound-bank source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-setup-check --accept-boundary-change audio-setup \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-audio-setup/assemble.py {project} /tmp/dx-setup-check' \
  --check-command 'make -j2' --check-command 'python check-audio-setup.py'
```

The standalone consumer needs neither Wine nor the original executable. With
AArch64 `CC`/`AR`, use `python check-audio-setup.py --runner /path/to/qemu-aarch64`.
Existing sound-bank implementation and contract identities remain unchanged;
its comparison-binding references are updated for the connected evidence. Unaffected
compiled objects and consumers are reused.

A local defect demonstration changes `if (!result) break;` to
`if (result<=1) break;`, incorrectly treating positive creation status as success.
Use the public command to retain the workspace's unchanged source headers:

```sh
spaghetti-extractor component start dxball audio-setup \
  --comparison-package /tmp/dx-setup-check/inputs \
  --source-file source/setup.c=/tmp/setup-wrong.c --output /tmp/dx-setup-wrong
spaghetti-headless-wayland spaghetti-extractor component check dxball audio-setup \
  --comparison-package /tmp/dx-setup-wrong --case create-positive-published \
  --reuse-comparison /tmp/dx-setup-check --output /tmp/dx-setup-wrong-check
```

The focused check rejects the changed interaction independently of the game.
Normal integration is additional evidence:

```sh
python tests/fixtures/dxball-audio-setup/prepare-normal.py /tmp/dx-setup-check/inputs \
  /path/to/audio-normal-check/inputs /tmp/dx-setup-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball audio-setup \
  --comparison-package /tmp/dx-setup-normal/package --output /tmp/dx-setup-normal-check
```

Preparation explicitly replaces the selected local bank adapter with its normal
backend and dependencies. Keeping both conflicting selections is rejected.
The mixed backend retains native WAV loading and DirectSound. Incoming sample
records must be live; existing status/capability queries must provide complete
successful outputs. Loader failure/lifetime behavior and failed-query caller
history still require transport work. The normal workload cannot discharge those
obligations or replace the independent error cases.
