# Complete DX-Ball display setup

`display.c` lifts the real windowed and fullscreen setup entries, including window
class/creation, DirectDraw resources, capability decisions, clipping, error paths
and the final sprite-table reset/destination bind. Existing application, scene,
damage, title and font objects carry shared state. The [boundary](BOUNDARY.md)
records the native quirks and the two historical capability words explicitly.

The local driver calls original entry bodies without game startup or actual
DirectDraw. Forty-six cases compare both modes, resource failures and positive
nonzero statuses, partial/unwritten capability outputs, low-memory decisions,
callbacks and descriptor reuse. Source-side traps forbid fallbacks to the two
private original helpers. Bank slots/counts/tails, former object contents and
lifetimes, shared state and ordered platform interactions remain observable.

Use the existing development environment and retained application-shell package:

```sh
python tests/fixtures/dxball-display/prepare.py /path/to/DXBall.exe \
  /path/to/application-normal-check/inputs /tmp/dx-display
spaghetti-headless-wayland spaghetti-extractor component check dxball display-setup \
  --comparison-package /tmp/dx-display/display-setup --output /tmp/dx-display-check
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-display-check --accept-boundary-change display-setup \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-display/assemble.py {project} /tmp/dx-display-check' \
  --check-command 'make -j2' --check-command 'python check-display.py'
```

Use a copy of the preceding 34-component source project. Shared headers come
from the selected package and its suppliers. The standalone consumer runs without
Wine or the original executable. With AArch64 `CC`/`AR`, use
`--check-command 'python check-display.py --runner /path/to/qemu-aarch64'`.
Unchanged neighboring records and compiled objects can be retained.

For a focused binding defect, change `title->font->destination=title->primary`
to `title->font->destination=NULL` in a copied comparison workspace and check
`--case windowed-success`. The final destination observation must differ even
though the initializer still returns success. Replay uses retained input files.

For normal integration with the same real game network:

```sh
python tests/fixtures/dxball-display/prepare-normal.py /tmp/dx-display-check/inputs \
  /path/to/application-normal-check/inputs /tmp/dx-display-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball display-setup \
  --comparison-package /tmp/dx-display-normal/package --output /tmp/dx-display-normal-check
```

The native backend still uses Win32/DirectDraw and remaining runtime helpers.
It requires a successful GetCaps call that writes both consumed fields. Failed
queries need explicit original-caller history transport, which this normal
backend does not yet provide; they fail with a diagnostic rather than consuming
invented fallback values. The independent component already supports such history
and checks unwritten/partial outputs on both architectures. Portable platform
delivery must discharge this backend obligation or supply a verified complete
output contract; a passing normal run does not remove it.

The normal graphics observer records the initializer's actual destination binding
at successful completion. The C includes that helper's store, so requiring a call
to the old native instruction would reject valid inlining. This projection reads
the actual result; it does not execute a production helper or assume the intended
destination. Local comparisons check the store with original helper fallbacks
trapped. Other application observations remain intact.
