# DX-Ball application bootstrap

`bootstrap.c` lifts first-frame initialization, initial palette creation and
surface clearing from the pinned machine bodies. It shares the existing
application/scene/flow/palette objects. [BOUNDARY.md](BOUNDARY.md) specifies
resource publication, callback behavior, descriptor fields and clock inputs.
No original application source is consulted.

Use retained inputs inside the existing development environment:

```sh
python tests/fixtures/dxball-bootstrap/prepare.py /path/to/DXBall.exe \
  /path/to/palette-normal-check/inputs /tmp/bootstrap
spaghetti-headless-wayland spaghetti-extractor component check dxball application-bootstrap \
  --comparison-package /tmp/bootstrap/application-bootstrap --output /tmp/bootstrap-check
```

The 29 cases compare full palettes, resource identities and publication, scalar
state, ordered service calls, callback changes and exit outcomes. They cover the
strict refresh threshold, unsigned wrap, exact-one fast mode and ignored API
statuses. The native call adapters supply declared component inputs; they are
not a DirectDraw implementation. Normal execution below uses real objects.

To replay a meaningful difference, change `channel < 3` to `channel < 4` in a
copy of the source. This wrongly clears retained palette flags:

```sh
spaghetti-extractor component start dxball application-bootstrap \
  --comparison-package /tmp/bootstrap-check/inputs \
  --source-file source/bootstrap.c=/path/to/edit.c --output /tmp/bootstrap-edit
spaghetti-headless-wayland spaghetti-extractor component check dxball application-bootstrap \
  --comparison-package /tmp/bootstrap-edit --case palette-only \
  --reuse-comparison /tmp/bootstrap-check --output /tmp/bootstrap-replay
```

Apply the matching selection to a copy of the preceding palette source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/bootstrap-check --accept-boundary-change application-bootstrap \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-bootstrap/assemble.py {project} /tmp/bootstrap-check' \
  --check-command 'make -C {project} bootstrap' \
  --check-command 'python {project}/check-bootstrap.py'
```

For AArch64, supply its `CC` and `AR` in the make command and pass
`--runner /path/to/qemu-aarch64` to the check. This is a portable source consumer
of the boundary, not the standalone desktop game. Existing components, objects
and binaries are reused; the new consumer is the only required build.

Exercise the implementation through the real application and scene callers:

```sh
python tests/fixtures/dxball-bootstrap/prepare-normal.py /tmp/bootstrap-check/inputs \
  /path/to/palette-normal-check/inputs /tmp/bootstrap-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball music-control \
  --comparison-package /tmp/bootstrap-normal/package \
  --reuse-comparison /path/to/palette-normal-check --output /tmp/bootstrap-normal-check
```

The enclosing comparison keeps its `music-control` identity; bootstrap is an
independent program entry. Scores and boards reach existing C replacements.
Seed/clock helpers and platform calls remain native services. The new observations
record outer bootstrap calls, state and palette/surface hashes; absolute clocks
are diagnostics. Exact timing behavior is checked with explicit local inputs.

Continue with the [standalone worklist](../dxball-standalone/README.md). Remaining
timing, random, math and raster application bodies, program-owned state, service
wiring and platform backends still need to become a normal-entry source program.
