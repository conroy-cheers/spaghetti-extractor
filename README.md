# Windows Clean-Room Catalog Toolkit

This repository builds a generic clean-room toolkit for Windows programs and
libraries. The first deliverable is not a port. It is a reproducible private
dirty corpus, catalog, coverage ledger, interface specs, mocks, and
oracle-test scaffold measured against original runtime binaries by module hash
and RVA.
For large targets with small public APIs, the generated spec may also include
sanitized internal routine contracts: label-first behavioral APIs for original
functions, states, and data structures, backed privately by module SHA256 plus
RVA oracle mappings.

Halo CE is now a packaged target preset and compatibility workflow, not the
only shape the tooling can analyze. New targets are described by TOML manifests
that declare runtime binaries, exclusions, trace targets, VM staging defaults,
and target-specific oracle/mutation/data-state gates.

The tooling never stores original binaries, assets, CD keys, or public copied
pseudocode in the repo. Ghidra may export private high-taint decompiler C,
p-code, instruction metadata, variables, refs, and callsites into the dirty
corpus when available; those artifacts are never emitted into public reports.
Private catalog data may retain raw module-hash/RVA mappings; specs should use
stable labels as their primary identity. Short routine names and purpose
summaries are allowed when they are sanitized behavioral annotations with
provenance, confidence, and review status; implementation-expression summaries
remain private.

The primary generated artifact for reverse-engineering work is the private
dirty corpus. It is organized into small module/routine/test-surface packets
that may contain disassembly, RVA mappings, trace evidence, raw oracle links,
raw sidecars, dirty packet data, and draft contracts. Public specs/tests are a
downstream reviewed derivation and only include publication-safe, label-first
records.

## Quick Start

Enter the dev shell:

```sh
nix develop
```

Build a catalog from the reference install tree produced by the configured
private `nix-haloce` flake input. The default manifest is the packaged Halo CE
preset, so existing Halo commands keep working. By default this flake points at
the sibling Git checkout `../nix-haloce`; override it for another private source
with `--override-input nix-haloce <flake-url>`.

```sh
nix run .#haloce-reference-analyze
```

The app writes `build/catalog/catalog.db`, `build/reports/`, and
`build/ghidra/` by default. Override those locations with
`HALOCE_ANALYZE_DB`, `HALOCE_ANALYZE_REPORT_DIR`, `HALOCE_ANALYZE_GHIDRA_OUT`,
and `HALOCE_ANALYZE_GHIDRA_PROJECTS`.

The equivalent explicit command is:

```sh
HALOCE_REFERENCE_PACKAGE="$(nix build --no-link --print-out-paths .#haloce-reference)"
HALOCE_NIX_HALOCE_SOURCE_INFO="$(nix run .#haloce-reference-provenance)"
HALOCE_INSTALL_ROOT="$(nix run .#haloce-reference-root)"
python -m haloce_catalog analyze-reference \
  --install-root "$HALOCE_INSTALL_ROOT" \
  --db build/catalog/catalog.db \
  --report-dir build/reports \
  --ghidra-timeout-seconds 240
```

For a non-Halo target, create a TOML manifest and pass it explicitly:

```sh
python -m wincr build \
  --target-config targets/my-program.toml \
  --install-root /path/to/private/reference/install \
  --db build/my-program/catalog.db \
  --report-dir build/my-program/reports
```

The manifest controls binary role rules, trace target IDs, Windows VM staging
names, and the oracle/mutation/data-state gate requirements recorded in the
catalog metadata. The built-in Halo preset lives at
`src/haloce_catalog/presets/halo-ce.toml`.

Generated artifacts:

- `build/catalog/catalog.db`: canonical SQLite catalog.
- `build/reports/manifest.json`: private manifest with hashes, PE metadata, role decisions, imports/exports, sections, labels, and counts.
- `build/reports/catalog.md`: human-readable catalog summary.
- `build/reports/coverage.json`: coverage ledger summary.
- `build/reports/coverage.md`: coverage gate report.
- `build/reports/gates.json`: objective gate status.
- `build/reports/specs.json`: label-first generated report specs/tests, dynamic
  coverage observations, waivers, and trace probe evidence derived from catalog
  and behavior evidence, without raw RVAs or module hashes. Treat this as an
  automated report surface; the private dirty corpus is the review target for
  deriving final clean output.
- `build/reports/specs.md`: human-readable summary of the generated specs.
- `build/reports/tests.json`: label-first test evidence report for coverage
  runs, oracle rows, interface cases, data/state cases, mutation cases,
  internal harnesses, and trace compatibility probes.
- `build/reports/tests.md`: human-readable summary of the test evidence report.
- `private/wincr-artifacts/`: primary private dirty corpus for human/LLM
  cleanup into clean contracts and tests. This path may contain disassembly,
  raw RVAs, module hashes, raw test sidecars, and private harness/oracle
  evidence; do not publish it verbatim.
- `private/wincr-artifacts/dirty-specs.json` and `dirty-specs.md`: private
  dirty spec review indexes. They embed the label-first draft spec and link it
  to packet-local dirty evidence, module/routine/basic-block dossiers, and
  clean rewrite targets.
- `private/wincr-artifacts/dirty-tests.json` and `dirty-tests.md`: private
  dirty test-suite review indexes. They embed observed test evidence and a gate
  snapshot, while pointing reviewers to the raw sidecars and review packets
  needed to derive clean tests later.
- `build/reports/dirty-corpus-validation.json` and
  `build/reports/dirty-corpus-validation.md`: optional validation reports that
  prove the private corpus is structurally complete enough to review.

See `docs/internal-routine-contracts.md` for the policy on internal APIs,
LLM-assisted routine names/descriptions, and private module-hash/RVA mappings.

The catalog also infers `HALOCE_REFERENCE_PACKAGE` from an install root ending
in `/basePackage`, but setting it explicitly keeps provenance unambiguous in
`build/reports/manifest.json` and the `reproducible` gate.

`analyze-reference` is the one-shot private regeneration path. It builds the
catalog, runs Ghidra metadata export/import for all included and candidate
runtime PEs, runs independent LLVM/rizin static cross-checks for included and
candidate runtime PEs, and regenerates all reports. It returns nonzero if
cataloging records errors, Ghidra export/import fails, or any static cross-check
fails. For a quick focused rebuild while developing the Ghidra importer, pass
`--ghidra-filename haloce.exe --ghidra-filename haloceded.exe`.

For a catalog-only run without Ghidra or static cross-checks, use:

```sh
python -m haloce_catalog build \
  --install-root "$HALOCE_INSTALL_ROOT" \
  --db build/catalog/catalog.db \
  --report-dir build/reports
```

The default build records complete PE metadata, executable section ranges, and
a non-overlapping executable-byte classification partition. Included and
candidate runtime bytes start as `unknown` until Ghidra/static metadata,
dynamic coverage, or waivers refine them.
Capstone linear block discovery is intentionally opt-in because large shipped
DLLs can make bytewise discovery slow and noisy:

```sh
python -m haloce_catalog build --static-depth included
```

Ghidra metadata import is the preferred path for authoritative functions,
blocks, edges, and data refs. Byte classifications are rebuilt automatically
after catalog builds, Ghidra imports, coverage ingests, and waiver edits; they
can also be regenerated directly with:

```sh
python -m haloce_catalog rebuild-byte-classes --db build/catalog/catalog.db
```

Export the private dirty corpus before asking a human or LLM to derive clean
specs/tests. `export-dirty-corpus` is an alias for the same command and is the
preferred wording when treating the private corpus as the primary automated
deliverable:

```sh
python -m wincr export-private-artifacts \
  --db build/catalog/catalog.db \
  --out-dir private/wincr-artifacts \
  --report-dir build/reports
```

The exporter writes a root manifest plus per-module, per-routine, and
per-basic-block packets. Module/routine packets contain static metadata,
disassembly when available, CFG/call/data-ref summaries, dynamic coverage
observations, private oracle mappings, waivers, and dirty routine-contract
drafts. Basic-block packets live under `modules/<module>/blocks/<label>/` and
contain `manifest.json`, `static/context.json`, block-local
`static/disassembly.asm`, `static/decompiler-status.json`,
`static/instructions.json`, `static/pcode.json`, `static/data-flow.json`,
`static/xrefs.json`, `semantic-summary.md`, and `draft/clean-template.json`.
When Ghidra semantic export succeeds, routine packets also include private
decompiler status, decompiled C, p-code, variables, inferred types, stack/global
references, strings, and callsites; otherwise explicit unavailable/error
artifacts are written. The root corpus includes `reimplementation-plan.*`,
`cli-index.json`, and `review-html/index.html` for offline review. It also writes per-row review packets
under `review/` for behavior contracts, JSON observations, process
observations, oracle rows, internal routine contracts, interface cases,
data/state cases, mutation cases, and internal harness rows.
Each review packet contains `dirty.json`, `index.md`, a `clean-template.json`
rewrite target, and copied small text-like raw sidecars when available. The
root `dirty-specs.*` and `dirty-tests.*` files are private review indexes over
those pieces; they are not the final clean-room distribution.
`private-artifact-complete` gate requires module/routine/basic-block packets,
block-local disassembly/context/templates, plus these review packets and clean
templates for every recorded test surface. The
`publication-clean` gate requires public routine contracts to be reviewed before
they appear in generated public specs.

Render or query the workbench explicitly when regenerating from an existing
corpus:

```sh
python -m wincr render-dirty-corpus \
  --corpus-dir private/wincr-artifacts \
  --out-dir private/wincr-artifacts/review-html

python -m wincr review-dirty-corpus \
  --corpus-dir private/wincr-artifacts \
  --search startup \
  --todos
```

Validate the private corpus itself before handing it to a human or LLM:

```sh
python -m wincr validate-dirty-corpus \
  --corpus-dir private/wincr-artifacts \
  --report-json build/reports/dirty-corpus-validation.json \
  --report-md build/reports/dirty-corpus-validation.md
```

This validator intentionally permits private material such as RVAs, module
hashes, disassembly, raw harness details, and absolute source evidence paths.
It checks reviewability instead: root manifests, content-manifest hashes,
module/routine/basic-block dossier files, per-row dirty packets, adjacent clean
templates, block-local disassembly/context packets, and copied or
still-available evidence sidecars.

After a human or LLM rewrites packet-local `clean-template.json` files and a
reviewer marks them publishable, run the separate clean derivation stage. The
automated discovery/observation path should stop at the validated dirty corpus;
this later command validates the public fields before writing the publishable
state:

```sh
python -m wincr promote-clean-templates \
  --corpus-dir private/wincr-artifacts \
  --reviewer reviewer-id
```

Then derive the clean output:

```sh
python -m wincr derive-clean-specs \
  --corpus-dir private/wincr-artifacts \
  --out-dir build/clean-specs
```

Validate the derived artifacts before using them as public test inputs:

```sh
python -m wincr validate-clean-specs \
  --spec-json build/clean-specs/specs.json \
  --tests-json build/clean-specs/tests.json
```

Only templates with `review_status = reviewed`, `taint_level = reviewed_public`,
and `publication_decision = publish`/`public`/`approved` are emitted. Draft
templates are skipped, while publishable templates containing private paths,
redacted private-path placeholders, raw oracle identity fields, disassembly
references, or harness-sensitive keys fail the derivation. The command writes
clean `specs.json`, `specs.md`, `tests.json`, and `tests.md`;
`derivation-report.json` is an audit report for skipped/rejected templates and
should be reviewed before publication. `validate-clean-specs` checks public leak
rules again, verifies record counts and cross-file consistency, rejects orphan
behavior observations, and ensures process observations carry replayable argv
inputs.
Behavior contracts may also declare
`contract.coverage_requirements.required_records`: a list of required public
records identified by `entity_type` and exact field matches such as `test_id`,
`status`, `contract_id`, or nested paths like `inputs.mutation_kind`.
`validate-clean-specs` fails when these declared records are missing, which lets
each target state what evidence must survive the dirty-to-clean derivation.

After public reports are generated, validate a JSON-emitting clean-room
implementation directly against behavior observations embedded in `specs.json`:

```sh
python -m wincr compare-json-spec-observations \
  --spec-json build/reports/specs.json \
  --contract-id example.target.contract \
  -- ./candidate --json --scenario "{observed.scenario}" --seed "{observed.seed}"
```

The command expands placeholders from each selected observation and compares the
candidate's stdout JSON to the expected public observation. Private oracle paths
and commands remain outside the public spec.

For non-JSON process behavior such as usage text, default arguments, parser
edge cases, and error exits, record stdout/stderr/exit-code observations and
validate them from the same public spec:

```sh
python -m wincr compare-process-spec-observations \
  --spec-json build/reports/specs.json \
  --contract-id example.target.contract \
  -- ./candidate "{input.argv}"
```

For normal clean-room conformance runs, use the aggregate suite command so one
public spec drives every supported observation kind:

```sh
json_template='["./candidate","--json","--scenario","{observed.scenario}","--seed","{observed.seed}"]'
process_template='["./candidate","{input.argv}"]'
python -m wincr run-clean-spec-suite \
  --spec-json build/clean-specs/specs.json \
  --contract-id example.target.contract \
  --json-command-template-json "$json_template" \
  --process-command-template-json "$process_template" \
  --artifact-dir build/clean-spec-suite
```

The suite runner writes `summary.json` plus per-kind comparison artifacts under
the artifact directory. Missing templates for observation kinds present in the
spec fail the suite, which keeps public conformance checks explicit.

`run-process-behavior-test` can strip harness/runtime noise with
`--strip-stdout-line-regex` and `--strip-stderr-line-regex`; raw stream files
remain in the private artifacts, while the public observation stores normalized
target behavior.

Cross-check executable section metadata with independent tools before treating
Ghidra/static results as catalog-complete:

```sh
python -m haloce_catalog cross-check-static \
  --db build/catalog/catalog.db \
  --filename haloce.exe \
  --filename haloceded.exe
```

The command records passing or failing `llvm-readobj` and `rizin`/radare2
evidence in SQLite. `catalog-complete` remains open for included/candidate
binaries until both independent tool families have passing rows.

Seed the public behavior mock suite after imports are cataloged:

```sh
python -m haloce_catalog record-mock-interface-suite \
  --db build/catalog/catalog.db \
  --report-dir build/reports
```

Known Win32, graphics, input, audio, networking, Bink, and CRT/runtime imports
are classified endpoint-by-endpoint. The suite command marks only those known
mocked endpoints `complete` and records the required `success`, `failure`, and
`error_path` evidence rows. Unknown imported endpoints remain visible as
`partial` or `missing` until a behavior mock and tests are added.

Fast Python-only development checks can use the lightweight test shell:

```sh
nix develop .#test --command python -m unittest discover -s tests
```

## Coverage

The required dynamic source is the custom DynamoRIO tracer running inside the
declarative Windows VM with Windows `bin32\drrun.exe`. It records basic-block,
CFG-edge, and call-edge execution for 32-bit Halo CE processes. Wine probes and
stock `drcov` remain diagnostics only. The ingester maps observed modules back
to cataloged binaries by SHA256 when paths resolve, then stores private RVA
mappings and report-facing labels in SQLite:

```sh
python -m haloce_catalog ingest-drcov \
  --db build/catalog/catalog.db \
  --log path/to/drcov.log \
  --test-id client-startup-smoke
```

The custom tracer JSONL format records block, CFG-edge, and call-edge events:

```sh
HALOCE_REFERENCE_APP="$(nix build --no-link --print-out-paths .#haloce-reference)/bin/haloce"
python -m wincr prove-trace \
  --db build/catalog/catalog.db \
  --out build/traces/client-startup.jsonl \
  --test-id client-startup \
  --expected-filename haloce.exe \
  --timeout-seconds 45 \
  --arch auto \
  -- "$HALOCE_REFERENCE_APP" -window
```

`prove-trace` runs the configured trace runner, ingests the JSONL trace,
regenerates reports, and fails unless the expected cataloged module has mapped
dynamic blocks, CFG edges, and call edges. `prove-halo-trace` remains as a
compatibility alias that defaults to `halo-trace-run`; new target manifests
should use `prove-trace` and `WINCR_TRACE_RUNNER`. For manual debugging, the
same trace can be recorded and ingested directly:

```sh
nix run .#halo-trace-run -- \
  --out build/traces/client-startup.jsonl \
  --test-id client-startup-debug \
  --arch auto \
  -- "$HALOCE_REFERENCE_APP" -window

python -m wincr ingest-trace \
  --db build/catalog/catalog.db \
  --log build/traces/client-startup.jsonl
```

After either path:

```sh
python -m haloce_catalog check-gates --db build/catalog/catalog.db
```

Check the local `drrun`/`drcov` runtime:

```sh
python -m haloce_catalog doctor-drcov
```

`doctor-drcov` is only a bootstrap check. The real coverage gate requires
dynamic block, CFG-edge, and call-edge traces from the original 32-bit Halo CE
PEs, mapped to module SHA256/RVA and stable labels. The primary runtime path is
now Windows `bin32\drrun.exe` inside a declarative Windows VM; Wine probes remain
diagnostic compatibility checks.

The repo includes a generated public 32-bit Windows fixture for proving or
reproducing the Wine/DynamoRIO path without private Halo binaries:

```sh
HALOCE_WINE_SMOKE_ROOT="$(nix run .#halo-trace-win32-smoke-root)"
HALOCE_RUN_WINE_TRACE_SMOKE=1 \
HALOCE_WINE_SMOKE_ROOT="$HALOCE_WINE_SMOKE_ROOT" \
nix develop .#default --command python -m unittest tests.test_trace_wine_smoke
```

That test catalogs the generated PE fixture, runs it under Wine through
`halo-trace-run`, and requires mapped dynamic basic blocks, CFG edges, and call
edges for the fixture module. A passing run proves the public 32-bit PE path. If
it fails with `wine-preloader` signal handling errors before the fixture module
appears in the raw trace, the local blocker is still DynamoRIO/Wine preloader
compatibility rather than Halo-specific behavior.

The flake also builds a Windows 32-bit trace client:

```sh
nix build .#halo-trace-client-win32
```

That package produces `halo_trace.dll` against the pinned Windows DynamoRIO SDK.
It is for Windows-side injection probes and future Wine/DynamoRIO compatibility
checks. On the current local Wine runtimes, Windows `drrun.exe` either fails
before injecting `dynamorio.dll` or crashes in the WOW64 injector path, so this
artifact is not counted as coverage evidence until a trace contains the expected
PE module SHA256 plus nonzero block, CFG-edge, and call-edge records.

To compare the currently pinned Wine builds against the same public PE proof
target, use the flake app:

```sh
nix run .#halo-trace-wine-probe
```

It writes reports to `build/wine-trace-probes/` by default. Override the output
directory or timeout with `HALOCE_WINE_TRACE_PROBE_DIR=...` and
`HALOCE_WINE_TRACE_TIMEOUT=...`. Unless `WINEPREFIX` is already set, each
candidate Wine command gets its own prefix under the probe output directory so
an existing `~/.wine` cannot affect compatibility results.

The repository also carries an exact control for the legacy suggestion of Linux
DynamoRIO 8.0.0-1, `bin32/drrun`, a real i386 Wine process, and late injection:

```sh
nix run .#halo-trace-wine-probe-i386-late
nix run .#halo-trace-wine-probe-dr8-i386-late
```

The current-DR app uses Linux DynamoRIO's `bin32/drrun -late`, forces the trace
target to be an ELF 32-bit process, and defaults to `WINEARCH=win32`, an
isolated prefix, and `GLIBC_TUNABLES=glibc.pthread.rseq=0`. Its i386-late
runner does not follow children by default because fresh Wine prefixes spawn
long-running service processes that can dominate the trace; set
`HALOCE_TRACE_FOLLOW_CHILDREN=1` or pass `--follow-children` to the runner when
a target genuinely launches another process. The DR8 app pins the upstream DR
8.0.0-1 Linux binary release for comparison. On the current Nix Wine
11.0/glibc 2.42 environment, direct i386 Wine runs the PE smoke fixture and the
current-DR i386-late path records PE module/block/edge evidence, while DR8
crashes internally before any module/block/edge trace records are emitted.
Stock DR8 `drcov` with `-late` also lets the process run while producing only
empty process logs, so the DR8 path is diagnostic and not coverage evidence
yet.

The Wine probe apps pass `--isolate-catalog-build` so PE catalog generation
runs in a short-lived helper process before the traced Wine launch. They also
pass `--isolate-trace-proof` and warm Wine with stdout/stderr redirected to
temporary files. On the current Wine/DynamoRIO combination, running the warm-up
with Python pipe capture leaves Wine bootstrap work for the traced run; the
file-backed warm-up plus helper-process proof records the target PE while still
writing the same `catalog.db`.

For custom Wine builds/configurations, use the lower-level matrix probe. Each
`--wine-command` is parsed as a shell-style command, so it can include wrapper
arguments:

```sh
SMOKE_ROOT="$(nix run .#halo-trace-win32-smoke-root)"
nix develop .#default --command python -m haloce_catalog probe-wine-trace \
  --smoke-root "$SMOKE_ROOT" \
  --out-dir build/wine-trace-probes \
  --wine-command "$(nix eval --raw nixpkgs#winePackages.stable.outPath)/bin/wine" \
  --wine-command "$(nix eval --raw nixpkgs#wineWow64Packages.stable.outPath)/bin/wine"
```

The probe builds a private catalog for the smoke fixture once, records one trace
log per Wine command, persists each candidate result in
`build/wine-trace-probes/catalog.db`, and regenerates reports under
`build/wine-trace-probes/reports/`. Probe rows are diagnostic compatibility
evidence only; they do not count as dynamic coverage unless the expected PE
module also produces mapped block, CFG-edge, and call-edge records. A candidate
Wine runtime is usable only when its row has `ok: true`. The report includes the
candidate Wine version, compact observed-module samples, return code, timeout
status, the isolated or caller-provided `WINEPREFIX`, a direct
non-instrumented PE launch result, and the
expected-module/mapped-row counts needed to compare Wine builds or wrapper
configurations. If the direct launch passes but the traced launch reaches only
`wine-preloader`, `ntdll.so`, and host libraries, the candidate can run the PE
fixture but still cannot provide DynamoRIO PE coverage. If a Nix Wine package
exposes `bin/wine` as a shell wrapper with `WINELOADER=.../bin/.wine`, the probe
traces the hidden ELF loader and records both the wrapper and loader paths in
provenance.

`halo-trace-run` accepts `--arch auto|32|64`. Use `auto` for Halo CE under Wine:
the host `wine` launcher is a 64-bit ELF, while the target PE code is still
mapped and checked by expected module SHA256. Force `--arch 32` only for a
directly launched 32-bit ELF helper.

The live unit proof is skipped unless explicitly enabled:

```sh
HALOCE_RUN_LIVE_TRACE_PROOF=1 \
HALOCE_INSTALL_ROOT="$HALOCE_INSTALL_ROOT" \
HALOCE_REFERENCE_APP="$HALOCE_REFERENCE_APP" \
nix develop .#default --command python -m unittest tests.test_trace_live
```

## Windows VM Tracing

Generate the private Windows VM bundle:

```sh
nix run .#haloce-windows-vm-bundle
```

The bundle writes libvirt XML, `Autounattend.xml`, first-logon provisioning,
`Run-HaloTrace.ps1`, snapshot helper scripts, and a staging manifest under
`build/windows-vm/` by default. It does not include Windows media, Halo assets,
CD keys, or binaries in the repo. Stage those private inputs into installation
media with:

```sh
build/windows-vm/scripts/build-staging-iso.sh
```

The generated guest provisioning enables WinRM/OpenSSH, installs virtio/SPICE
tools when present, installs the pinned Windows DynamoRIO package, copies
`halo_trace.dll`, and stages the private Halo runtime into `C:\HaloTrace`.
After `C:\HaloTrace\guest-ready.json` exists, run the generated proof wrapper:

```sh
build/windows-vm/scripts/prove-guest-trace.sh <guest-ip-or-name> halo
```

The wrapper defaults `HALOCE_WINDOWS_VM_PASSWORD` to the generated local VM
password in `Autounattend.xml`; override that environment variable if you pass
`--admin-password` when generating the bundle or if you replace password auth
with a VM-specific credential.

For non-Halo targets, the same VM generator reads these defaults from the
target manifest's `[windows_vm]` table: `admin_user`, `admin_password`,
`password_env`, `skip_reports_env`, `default_trace_target`,
`runtime_stage_dir`, and `runtime_stage_aliases`. The Halo preset uses those
fields to preserve `HALOCE_WINDOWS_VM_PASSWORD`, the dedicated-server default
trace target, and the legacy `HaloRuntime` staging alias without hardcoding
that policy into the generic VM generator.

The guest script runs Windows `bin32\drrun.exe` against both `haloce.exe` and
`haloceded.exe`, copies only the selected test's result/log/part files back
under `private/windows-vm/logs/`, ingests the copied trace, and fails unless the
expected module has nonzero mapped block, CFG-edge, and call-edge rows. Set
`HALOCE_WINDOWS_VM_SKIP_REPORTS=1` for quick iteration when you only need the
proof result and not regenerated Markdown/JSON reports. Use
`scripts/run-guest-trace.sh` for raw trace collection without ingestion, or pass
`--copy-all-logs` to the CLI for diagnostics that need the whole guest log
directory.

`haloceded.exe` can be traced through the normal SPICE/QXL VM profile, but
`haloce.exe` needs a real 3D-capable adapter for useful menu/gameplay coverage.
The default `--display-mode spice-qxl` is for unattended install, provisioning,
and recovery. If PCI GPU passthrough is available, provision the disk first,
then stop the VM and define a runtime profile with the same disk and OVMF vars:

```sh
nix run .#haloce-windows-vm-bundle -- \
  --name haloce-client-trace-gpu \
  --disk private/windows-vm/haloce-client-trace-gpu.qcow2 \
  --ovmf-vars private/windows-vm/OVMF_CLIENT_GPU_VARS.fd \
  --gpu-pci-address 0000:12:00.0 \
  --gpu-pci-address 0000:12:00.1 \
  --display-mode gpu-only
```

`gpu-only` emits no SPICE graphics device and no emulated video adapter, so the
guest must use the passthrough GPU. Start it only after the host has booted with
the selected PCI functions bound to `vfio-pci`, and attach a physical display,
dummy plug, or other capture path suitable for the passthrough GPU.
Check the host state before starting the GPU-only VM:

```sh
python -m haloce_catalog check-vfio-host \
  --pci-address 0000:12:00.0 \
  --pci-address 0000:12:00.1 \
  --required-kernel-param amd_iommu=on \
  --required-kernel-param iommu=pt \
  --required-kernel-param vfio-pci.ids=1002:13c0,1002:1640
```

Captured evdev gameplay fixtures can be converted into QMP input events for
deterministic VM driving:

```sh
python -m haloce_catalog emit-qmp-input \
  --log private/input-traces/client-menu-walk.jsonl \
  --out private/input-traces/client-menu-walk.qmp.jsonl
```

Replay those records into a running libvirt VM with the generated wrapper:

```sh
build/windows-vm/scripts/replay-qmp-input.sh \
  private/input-traces/client-menu-walk.qmp.jsonl
```

For ad hoc targets, use the CLI directly:

```sh
python -m haloce_catalog replay-qmp-input \
  --log private/input-traces/client-menu-walk.qmp.jsonl \
  --domain haloce-wintrace
```

## Oracle Evidence

The `oracle-complete` gate is driven by catalog evidence rows. Each required
black-box process suite and the private original-code harness suite must have at
least one passing original-binary run:

```sh
python -m haloce_catalog run-oracle-process-test \
  --db build/catalog/catalog.db \
  --suite-id client-startup \
  --test-id client-startup-windowed \
  --artifact-dir private/oracle/artifacts \
  --timeout-seconds 45 \
  --offscreen-display auto \
  -- "$HALOCE_REFERENCE_APP" -window
```

Use `--offscreen-display auto` for graphical client paths when the physical
display may be unavailable. It preserves an existing `DISPLAY`/`WAYLAND_DISPLAY`
when present and otherwise starts an Xvfb display from the pinned dev shell. Use
`--offscreen-display x11` to force Xvfb even when a display variable already
exists.

Use `--case-kind private_harness --suite-id private-internal-harness` for
private internal-call harnesses that execute original PE code without exposing
decompiled bodies or proprietary control flow. For externally orchestrated
process runs or private harnesses, `record-oracle-test` can still attach
existing command, fixture, and trace-log evidence to the catalog.
These harnesses are the private execution side of sanitized internal routine
contracts: the public spec names behavior by stable label, while private catalog
rows identify the exact original routine by module SHA256 plus RVA.

Private internal-call harness targets are registered by stable label and can be
run through the catalog tool:

```sh
python -m haloce_catalog upsert-internal-harness \
  --db build/catalog/catalog.db \
  --target-label fn_target_state_probe_... \
  --harness-id function-state-probe \
  --harness-kind function \
  --expected-observation "behavior fixture matches original PE output"

python -m haloce_catalog run-internal-harness \
  --db build/catalog/catalog.db \
  --harness-label harness_function_state_probe_... \
  --test-id function-state-probe-pass \
  --artifact-dir private/internal-harness/artifacts \
  -- private/harness function-state-probe
```

## Mutation Evidence

The `mutation-effective` gate records whether detailed specs and tests reject
representative wrong implementations. Only `status = killed` satisfies the gate;
planned, survived, or invalid mutation runs remain visible in reports:

```sh
python -m haloce_catalog record-mutation-test \
  --db build/catalog/catalog.db \
  --mutation-kind inverted_branch \
  --target-label fn_menu_state_update_... \
  --test-id menu-state-inverted-branch \
  --status killed \
  --command "private/mutation/run menu-state-inverted-branch" \
  --evidence "detailed state-machine tests fail when the observed branch is inverted"
```

Required mutation kinds are `wrong_implementation`, `inverted_branch`,
`skipped_external_call`, `corrupted_serializer`, `bad_packet_codec`, and
`changed_mock_api_behavior`.

## Gameplay Input Traces

Repeatable black-box gameplay tests need deterministic keyboard and mouse
inputs. The input recorder captures Linux evdev events from explicit devices and
writes JSONL fixtures with relative timings and human-readable key/button names:

```sh
python -m haloce_catalog list-input-devices
python -m haloce_catalog list-input-devices | jq '.devices[] | select(.capture_relevant)'

python -m haloce_catalog record-input \
  --out private/input-traces/client-menu-walk.jsonl \
  --test-id client-menu-walk \
  --scenario "menu navigation into walking and firing" \
  --device /dev/input/event-keyboard \
  --device /dev/input/event-mouse \
  --duration-seconds 45
```

On most systems, reading `/dev/input/event*` requires membership in the `input`
group or elevated privileges. Capture only during the Halo sequence; these logs
can include real keystrokes and should stay private unless reviewed and
sanitized. The device listing includes `role_hints` and `capture_relevant` to
help choose the keyboard and mouse event nodes, but those are only heuristics;
prefer the specific devices that generate events while Halo has focus.

Summarize or dry-run validate a fixture without touching input devices:

```sh
python -m haloce_catalog summarize-input \
  --log private/input-traces/client-menu-walk.jsonl

python -m haloce_catalog replay-input \
  --log private/input-traces/client-menu-walk.jsonl
```

Actual replay is deliberately guarded because it injects events into the
focused desktop through `/dev/uinput`:

```sh
python -m haloce_catalog replay-input \
  --log private/input-traces/client-menu-walk.jsonl \
  --force
```

## Ghidra Metadata

Run headless analysis outside any sanitized distribution artifacts, then export
only private metadata:

```sh
python -m haloce_catalog export-ghidra \
  --db build/catalog/catalog.db \
  --project-dir build/ghidra/projects \
  --out-dir build/ghidra/exports
```

The command selects included and candidate cataloged binaries by default, runs
the private Ghidra headless exporter, and imports the resulting metadata back
into SQLite. Use `--filename ...` or `--scope ...` for focused exports. It
defaults to `HALOCE_GHIDRA_HEADLESS` or `analyzeHeadless` on `PATH`; inside the
Nix dev shell this is pinned to the packaged Ghidra `support/analyzeHeadless`.

Manual export/import remains available:

```sh
analyzeHeadless "$HALOCE_GHIDRA_PROJECT_DIR" halo-catalog \
  -import haloce.exe \
  -scriptPath tools/ghidra \
  -postScript HaloCatalogExport.java build/ghidra/haloce.json <sha256> \
  -deleteProject

python -m haloce_catalog import-ghidra \
  --db build/catalog/catalog.db \
  --json build/ghidra/haloce.json
```

The JSON must not contain decompiler text, instruction bytes, or original code.
Raw RVAs in this private metadata must be converted to stable labels before any
sanitized public distribution.

## Repository Map

- `src/haloce_catalog/`: catalog, coverage, report, mock, and CLI code.
- `tools/ghidra/`: headless Ghidra metadata exporter.
- `docs/`: clean-room rules, internal routine contract policy, catalog model,
  coverage gates, and waiver policy.
- `specs/`: detailed oracle-suite, internal-harness, interface, data/state, and mutation-effectiveness specifications.
- `tests/`: unit tests and local-runtime smoke checks.

The public mock package includes behavior-level models for Win32 file handles,
directory access, registry, time, console, thread/event waits, Winsock queues,
graphics/window/gamma, DirectInput, DirectSound, GameSpy/Keystone-style
services, Bink media stepping, and CRT/TLS/heap runtime state.
