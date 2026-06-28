# Detailed Oracle Suite

The detailed suite describes behavior that a future clean-room runtime must
satisfy. The original binaries must pass the same suite under the declarative
Wine prefix before a clean-room implementation is judged against it.

Initial process-level suites:

- `client-startup`: launch client with non-networked startup options, suppress video where possible, assert process lifetime, log/config effects, registry reads/writes, and module load set.
- `dedicated-server-console`: launch `haloceded.exe`, feed command scripts, assert console output, config parsing, map-cycle behavior, and clean shutdown.
- `map-discovery-loading`: enumerate stock maps, malformed map fixtures, missing-map errors, and selected multiplayer/single-player load paths.
- `profile-save-config`: create/read/update/delete profile, save, controls, video, audio, and network configuration state without storing real user secrets.
- `loopback-networking`: establish local client/server discovery, connection, packet exchange, timeout, retry, and disconnect behavior.
- `logging-errors`: verify filesystem paths, log formats, error codes, and failure behavior for missing files, denied writes, invalid registry values, and unavailable network endpoints.
- `representative-client-launch`: launch representative client paths with captured input fixtures, common video/audio/input flags, menu navigation, and controlled shutdown.

Private harness suites may call routines that process tests cannot reach. Those
harnesses must still execute original PE code and produce behavior-derived
fixtures/results that do not leak proprietary expression. Specs and tests should
refer to stable labels; raw module-hash/RVA mappings stay in private catalog
data and can be removed during a later sanitization pass.
For complex targets, these stable labels may identify sanitized internal
routine contracts. The contract is public behavior; the module-hash/RVA mapping
and call glue are private oracle machinery.

Oracle completion is tracked in the catalog as behavior evidence, not copied
implementation material. Run public process suites with:

```sh
python -m haloce_catalog run-oracle-process-test \
  --db build/catalog/catalog.db \
  --suite-id client-startup \
  --test-id client-startup-windowed \
  --artifact-dir private/oracle/artifacts \
  --timeout-seconds 45 \
  --offscreen-display auto \
  --stdout-contains "expected startup signal" \
  -- "$HALOCE_REFERENCE_APP" -window
```

The process runner captures stdout, stderr, and a result JSON file under the
artifact directory, then records an auditable `oracle_test_cases` row. Manual
recording remains available for private harnesses or externally orchestrated
runs:

When stdout/stderr/exit-code behavior is part of the public clean-room contract,
record it as a behavior-contract process observation instead of only as private
oracle evidence:

```sh
python -m wincr run-process-behavior-test \
  --db build/catalog/catalog.db \
  --behavior-contract-label "$CONTRACT_LABEL" \
  --test-id usage-help \
  --artifact-dir private/process-behavior \
  --input-json fixtures/usage-help.input.json \
  --expect-exit-code 0 \
  --stdout-contains "usage:" \
  --strip-stderr-line-regex "^known harness noise$" \
  -- ./target.exe --help
```

The generated `specs.json` can then drive a clean-room implementation with
`compare-process-spec-observations`. The raw process artifacts remain private;
the public observation contains normalized target behavior.

Graphical client suites should pass `--offscreen-display auto` when an operator
might turn off the physical display or run without a compositor. The runner uses
an existing display when one is configured and otherwise starts an Xvfb display
from the pinned dev/reference shell.

```sh
python -m haloce_catalog record-oracle-test \
  --db build/catalog/catalog.db \
  --suite-id client-startup \
  --test-id client-startup-windowed \
  --case-kind black_box_process \
  --status pass \
  --command "private/oracle/run-suite client-startup" \
  --fixture-path private/oracle/artifacts/client-startup-windowed/result.json \
  --trace-log private/traces/client-startup.jsonl \
  --evidence "original haloce.exe passed startup assertions under Wine"
```

The private harness requirement is represented by the
`private-internal-harness` suite with `--case-kind private_harness`. Prefer
`upsert-internal-harness` and `run-internal-harness` for routine-level original
PE probes; those commands keep stable labels in the catalog and private
module-hash/RVA mappings in `oracle_mappings`. Reviewed routine names and
purpose summaries may appear in public specs when they are functional
descriptions with provenance and confidence; implementation-expression
walkthroughs remain private-only.
