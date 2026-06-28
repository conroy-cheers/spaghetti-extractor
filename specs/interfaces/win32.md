# Win32 Interface Spec

The initial detailed mocks cover deterministic subsets of:

- File and directory access, including handle create/read/write/seek/close
  behavior and invalid-handle/access-denied paths.
- Registry reads/writes/deletes with typed values.
- Tick count and performance-counter time.
- Console input/output.
- Thread creation, suspended/resumed/exited states, event signaling, auto-reset
  versus manual-reset waits, and timeout behavior.
- Packet-level Winsock send/receive queues.
- Graphics/window/gamma, DirectInput, DirectSound, service networking, Bink, and
  CRT/TLS/heap behavior through the companion media/runtime mocks.

Future interface specs must add each observed imported endpoint with:

- Success behavior.
- Failure behavior.
- Win32 error value or Winsock error value.
- Ordering and side effects.
- Concurrency/threading expectations when relevant.
- Detailed tests that fail for skipped calls or incorrect error handling.

Static import extraction starts the endpoint list. Dynamic tracing and targeted
probes must add delayed loads, ordinal calls, callback behavior, and endpoints
reached only under error paths.

Interface completion is tracked per `platform_endpoints` row. An endpoint must
have `mock_status = complete` and passing `success`, `failure`, and `error_path`
test cases before `interface-complete` can pass:

```sh
python -m haloce_catalog record-mock-interface-suite \
  --db build/catalog/catalog.db \
  --report-dir build/reports
```

The built-in suite records coverage for the known public mock endpoints. Static
imports outside that endpoint registry remain `partial` or `missing` until their
behavior is modeled and tested.

```sh
python -m haloce_catalog record-interface-test \
  --db build/catalog/catalog.db \
  --endpoint-label api_kernel32_dll_createfilea_... \
  --case-kind success \
  --test-id kernel32-createfile-success \
  --status pass \
  --evidence "mock asserts normal file-open behavior"
```

The command records labels and evidence only. It must not store original binary
code, decompiler text, or proprietary implementation expression.
