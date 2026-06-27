# Win32 Interface Spec

The initial detailed mocks cover deterministic subsets of:

- File and directory access.
- Registry reads/writes/deletes with typed values.
- Tick count and performance-counter time.
- Console input/output.
- Packet-level Winsock send/receive queues.

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
