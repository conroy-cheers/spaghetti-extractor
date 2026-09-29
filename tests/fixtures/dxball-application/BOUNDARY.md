# Application shell boundary

The pinned DX-Ball image has SHA256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`.
This component borrows the existing scene, title, flow and palette objects.
Its entries are WinMain at `0x40d010`, the window procedure at `0x40d130`,
instance acquisition at `0x40d4b0` and release at `0x40d500`. The unused native
WinMain previous-instance and command-line arguments are omitted from portable C.
No original game source is used.

The shell owns cursor, activation, modifier and suspension state, plus instance,
graphics and palette references. The title's primary/back references and scene's
flip reference describe the same live surfaces as their native globals. Flow's
duplicate primary/back views are synchronized at native service boundaries.
Object identities are stable through a call; a released object must not be
dereferenced. Null and alias relationships are preserved. Services may change
shared fields and resource slots synchronously; disposal reloads subsequent
slots after each callback. It does not snapshot all resources before cleanup.
Actual graphics setup, sound, rendering and game operations remain services.

Instance acquisition uses a named semaphore, with the original access,
inheritance and count parameters. An existing semaphore is opened and then
abandoned without closing the returned handle. The existing instance slot is
left untouched on that path. Release clears the slot after CloseHandle, even
if a callback changed it. Destruction clears the graphics pointer without
releasing that interface, and only clears flip when primary was nonnull.
These native behaviors are preserved rather than repaired.

Message schedules are explicit service inputs. A successful peek initializes
the complete message record before any consumer reads it. A failed peek leaves
that output unread. GetMessage may return zero, positive or the unsigned bits
of minus one; the original treats the last as nonzero and dispatches it. An
error may preserve the preceding initialized message. TranslateMessage and
DispatchMessage receive the same invocation-local message record. Dispatch
can synchronously call the actual window procedure, and graphics setup can
reenter it before returning. These cases assume serialized callbacks, no
concurrency and no retention of the private message address after the call.

The selected process termination service exits nonlocally with `process-exit`.
It never returns synchronously; the C abort following it is a provider-contract
failure guard. Comparisons use the existing nonlocal service handler and a
local landing point to observe the requested exit. They do not model arbitrary
CRT teardown. The service schema also requires a synchronous return declaration;
that declaration is not evidence that a returning exit provider is compatible.

Coordinates, message arguments and return values retain their 32-bit bit
patterns. Cursor acquisition may fail without writing its output. Mouse motion
still calls the default window procedure after updating coordinates. All
service arguments, ordering, public state before/after callbacks, message
contents, object identities, palette bytes and resource lifetimes are observed.
Window/graphics handles are opaque identities, not dereferenceable host casts.

Local cases execute the actual original entry bodies under controlled services,
without opening the game or initializing DirectDraw. Portable consumers replay
the same cases without Wine or the original executable. Finite comparisons are
practical evidence, not universal qualification or checked heap summaries.
Every semantic integration discrepancy must become a local or small connected
reproducer. If it cannot be represented, driven or observed there, the boundary
or tooling is incomplete; a passing full-game rerun cannot close that gap.
