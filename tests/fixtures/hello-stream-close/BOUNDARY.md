# Stream close boundary

`run(stream)` owns the complete pinned Hello `close_stream` operation, RVA
`0x6894..0x68f8`. The native disassembly supplies the algorithm. Its result is zero
or minus one. Both results consume the stream: never close or access it again.

The shared `stream-view.h` holds a call-scoped reference to an existing live stream.
It neither copies the FILE object nor recreates its storage from a pointer value.
Aliases of that view see its consumption. Native FILE fields and platform errno
values are adapter responsibilities; portable algorithm C sees only its services.

| Service | Required behavior |
| --- | --- |
| `pending` | Borrow the live stream and report pending byte count |
| `error` | Borrow the live stream and report its prior error indicator |
| `close` | Consume exactly once, preserve its real effects, return the actual close result |
| `bad_descriptor` | Read errno and report whether it is EBADF (9 in the pinned target); preserve errno |
| `clear_errno` | Set errno to zero |

Calls occur in pending/error/close order. If a prior error exists but close
succeeds, clear errno and return minus one. If close fails, return minus one
except when there was neither a prior error nor pending data and errno is EBADF.
Other success paths preserve the close service's errno. No stream access follows
close. Synchronous service observations include argument identity, results and
errno effects; controlled fixtures retain stream/backing frames too.

The first working trial exposed target errno numbers in the C interface. Before
program integration the boundary was refined to a bad-descriptor predicate and
clear operation. Ordinary C adapters now own platform constants; the authored
algorithm does not assume the host's EBADF value. This changes the contract and
requires fresh comparison/export, not same-signature compatibility or reuse.

Seven selected cases separate two controlled caller identities from five real
MSVCRT file scenarios. They do not establish all FILE states or platform behavior.
The declared services and generated traces are not formal summaries. No concurrent
use, reentrant callbacks, invalid FILE pointer or repeated close is admitted.
The native routine image omits startup/TLS. Normal program execution and another
architecture are separate integration obligations.
