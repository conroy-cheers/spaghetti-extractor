# Persistent score table

Authority is DXBall.exe SHA-256
191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f.
Native cdecl entries are load 9a30..9a6c, initialize 9bb0..9f7e and insert
9a70..9bac. Insert accepts a terminated name and unsigned score and returns an
unsigned rank or ffffffff. The other callers discard the native return register.
Only executable instructions and literal data are used; no original source.

Fifteen records at 431cc8 contain 40 name bytes and a little-endian unsigned score.
The representation retains all 660 bytes, including padding after each terminator.
Loading leaves unread bytes unchanged and ignores the returned element count.
Insertion reloads first, rejects scores below the final record, scans backward
using unsigned comparisons and inserts before equal scores. Moves copy names only
through NUL and copy the score; they do not copy padding or sort the whole table.
Names read or shifted must terminate within their 40-byte field. The insert name
is a readable terminated borrow of at most 39 bytes, disjoint from table storage,
and unchanged by file services. Descending order is not required by the code.

The C service boundary preserves fixed score.dat binary open/read/write/close and
access behavior. Failed open is null, partial I/O is permitted, and ignored I/O
return values stay ignored. Open-for-write truncates as the native CRT does.
Insertion saves only when access(mode=2) returns zero; initialization creates the
file only when access(mode=0) returns exactly ffffffff. Initialization replaces
names and scores while preserving other bytes. Synchronous CRT services do not
reenter the component or mutate records apart from a read's explicit byte view.

The last file handle at 434964 is retained after close, just as in the original.
It is an identity token, not permission to use closed storage. Adapters preserve
handle equality, byte backing, open/closed state and the actual transfer effects.
The local backend observes failures, partial transfers, complete record bytes,
file contents and call order. Actual file services and existing game consumers
are exercised separately. These finite cases do not establish arbitrary corrupt
files, nonterminated names or whole-game correctness.
