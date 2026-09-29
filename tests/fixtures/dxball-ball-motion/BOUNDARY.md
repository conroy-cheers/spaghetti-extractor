# Ball motion, contact and lifetime

The pinned DX-Ball PE32 has SHA256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`.
This component owns five natural entries: create (`0x404d70..0x404e79`), update
(`0x404e80..0x405707`), paddle rebound (`0x405710..0x405901`), point/brick contact
(`0x405910..0x4059f8`) and removal (`0x405a00..0x405a6f`). Calls between those
operations execute the same component. Authoring uses binary instructions/data
and existing interfaces, with no original game source.

The component borrows the existing `play_state`, ball records and sprite objects,
plus the current board's 400 bytes. Its additional scalar view holds ball count,
gravity, paddle width/power, sticky/piercing flags and the impact velocity words
consumed by brick services. Sprite selection uses the shared current bank.
Dimensions and state can change around synchronous service calls; cached values
and reloaded values follow the executable's actual access order.

Ball allocation returns a fresh writable record, which is linked and initialized
before it is used. The original increments the count before allocation and exits
with status 1 if allocation fails; the C preserves that path. Removal rewrites
neighbors, cursor, head and tail before freeing the record, then decrements the
current count after the callback. A positive count with a null cursor still
decrements. The update loop advances again from the post-removal cursor, so it
can skip an intervening ball. Free/callback boundaries must preserve this order.
Old borrowed records are not readable merely because a previous call saw them.

Successful tested allocations and live, initialized objects form the local
comparison domain. Traversed lists are finite and acyclic. Services may mutate
shared state, live payloads, cursor and membership, but must leave every object
subsequently dereferenced by the native routine live. Allocation failure retains
its production exit behavior; successful local snapshots do not qualify it.
Manual fixtures expose all payload words and links and record allocation/free
identities. Native address reconstruction alone is not evidence of preserved
contents or lifetime.

Arithmetic is explicit wrapping 32-bit state with signed comparisons and
truncating signed division. Rebound uses the native binary32 position before
comparing binary64 thresholds; velocity uses binary64 intermediates under nearest
rounding and 53-bit x87 precision. Paddle width is nonzero, referenced sprite
dimensions are live and positive, and random limits are positive in admitted
cases. Trig views expose 361 signed words, as in the frame boundary; INT32_MIN
angles lie outside that view. Side-contact sample points preserve the native
negative scaling constants rather than replacing them with geometric intuition.

The sprite-61 contact converts a nonzero tile to 8, with the original count,
explosion, hit and score effects. Brick processing, particles, audio, special
paddle effects and life loss remain explicit services. Their bodies are separate
lifting work. Finite local/native comparisons and portable execution provide
practical evidence; declared effects do not become checked heap summaries.
Every integration finding must be reducible to a local or connected consumer,
including clocks, random inputs, aliases, lifetime and callback behavior.
