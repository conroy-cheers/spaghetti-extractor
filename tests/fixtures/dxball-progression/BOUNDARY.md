# Gameplay progression boundary

Eight pinned native entries refresh/draw score and lives (0x408740..0x408770,
0x408770..0x4088f1), count remaining cells (0x408900..0x40892c), advance the board
(0x408930..0x40898e), lose a life (0x408990..0x4089d9), request the score screen
(0x4089e0..0x4089ff), restart a round (0x408a00..0x408b35), and finish a pending
round transition (0x408b40..0x408c15).

The component borrows existing paddle, pickup, motion, gameplay, brick, palette,
menu and graphics objects. Paddle and brick state refer to the same motion and
board. It owns pending (0x42ca5c), board-changed (0x431cc0), warning-y (0x42cdc8)
and warning-frames (0x431cb0) words. The last-brick display also writes the latter
two; they are shared state rather than private invariants. Existing pickup
next_life (0x431c7c) is the cached score in these operations; the field name is
retained to avoid changing neighboring declarations.

Services are synchronous and may change surviving state, surfaces, palette bytes,
sprite records and list roots. Shared object identities remain stable across the
call. Complete live payloads and links, aliases and relevant state cross boundaries.
Create-ball must leave a live current ball; round restart marks that object
attached after the callback. Object cleanup and board loading are explicit services
whose concrete implementations are selected independently.

Score conversion is unsigned decimal, confirmed by the actual native conversion
helper. Refresh resets scores above 999999999 only when the cache differs, then
caches the score after rendering callbacks. Rendering captures the decimal string
before callbacks but rereads lives for icon iteration. Rectangle callback writes
remain visible to damage. Signed life comparisons and unsigned counter wrapping
remain intact; comparisons exercise terminating service/loop scenarios.

Next-board uses signed comparison after a wrapping increment and counts cells
after loading. A board cell counts unless it is 0 or 2. Life loss plays sound with
the actual returned pan value and then requests the deferred transition. Advancing
a lost life grayscales only staged RGB bytes, leaving each fourth palette byte
unchanged. It preserves fade, clear, disposal and damage-reset order and checks
the current next-scene and lives after those callbacks. Restart retains the native
order of old-width cursor positioning, new sprite width selection and ball creation.

Concrete comparisons are practical evidence, not strong qualification. Every
semantic integration discrepancy must have a retained local or small connected
reproduction without the complete game workflow.
