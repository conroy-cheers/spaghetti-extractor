# Powerup actions boundary

The pinned executable supplies seven entries: split balls (0x407eb0..0x408253),
expand explosive cells (0x408260..0x4084a1), soften bricks (0x4084b0..0x408538),
detonate (0x408540..0x40857a), super balls (0x408580..0x4085c3), drop the board
(0x4085d0..0x4086d3), and release attached balls (0x4086e0..0x408736).

The component borrows existing motion, gameplay, board, menu and graphics objects.
It owns the temporary ball roots at 0x431c98 and cell roots at 0x42ca40, including
their retained words. Temporary and live records share the existing ball/event
layouts. These are actual native lists, not new production APIs. The temporary
lists may already contain records on entry; the native operations append, consume
and dispose of them. Followed lists must be finite, valid and disjoint; shared
state objects keep identity and lifetime during synchronous calls.

Allocation supplies a ball or cell record with readable payload words, whose new
links are initialized by the component. Free consumes an unlinked record.
Allocation, free, termination, graphics, hits and rebound may update surviving
state and lists. Followed roots must remain live. Allocation failure calls
termination(1); a controlled returning backend must supply a valid current record
for the native continuation. Returning comparisons do not establish process-exit
coverage. Each boundary transports payloads and links, not just addresses.

Ball splitting copies all thirteen payload words through the temporary list,
negates dx with 32-bit wrapping, and decrements/clamps speed only for attached==1.
Ball count increments before allocation into the live list. Iterators reset current
to first on reaching the end. Queued cells retain their allocation's kind word.
Board scans are column-major. Expansion uses coordinates cached before graphics
callbacks; callbacks may change the current iterator and future cells. Softening
performs three separate checks, so a callback can make the same cell change again.
Board indices and queued coordinates must lie within the existing 20 by 20 board.

Board drop shifts each occupied cell down at most one row when its destination is
empty, starting at row 18. A changed board blits the existing background into the
back surface, selects the destination, redraws remaining cells, then queues damage.
Source and destination rectangles in that blit are the same mutable object;
callback edits remain visible to final damage. Surface handles use existing types.
The C preserves service order, arguments, ignored results and wrapping counters.

Concrete original/replacement comparisons are practical evidence, separate from
strong qualification. Every semantic integration finding must be reproducible in
a retained local or small connected consumer without the complete game workflow.
