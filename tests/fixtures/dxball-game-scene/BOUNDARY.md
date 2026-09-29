# Gameplay scene entry, redraw and keyboard input

The pinned executable entries are 0x404120..0x4043cc (enter),
0x4043d0..0x4044c5 (redraw) and 0x404ad0..0x404ccf (key), with key dispatch tables
through 0x404d6b. This component borrows the existing progression and damage
objects. Their scene/graphics references name the same objects. Existing sprite
bank counts and retention fields, cached score, input-ready flag and paddle state
retain their representations. Input-ready also gates the native cheat keys.
The only new scalar is the stereo direction at 0x416068: binary64 initialized to
1.0, multiplied by -1.0 by the key handler and read by the pan service.

Object identities and parent links remain stable across synchronous calls;
contents, selected banks, surfaces, counters and transition state can change.
Entry loads assets and 25 sound slots in native order, resets selected gameplay
fields, then calls board loading and restart before installing damage surfaces.
Services implement platform work and neighboring operations; they do not become
checked summaries merely by being declared. Shared layouts are reused directly.

Redraw passes the same live rectangle as both source and destination arguments
to each blit. Callback edits persist to later blits. Paused text depends on the
post-board-render state; final flip depends on the post-primary-blit capability
and presentation mode. Source and native service adapters preserve aliases.

Any key resumes paused==1, regardless of the key byte; uppercase P pauses only
paused==0. Other handlers use the signed native input byte, so high-bit bytes
select no action. Both rules are equivalent to the authored low-byte switch for
the actual key set. Fade is skipped only for the pre-call pending transition;
redraw and fade-in still occur. Cheat keys p/q/r/s read the current sprite bank.
Track selection retains the random result across stop-music callbacks, including
out-of-range service results, for which music is stopped but no track starts.

Local comparisons retain shared state, live ball contents, board/palette bytes,
sprite metadata, ordered calls and rectangle aliasing. Connected consumers run
the existing progression bodies over the same objects without the complete game.
Controlled service behavior and finite cases are practical evidence, not strong
qualification. Every semantic integration discrepancy must have a retained local
or small connected reproduction; missing representability or observability is a
tooling gap, while missing inputs are a coverage gap.
