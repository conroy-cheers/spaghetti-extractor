# Complete display setup boundary

The original is the pinned DX-Ball PE32 with SHA256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`.
Windowed setup is `0x40cc60..0x40d006`; fullscreen setup is
`0x40c810..0x40cc52`. The replacement also implements their private table-reset
and destination-bind helpers at `0x40bc90` and `0x40bd60`. Original bodies supply
the comparison oracle, with controlled platform operations. No original game
source is used. No synthetic production API is introduced for internal cuts.

The display view borrows existing application, scene, damage, title, font and
sprite-bank objects. It owns the global window and clipper references and the
registered event target. Primary/back surfaces belong to title; flip belongs
to scene; graphics belongs to the application. Opaque handles retain identity
and null/alias relationships. The same owner supplies each shared field; a
pointer reconstruction alone does not establish contents or lifetime.

Services may synchronously mutate shared state, including window and resource
slots. Every later call reloads the fields the native code reloads. Creation
services publish outputs independently of status: a positive nonzero status
may publish an object before the caller takes its failure path. The initializer
does not invent releases on failure. Fullscreen's later failures only destroy
the window, while windowed failures also hide it and display their specific
message. A destroy provider may invoke window callbacks and must transport
their effects. Concurrency and writes into unpassed private caller storage
are outside these cases.

The instance, icon, cursor, brush, event target, class flags, extra bytes and
class/menu names are explicit registration inputs. CreateWindow's extended
style, x/y coordinates, parent, menu and creation-data pointer are zero; the
service validates those fixed fields on native ingress. Width/height/style,
instance and name are arguments. Window services and sound initialization must
preserve call order and admit callbacks. Private class/name storage is not
retained after return; a backend that needs it must copy it.

Capability history is an invocation-local input: the two native words at entry
ESP minus `0x178` and `0x13c`. Both functions consume them if GetCaps leaves the
corresponding flags/video-memory outputs unwritten. These slots are inside the
reserved caller frame and are not changed by earlier conforming services.
The portable C initializes real local fields from this explicit history, never
from its own uninitialized stack. GetCaps return status is ignored. The supplied
size is 380; only flags and the video-memory word affect the original decisions.
A partial write preserves the other field. This is input transport, not proof
of universal platform error behavior or of arbitrary caller history generation.

Surface descriptors expose size, flags, caps and the dimensions/backbuffer count
selected by those flags. Other native descriptor bytes are not initialized or
read by the component; a backend must obey this field-selection contract.
The same descriptor is reused for the back surface. Size changes made by a
provider survive, while the original overwrites flags, caps, height and width.
The first descriptor's dimensions and a disabled backbuffer count are not
read; their convenient initialized C values have no observable meaning.

Table reset clears 255 slots and the count in each of three banks, preserving
the six following words and the former objects' contents/lifetimes. Binding
sets the current font destination to the current primary surface. It does not
validate or dereference that surface. All borrowed shared owners remain stable
through the call, even when their fields change.

Observations cover public fields, resource identities/lifetimes, complete bank
slots/counts/tails and object contents, ordered calls, selected descriptor fields
and explicit capability history. These are finite practical comparisons, not
checked heap summaries or strong qualification. Every semantic integration
discrepancy must be reproducible in a local or small connected consumer. Missing
cases are coverage gaps; inability to represent, drive or observe them is a
boundary/tooling gap. Actual platform backends remain separate delivery work.
