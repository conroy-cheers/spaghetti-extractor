# Sound device setup and focus boundary

The pinned original DX-Ball PE32 has SHA256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`.
Initialize is `0x402c60..0x402c73`; focus/setup is `0x402c80..0x402f1b`.
The original entry bodies provide the oracle. No original game source is used.

The component borrows the existing sound bank and application owner. Device,
primary buffer, sample slots and their 33 payload bytes keep the sound-bank
layout, identities and lifetime rules. The graphics-device presence used to
select dialogs belongs to the application, not a duplicate global. Window is
an explicit borrowed handle. Providers may synchronously mutate these shared
owners; subsequent reads and cleanup follow the original's reloads.

Initialize releases all sample records before setup, even if an existing device
makes setup immediately return. Focus/setup preserves existing samples and, after
creating a device and looping primary buffer, reloads their saved names in slot
order. It copies a name before its loader can dispose the old record. Names in
this boundary terminate within the sample payload. Adjacent-memory strings and
invalid records require a refined byte/lifetime boundary; pointer reconstruction
alone does not establish their validity.

Every nonzero creation/cooperation/primary-play result follows the original
failure branch, including positive statuses. A failed device creation can publish
a device that is then abandoned; there is no invented release. An occupied sound
system retries according to the dialog result. Other failures offer continuation
or process termination only while no graphics device is present. Exact texts,
flags, window identity and exit codes are retained. Termination does not return.
No retry bound is added to the production C; local providers give finite schedules.

Primary creation uses the complete 20-byte original descriptor with flags one,
zero length/reserved and no format. Error cleanup preserves the original
distinction between absent and published primary buffers. Release callbacks can
redirect device or primary references; the original's subsequent clear overwrites
those replacements. Mandatory buffer/device method calls require live nonnull
receivers on the admitted path. No concurrent or private-frame mutation is assumed.

Release-all executes the actual preceding sound-bank component. The independent
reload provider executes its real release-one operation before publishing a new
record and overwrites disposed payloads. Thus the consumer exercises shared-state
composition rather than replacing disposal with an assumed effect. Native WAV
loading and device implementations remain platform services for this comparison.
The existing sound-bank C and contracts are reused unchanged.

The independent observer retains bank fields, references, payload bytes, resource
lifetimes, application graphics presence, dialogs, provider order and termination.
It needs neither game startup nor a sound device. Finite tests remain practical
evidence, not checked summaries or formal qualification. Semantic integration
findings must remain locally reproducible; missing representation, execution or
observation is a boundary/tooling gap. Whole-program platform and loader delivery
remain required.
