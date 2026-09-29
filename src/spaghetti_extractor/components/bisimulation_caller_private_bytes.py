"""Byte-addressed private storage for the existing typed native access inventory.

Overlapping byte spans share one bounded backing array and initialization map.
The data and initialization arrays are separate C objects from slot metadata,
matching the fact that machine-addressed writes cannot address the checker.
Scalar ABI slots remain separate and must not overlap that storage. Capacities,
access grants and initialization are checked obligations, never input premises.
The enclosing call rule must separately establish effects and lifetime.
"""


def extend_private_bytes_runtime(source, slots, capacity):
    def replace(before, after):
        nonlocal source
        if source.count(before) != 1:
            raise ValueError('caller private bytes: native runtime integration differs')
        source = source.replace(before, after)

    source = f'''typedef uint8_t spx_caller_private_byte_storage[{capacity}];
struct spx_caller_private_bytes {{
 uint64_t low,high;
 uint8_t *bytes;
 uint8_t *initialized;
}};
''' + source
    replace('struct spx_caller_memory {', 'struct spx_caller_memory { struct spx_caller_private_bytes local;')
    replace(' for(uint32_t i=0;i<'+str(slots)+'U;i++){\n  const struct spx_caller_slot *a=',
        f''' __CPROVER_assert(private_low<=memory->local.low && memory->local.low<=memory->local.high &&
  memory->local.high<=private_high && memory->local.high-memory->local.low<={capacity}U,
  "spx-caller-private-byte-capacity");
 for(uint32_t i=0;i<{slots}U;i++){{
  const struct spx_caller_slot *a=''')
    replace('(a->width==1U || a->width==2U || a->width==4U) &&',
        '((a->private_storage==2U && a->width>=1U && a->width<=256U) ||\n'
        '   (a->private_storage!=2U && (a->width==1U || a->width==2U || a->width==4U))) &&')
    replace('!(a->private_storage || b->private_storage) ||',
        '!(a->private_storage || b->private_storage) ||\n'
        '    (a->private_storage==2U && b->private_storage==2U) ||')
    helpers=f'''
static uint32_t spx_caller_has_private_bytes(const struct spx_caller_memory *memory,
 uint32_t address,uint64_t extent,uint32_t permissions) {{
 if(permissions<1U || permissions>3U || extent>UINT64_C(4294967296)-(uint64_t)address)return 0U;
 for(uint32_t i=0;i<{slots}U;i++){{
  const struct spx_caller_slot *slot=&memory->slots[i];
  if(slot->private_storage==2U && address>=slot->address &&
   (uint64_t)address+extent<=(uint64_t)slot->address+slot->width &&
   (!(permissions&1U) || slot->readable) && (!(permissions&2U) || slot->writable))return 1U;
 }}
 return 0U;
}}
static uint8_t *spx_caller_private_storage(struct spx_caller_memory *memory,
 uint32_t address,uint64_t extent,uint32_t permissions) {{
 uint32_t start=memory->local.low<=address && address<=memory->local.high;
 __CPROVER_assert(start,"spx-caller-private-byte-start");
 __CPROVER_assume(start);
 uint32_t end=extent<=memory->local.high-(uint64_t)address;
 __CPROVER_assert(end,"spx-caller-private-byte-end");
 __CPROVER_assume(end);
 uint64_t offset=(uint64_t)address-memory->local.low;
 __CPROVER_assert(offset<={capacity}U,"spx-caller-private-byte-offset");
 __CPROVER_assume(offset<={capacity}U);
 __CPROVER_assert(extent<={capacity}U-offset,"spx-caller-private-byte-backing");
 __CPROVER_assume(extent<={capacity}U-offset);
 if(permissions&1U)for(uint64_t i=0;i<extent;i++)
  __CPROVER_assert(memory->local.initialized[offset+i],"spx-caller-private-byte-initialized");
 return memory->local.bytes+offset;
}}
static uint8_t *spx_caller_private_bytes(struct spx_caller_memory *memory,
 uint32_t address,uint64_t extent,uint32_t permissions) {{
 uint32_t granted=spx_caller_has_private_bytes(memory,address,extent,permissions);
 __CPROVER_assert(granted,"spx-caller-private-byte-view");
 __CPROVER_assume(granted);
 return spx_caller_private_storage(memory,address,extent,permissions);
}}
static uint32_t spx_caller_private_byte_value(struct spx_caller_memory *memory,uint32_t address,uint32_t width) {{
 __CPROVER_assert(width>=1U && width<=4U,"spx-caller-private-byte-access-width");
 __CPROVER_assume(width>=1U && width<=4U);
 /* Only called after the native read/ABI transport has checked its grant. */
 const uint8_t *bytes=spx_caller_private_storage(memory,address,width,1U);
 uint32_t value=0U;
 for(uint32_t i=0;i<width;i++)value|=(uint32_t)bytes[i]<<(8U*i);
 return value;
}}
static void spx_caller_initialize_private_bytes(struct spx_caller_memory *memory,uint32_t address,uint64_t extent) {{
 /* Called only after a normal paired invocation with a checked initialization
  * guarantee. Merely allowing or modeling a write never calls this function. */
 (void)spx_caller_private_bytes(memory,address,extent,2U);
 for(uint64_t i=0;i<extent;i++)memory->local.initialized[(uint64_t)address-memory->local.low+i]=1U;
}}
'''
    replace('static uint32_t spx_caller_read(', helpers+'static uint32_t spx_caller_read(')
    replace(' uint32_t public_read=0U;', ''' if(spx_caller_has_private_bytes(memory,address,width,1U)){
  *fault=0U;return spx_caller_private_byte_value(memory,address,width);
 }
 uint32_t public_read=0U;''')
    replace(' uint32_t public_write=0U;', ''' if(spx_caller_has_private_bytes(memory,address,width,2U)){
  __CPROVER_assert(width>=1U && width<=4U,"spx-caller-private-byte-access-width");
  __CPROVER_assume(width>=1U && width<=4U);
  uint8_t *bytes=spx_caller_private_storage(memory,address,width,2U);
  for(uint32_t i=0;i<width;i++){
   bytes[i]=(uint8_t)(value>>(8U*i));
   memory->local.initialized[(uint64_t)address-memory->local.low+i]=1U;
  }
  memory->private_writes++;*fault=0U;return;
 }
 uint32_t public_write=0U;''')
    replace('static uint32_t spx_caller_private_value(const struct spx_caller_memory *memory,uint32_t address,uint32_t width) {',
        '''static uint32_t spx_caller_private_value(struct spx_caller_memory *memory,uint32_t address,uint32_t width) {
 if(spx_caller_has_private_bytes(memory,address,width,1U))return spx_caller_private_byte_value(memory,address,width);''')
    replace('slot->width==width && slot->private_storage){', 'slot->width==width && slot->private_storage==1U){')
    return source
