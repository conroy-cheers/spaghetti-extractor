"""Per-call borrowed views over current paired memory, with explicit lifetime.

This is a conditional runtime rule, not allocation or native object authority.
The runtime premise supplies a nonnull public range until the next service call.
It supplies no new bytes, freshness, stable address, or lifetime across a call.
Accesses use the shared sparse world so overlapping returns retain their aliases.
"""


def checked_returned_view(premise, intent, service_id):
    from .bisimulation_caller_interface import _view
    from .relation_ir import RelationExpressionV1, RelationSortV1
    contract = premise.get('returned_view')
    if contract is None:
        return None
    required = {'contents': 'current-memory', 'lifetime': 'until-next-call', 'private_frame': 'disjoint'}
    if (not isinstance(contract,dict) or set(contract)-{'separate_from'}!=set(required)
            or any(contract[k]!=v for k,v in required.items())):
        raise ValueError('returned view requires current memory, explicit call-scoped lifetime and private separation')
    separate = contract.get('separate_from', [])
    if not isinstance(separate,list) or len(separate)>32:
        raise ValueError('returned view separation inventory is invalid')
    for span in separate:
        if (not isinstance(span,dict) or set(span)!={'address','extent'}
                or RelationExpressionV1.parse(span['address']).sort!=RelationSortV1('bitvector',width=32)
                or RelationExpressionV1.parse(span['extent']).sort not in
                    {RelationSortV1('bitvector',width=32),RelationSortV1('bitvector',width=64)}):
            raise ValueError('returned view separation requires typed address and extent')
    service = next(row for row in intent.services if row['id'] == service_id)
    signature = intent.schema.signature_index[service['signature_id']]
    if len(signature.results) != 1:
        raise ValueError('returned view requires one service result')
    result = signature.results[0]
    if (not _view(intent.schema.type_index, result) or result.nullable is not False
            or result.extent['kind'] != 'fixed' or not 0 < result.extent['bytes'] < 2**32
            or result.access not in {'read', 'write', 'read_write'}):
        raise ValueError('returned view requires a nonnull fixed byte span with explicit permissions')
    return {**contract, 'separate_from': separate, 'extent': result.extent['bytes'],
            'permissions': {'read': 1, 'write': 2, 'read_write': 3}[result.access]}


def returned_view_candidate(rule, lower):
    """Lower explicit separation premises; never infer them from read permission."""
    ranges=['{calls.private_low,calls.private_high}'];checks=[]
    for span in rule['separate_from']:
        address,extent=lower(span['address']),lower(span['extent'])
        checks.append(f'__CPROVER_assert({address.defined} && {extent.defined} && '
            f'(uint64_t)({extent.value})<=UINT64_C(4294967296)-(uint64_t)({address.value}),'
            '"spx-returned-separation-defined");')
        ranges.append('{'+address.value+',(uint64_t)('+address.value+')+(uint64_t)('+extent.value+')}')
    return [*checks,f'const struct spx_returned_exclusion excluded[{len(ranges)}]={{'+','.join(ranges)+'};',
            f'spx_returned_candidate(candidate_value,UINT64_C({rule["extent"]}),excluded,{len(ranges)}U);']


def returned_view_runtime(capacity):
    if type(capacity) is not int or not 1 <= capacity <= 64:
        raise ValueError('returned view capacity must match the bounded call trace')
    return f'''
struct spx_returned_span {{ uint32_t address,permissions,present;uint64_t extent; }};
struct spx_returned_exclusion {{ uint64_t low,high; }};
static struct spx_returned_span spx_returned_spans[{capacity}];
static uint32_t spx_returned_current[2],spx_returned_live[2];
/* Opaque tokens are separate C objects: their bytes expose no checker metadata. */
static uint8_t spx_returned_tokens[{capacity}];
static void spx_returned_begin(uint32_t side) {{
 __CPROVER_assert(side<=1U && side==calls.source_phase,"spx-returned-call-phase");
 __CPROVER_assume(side<=1U && side==calls.source_phase);
 spx_returned_live[side]=0U;
}}
static void spx_returned_candidate(uint32_t address,uint64_t extent,
 const struct spx_returned_exclusion *excluded,uint32_t count) {{
 __CPROVER_assert(extent>0U && extent<UINT64_C(4294967296) && count>0U && count<=33U,
  "spx-returned-domain");
 /* Greedily find the first available nonnull span, before any result assumption.
  * Each advance passes an exclusion's end; at most count advances are needed. */
 uint64_t witness=1U;
 for(uint32_t pass=0U;pass<=count;pass++)for(uint32_t i=0U;i<count;i++){{
  __CPROVER_assert(excluded[i].low<=excluded[i].high && excluded[i].high<=UINT64_C(4294967296),
   "spx-returned-exclusion-domain");
  if(excluded[i].low<excluded[i].high && witness<excluded[i].high &&
     excluded[i].low<witness+extent)witness=excluded[i].high;
 }}
 __CPROVER_assert(witness+extent<=UINT64_C(4294967296),"spx-returned-domain-inhabited");
 for(uint32_t i=0U;i<count;i++)
  __CPROVER_assert(excluded[i].low==excluded[i].high || witness>=excluded[i].high ||
   witness+extent<=excluded[i].low,"spx-returned-witness-separated");
 __CPROVER_assume(address!=0U && (uint64_t)address+extent<=UINT64_C(4294967296));
 for(uint32_t i=0U;i<count;i++)
  __CPROVER_assume(excluded[i].low==excluded[i].high || (uint64_t)address>=excluded[i].high ||
   (uint64_t)address+extent<=excluded[i].low);
}}
static void spx_returned_grant(uint32_t side,uint32_t address,uint64_t extent,uint32_t permissions) {{
 __CPROVER_assert(side<=1U && calls.count[side]>0U && calls.count[side]<={capacity}U,
  "spx-returned-call-present");
 __CPROVER_assume(side<=1U && calls.count[side]>0U && calls.count[side]<={capacity}U);
 uint32_t position=calls.count[side]-1U;
 struct spx_returned_span *span=&spx_returned_spans[position];
 if(side==0U)*span=(struct spx_returned_span){{address,permissions,1U,extent}};
 else __CPROVER_assert(span->present && span->address==address && span->extent==extent &&
  span->permissions==permissions,"spx-returned-paired-range");
 spx_returned_current[side]=position;spx_returned_live[side]=1U;
}}
static uint32_t spx_returned_native_access(uint32_t address,uint32_t width,uint32_t permission) {{
 if(!spx_returned_live[0])return 0U;
 const struct spx_returned_span *span=&spx_returned_spans[spx_returned_current[0]];
 return (span->permissions&permission)==permission && width>=1U && width<=4U &&
  address>=span->address && (uint64_t)address+width<=(uint64_t)span->address+span->extent;
}}
static const struct spx_returned_span *spx_returned_source_span(void *token) {{
 uint32_t index={capacity}U;
 for(uint32_t i=0U;i<{capacity}U;i++)if(token==&spx_returned_tokens[i])index=i;
 __CPROVER_assert(index<{capacity}U,"spx-returned-context");
 __CPROVER_assume(index<{capacity}U);
 __CPROVER_assert(spx_returned_live[1] && spx_returned_current[1]==index,
  "spx-returned-lifetime");
 return &spx_returned_spans[index];
}}
static uint32_t spx_returned_read(void *token,spx_ref_v1 base,uint64_t offset,uint32_t width,uint64_t *result) {{
 const struct spx_returned_span *span=spx_returned_source_span(token);(void)base;
 if(!result || !(span->permissions&1U) || width==0U || width>4U ||
  offset>span->extent || width>span->extent-offset)return 1U;
 uint32_t address=span->address+(uint32_t)offset;uint64_t value=0U;
 for(uint32_t i=0U;i<width;i++)value|=(uint64_t)spx_mutable_byte(&right,address+i)<<(8U*i);
 *result=value;return 0U;
}}
static uint32_t spx_returned_write(void *token,spx_ref_v1 base,uint64_t offset,uint32_t width,uint64_t value) {{
 const struct spx_returned_span *span=spx_returned_source_span(token);(void)base;
 if(!(span->permissions&2U) || width==0U || width>4U ||
  offset>span->extent || width>span->extent-offset)return 1U;
 spx_mutable_event(&right,span->address+(uint32_t)offset,width,(uint32_t)value,0U,0U);return 0U;
}}
static uint32_t spx_returned_read_u8(void *token,uint32_t offset,uint8_t *result) {{
 uint64_t value=0U;if(!result)return 1U;
 uint32_t status=spx_returned_read(token,(spx_ref_v1){{0}},offset,1U,&value);
 if(!status)*result=(uint8_t)value;return status;
}}
static uint32_t spx_returned_write_u8(void *token,uint32_t offset,uint8_t value) {{
 return spx_returned_write(token,(spx_ref_v1){{0}},offset,1U,value);
}}
static spx_view_v5 spx_returned_source_view(uint32_t address) {{
 __CPROVER_assert(spx_returned_live[1],"spx-returned-source-live");
 uint32_t index=spx_returned_current[1];
 const struct spx_returned_span *span=&spx_returned_spans[index];
 __CPROVER_assert(span->present && address==span->address,"spx-returned-source-address");
 /* This reference names a byte span, not an allocation or a new heap generation. */
 return (spx_view_v5){{.base={{1U,address,1U,0U,span->extent,span->permissions}},
  .extent=span->extent,.element_width=1U,.context=&spx_returned_tokens[index],
  .access_context=&spx_returned_tokens[index],.read_u8=spx_returned_read_u8,
  .write_u8=spx_returned_write_u8,.read=spx_returned_read,.write=spx_returned_write}};
}}
'''.strip().splitlines()
