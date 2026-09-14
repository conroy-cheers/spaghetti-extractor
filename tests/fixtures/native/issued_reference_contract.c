/* Finite runtime-contract validation; never machine-equivalence authority. */

static int reference_equal(spx_machine_reference_v1 a,spx_machine_reference_v1 b) {
  return a.domain==b.domain && a.object==b.object && a.generation==b.generation &&
    a.offset==b.offset && a.extent==b.extent && a.permissions==b.permissions;
}
static unsigned event_count;
static unsigned events[8];
static HGLOBAL observed_allocate(SIZE_T size) {
  HGLOBAL result=GlobalAlloc(GMEM_FIXED|GMEM_ZEROINIT,size);
  events[event_count++]=result ? 1U : 2U;
  return result;
}
static void observed_release(HGLOBAL block,unsigned event) {
  require(GlobalFree(block)==NULL,"actual GlobalFree outcome");
  events[event_count++]=event;
}
static void register_block(void *block,uint32_t size) {
  require(spx_native_add_external_range((uint32_t)(uintptr_t)block,size,100U,1U,7U,1U)==SPX_CALL_OK,
      "actual native allocation registration");
}
static void start_native_admission(void) {
  unsigned char *image=(unsigned char *)GetModuleHandleA(NULL);
  IMAGE_DOS_HEADER *dos=(IMAGE_DOS_HEADER *)image;
  IMAGE_NT_HEADERS32 *nt=(IMAGE_NT_HEADERS32 *)(image+dos->e_lfanew);
  NT_TIB *tib=(NT_TIB *)NtCurrentTeb();
  spx_native_context_value.image_base=(uint32_t)(uintptr_t)image;
  spx_native_context_value.image_size=nt->OptionalHeader.SizeOfImage;
  spx_native_context_value.headers_size=nt->OptionalHeader.SizeOfHeaders;
  spx_native_context_value.section_table=(uint32_t)(uintptr_t)IMAGE_FIRST_SECTION(nt);
  spx_native_context_value.section_count=nt->FileHeader.NumberOfSections;
  spx_native_context_value.stack_low=(uint32_t)(uintptr_t)tib->StackLimit;
  spx_native_context_value.stack_high=(uint32_t)(uintptr_t)tib->StackBase;
  spx_native_context_value.owner_fs_base=(uint32_t)(uintptr_t)tib;
  MEMORY_BASIC_INFORMATION page;
  require(VirtualQuery(NULL,&page,sizeof(page))==sizeof(page) &&
      (page.State!=MEM_COMMIT || (page.Protect & (PAGE_NOACCESS|PAGE_GUARD))!=0U),
      "observed native null page is inaccessible");
}
static void require_native_span(void *block,uint32_t width) {
  uint32_t address=(uint32_t)(uintptr_t)block;
  require(spx_native_read_allowed(address,width) && spx_native_write_allowed(address,width),
      "live registered span has native read and write admission");
}
static spx_machine_reference_v1 resolve(void *address,uint32_t count) {
  spx_machine_reference_v1 ref={0};
  require(spx_native_resolve_reference(&spx_native_context_value,(uint32_t)(uintptr_t)address,
      count,3U,"cleanup.scratch",0U,0U,&ref)==SPX_BOUNDARY_OK,"actual native resolver");
  return ref;
}
int main(int argc,char **argv) {
  require(sizeof(void *)==4 && sizeof(SIZE_T)==4,"PE32 pointer and allocation widths");
  unsigned mutation=argc>1 ? (unsigned)strtoul(argv[1],0,10) : 0U;
  start_native_admission();
  unsigned char *old=(unsigned char *)observed_allocate(33U);
  require(old!=NULL,"first actual allocation");
  require(!spx_native_read_allowed((uint32_t)(uintptr_t)old,1U) &&
      !spx_native_write_allowed((uint32_t)(uintptr_t)old,1U),
      "unregistered nonnull allocation does not acquire native admission");
  register_block(old,33U);require_native_span(old,33U);
  if (mutation==9U) ++spx_native_context_value.external_ranges[0].size;
  require(!spx_native_write_allowed((uint32_t)(uintptr_t)(old+32U),2U),
      "native range extent rejects a crossing write");
  require(GlobalSize((HGLOBAL)old)>=33U,"native allocation admits requested extent");
  for (unsigned i=0;i<33U;++i) require(old[i]==0,"initial zero bytes");
  spx_machine_reference_v1 issued=resolve(old,33U),alias=resolve(old+5U,28U);
  require(issued.extent==33U && alias.extent==33U && alias.offset==5U &&
    alias.domain==issued.domain && alias.object==issued.object && alias.generation==issued.generation,
    "interior alias shares original identity and lifetime");
  for (unsigned i=0;i<33U;++i) old[i]=(unsigned char)(i*17U+5U);
  unsigned char snapshot[33];memcpy(snapshot,old,33U);
  unsigned char *fresh=(unsigned char *)observed_allocate(19U);
  require(fresh!=NULL,"second actual allocation");register_block(fresh,19U);
  require_native_span(fresh,19U);require_native_span(old+5U,28U);
  for (unsigned i=0;i<19U;++i) require(fresh[i]==0,"new allocation zero bytes");
  spx_machine_reference_v1 fresh_alias=resolve(fresh+7U,12U);
  spx_machine_reference_v1 fresh_base=resolve(fresh,19U);
  if (mutation==6U) fresh_base.generation=issued.generation;
  require(fresh_base.domain==3U && fresh_base.object==1U && fresh_base.offset==0U &&
      fresh_base.extent==19U && fresh_base.permissions==3U &&
      fresh_base.generation==fresh_alias.generation && fresh_base.generation!=issued.generation,
      "allocation result contract binds identity extent permissions and fresh generation");
  uint32_t fresh_alias_address=0;
  require(spx_native_realize_reference(&spx_native_context_value,&fresh_alias,3U,0U,0U,
      &fresh_alias_address)==SPX_BOUNDARY_OK &&
      fresh_alias_address==(uint32_t)(uintptr_t)(fresh+7U),"fresh alias realizes before write");
  *(unsigned char *)(uintptr_t)fresh_alias_address=0x5aU;
  if (mutation==5U) memset(fresh,0,19U);
  require(fresh[7]==0x5aU,"birth zero initialization does not erase a later alias write");
  require((uintptr_t)old+33U<=(uintptr_t)fresh || (uintptr_t)fresh+19U<=(uintptr_t)old,
    "live allocations have disjoint requested spans");
  if (mutation==1U) issued.extent^=1U;
  if (mutation==2U) old[5]^=1U;
  require(reference_equal(issued,resolve(old,33U)),"cached reference versus original native resolver");
  require(memcmp(snapshot,old,33U)==0,"fresh allocation preserves old contents");
  for (unsigned i=0;i<33U;++i) {
    spx_machine_reference_v1 interior=issued;
    interior.offset=i;
    if (mutation==7U && i==5U) ++interior.offset;
    uint32_t address=0;
    require(spx_native_realize_reference(&spx_native_context_value,&interior,1U,0U,0U,
        &address)==SPX_BOUNDARY_OK && address==(uint32_t)(uintptr_t)(old+i) &&
        *(unsigned char *)(uintptr_t)address==snapshot[i],
        "issued-object offsets preserve address and current contents");
  }
  spx_machine_reference_v1 one_past=issued;
  one_past.offset=one_past.extent;
  uint32_t invalid_address=0;
  require(spx_native_realize_reference(&spx_native_context_value,&one_past,1U,0U,0U,
      &invalid_address)==SPX_BOUNDARY_MEMORY_FAULT,
      "one-past reference is not an in-bounds byte");
  require(spx_native_realize_reference(&spx_native_context_value,&one_past,1U,0U,1U,
      &invalid_address)==SPX_BOUNDARY_OK &&
      invalid_address==(uint32_t)(uintptr_t)(old+33U),
      "explicit one-past transport does not authorize a byte access");
  require(spx_native_realize_reference(&spx_native_context_value,&issued,4U,0U,0U,
      &invalid_address)==SPX_BOUNDARY_MEMORY_FAULT,
      "issued reference cannot grant an unavailable permission");
  spx_machine_reference_v1 forged=issued;
  forged.permissions=1U;
  require(spx_native_realize_reference(&spx_native_context_value,&forged,1U,0U,0U,
      &invalid_address)==SPX_BOUNDARY_MEMORY_FAULT,
      "issued reference permission metadata remains bound to its origin");
  forged=issued;forged.extent=32U;
  require(spx_native_realize_reference(&spx_native_context_value,&forged,1U,0U,0U,
      &invalid_address)==SPX_BOUNDARY_MEMORY_FAULT,
      "issued reference extent metadata remains bound to its origin");
  forged=issued;forged.generation=UINT64_MAX;
  require(spx_native_realize_reference(&spx_native_context_value,&forged,1U,0U,0U,
      &invalid_address)==SPX_BOUNDARY_EXPIRED,
      "unissued generation cannot acquire the issued object's lifetime");
  forged=issued;forged.offset=UINT64_MAX;
  require(spx_native_realize_reference(&spx_native_context_value,&forged,1U,0U,0U,
      &invalid_address)==SPX_BOUNDARY_MEMORY_FAULT,
      "wide offset cannot wrap into an issued object");
  uint32_t alias_address=0;
  require(spx_native_realize_reference(&spx_native_context_value,&alias,3U,0U,0U,&alias_address)==SPX_BOUNDARY_OK &&
      alias_address==(uint32_t)(uintptr_t)(old+5U) && *(unsigned char *)(uintptr_t)alias_address==snapshot[5],
      "alias realizes to preserved live contents");
  /* Actual 32-bit address-space exhaustion, not injected NULL. Do not touch
     the result if this runtime unexpectedly admits it. */
  HGLOBAL failed=observed_allocate((SIZE_T)UINT32_MAX);
  if (failed!=NULL) { GlobalFree(failed); require(0,"maximum-width allocation must fail in this run"); }
  if (mutation==8U) spx_native_context_value.stack_low=0U;
  require(!spx_native_read_allowed((uint32_t)(uintptr_t)failed,1U) &&
      !spx_native_write_allowed((uint32_t)(uintptr_t)failed,1U),
      "failed allocation has no native read or write admission");
  require_native_span(old,33U);require_native_span(fresh,19U);
  require(reference_equal(issued,resolve(old,33U)) && memcmp(snapshot,old,33U)==0,
      "failed allocation preserves reference and contents");
  require(reference_equal(fresh_alias,resolve(fresh+7U,12U)) && fresh[7]==0x5aU,
      "failed allocation preserves a newer object's current written byte");
  if (mutation==4U) {
    observed_release((HGLOBAL)fresh,4U);
    require(spx_native_release_external_range((uint32_t)(uintptr_t)fresh,101U)==SPX_CALL_OK,"early neighbor release registration");
  }
  observed_release((HGLOBAL)old,3U);
  if (mutation!=3U) require(spx_native_release_external_range((uint32_t)(uintptr_t)old,101U)==SPX_CALL_OK,
      "actual native release registration");
  uint32_t stale=0;
  require(spx_native_realize_reference(&spx_native_context_value,&issued,3U,0U,0U,&stale)==SPX_BOUNDARY_EXPIRED,
      "released reference expires without dereferencing freed storage");
  require(!spx_native_read_allowed((uint32_t)(uintptr_t)old,1U) &&
      !spx_native_write_allowed((uint32_t)(uintptr_t)old,1U),
      "released allocation loses native admission without touching freed storage");
  if (mutation!=4U) {
    require(resolve(fresh,19U).extent==19U,"neighbor remains live after release");
    observed_release((HGLOBAL)fresh,4U);
    require(spx_native_release_external_range((uint32_t)(uintptr_t)fresh,101U)==SPX_CALL_OK,"neighbor release registration");
  }
  const unsigned expected[]={1U,1U,2U,3U,4U};
  require(event_count==5U && memcmp(events,expected,sizeof(expected))==0,"allocation and release outcome order");
  printf("PE32 runtime comparison passed: success failure extent contents alias offsets lifetime integer-limit event-order native-admission\n");
  return 0;
}
