#include "portable-component-implementation.h"
#include "portable-component-local-bytes.h"

uint32_t authored_quote_character(spx_quote_character_context_v5 *context,
    uint32_t text, uint32_t size, uint8_t character) {
  uint8_t options[48];
  for(uint32_t i=0U;i<48U;i++)
    if(spx_view_read_u8(&context->state.defaults,i,&options[i])) return 0U;
  spx_local_bytes_v5 owner={0};spx_view_v5 view;
  if(spx_local_bytes_open(&owner,options,sizeof(options),3U,&view)) return 0U;
  uint32_t character_word=character<128U ? character : ((uint32_t)character | 0xffffff00U);
  context->services->set_character(context->services->context,&view,character_word,1U);
  uint32_t result=context->services->quote(context->services->context,text,size,&view);
  spx_local_bytes_close(&owner);
  return result;
}
