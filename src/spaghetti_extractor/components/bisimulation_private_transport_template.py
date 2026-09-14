"""Reusable byte/private-cell simulation recipe; only layout tables vary."""

TEMPLATE = r'''typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
#include "private-layout.h"
#define COUNT(a) (sizeof(a)/sizeof((a)[0]))
static uint32_t reference_read(const uint8_t *bytes,uint32_t offset,uint32_t width){
 uint32_t value=bytes[offset];
 if(width>=2U)value|=(uint32_t)bytes[offset+1U]<<8U;
 if(width==4U){value|=(uint32_t)bytes[offset+2U]<<16U;value|=(uint32_t)bytes[offset+3U]<<24U;}
 return value;
}
static void project(const uint8_t *bytes,const uint32_t cells[][2],uint32_t count,uint32_t *values){
 for(uint32_t i=0;i<count;++i){
  uint32_t value=0U,offset=cells[i][0],width=cells[i][1];
  __CPROVER_assert((width==1U || width==2U || width==4U) && offset+width<=PRIVATE_SIZE,"private-cell-span");
  for(uint32_t k=width;k>0U;--k)value=(value<<8U)|bytes[offset+k-1U];
  values[i]=value;
 }
}
static void relation(const uint8_t *bytes,const uint32_t cells[][2],uint32_t count,const uint32_t *values){
 for(uint32_t i=0;i<count;++i)
  __CPROVER_assert(values[i]==reference_read(bytes,cells[i][0],cells[i][1]),"private-cell-byte-relation");
}
static uint32_t private_store(const uint32_t cells[][2],const uint32_t writable[][1],uint32_t count,uint32_t *values,uint32_t value){
 uint32_t choice;__CPROVER_assume(choice<count);
 uint32_t field=writable[choice][0],width=cells[field][1];
 __CPROVER_assert(field<CELL_CAPACITY,"private-write-cell");
 values[field]=width==4U ? value : value&((1U<<(8U*width))-1U);
 return field;
}
static void update_bytes(uint8_t *bytes,const uint32_t cells[][2],uint32_t field,uint32_t value){
 uint32_t offset=cells[field][0],width=cells[field][1];
 for(uint32_t i=0;i<width;++i)bytes[offset+i]=(uint8_t)(value>>(8U*i));
}
static void accessors(const uint32_t cells[][2],uint32_t cell_count,const uint32_t writable[][1],uint32_t write_count){
 uint8_t bytes[PRIVATE_SIZE];uint32_t values[CELL_CAPACITY],probe,value;
 __CPROVER_assume(probe<PRIVATE_SIZE);uint8_t before=bytes[probe];
 project(bytes,cells,cell_count,values);relation(bytes,cells,cell_count,values);
 uint32_t field=private_store(cells,writable,write_count,values,value);
 update_bytes(bytes,cells,field,value);relation(bytes,cells,cell_count,values);
 __CPROVER_assert((probe>=cells[field][0] && probe<cells[field][0]+cells[field][1]) || bytes[probe]==before,"private-outside-write-frame");
}
static void cut_transport(void){
 uint8_t bytes[PRIVATE_SIZE];uint32_t entry[CELL_CAPACITY],loop[CELL_CAPACITY],tail[CELL_CAPACITY],probe,value;
 __CPROVER_assume(probe<PRIVATE_SIZE);uint8_t before=bytes[probe];
 project(bytes,entry_cells,COUNT(entry_cells),entry);
 project(bytes,loop_cells,COUNT(loop_cells),loop);
 __CPROVER_assert(entry[removed_cells[0][0]]==loop[removed_cells[1][0]],"entry-loop-private-count");
 uint32_t field=private_store(loop_cells,loop_writable,COUNT(loop_writable),loop,value);
 update_bytes(bytes,loop_cells,field,value);
 project(bytes,tail_cells,COUNT(tail_cells),tail);relation(bytes,tail_cells,COUNT(tail_cells),tail);
 for(uint32_t i=0;i<COUNT(saved_frame);++i)
  __CPROVER_assert(entry[saved_frame[i][0]]==tail[saved_frame[i][1]],"cut-saved-frame");
 __CPROVER_assert(loop[removed_cells[1][0]]==tail[removed_cells[2][0]],"loop-tail-private-count");
 __CPROVER_assert((entry[partial_word[0][0]]&65535U)==(tail[partial_word[1][0]]&65535U),"cut-partial-word-frame");
 __CPROVER_assert(((tail[partial_word[1][0]]>>16U)&255U)==loop[partial_word[2][0]],"cut-private-c-byte");
 __CPROVER_assert((tail[partial_word[1][0]]>>24U)==loop[partial_word[3][0]],"cut-private-b-byte");
 __CPROVER_assert((probe>=loop_cells[field][0] && probe<loop_cells[field][0]+loop_cells[field][1]) || bytes[probe]==before,"cut-preserved-private-bytes");
}
void check_admission(void){
 accessors(entry_cells,COUNT(entry_cells),entry_writable,COUNT(entry_writable));
 accessors(loop_cells,COUNT(loop_cells),loop_writable,COUNT(loop_writable));
 accessors(tail_cells,COUNT(tail_cells),tail_writable,COUNT(tail_writable));
 cut_transport();
}
'''
