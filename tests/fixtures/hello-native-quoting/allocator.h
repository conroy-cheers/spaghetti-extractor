#ifndef HELLO_NATIVE_ALLOCATOR_H
#define HELLO_NATIVE_ALLOCATOR_H
#include "pe32-import-hook.h"
#include "native-runtime.h"
#include <stdio.h>
#if HELLO_NATIVE_REALLOCATE || HELLO_NATIVE_CHECKED_ALLOCATION
#include <errno.h>
static unsigned force_reallocation_failure;
#endif
#if HELLO_NATIVE_CHECKED_ALLOCATION
static unsigned force_allocation_failure;
static spx_fixture_import_hook calloc_hook;
#endif

/* Observe only allocations made through this image's CRT imports. Realloc keeps
 * a logical identity whether the CRT moves it or not; physical move decisions
 * and uninitialized bytes are deliberately not compared. */
static spx_fixture_import_hook malloc_hook, realloc_hook, free_hook;
static struct { void *pointer; uint32_t bytes, alive; } allocations[256];
static uint32_t allocation_count, event_count, allocation_events[1024][4];

static uint32_t allocation_id(void *pointer) {
  if (!pointer) return 0;
  for (uint32_t i=0;i<allocation_count;++i)
    if (allocations[i].alive && allocations[i].pointer==pointer) return i+1;
  native_require(0,"allocator receives a live observed identity");return 0;
}
static void allocation_event(uint32_t kind,uint32_t old,uint32_t size,uint32_t result) {
  native_require(event_count<1024,"allocation event capacity");
  uint32_t *event=allocation_events[event_count++];
  event[0]=kind;event[1]=old;event[2]=size;event[3]=result;
}
static uint32_t allocated(void *pointer,uint32_t bytes) {
  if(!pointer)return 0;
  native_require(allocation_count<256,"allocation identity capacity");
  allocations[allocation_count].pointer=pointer;allocations[allocation_count].bytes=bytes;
  allocations[allocation_count++].alive=1;return allocation_count;
}
static void *observed_malloc(size_t bytes) {
  void *(*call)(size_t)=(void *)(uintptr_t)malloc_hook.original;
  void *result;
#if HELLO_NATIVE_CHECKED_ALLOCATION
  if(force_allocation_failure){errno=5;result=NULL;}
  else
#endif
    result=call(bytes);
  uint32_t id=allocated(result,(uint32_t)bytes);
  allocation_event(1,0,(uint32_t)bytes,id);return result;
}
static void *observed_realloc(void *pointer,size_t bytes) {
  void *(*call)(void *,size_t)=(void *)(uintptr_t)realloc_hook.original;
  uint32_t old=allocation_id(pointer);void *result;
#if HELLO_NATIVE_REALLOCATE || HELLO_NATIVE_CHECKED_ALLOCATION
  if(force_reallocation_failure){errno=5;result=NULL;}
  else
#endif
    result=call(pointer,bytes);
  uint32_t id=0;
  if(result) {
    if(old) {id=old;allocations[id-1].pointer=result;allocations[id-1].bytes=(uint32_t)bytes;}
    else id=allocated(result,(uint32_t)bytes);
  } else if(old && !bytes) allocations[old-1].alive=0;
  allocation_event(2,old,(uint32_t)bytes,id);return result;
}
#if HELLO_NATIVE_CHECKED_ALLOCATION
static void *observed_calloc(size_t count,size_t width) {
  void *(*call)(size_t,size_t)=(void *)(uintptr_t)calloc_hook.original;
  void *result;
  if(force_allocation_failure){errno=5;result=NULL;}else result=call(count,width);
  uint32_t id=allocated(result,(uint32_t)(count*width));
  allocation_event(4,(uint32_t)count,(uint32_t)width,id);return result;
}
#endif
static void observed_free(void *pointer) {
  void (*call)(void *)=(void *)(uintptr_t)free_hook.original;
  uint32_t id=allocation_id(pointer);
  allocation_event(3,id,0,0);if(id)allocations[id-1].alive=0;
  call(pointer);
}
static void observe_allocator(void) {
  printf("\"allocation_events\":[");
  for(uint32_t i=0;i<event_count;++i) {
    printf("%s[",i?",":"");for(unsigned j=0;j<4;++j)printf("%s%u",j?",":"",allocation_events[i][j]);putchar(']');
  }
  printf("],\"remaining_allocations\":[");unsigned count=0;
  for(uint32_t i=0;i<allocation_count;++i)if(allocations[i].alive)
    printf("%s[%u,%u]",count++?",":"",i+1,allocations[i].bytes);
  printf("]");
}
static void install_allocator(void) {
  native_require(spx_fixture_redirect_import(&malloc_hook,image_module,"msvcrt.dll","malloc",
      (void (*)(void))observed_malloc),"bind native malloc import");
  native_require(spx_fixture_redirect_import(&realloc_hook,image_module,"msvcrt.dll","realloc",
      (void (*)(void))observed_realloc),"bind native realloc import");
  native_require(spx_fixture_redirect_import(&free_hook,image_module,"msvcrt.dll","free",
      (void (*)(void))observed_free),"bind native free import");
#if HELLO_NATIVE_CHECKED_ALLOCATION
  native_require(spx_fixture_redirect_import(&calloc_hook,image_module,"msvcrt.dll","calloc",
      (void (*)(void))observed_calloc),"bind native calloc import");
#endif
}
#endif
