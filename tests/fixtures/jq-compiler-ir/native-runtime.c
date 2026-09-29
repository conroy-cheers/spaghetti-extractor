/* Native comparison adapter only: ABI and image-specific runtime bindings. */
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "compile.h"

static void *entry(uint32_t rva) { (void)&jv_is_valid; HMODULE m=GetModuleHandleA("libjq-1.dll");
  if(!m)ExitProcess(84);
  return (unsigned char *)m+rva; }
void locfile_free(struct locfile* file) { ((void (*)(struct locfile*))entry(0x44419))(file); }
const struct opcode_description *opcode_describe(opcode op) { return ((const struct opcode_description *(*)(opcode))entry(0x13d10))(op); }
struct locfile *locfile_retain(struct locfile *file) { return ((struct locfile *(*)(struct locfile *))entry(0x44410))(file); }
void locfile_locate(struct locfile *file, location where, const char *format, ...) {
  va_list args, copy; va_start(args,format);va_copy(copy,args);
  int length=vsnprintf(NULL,0,format,copy);va_end(copy);if(length<0)abort();
  char *message=malloc((size_t)length+1);if(!message)abort();
  vsnprintf(message,(size_t)length+1,format,args);va_end(args);
  ((void (*)(struct locfile*,location,const char*,...))entry(0x444f5))(file,where,"%s",message);
  free(message);
}
