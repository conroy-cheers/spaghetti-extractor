#include "windows-argv.h"
#include <stdint.h>
#include <stdlib.h>
#include "windows-1252-best-fit.h"

static int scalar(const unsigned char **input, uint32_t *value) {
    const unsigned char *text=*input;
    unsigned lead=text[0], width;
    uint32_t code;
    if (lead<0x80) { *value=lead; *input=text+1; return 1; }
    if (lead>=0xc2 && lead<=0xdf) { width=2; code=lead&0x1f; }
    else if (lead>=0xe0 && lead<=0xef) { width=3; code=lead&0x0f; }
    else if (lead>=0xf0 && lead<=0xf4) { width=4; code=lead&7; }
    else return 0;
    for (unsigned i=1;i<width;++i) {
        if ((text[i]&0xc0)!=0x80) return 0; /* Also stops at NUL, before a later read. */
        code=(code<<6)|(text[i]&0x3f);
    }
    if ((width==3 && code<0x800) || (width==4 && code<0x10000) ||
        code>0x10ffff || (code>=0xd800 && code<=0xdfff)) return 0;
    *value=code; *input=text+width; return 1;
}

static unsigned char narrow(uint32_t value) {
    if (value<0x80 || (value>=0xa0 && value<=0xff)) return (unsigned char)value;
    size_t low=0,high=sizeof(windows1252_best_fit)/sizeof(windows1252_best_fit[0]);
    while (low<high) {
        size_t middle=low+(high-low)/2;
        if (windows1252_best_fit[middle].word<value) low=middle+1;
        else if (windows1252_best_fit[middle].word>value) high=middle;
        else return windows1252_best_fit[middle].byte;
    }
    return '?';
}

int spx_windows1252_from_utf8(const char *input, char *output, size_t capacity, size_t *required) {
    if (required) *required=0;
    if (!input) return SPX_ARGV_INVALID_UTF8;
    const unsigned char *cursor=(const unsigned char *)input;
    size_t count=1; uint32_t value;
    while (*cursor) {
        if (!scalar(&cursor,&value)) return SPX_ARGV_INVALID_UTF8;
        size_t width=value>0xffff ? 2 : 1;
        if (count>SIZE_MAX-width) return SPX_ARGV_NO_SPACE;
        count+=width;
    }
    if (required) *required=count;
    if (!output) return SPX_ARGV_OK;
    if (capacity<count) return SPX_ARGV_NO_SPACE;
    cursor=(const unsigned char *)input;
    while (*cursor) {
        if (!scalar(&cursor,&value)) return SPX_ARGV_INVALID_UTF8;
        if (value>0xffff) { *output++='?'; *output++='?'; }
        else *output++=(char)narrow(value);
    }
    *output=0; return SPX_ARGV_OK;
}

int spx_windows1252_argv_init(spx_windows_argv *owner, int argc, char *const argv[]) {
    *owner=(spx_windows_argv){0};
    if (argc<0 || (argc && !argv)) return SPX_ARGV_INVALID_UTF8;
    size_t entries=(size_t)argc+1;
    if (entries>SIZE_MAX/sizeof(char *)) return SPX_ARGV_NO_SPACE;
    size_t vector_bytes=entries*sizeof(char *), total=vector_bytes;
    for (int i=0;i<argc;++i) {
        size_t required;
        int result=spx_windows1252_from_utf8(argv[i],NULL,0,&required);
        if (result!=SPX_ARGV_OK) return result;
        if (total>SIZE_MAX-required) return SPX_ARGV_NO_SPACE;
        total+=required;
    }
    void *allocation=malloc(total);
    if (!allocation) return SPX_ARGV_NO_MEMORY;
    char **values=allocation; size_t used=vector_bytes;
    for (int i=0;i<argc;++i) {
        char *text=(char *)allocation+used;
        size_t required;
        int result=spx_windows1252_from_utf8(argv[i],text,total-used,&required);
        if (result!=SPX_ARGV_OK) { free(allocation); return result; }
        values[i]=text; used+=required;
    }
    values[argc]=NULL;
    *owner=(spx_windows_argv){argc,values,allocation}; return SPX_ARGV_OK;
}

void spx_windows1252_argv_dispose(spx_windows_argv *owner) {
    free(owner->storage); *owner=(spx_windows_argv){0};
}
