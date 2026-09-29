/* Independent native-service reference and portable consumer. Compare every
 * non-NUL Unicode scalar and generated multi-scalar strings as binary records. */
#include <stdint.h>
#include <stdio.h>
#ifdef SPX_WINDOWS_REFERENCE
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#else
#include "windows-argv.h"
#endif

static int observe(const uint32_t *values, unsigned count) {
    unsigned char out[513]; unsigned n;
#ifdef SPX_WINDOWS_REFERENCE
    wchar_t wide[512]; unsigned used=0;
    for (unsigned i=0;i<count;++i) {
        uint32_t value=values[i];
        if (value>0xffff) {
            value-=0x10000; wide[used++]=(wchar_t)(0xd800+(value>>10));
            wide[used++]=(wchar_t)(0xdc00+(value&0x3ff));
        } else wide[used++]=(wchar_t)value;
    }
    int result=WideCharToMultiByte(1252,0,wide,(int)used,(char *)out,sizeof(out),NULL,NULL);
    if (result<=0) return 90;
    n=(unsigned)result;
#else
    char utf8[1025]; unsigned used=0;
    for (unsigned i=0;i<count;++i) {
        uint32_t value=values[i];
        if (value<0x80) utf8[used++]=(char)value;
        else if (value<0x800) {
            utf8[used++]=(char)(0xc0|(value>>6)); utf8[used++]=(char)(0x80|(value&63));
        } else if (value<0x10000) {
            utf8[used++]=(char)(0xe0|(value>>12)); utf8[used++]=(char)(0x80|((value>>6)&63));
            utf8[used++]=(char)(0x80|(value&63));
        } else {
            utf8[used++]=(char)(0xf0|(value>>18)); utf8[used++]=(char)(0x80|((value>>12)&63));
            utf8[used++]=(char)(0x80|((value>>6)&63)); utf8[used++]=(char)(0x80|(value&63));
        }
    }
    utf8[used]=0;
    size_t required;
    if (spx_windows1252_from_utf8(utf8,(char *)out,sizeof(out),&required)!=SPX_ARGV_OK) return 91;
    n=(unsigned)(required-1);
#endif
    unsigned char length[2]={(unsigned char)n,(unsigned char)(n>>8)};
    if (fwrite(length,1,2,stdout)!=2 || fwrite(out,1,n,stdout)!=n) return 92;
    return 0;
}

int main(void) {
#ifdef SPX_WINDOWS_REFERENCE
    _setmode(_fileno(stdout),_O_BINARY);
#endif
    for (uint32_t value=1;value<=0x10ffff;++value) {
        if (value>=0xd800 && value<=0xdfff) continue;
        int code=observe(&value,1); if (code) return code;
    }
    uint32_t seed=0x20260922;
    for (unsigned run=0;run<1024;++run) {
        uint32_t values[256]; unsigned length=1+run%256;
        for (unsigned i=0;i<length;++i) {
            seed=seed*1664525U+1013904223U;
            uint32_t value=1+seed%0x10ffff;
            if (value>=0xd800 && value<=0xdfff) value=0x301;
            values[i]=value;
        }
        int code=observe(values,length); if (code) return code;
    }
    return fclose(stdout)!=0;
}
