/* Independent real CRT consumer for the console sink; no Hello application. */
#include <stdlib.h>
#include <stdio.h>
#ifdef _WIN32
#include <locale.h>
#include <wchar.h>
int main(int argc, char **argv) {
    if (argc!=3 || !setlocale(LC_ALL,"English_United States.1252")) return 125;
    wchar_t words[8192];
    if (mbstowcs(words,argv[1],8192)==(size_t)-1 || _putws(words)<0) return 125;
    if (fprintf(stderr,"%s\n",argv[2])<0) return 125;
    if (fprintf(stdout,"%s\n",argv[2])<0) return 125;
    return fclose(stdout) || fclose(stderr) ? 125 : 0;
}
#else
#include "windows-1252.h"
#include "windows-argv.h"
int main(int argc, char **argv) {
    if (argc!=3) return 125;
    spx_windows_argv converted={0};
    if (spx_windows1252_argv_init(&converted,argc,argv)!=SPX_ARGV_OK) return 125;
    spx_target_console_init();uint16_t words[8192];size_t i=0;unsigned char state[4]={0};
    do { if (i==8192) return 125;
        spx_target_decode16(&words[i],(const unsigned char *)converted.values[1]+i,1,state);
    } while (words[i++]);
    if (spx_target_put16(stdout,words)<0 || spx_target_fprintf(stderr,"%s\n",converted.values[2])<0) return 125;
    if (spx_target_fprintf(stdout,"%s\n",converted.values[2])<0) return 125;
    int failed=spx_target_stream_close(stdout) || spx_target_stream_close(stderr);
    spx_windows1252_argv_dispose(&converted);return failed ? 125 : 0;
}
#endif
