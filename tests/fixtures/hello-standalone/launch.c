/* Test-input transport: Wine's Unix launcher reads UTF-8. Record the Windows
 * narrow argument mapping independently of the program, then launch its normal
 * entry. MSVCRT setlocale(LC_ALL, "") still selects the Windows user locale. */
#include <windows.h>
#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>
int wmain(int argc,wchar_t **argv) {
    wchar_t *tail=GetCommandLineW();
    if (*tail==L'"') {
        tail=wcschr(tail+1,L'"'); if (!tail) return 125; ++tail;
    } else while (*tail && *tail!=L' ' && *tail!=L'\t') ++tail;
    while (*tail==L' ' || *tail==L'\t') ++tail;
    if (!*tail || !SetEnvironmentVariableW(L"LC_ALL",L"C")) return 125;
    char path[32768]; DWORD n=GetEnvironmentVariableA("SPX_ARGV_REPORT",path,sizeof(path));
    if (n && n<sizeof(path)) {
        FILE *out=fopen(path,"wb"); if (!out) return 125;
        fprintf(out,"{\"code_page\":%u,\"argv_hex\":[",GetACP());
        for (int i=1;i<argc;++i) {
            int size=WideCharToMultiByte(CP_ACP,0,argv[i],-1,NULL,0,NULL,NULL);
            if (!size) return 125;
            char *bytes=malloc((size_t)size); if (!bytes) return 125;
            if (!WideCharToMultiByte(CP_ACP,0,argv[i],-1,bytes,size,NULL,NULL)) return 125;
            fprintf(out,"%s\"",i>1 ? "," : "");
            for (int j=0;j<size-1;++j) fprintf(out,"%02x",(unsigned char)bytes[j]);
            fputc('"',out);free(bytes);
        }
        fprintf(out,"]}\n");int failed=ferror(out);if (fclose(out)) failed=1;
        if (failed) return 125;
    }
    STARTUPINFOW startup={0}; PROCESS_INFORMATION child={0}; startup.cb=sizeof(startup);
    startup.dwFlags=STARTF_USESTDHANDLES;
    startup.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput=GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError=GetStdHandle(STD_ERROR_HANDLE);
    if (!CreateProcessW(NULL,tail,NULL,NULL,TRUE,0,NULL,NULL,&startup,&child)) return 125;
    CloseHandle(child.hThread);
    if (WaitForSingleObject(child.hProcess,INFINITE)!=WAIT_OBJECT_0) return 125;
    DWORD code;
    if (!GetExitCodeProcess(child.hProcess,&code)) return 125;
    CloseHandle(child.hProcess); ExitProcess(code);
}
