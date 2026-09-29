/* Test-only normal-entry launcher with an actual private Win32 screen buffer.
 * Observe Unicode cells/cursor after exit; never substitute application output. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static int failure(FILE *report, const char *stage) {
    fprintf(report,"{\"observer_error\":\"%s\",\"win32_error\":%lu}\n",stage,GetLastError());
    fclose(report);return 125;
}

int wmain(void) {
    const char *path=getenv("SPX_CONSOLE_REPORT"), *mode=getenv("SPX_CONSOLE_STREAMS");
    if (!path || !mode) return 125;
    FILE *report=fopen(path,"wb");if (!report) return 125;
    int output=!strcmp(mode,"both") || !strcmp(mode,"stdout");
    int error=!strcmp(mode,"both") || !strcmp(mode,"stderr");
    if (!output && !error) return failure(report,"stream selection");
    wchar_t *tail=GetCommandLineW();
    if (*tail==L'"') { tail=wcschr(tail+1,L'"');if (!tail) return failure(report,"command line");++tail; }
    else while (*tail && *tail!=L' ' && *tail!=L'\t') ++tail;
    while (*tail==L' ' || *tail==L'\t') ++tail;
    if (!*tail || !SetEnvironmentVariableW(L"LC_ALL",L"C")) return failure(report,"environment");
    HANDLE redirected_out=GetStdHandle(STD_OUTPUT_HANDLE),redirected_err=GetStdHandle(STD_ERROR_HANDLE);
    FreeConsole();if (!AllocConsole()) return failure(report,"allocate console");
    SECURITY_ATTRIBUTES security={sizeof(security),NULL,TRUE};
    HANDLE out=CreateConsoleScreenBuffer(GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,
        &security,CONSOLE_TEXTMODE_BUFFER,NULL);
    if (out==INVALID_HANDLE_VALUE) return failure(report,"screen buffer");
    const char *width=getenv("SPX_CONSOLE_COLUMNS"),*page=getenv("SPX_CONSOLE_CP");
    int columns=width ? atoi(width) : 100;UINT codepage=page ? (UINT)atoi(page) : 437;
    if (columns<80 || columns>200 || (codepage!=437 && codepage!=1252 && codepage!=65001))
        return failure(report,"console profile");
    COORD size={(SHORT)columns,120},origin={0,0};DWORD count,total=(DWORD)columns*120;
    if (!SetConsoleScreenBufferSize(out,size) || !SetConsoleActiveScreenBuffer(out) ||
        !SetConsoleMode(out,ENABLE_PROCESSED_OUTPUT|ENABLE_WRAP_AT_EOL_OUTPUT) ||
        !FillConsoleOutputCharacterW(out,L' ',total,origin,&count) || count!=total ||
        !SetConsoleCursorPosition(out,origin) || !SetConsoleOutputCP(codepage))
        return failure(report,"console setup");
    HANDLE in=CreateFileW(L"CONIN$",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,
        &security,OPEN_EXISTING,0,NULL);
    if (in==INVALID_HANDLE_VALUE) return failure(report,"console input");
    STARTUPINFOW startup={0};PROCESS_INFORMATION child={0};startup.cb=sizeof(startup);
    startup.dwFlags=STARTF_USESTDHANDLES;startup.hStdInput=in;
    startup.hStdOutput=output ? out : redirected_out;startup.hStdError=error ? out : redirected_err;
    if (!CreateProcessW(NULL,tail,NULL,NULL,TRUE,0,NULL,NULL,&startup,&child)) return failure(report,"child entry");
    CloseHandle(child.hThread);
    if (WaitForSingleObject(child.hProcess,30000)!=WAIT_OBJECT_0) {
        TerminateProcess(child.hProcess,126);WaitForSingleObject(child.hProcess,5000);
        return failure(report,"child timeout");
    }
    DWORD code;if (!GetExitCodeProcess(child.hProcess,&code)) return failure(report,"child exit");
    CONSOLE_SCREEN_BUFFER_INFO info;WCHAR text[24000];
    if (!GetConsoleScreenBufferInfo(out,&info) || !ReadConsoleOutputCharacterW(out,text,total,origin,&count) || count!=total)
        return failure(report,"screen observation");
    fprintf(report,"{\"exit_code\":%lu,\"acp\":%u,\"code_page\":%u,\"columns\":%d,\"rows\":120,\"cursor\":[%d,%d],\"lines\":[",
        code,GetACP(),GetConsoleOutputCP(),columns,info.dwCursorPosition.X,info.dwCursorPosition.Y);
    for (int y=0;y<120;++y) {
        int end=columns;while (end && text[y*columns+end-1]==L' ') --end;
        fprintf(report,"%s[",y ? "," : "");
        for (int x=0;x<end;++x) fprintf(report,"%s%u",x ? ",":"",text[y*columns+x]);
        fputc(']',report);
    }
    fputs("]}\n",report);int failed=ferror(report);if (fclose(report)) failed=1;
    CloseHandle(child.hProcess);CloseHandle(in);CloseHandle(out);FreeConsole();return failed ? 125 : 0;
}
