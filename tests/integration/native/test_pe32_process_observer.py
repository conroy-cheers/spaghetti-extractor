"""Real process exits are observations; capture failures must remain failures."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.testkit import fixture
from spaghetti_extractor.components.comparison_environment import native_adapter_headers

TESTKIT = {'fixtures': ('compiler', 'headless-wine')}

DRIVER = r'''
#include "pe32-process-observer.h"
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"failed line %d status=%d error=%lu\n",__LINE__,result.status,result.error); return 42; } } while(0)
static spx_fixture_process_result result;
static wchar_t image[32768], command[32768];
static void bytes(HANDLE handle, const void *value, DWORD size) {
  DWORD done; if (!WriteFile(handle,value,size,&done,NULL) || done!=size) ExitProcess(91);
}
static int dead(DWORD pid) {
  HANDLE process=OpenProcess(SYNCHRONIZE,FALSE,pid);
  if (!process) return GetLastError()==ERROR_INVALID_PARAMETER;
  DWORD waited=WaitForSingleObject(process,2000);CloseHandle(process);return waited==WAIT_OBJECT_0;
}
static int observe(const wchar_t *mode,DWORD timeout) {
  if (swprintf(command,32768,L"\"%ls\" %ls",image,mode)<0) return 0;
  return spx_fixture_observe_process(image,command,timeout,&result);
}
int main(int argc,char **argv) {
  SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
  DWORD length=GetModuleFileNameW(NULL,image,32768);CHECK(length && length<32768);
  if (argc==2) {
    HANDLE out=GetStdHandle(STD_OUTPUT_HANDLE),err=GetStdHandle(STD_ERROR_HANDLE);
    if (!strcmp(argv[1],"bytes")) {
      const unsigned char sample[]={0,13,10,255,'x'};
      for(unsigned i=0;i<2400;++i){bytes(out,sample,5);bytes(err,sample,5);}
      ExitProcess(0xc0000123U);
    }
    if (!strcmp(argv[1],"259")) ExitProcess(259);
    if (!strcmp(argv[1],"abort")) {bytes(out,"before-abort",12);abort();}
    if (!strcmp(argv[1],"hang")) {DWORD pid=GetCurrentProcessId();bytes(out,&pid,4);Sleep(INFINITE);}
    if (!strcmp(argv[1],"overflow")) {
      unsigned char payload[1024]={0};for(unsigned i=0;i<17;++i)bytes(out,payload,sizeof(payload));
      return 0;
    }
    if (!strcmp(argv[1],"descendant")) {
      STARTUPINFOW startup={0};PROCESS_INFORMATION child={0};startup.cb=sizeof(startup);
      startup.dwFlags=STARTF_USESTDHANDLES;startup.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
      startup.hStdOutput=out;startup.hStdError=err;
      swprintf(command,32768,L"\"%ls\" hang",image);
      CHECK(CreateProcessW(image,command,NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,NULL,&startup,&child));
      CloseHandle(child.hThread);CloseHandle(child.hProcess);return 0;
    }
    return 92;
  }
  CHECK(observe(L"bytes",5000));
  CHECK(result.exit_code==0xc0000123U && result.out_size==12000 && result.err_size==12000);
  const unsigned char sample[]={0,13,10,255,'x'};
  for(unsigned i=0;i<12000;++i)CHECK(result.out[i]==sample[i%5] && result.err[i]==sample[i%5]);
  CHECK(observe(L"259",5000) && result.exit_code==259);
  CHECK(observe(L"abort",5000) && result.exit_code!=0 && result.out_size==12 && !memcmp(result.out,"before-abort",12));
  CHECK(!observe(L"hang",500) && result.status==SPX_PROCESS_TIMEOUT && result.out_size==4);
  DWORD pid;memcpy(&pid,result.out,4);CHECK(dead(pid));
  CHECK(!observe(L"descendant",1000) && result.status==SPX_PROCESS_TIMEOUT && result.out_size==4);
  memcpy(&pid,result.out,4);CHECK(dead(pid));
  CHECK(!observe(L"overflow",5000) && result.status==SPX_PROCESS_OVERFLOW);
  wcscpy(command,L"absent");
  CHECK(!spx_fixture_observe_process(L"Z:\\no-such-spaghetti-child.exe",command,5000,&result));
  CHECK(result.status==SPX_PROCESS_SPAWN);
  CHECK(!observe(L"259",0) && result.status==SPX_PROCESS_SETUP);
  puts("binary streams and full exit codes; abort observed; timeout, descendant, overflow and launch failures rejected");
  return 0;
}
'''


class Pe32ProcessObserverTests(unittest.TestCase):
    def test_terminal_observation_and_fail_closed_capture(self):
        compiler = fixture('compiler')/'bin/i686-w64-mingw32-gcc'
        runner = fixture('headless-wine')/'bin/spaghetti-headless-wine'
        with tempfile.TemporaryDirectory(prefix='pe32-process-observer-') as temporary:
            root = Path(temporary)
            header=native_adapter_headers('pe32-process-observer.h')['pe32-process-observer.h']
            shutil.copyfile(header,root/'pe32-process-observer.h')
            (root/'driver.c').write_text(DRIVER)
            built = subprocess.run([str(compiler), '-std=c11', '-Wall', '-Wextra', '-Werror',
                                    'driver.c', '-o', 'observer.exe'], cwd=root,
                                   capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stderr)
            environment = dict(os.environ, WINEPREFIX=str(root/'wine'), WINEDEBUG='-all',
                WINEDLLOVERRIDES='mscoree,mshtml,winemenubuilder.exe=')
            ran = subprocess.run([str(runner), str(root/'observer.exe')], cwd=root,
                env=environment, capture_output=True, text=True, timeout=60)
            self.assertEqual(ran.returncode, 0, ran.stderr)
            self.assertIn('failures rejected', ran.stdout)
