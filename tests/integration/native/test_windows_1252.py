"""The reusable single-byte backend agrees with the actual MSVCRT decoder."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.testkit import fixture

TESTKIT={'fixtures':('compiler','headless-wine'),
         'resources':('tests/fixtures/portable-runtime',)}

ORIGINAL=r'''
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <locale.h>
int main(void) {
    if(!setlocale(LC_ALL,"English_United States.1252")) return 90;
    HMODULE runtime=GetModuleHandleA("msvcrt.dll");
    uint32_t (*decode)(uint16_t *,const char *,uint32_t,void *)=(void *)GetProcAddress(runtime,"mbrtowc");
    int *(*error_number)(void)=(void *)GetProcAddress(runtime,"_errno");
    if(!decode || !error_number) return 91;
    printf("[");
    for(unsigned i=0;i<256;++i) {
        unsigned char input=(unsigned char)i,state[4]={0};uint16_t word=0x5a5a;
        *error_number()=0;
        uint32_t result=decode(&word,(const char *)&input,1,state);
        printf("%s[%u,%u,%u,%d,[%u,%u,%u,%u]]",i?",":"",i,result,word,*error_number(),state[0],state[1],state[2],state[3]);
    }
    printf("]\n");return 0;
}
'''
PORTABLE=r'''
#include "windows-1252.h"
#include <errno.h>
int main(void) {
    printf("[");
    for(unsigned i=0;i<256;++i) {
        unsigned char input=(unsigned char)i,state[4]={0};uint16_t word=0x5a5a;
        errno=0;
        uint32_t result=spx_target_decode16(&word,&input,1,state);
        printf("%s[%u,%u,%u,%d,[%u,%u,%u,%u]]",i?",":"",i,result,word,errno,state[0],state[1],state[2],state[3]);
    }
    printf("]\n");return 0;
}
'''


class Windows1252Tests(unittest.TestCase):
    def test_all_byte_values_preserve_words_results_and_state(self):
        compiler=fixture('compiler')/'bin/i686-w64-mingw32-gcc'
        runner=fixture('headless-wine')/'bin/spaghetti-headless-wine'
        backend=Path(__file__).parents[2]/'fixtures/portable-runtime'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'original.c').write_text(ORIGINAL);(root/'portable.c').write_text(PORTABLE)
            commands=[
                [str(compiler),'-std=c11','-Wall','-Wextra','-Werror','original.c','-o','original.exe'],
                [shutil.which('cc'),'-std=c11','-Wall','-Wextra','-Werror','-I'+str(backend),
                 'portable.c',str(backend/'windows-1252.c'),'-o','portable']]
            for command in commands:
                result=subprocess.run(command,cwd=root,capture_output=True,text=True,timeout=60)
                self.assertEqual(result.returncode,0,result.stderr)
            environment={**os.environ,'WINEPREFIX':str(root/'wine'),'WINEDEBUG':'-all',
                'WINEDLLOVERRIDES':'mscoree,mshtml,winemenubuilder.exe='}
            original=subprocess.run([str(runner),str(root/'original.exe')],cwd=root,env=environment,
                capture_output=True,text=True,timeout=60)
            self.assertEqual(original.returncode,0,original.stderr)
            portable=subprocess.run([str(root/'portable')],cwd=root,capture_output=True,text=True,timeout=10)
            self.assertEqual(portable.returncode,0,portable.stderr)
            self.assertEqual(json.loads(original.stdout),json.loads(portable.stdout))


if __name__=='__main__':unittest.main()
