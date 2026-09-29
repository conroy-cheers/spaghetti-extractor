"""Portable Unicode entry transport agrees with the actual Windows service."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.testkit import fixture

TESTKIT={'fixtures':('compiler','headless-wine'),
         'resources':('tests/fixtures/portable-runtime',)}

CONTRACT=r'''
#include "windows-argv.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
int main(void) {
    const unsigned char invalid[][6]={
        {0x80,0},{0xc0,0x80,0},{0xc1,0xbf,0},{0xc2,0},{0xe0,0x80,0x80,0},
        {0xe1,0x80,0},{0xed,0xa0,0x80,0},{0xed,0xbf,0xbf,0},{0xf0,0x80,0x80,0x80,0},
        {0xf0,0x90,0x80,0},{0xf4,0x90,0x80,0x80,0},{0xf5,0x80,0x80,0x80,0},
        {0xff,0}, {'a',0xc2,'b',0}};
    for (unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i) {
        /* Exact allocation puts the NUL at ASan's object boundary. */
        size_t length=strlen((const char *)invalid[i]); char *input=malloc(length+1);
        assert(input);memcpy(input,invalid[i],length+1);
        char out[16];memset(out,'!',sizeof(out));size_t required=99;
        assert(spx_windows1252_from_utf8(input,out,sizeof(out),&required)==SPX_ARGV_INVALID_UTF8);
        assert(required==0);
        for(unsigned j=0;j<sizeof(out);++j)assert(out[j]=='!');
        char *args[]={"program",input};spx_windows_argv owner={0};
        assert(spx_windows1252_argv_init(&owner,2,args)==SPX_ARGV_INVALID_UTF8);
        assert(!owner.storage && !owner.values && !owner.argc);
        spx_windows1252_argv_dispose(&owner);free(input);
    }
    const char input[]="caf\xc3\xa9 \xf0\x9f\x99\x82";
    size_t required=0;char out[16];memset(out,'!',sizeof(out));
    assert(spx_windows1252_from_utf8(input,NULL,0,&required)==SPX_ARGV_OK && required==8);
    assert(spx_windows1252_from_utf8(input,out,required-1,&required)==SPX_ARGV_NO_SPACE);
    for(unsigned j=0;j<sizeof(out);++j)assert(out[j]=='!');
    assert(spx_windows1252_from_utf8(input,out,required,&required)==SPX_ARGV_OK);
    assert(!memcmp(out,"caf\xe9 ??",8) && out[8]=='!');
    char inplace[32];strcpy(inplace,input);
    assert(spx_windows1252_from_utf8(inplace,inplace,sizeof(inplace),&required)==SPX_ARGV_OK);
    assert(!strcmp(inplace,out));
    assert(spx_windows1252_from_utf8("",out,0,&required)==SPX_ARGV_NO_SPACE && required==1);
    assert(spx_windows1252_from_utf8("",out,1,&required)==SPX_ARGV_OK && out[0]==0);
    char *args[]={"program","-g",(char *)input};spx_windows_argv owner={0};
    assert(spx_windows1252_argv_init(&owner,3,args)==SPX_ARGV_OK);
    assert(owner.argc==3 && !owner.values[3] && !strcmp(owner.values[2],inplace));
    char *swap=owner.values[0];owner.values[0]=owner.values[2];owner.values[2]=swap;
    assert(!strcmp(owner.values[0],inplace));
    spx_windows1252_argv_dispose(&owner);assert(!owner.storage && !owner.values && !owner.argc);
    spx_windows1252_argv_dispose(&owner);
    return 0;
}
'''


class WindowsArgvTests(unittest.TestCase):
    def test_all_scalars_and_generated_sequences_against_windows(self):
        compiler=fixture('compiler')/'bin/i686-w64-mingw32-gcc'
        runner=fixture('headless-wine')/'bin/spaghetti-headless-wine'
        backend=Path(__file__).parents[2]/'fixtures/portable-runtime'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            probe=str(backend/'windows-argv-probe.c')
            commands=[
                [str(compiler),'-std=c11','-O2','-Wall','-Wextra','-Werror','-DSPX_WINDOWS_REFERENCE=1',probe,'-o','original.exe'],
                [shutil.which('cc'),'-std=c11','-O2','-Wall','-Wextra','-Werror',probe,str(backend/'windows-argv.c'),'-o','portable']]
            for command in commands:
                result=subprocess.run(command,cwd=root,capture_output=True,text=True,timeout=60)
                self.assertEqual(result.returncode,0,result.stderr)
            environment={**os.environ,'WINEPREFIX':str(root/'wine'),'WINEDEBUG':'-all',
                         'WINEDLLOVERRIDES':'mscoree,mshtml,winemenubuilder.exe='}
            original=subprocess.run([str(runner),str(root/'original.exe')],cwd=root,env=environment,capture_output=True,timeout=60)
            self.assertEqual(original.returncode,0,original.stderr)
            portable=subprocess.run([str(root/'portable')],cwd=root,capture_output=True,timeout=30)
            self.assertEqual(portable.returncode,0,portable.stderr)
            # Avoid dumping megabytes on a discrepancy; identify the first byte.
            self.assertEqual(len(original.stdout),len(portable.stdout))
            different=next((i for i,(a,b) in enumerate(zip(original.stdout,portable.stdout)) if a!=b),None)
            self.assertIsNone(different,f'Windows/portable observation differs at byte {different}')
            offset=records=0
            while offset<len(original.stdout):
                n=int.from_bytes(original.stdout[offset:offset+2],'little')
                self.assertGreater(n,0);self.assertLessEqual(n,512)
                offset+=2+n;records+=1
            self.assertEqual(offset,len(original.stdout))
            self.assertEqual(records,0x10ffff-0x800+1024)

    def test_utf8_rejection_frames_capacity_aliasing_and_owner_lifetime(self):
        backend=Path(__file__).parents[2]/'fixtures/portable-runtime'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'contract.c').write_text(CONTRACT)
            command=[shutil.which('cc'),'-std=c11','-O1','-g','-Wall','-Wextra','-Werror',
                     '-fsanitize=address,undefined','-fno-omit-frame-pointer','-I'+str(backend),
                     'contract.c',str(backend/'windows-argv.c'),'-o','contract']
            result=subprocess.run(command,cwd=root,capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stderr)
            ran=subprocess.run([str(root/'contract')],cwd=root,capture_output=True,text=True,timeout=10,
                               env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1:halt_on_error=1','UBSAN_OPTIONS':'halt_on_error=1'})
            self.assertEqual(ran.returncode,0,ran.stderr)


if __name__=='__main__':unittest.main()
