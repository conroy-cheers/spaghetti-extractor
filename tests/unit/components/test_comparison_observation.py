"""The portable adapter helper retains exact JSON values and reports bad output."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.comparison_environment import observation_headers

TESTKIT = {'fixtures': ('compiler',)}


class ComparisonObservationTests(unittest.TestCase):
    def test_nested_values_exact_integers_bytes_and_unfinished_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for name,path in observation_headers().items():shutil.copyfile(path,root/name)
            source=root/'observe.c'
            source.write_text(r'''
#include "spx-observation.h"
int main(int argc, char **argv) {
    (void)argv;
    spx_observer out=spx_observe_begin(stdout);
    const unsigned char bytes[]={0,34,92,255,128,10};
    const uint32_t words[]={0,UINT32_MAX};
    spx_observe_u64(&out,"large",UINT64_MAX);
    spx_observe_i64(&out,"negative",INT64_MIN);
    spx_observe_bytes(&out,"bytes",bytes,sizeof bytes);
    spx_observe_bytes(&out,"empty",NULL,0);
    spx_observe_object(&out,"key\"\\\n\xc3\xa9");
    spx_observe_bool(&out,"present",1);spx_observe_null(&out,"absent");spx_observe_end(&out);
    spx_observe_array(&out,"events");spx_observe_u32s(&out,NULL,words,2);
    spx_observe_u32s(&out,NULL,NULL,0);
    if(argc==1)spx_observe_end(&out);
    return spx_observe_finish(&out)?0:77;
}
''')
            binary=root/'observe'
            built=subprocess.run([shutil.which('cc'),'-std=c11','-Wall','-Wextra','-Werror',
                str(source),'-o',str(binary)],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            observed=subprocess.run([str(binary)],capture_output=True,text=True)
            self.assertEqual(observed.returncode,0,observed.stderr)
            self.assertEqual(json.loads(observed.stdout),dict(large=2**64-1,negative=-(2**63),
                bytes='00225cff800a',empty='',events=[[0,2**32-1],[]],
                **{'key"\\\né':dict(present=True,absent=None)}))
            unfinished=subprocess.run([str(binary),'unfinished'],capture_output=True,text=True)
            self.assertEqual(unfinished.returncode,77)
            with self.assertRaises(json.JSONDecodeError):json.loads(unfinished.stdout)


if __name__=='__main__':unittest.main()
