from __future__ import annotations
import contextlib
import io
from pathlib import Path
import shutil
import tempfile
import unittest
from spaghetti_extractor.cli import main
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.source import build_component_source_package
TESTKIT = {'fixtures':('compiler',),'commands':('component start','component check','component status'),
           'resources':('tests/fixtures/jq-array-concat',)}


class ComparisonFixture(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.authored=self.root/'component.c'
        self.authored.write_text('#include "portable-component-implementation.h"\n'
            'spx_jv_value_v2 lifted_array_concat(spx_array_concat_context_v5 *ctx, spx_jv_value_v2 a, spx_jv_value_v2 b) {\n'
            '(void)ctx; a.metadata += b.metadata; return a; }\n')
        driver=self.root/'driver.c'
        driver.write_text('#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n'
            '#include "portable-component-implementation.h"\n'
            'int main(int argc, char **argv) {\n'
            'if(argc!=3) return 2;\nif(!strcmp(argv[2],"missing")) { puts("{}"); return 0; }\n'
            'if(!strcmp(argv[2],"timeout")) { for(;;) {} }\n'
            'spx_jv_value_v2 a={0}, b={0}; a.metadata=(uint32_t)atoi(argv[2]); b.metadata=2;\n'
            'uint32_t result=!strcmp(argv[1],"original") ? a.metadata+b.metadata : lifted_array_concat(0,a,b).metadata;\n'
            'printf("{\\\"value\\\":%u}\\n",result); return 0; }\n')
        source=self.root/'source'
        build_component_source_package(lift_unit_id='array-concat',files={'component.c':self.authored},
            shared_inputs={},operation_symbols={'run':'lifted_array_concat'},out_dir=source)
        fixture=Path(__file__).parents[2]/'fixtures/jq-array-concat'
        self.package=self.root/'package'
        prepare_comparison_package(interface_package=fixture,source_package=source,target_id='fixture',component_id='array-concat',
            adapter_files={'driver.c':driver},include_files={},link_files={},runtime_files={},original_files=['adapters/driver.c'],
            oracle_kind='fixture',cases=[{'id':'three','arguments':['3']}],observation_fields=['value'],
            assumptions=['synthetic scalar fixture only'],scope='synthetic interface transport',
            compiler=Path(shutil.which('cc')),runner=None,server=None,output=self.package)

    def command(self,*arguments):
        stdout=io.StringIO()
        with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stdout):
            code=main(['component',*arguments])
        return code,stdout.getvalue()

    def check(self,package,name,*arguments):
        output=self.root/name
        code,text=self.command('check','fixture','array-concat','--comparison-package',str(package),
                               '--output',str(output),*arguments)
        return code,text,output
