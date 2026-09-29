import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from spaghetti_extractor.components.comparison_package import (
    prepare_comparison_package,load_comparison_package,
)
from spaghetti_extractor.components.comparison_composition import requirement
from spaghetti_extractor.components.service_authoring import component_interface
from spaghetti_extractor.components.source import build_component_source_package
TESTKIT={'fixtures':('compiler',)}
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False)]


class CompositionFixture(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)

    def make(self,name,expression='x+1',*,oracle=None,selections=None,requirements=None):
        setup=self.root/(name+'-setup');setup.mkdir()
        interface=component_interface(component_id=name,types=TYPES,parameters=[('x','u32')],result='u32',services={})
        (setup/'interface.json').write_text(json.dumps(interface.to_payload()))
        source=setup/'body.c';source.write_text('#include "portable-component-implementation.h"\n'+
            ''.join('extern uint32_t '+fn+'(uint32_t);\n' for fn in sorted(set(re.findall(r'exported_[a-z]+',expression))))+
            f'uint32_t lifted_{name}(spx_{name}_context_v5 *ctx, uint32_t x) {{ (void)ctx; return {expression}; }}\n')
        build_component_source_package(lift_unit_id=name,files={'body.c':source},shared_inputs={},operation_symbols={'run':'lifted_'+name},out_dir=setup/'source')
        bridge=setup/'bridge.c';bridge.write_text('#include "portable-component-implementation.h"\n'+
            f'uint32_t exported_{name}(uint32_t x) {{ return lifted_{name}(0,x); }}\n')
        driver=setup/'driver.c';driver.write_text('#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include "portable-component-implementation.h"\n'+
            'int main(int argc,char **argv) { if(argc!=3) return 2; uint32_t x=(uint32_t)strtoul(argv[2],0,10);\n'+
            f'uint32_t y=!strcmp(argv[1],"original") ? ({oracle or expression}) : lifted_{name}(0,x);\n'+
            'printf("{\\\"value\\\":%u}\\n",y);return 0;}\n')
        out=self.root/name
        prepare_comparison_package(interface_package=setup/'interface.json',source_package=setup/'source',
            target_id='fixture',component_id=name,adapter_files={'bridge.c':bridge,'driver.c':driver},include_files={},link_files={},runtime_files={},
            original_files=['adapters/driver.c'],oracle_kind='fixture',cases=[dict(id='three',arguments=['3'])],observation_fields=['value'],
            assumptions=['finite scalar composition fixture'],scope='synthetic synchronous selection',compiler=Path(shutil.which('cc')),
            runner=None,server=None,output=out,dependencies=selections,requirements=requirements,export_adapters=['adapters/bridge.c'])
        return out

    def req(self,name,package,**kw):
        plan,_=load_comparison_package(package)
        return requirement(identity=name,supplier=plan['component_id'],root=package,unit=plan,**kw)

    def chain(self):
        leaf=self.make('leaf')
        mid=self.make('mid','exported_leaf(x)+1',oracle='x+2',selections=[dict(id='leaf',package=leaf)])
        root=self.make('root','exported_mid(x)+exported_leaf(x)',oracle='2*x+3',selections=[dict(id='mid',package=mid),dict(id='leaf',package=leaf)])
        return root,mid,leaf
