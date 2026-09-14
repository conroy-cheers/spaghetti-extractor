"""Outcome-aware transport through the actual production returned-view helpers."""
import ast
import inspect
import re
from pathlib import Path

from .bisimulation_compaction_contract import require
from .machine_overlay_result_views import result_view_runtime_helpers
from .bisimulation_runtime_dispatch import runtime_dispatch_contract, SYMBOL, NATIVE_CALL
from ..artifacts.artifact_set import canonical_sha256_v3


def runtime_view_recipe():
    """Bind literal accessor code without invoking its model/header generator.

    The ordinary build selects the native write branch. The fixed compiler
    command admits no conditional-runtime defines. Optional decoder/codecs are
    absent; changes to this source expression must gain a new checked recipe.
    """
    function, = ast.parse(inspect.getsource(result_view_runtime_helpers)).body
    matches = [node.value for node in function.body if isinstance(node, ast.Assign)
        and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'source']
    require(len(matches) == 1, 'runtime view recipe has ambiguous source assignment')
    expression, = matches
    require(isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Add)
        and isinstance(expression.right, ast.Constant) and isinstance(expression.right.value, str)
        and isinstance(expression.left, ast.BinOp) and isinstance(expression.left.op, ast.Add),
        'runtime view recipe source expression differs')
    left = expression.left
    require(isinstance(left.left, ast.Constant) and isinstance(left.left.value, str)
        and isinstance(left.right, ast.Call) and isinstance(left.right.func, ast.Name)
        and left.right.func.id == 'conditional_write_call' and not left.right.args and not left.right.keywords,
        'runtime view recipe native dispatch expression differs')
    return {'profile': 'production-result-view-native-branch-v1', 'prefix': left.left.value,
        'suffix': expression.right.value.removesuffix('\n'),
        'dispatch_sha256': canonical_sha256_v3(runtime_dispatch_contract()),
        'dispatch_symbol': SYMBOL, 'native_call': NATIVE_CALL,
        'requires': ['Issued-reference realization is pure, preserves live origin coordinates and rejects expired or mismatched references.',
            'Related views denote the same admitted byte span with read/write permission and live access contexts.',
            'Corresponding memory hooks agree on current contents, faults and complete effects.',
            'The owned source treats references opaquely, uses widths one, two or four, and cannot observe failed-read output values.',
            'Services preserve the representation relation, including returned references and allocation failure.'],
        'scope': 'Conditional accessor observations and single-hook effects; concrete issuer, service and caller qualification and complete state/control composition remain separate.'}


def runtime_view_files():
    return {'runtime-accessors.h': '\n'.join(result_view_runtime_helpers())}


def check_runtime_view_files(root, recipe):
    source = (Path(root)/'runtime-accessors.h').read_text()
    prefix, suffix = recipe['prefix'], recipe['suffix']
    require(source.startswith(prefix) and source.endswith(suffix), 'actual runtime view accessor code differs')
    middle = source[len(prefix):len(source)-len(suffix)]
    symbol = re.escape(recipe['dispatch_symbol'])
    pattern = (r'#ifdef SPX_CONDITIONAL_RUNTIME_CONTRACT_'+re.escape(recipe['dispatch_sha256'])
        +r'\n  extern void '+symbol+r'\(spx_runtime \*, uint32_t, uint32_t, uint32_t, uint32_t \*\);'
        +r'\n  '+symbol+r'\(runtime, address, width, \(uint32_t\)value, &fault\);'
        +r'\n#else\n'+re.escape(recipe['native_call'])+r'\n#endif')
    require(re.fullmatch(pattern, middle) is not None, 'runtime view conditional/native dispatch differs')


TEMPLATE = r'''#include "state-machine-runtime.h"
#include "portable-component-implementation.h"
#include "descriptor-accessors.h"
#include "runtime-accessors.h"
struct access_record {uint32_t count,kind,address,width,value;};
static uint32_t access_result,access_fault,origin_address,origin_live;
static spx_ref_v5 issued;
static uint32_t record_read(void *opaque,uint32_t address,uint32_t width,uint32_t *fault){
 struct access_record *r=opaque;*r=(struct access_record){r->count+1U,1U,address,width,0U};
 *fault=access_fault;return access_result;
}
static void record_write(void *opaque,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault){
 struct access_record *r=opaque;*r=(struct access_record){r->count+1U,2U,address,width,value};*fault=access_fault;
}
static spx_boundary_status realize(void *opaque,const spx_machine_reference_v1 *reference,
 uint32_t permissions,uint32_t nullable,uint32_t one_past,uint32_t *address){
 (void)opaque;
 __CPROVER_assert(nullable==0U && one_past==0U,"runtime-view-interior-access-policy");
 if(!origin_live || reference->domain!=issued.domain || reference->object!=issued.object ||
    reference->generation!=issued.generation || reference->extent!=issued.extent ||
    reference->permissions!=issued.permissions || (permissions&issued.permissions)!=permissions ||
    reference->offset>=issued.extent)return SPX_BOUNDARY_UNSUPPORTED;
 *address=origin_address+(uint32_t)reference->offset;return SPX_BOUNDARY_OK;
}
static uint32_t access(spx_view_v5 *view,uint32_t kind,uint64_t index,uint32_t width,uint64_t value,uint64_t *result){
 if(kind==0U){uint8_t byte=0;uint32_t status=spx_view_read_u8(view,index,&byte);*result=byte;return status;}
 if(kind==1U)return spx_view_write_u8(view,index,(uint8_t)value);
 return view->read(view->access_context,view->base,index,width,result);
}
void check_admission(void){
 uint32_t address,extent,origin_offset,kind,width,result,fault;uint64_t index,value,domain,object,generation;
 __CPROVER_assume(kind<3U && (kind<2U || extent>0U));
 __CPROVER_assume(width==1U || width==2U || width==4U);
 __CPROVER_assume((extent==0U && address==0U && origin_offset==0U) ||
  (extent>0U && address>0U && origin_offset<address));
 __CPROVER_assume((uint64_t)address+extent<=UINT64_C(4294967296));
 __CPROVER_assume(domain!=0U && object!=0U && generation!=0U);
 origin_address=address-origin_offset;origin_live=1U;
 issued=(spx_ref_v5){domain,object,generation,origin_offset,(uint64_t)origin_offset+extent,3U};
 access_result=result;access_fault=fault;
 struct access_record a={0},b={0};
 spx_runtime abstract_runtime={.context=&a,.read=record_read,.write=record_write};
 spx_runtime actual_runtime={.context=&b,.read=record_read,.write=record_write,.realize_reference=realize};
 spx_component_view_context abstract_context={&abstract_runtime,address,extent,3U};
 spx_view_v5 abstract={.base={1U,2U,1U,0U,extent,3U},.extent=extent,.element_width=1U,
  .context=&abstract_context,.access_context=&abstract_context,.read_u8=spx_component_view_read,
  .write_u8=spx_component_view_write,.read=spx_component_view_read_span,.write=spx_component_view_write_span};
 spx_view_v5 actual={0};
 if(extent)actual=(spx_view_v5){.base=issued,.extent=extent,.element_width=1U,
  .access_context=&actual_runtime,.read=spx_component_result_view_read,.write=spx_component_result_view_write};
 uint64_t abstract_value=0,actual_value=0;
 uint32_t abstract_status=access(&abstract,kind,index,width,value,&abstract_value);
 uint32_t actual_status=access(&actual,kind,index,width,value,&actual_value);
 __CPROVER_assert(abstract_status==actual_status,"runtime-view-outcome-correspondence");
 __CPROVER_assert(abstract_status!=0U || abstract_value==actual_value,"runtime-view-successful-value");
 __CPROVER_assert(a.count<=1U && b.count<=1U,"runtime-view-single-access-hook");
 __CPROVER_assert(a.count==b.count && a.kind==b.kind && a.address==b.address &&
  a.width==b.width && a.value==b.value,"runtime-view-complete-access-effect-arguments");
}
'''
