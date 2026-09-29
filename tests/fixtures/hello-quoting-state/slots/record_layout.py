"""Manual native/C record relations for the unchanged complete quoting source.

These use the original PE32 field offsets and ordinary C member names. An
inventory of incoming objects is supplied separately. This declaration alone
proves neither an object's lifetime nor growth, release or runtime applicability.
"""
from spaghetti_extractor.components.bisimulation_call_relations import constant
from spaghetti_extractor.components.bisimulation_caller_memory import entry_offset


def word(path, offset, *, writable=True):
    return {'path':path,'kind':'word','offset':offset,'writable':writable}


def reference(path, type_id, offset, *, nullable=True, writable=True):
    return {'path':path,'kind':'reference','type_id':type_id,'offset':offset,
            'nullable':nullable,'writable':writable}


def record_types(*, byte_extent=1):
    mask=[word(['words',i],i*4) for i in range(8)]
    return [
        {'id':'quote_bytes','extent':byte_extent,'fields':[],'subobjects':[]},
        {'id':'quote_word','extent':4,'fields':[word(['value'],0)],'subobjects':[]},
        {'id':'quote_mask','extent':32,'fields':mask,'subobjects':[]},
        {'id':'quote_options','extent':48,'fields':[
            word(['style'],0),word(['flags'],4),
            *[word(['mask',*member['path']],8+member['offset']) for member in mask],
            reference(['left_quote'],'quote_bytes',40),reference(['right_quote'],'quote_bytes',44)],
         'subobjects':[{'path':['mask'],'type_id':'quote_mask','offset':8}]},
        {'id':'quote_table','extent':8,'fields':[
            word(['size'],0),reference(['buffer'],'quote_bytes',4)],'subobjects':[]},
    ]


def state_projection():
    table=reference(['table'],'quote_table',0,nullable=False)
    count=word(['count'],0)
    initial_table=reference(['initial_table'],'quote_table',0,nullable=False,writable=False)
    initial_buffer=reference(['initial_buffer'],'quote_bytes',0,nullable=False,writable=False)
    for member in (table,count,initial_table,initial_buffer):del member['offset']
    table['address']=constant(0x420050).to_payload()
    count['address']=constant(0x42005c).to_payload()
    initial_table['value']=constant(0x420054).to_payload()
    initial_buffer['value']=constant(0x4300c0).to_payload()
    return {'id':'slot-state','type_id':'quote_state','fields':[table,count,initial_table,initial_buffer]}


def relation(objects, *, byte_extent=1):
    return {'header':'quote-objects.h','lifetime':'operation','types':record_types(byte_extent=byte_extent),
            'objects':objects,'projections':[state_projection()],'state':{'slots':'slot-state'}}


def local_count():
    # Both growth sites use call ESP+0x4c; call ESP is operation entry ESP-108.
    return {'id':'new-count','type_id':'quote_word',
            'address':entry_offset('esp',-32).to_payload(),'permissions':3}
