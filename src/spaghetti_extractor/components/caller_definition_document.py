"""Document boundary for finite caller definitions, with no artifact path fields.

This validates the document envelope only. Semantic checks, supplier evidence,
interfaces and original slices belong to the caller checker. Resource discovery
may use this envelope to distinguish data strings from filesystem references.
"""
PROFILE='finite-paired-caller-v1'
FIELDS={'profile','component_id','entry_rva','operation_id','unit_rvas','service_id','required_frame',
        'native_memory','boundary','native_calls','source_services','witnesses','runtime_contracts'}


def checked_caller_document(contract):
    def require(value,message):
        if not value:raise ValueError('caller definition: '+message)
    require(isinstance(contract,dict) and set(contract) in
            (FIELDS, FIELDS-{'service_id','required_frame'}|{'suppliers'}), 'definition fields differ')
    require(contract['profile']==PROFILE,'unsupported caller definition version')
    for field in ('component_id','operation_id'):
        require(isinstance(contract[field],str) and contract[field], 'invalid '+field)
    if 'suppliers' in contract:
        suppliers=contract['suppliers']
        require(isinstance(suppliers,dict) and len(suppliers)<=32, 'invalid checked supplier inventory')
        for service,row in suppliers.items():
            require(isinstance(service,str) and service and isinstance(row,dict)
                    and set(row)-{'bindings','parameter_transport','result_transport'}=={'required_frame'} and isinstance(row['required_frame'],list)
                    and ('bindings' not in row or isinstance(row['bindings'],dict))
                    and ('parameter_transport' not in row or isinstance(row['parameter_transport'],dict))
                    and ('result_transport' not in row or isinstance(row['result_transport'],dict)),
                    'invalid checked supplier requirements')
    else:
        require(isinstance(contract['service_id'],str) and contract['service_id']
                and isinstance(contract['required_frame'],list), 'invalid checked supplier requirements')
    units=contract['unit_rvas'];entry=contract['entry_rva']
    require(isinstance(units,list) and units and all(type(v) is int and 0<=v<2**32 for v in units)
            and units==sorted(set(units)) and type(entry) is int and entry in units,'invalid entry or ownership inventory')
    require(isinstance(contract['boundary'],dict) and not {'entry','operation','proof_entry'}&set(contract['boundary']),
            'mechanical boundary fields must be derived')
    require(all(isinstance(contract[k],list) for k in ('native_memory','native_calls','source_services'))
            and all(isinstance(contract[k],dict) for k in ('witnesses','runtime_contracts')), 'invalid definition inventory')
    return contract
