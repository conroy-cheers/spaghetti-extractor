def spx_assertion_single_strategy:
  "inventory_function_grouped_paired_language_safety_with_entry_unwinding_reuse_v11";
def spx_assertion_batch_strategy:
  "inventory_function_grouped_paired_language_safety_with_bounded_authored_batches_v12";
def spx_packed_safety_strategy:
  "inventory_bounded_safety_groups_with_bounded_authored_batches_v13";

def spx_application_first_strategy:
  "inventory_bounded_safety_groups_with_application_first_authored_batches_v14";
def spx_cut_control_first_strategy:
  "inventory_bounded_safety_groups_with_cut_control_first_authored_batches_v15";

def spx_packed_single_strategy:
  "inventory_bounded_safety_groups_with_single_authored_assertions_v16";

def spx_assertion_option:
  [.models.operation_models[].obligation_models[].property_checker_command.strategy] | unique |
  if . == [spx_assertion_single_strategy] or . == [spx_packed_single_strategy] then "authored-assertions=per-property-formula-sliced"
  elif . == [spx_assertion_batch_strategy] or . == [spx_packed_safety_strategy] or . == [spx_application_first_strategy] or . == [spx_cut_control_first_strategy] then "authored-assertions=bounded-groups-formula-sliced"
  else null end;

def spx_solver_binding_and_commands:
  try (
    .checker as $checker |
    ($checker | has("smt_solver")) as $smt |
    (if $smt then
       $checker.smt_solver as $solver |
       ($solver | type) == "object" and
       ($solver | keys) == ["executable", "id", "sha256", "version"] and
       $solver.id == "z3" and
       ($solver.version | type == "string" and startswith("Z3 version ")) and
       ($solver.executable | type == "string" and test("^/[A-Za-z0-9_./+\\-]+$")) and
       ($solver.sha256 | type == "string" and test("^[0-9a-f]{64}$"))
     else true end) and
    ((if $smt then ["--smt2", "--z3", "--external-smt2-solver", $checker.smt_solver.executable]
      else ["--sat-solver", "cadical"] end) as $solver_args |
     all(.models.operation_models[].obligation_models[];
       .property_checker_command as $command |
       ($smt and ($command.assertion_arguments | index("--no-array-field-sensitivity") != null)) as $arrays |
       ($solver_args + (if $arrays then ["--no-array-field-sensitivity"] else [] end)) as $expected |
       (if $smt then $command.smt_solver == $checker.smt_solver
        else ($command | has("smt_solver") | not) end) and
       all(($command.assertion_arguments, $command.entry_assertion_arguments,
            $command.language_safety_queries[].arguments,
            .nonvacuity_checker_command.queries[].arguments);
         . as $args |
         [range(0; length) | select($args[.] | test("^--(sat-solver|external-sat-solver|smt1|smt2|z3|boolector|bitwuzla|cvc3|cvc4|cvc5|mathsat|yices|external-smt2-solver)$"))] as $positions |
         ([$args[] | select(. == "--no-array-field-sensitivity")] | length) == (if $arrays then 1 else 0 end) and
         ([$args[] | select(test("^--(max-field-sensitivity-array-size|arrays-uf-always|arrays-uf-never)(=|$)"))] | length) == 0 and
         ($positions | length) == (if $smt then 3 else 1 end) and
         $args[$positions[0]:($positions[0] + ($expected | length))] == $expected)))
  ) catch false;

def spx_authored_query_order_for($strategy):
  (if (.description | startswith("spx-bisimulation-call-completion:")) then -2
   elif $strategy == spx_cut_control_first_strategy and (.description | startswith("spx-bisimulation-sync-alignment:")) then -1
   elif $strategy == spx_application_first_strategy or $strategy == spx_cut_control_first_strategy then
     if .description | startswith("spx-bisimulation-exit-control:") then 0
     elif .description | test("^spx-bisimulation-exit-(target|value):") then 1
     elif .description | test("^spx-bisimulation-(exit-observable|exit-world-memory|exit-world-calls|exit-world-atomics):") then 2
     elif .description | startswith("spx-bisimulation-capture-reference-memory:") then 3
     elif .description | test("^spx-bisimulation-capture-(methods|metadata|context|extent):") then 4
     else 5 end
   elif .description | test("^spx-bisimulation-(exit-control|capture-methods|capture-metadata|capture-context|capture-extent):") then 0
   elif .description | test("^spx-bisimulation-exit-(target|value):") then 1
   elif .description | startswith("spx-bisimulation-exit-observable:") then 2
   else 3 end) as $priority | [$priority, .property_id];

def spx_authored_query_order: spx_authored_query_order_for(spx_packed_safety_strategy);

def spx_selected_authored_queries:
  try (
    . as $evidence |
    (.strategy == spx_assertion_batch_strategy or .strategy == spx_packed_safety_strategy or .strategy == spx_application_first_strategy or .strategy == spx_cut_control_first_strategy) as $batched |
    ([.assertions[] | {key: .property_id, value: .}] | from_entries) as $index |
    [$evidence.queries[] | select(.kind == "authored_assertion")] as $queries |
    (if $batched then "property_ids" else "property_id" end) as $field |
    (["kind", $field, "entry_function", "status", "code", "properties", "output_sha256"] | sort) as $keys |
    ([$queries[] | if $batched then .property_ids[] else .property_id end]) as $selected |
    ($evidence.assertions | sort_by(spx_authored_query_order_for($evidence.strategy)) | map(.property_id)) as $expected |
    ($evidence.strategy == spx_assertion_single_strategy or $evidence.strategy == spx_packed_single_strategy or $batched) and
    all($evidence.queries[]; .kind == "language_safety" or .kind == "authored_assertion") and
    all($queries[];
      . as $query | (if $batched then .property_ids else [.property_id] end) as $ids |
      ((keys == $keys) or (keys == (($keys + ["detail"]) | sort))) and
      ($ids | type == "array" and length > 0 and length <= (if $batched then 4 else 1 end) and length == (unique | length)) and
      all($ids[]; type == "string" and ($index[.] != null) and $index[.].entry_function == $query.entry_function) and
      ([$ids[] | $index[.].source_function] | unique | length) == 1 and
      (if .status == "satisfied" then .properties == ($ids | length) else true end)) and
    $selected == $expected[0:($selected | length)] and
    (if all($evidence.queries[]; .status == "satisfied") then $selected == $expected else true end)
  ) catch false;

def spx_source_unwind_commands:
  .proof_plan.operations as $operations |
  all(.proof.models.operation_models[];
    .operation_id as $operation |
    [$operations[] | select(.operation_id == $operation)] as $planned |
    $planned[0].source as $source |
    ($source | has("source_unwind_limit")) as $explicit |
    (if $explicit then $source.source_unwind_limit else 2 end) as $limit |
    ($planned | length) == 1 and
    ($limit | type == "number" and . == floor and . >= 1 and . <= 65536) and
    all(.obligation_models[];
      .property_checker_command as $command |
      all(($command.assertion_arguments, $command.entry_assertion_arguments,
           $command.language_safety_discovery_arguments,
           $command.language_safety_baseline_discovery_arguments,
           $command.language_safety_queries[].arguments,
           .nonvacuity_checker_command.queries[].arguments);
        . as $args |
        ([$args[] | select(. == "--unwind")] | length) == 1 and
        $args[($args | index("--unwind")) + 1] == ($limit | tostring) and
        ([$args[] | select(. == "--no-self-loops-to-assumptions")] | length) ==
          (if $explicit then 1 else 0 end))));

def spx_unconditional_operation_entries:
  all(.proof_plan.operations[];
    .continuation == null and (.source | has("entry_allocation_history") | not));

def spx_entry_unwinding_commands:
  all(.models.operation_models[].obligation_models[];
    .property_checker_command as $command |
    ($command.assertion_arguments | type) == "array" and
    ([$command.assertion_arguments[] | select(. == "--unwinding-assertions")] | length) == 1 and
    ([$command.assertion_arguments[] | select(. == "--no-unwinding-assertions")] | length) == 0 and
    $command.entry_assertion_arguments == [$command.assertion_arguments[] |
      if . == "--unwinding-assertions" then "--no-unwinding-assertions" else . end]);

def spx_supported_slicing_commands:
  # CBMC 6.9 warns that full slicing may be unsound. Diagnostic experiments
  # using it cannot enter strong qualification, including discovery/cover paths.
  all(.models.operation_models[].obligation_models[];
    all((.property_checker_command.assertion_arguments,
         .property_checker_command.entry_assertion_arguments,
         .property_checker_command.language_safety_discovery_arguments,
         .property_checker_command.language_safety_baseline_discovery_arguments,
         .property_checker_command.language_safety_queries[].arguments,
         .nonvacuity_checker_command.queries[].arguments);
      type == "array" and index("--full-slice") == null));

def spx_reference_unwind_commands:
  (.models.reference_authority.rules // []) as $rules |
  all(.models.operation_models[];
    (.maximum_input_allocations // 0) as $inputs |
    ($inputs | type == "number" and . == floor and . >= 0 and . < 4294967295) and
    all(.obligation_models[];
      (.model_bounds.maximum_calls + $inputs) as $capacity |
      (if ($rules | length) == 0 then [] else
        ["spx_proof_authority_object_rule_identity_equal.0:" +
          (([$rules[].id | utf8bytelength] | max) + 1 | tostring)] +
        ["resolve_reference", "realize_reference" | . as $function |
          range(0; 2) | . as $index |
          "spx_proof_authority_" + $function + "." + ($index | tostring) + ":" +
          (([($rules | length), (if $index == 0 then $capacity else 1 end)] | max) + 1 | tostring)]
       end | sort) as $expected |
      .property_checker_command as $command |
      (.model_bounds.maximum_calls | type == "number" and . == floor and . > 0) and
      ($capacity < 4294967295) and
      all(($command.assertion_arguments, $command.entry_assertion_arguments,
           $command.language_safety_discovery_arguments,
           $command.language_safety_baseline_discovery_arguments,
           $command.language_safety_queries[].arguments,
           .nonvacuity_checker_command.queries[].arguments);
        . as $args |
        [range(0; $args | length) | select($args[.] == "--unwindset")] as $positions |
        ($positions | length) <= 1 and
        ([ $positions[] | $args[. + 1] | split(",")[] |
           select(startswith("spx_proof_authority_")) ] | sort) == $expected)));

def spx_nonvacuity_goal_selection:
  all(.models.operation_models[].obligation_models[];
    .witness_functions as $functions |
    .nonvacuity_checker_command.queries as $queries |
    ($functions | type == "array" and length > 0 and length == (unique | length)) and
    [$queries[].functions[]] == $functions and
    all($queries[];
      .arguments as $args |
      [range(0; $args | length) | select($args[.] == "--property") | $args[. + 1]] ==
        [.functions[] | . + ".coverage.1"]));

def spx_allocation_u32:
  type == "number" and . == floor and . >= 0 and . <= 4294967295;

def spx_allocation_argument($words):
  spx_allocation_u32 and . < $words;

def spx_allocation_effect($words):
  . as $effect |
  keys == ["action", "allocation", "minimum_size", "nullable", "ownership", "register",
    "size_argument", "size_kind", "size_right_argument", "size_value"] and
  .action == "add_result_range" and .register == "eax" and
  (.nullable | type) == "boolean" and (.minimum_size | spx_allocation_u32) and
  (.size_value | spx_allocation_u32) and
  (if .size_kind == "fixed" then .size_argument == null and .size_right_argument == null
   elif .size_kind == "argument" then (.size_argument | spx_allocation_argument($words)) and .size_right_argument == null
   elif .size_kind == "product" then .size_value == 0 and
     (.size_argument | spx_allocation_argument($words)) and (.size_right_argument | spx_allocation_argument($words))
   else false end) and
  (.ownership | keys == ["family", "owner_argument"] and
    (.family | type == "string" and test("^[a-z0-9._-]{1,96}$")) and
    (.owner_argument == null or (.owner_argument | spx_allocation_argument($words)))) and
  (.allocation | keys == ["argument_masks", "initialization"] and
    (.argument_masks | type == "array" and length <= $words) and
    ([.argument_masks[].argument_index] == ([.argument_masks[].argument_index] | sort | unique)) and
    all(.argument_masks[]; keys == ["allowed_mask", "argument_index"] and
      (.argument_index | spx_allocation_argument($words)) and (.allowed_mask | spx_allocation_u32)) and
    (.initialization | . as $init |
      if .kind == "zero" or .kind == "uninitialized" then keys == ["kind"]
      elif .kind == "argument_flag" then keys == ["argument_index", "kind", "mask"] and
        (.argument_index | spx_allocation_argument($words)) and (.mask | spx_allocation_u32) and
        any(range(0; 32); pow(2; .) == $init.mask) and
        any($effect.allocation.argument_masks[];
          .argument_index == $init.argument_index and ((.allowed_mask / $init.mask | floor) % 2) == 1)
      else false end));

def spx_reference_authority_extents:
  all(.rules[];
    (.extent | spx_allocation_u32) and
    (.extent > 0 or (.kind == "external" and .lifetime == "allocation" and
      .locator.kind == "external_allocation" and .extent_mode == "instance_remainder")));

def spx_allocation_class_inputs:
  .models as $models |
  $models.reference_allocation_requirements as $requirements |
  (if $requirements == null then
    $models.reference_allocation_requirements_sha256 == null
  else
    ($requirements | type) == "array" and
    ($models.reference_allocation_requirements_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    ([$requirements[].authority.id] == ([$requirements[].authority.id] | sort | unique)) and
    all($requirements[];
      . as $requirement |
      (keys == ["argument_words", "authority", "class_sha256", "contract_identity_sha256", "effect"]) and
      (.class_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      (.contract_identity_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      (.argument_words | spx_allocation_u32 and . <= 256) and
      (.effect | spx_allocation_effect($requirement.argument_words)) and
      any($models.reference_authority.rules[];
        .kind == "external" and .lifetime == "allocation" and .locator.kind == "external_allocation" and
        $requirement.authority == {
          id, domain, object, generation, extent, permissions, lifetime, interior_pointers,
          extent_mode: (.extent_mode // "fixed"),
          locator: {kind: .locator.kind, identity: .locator.allocation_id, offset: .locator.offset}}))
  end) and
  all($models.operation_models[].obligation_models[];
    [.proof_inputs[] | select(.role == "allocation_class_requirements")] ==
      (if $requirements == null then [] else
        [{role: "allocation_class_requirements", sha256: $models.reference_allocation_requirements_sha256}]
      end));

def spx_safety_query_groups:
  . as $evidence |
  [
    {partition: "bounds", classes: ["array bounds"]},
    {partition: "pointer", classes: ["pointer", "pointer arithmetic", "pointer dereference", "pointer primitives"]},
    {partition: "division", classes: ["division-by-zero"]},
    {partition: "signed_overflow", classes: ["overflow"]},
    {partition: "undefined_shift", classes: ["undefined-shift"]},
    {partition: "unwinding", classes: ["unwind"]}
  ] as $partitions |
  [$partitions[] as $partition |
    (if $partition.partition == "unwinding" then
       [[$evidence.loops[].unwinding_property_id]]
     else
       [$evidence.language_safety_inventory[] |
         select(.class as $class | ($partition.classes | index($class)) != null)] as $rows |
       if $evidence.strategy == spx_packed_single_strategy or $evidence.strategy == spx_packed_safety_strategy or $evidence.strategy == spx_application_first_strategy or $evidence.strategy == spx_cut_control_first_strategy then
         ($rows | map(.property_id) | sort) as $ids |
         [range(0; ($ids | length); 1024) as $offset | $ids[$offset:($offset + 1024)]]
       elif ($rows | length) > 1024 then
         ($rows | group_by(.source_function) | map(map(.property_id) | sort))
       else [($rows | map(.property_id) | sort)] end
     end)[] | select(length > 0) |
    {safety_partition: $partition.partition, expected_property_ids: .}];

def spx_safety_group_refinement($expected; $complete):
  reduce .[] as $query ({valid: true, group: 0, offset: 0};
    ($query.expected_property_ids | length) as $count |
    if ($complete | not) and .offset > 0 and
       ($query.safety_partition != $expected[.group].safety_partition or
        $query.expected_property_ids != $expected[.group].expected_property_ids[.offset:(.offset + $count)])
    then .group += 1 | .offset = 0 else . end |
    $expected[.group] as $base |
    if .valid and $base != null and
       ($query.expected_property_ids | type) == "array" and $count > 0 and
       $query.safety_partition == $base.safety_partition and
       $query.expected_property_ids == $base.expected_property_ids[.offset:(.offset + $count)] and
       ($query.safety_partition != "unwinding" or
        $query.expected_property_ids == $base.expected_property_ids)
    then .offset += $count |
      if .offset == ($base.expected_property_ids | length)
      then .group += 1 | .offset = 0 else . end
    else .valid = false end) |
  .valid and (($complete | not) or (.group == ($expected | length) and .offset == 0));

def spx_safety_group_refinement($expected): spx_safety_group_refinement($expected; true);

def spx_selected_safety_queries($complete):
  . as $evidence |
  [.language_safety_baseline_inventory[].property_id] as $baseline |
  spx_safety_query_groups as $expected |
  (all(.language_safety_inventory[];
    keys == ["class", "description", "property_id", "source_function"] and
    all(.[]; type == "string" and length > 0))) and
  ([.language_safety_inventory[].property_id] ==
    ([.language_safety_inventory[].property_id] | unique)) and
  ([$expected[] | select(.safety_partition != "unwinding") | .expected_property_ids[]] | sort) ==
    [.language_safety_inventory[].property_id] and
  ([.queries[] | select(.kind == "language_safety") |
     {safety_partition, expected_property_ids}] | spx_safety_group_refinement($expected; $complete)) and
  all(.queries[] | select(.kind == "language_safety" and .status == "satisfied");
    if .safety_partition == "unwinding" then
      (.property_ids - (.expected_property_ids + $baseline) | length) == 0
    else .property_ids == .expected_property_ids end);

def spx_selected_safety_queries: spx_selected_safety_queries(true);

def spx_allocation_history_model($planned):
  ([$planned.source.syncs[] | select(has("allocation_history")) | .allocation_history] +
   [$planned.source | select(has("entry_allocation_history")) | .entry_allocation_history]) as $histories |
  all($histories[];
    type == "object" and keys == ["classes", "maximum_instances"] and
    (.maximum_instances | type) == "number" and
    .maximum_instances > 0 and .maximum_instances < 4294967295 and
    (.maximum_instances | floor) == .maximum_instances and
    (.classes | type) == "array" and (.classes | length) > 0 and
    .classes == (.classes | unique) and
    all(.classes[]; type == "string" and length > 0 and (contains("\u0000") | not))) and
  if ($histories | length) == 0 then
    (has("allocation_history_policy") | not) and (has("maximum_input_allocations") | not)
  else .allocation_history_policy == "bounded-allocation-history-checked-class-current-memory-v2" and
    .maximum_input_allocations == ([$histories[].maximum_instances] | max) end;

def spx_memory_fact_coordinate_phases($sync; $fact):
  if any($sync.captures[]; .id == $fact.view and .projection.base.kind == "stack") or
      ($fact.start.op == "state_input" and
       any($sync.captures[]; .id == $fact.start.name and .projection.kind == "stack"))
  then ["coordinate-private", "coordinate-readable"] else [] end;

def spx_memory_fact_model($planned):
  all($planned.source.syncs[]; (has("memory_facts") | not) or (.memory_facts | type) == "array") and
  ([$planned.source.syncs[] | (.memory_facts // [])[]] as $facts |
  all($planned.source.syncs[];
    . as $sync | (.memory_facts // []) as $rows |
    ($rows | type) == "array" and
    ([$rows[].id] == ([$rows[].id] | sort | unique)) and
    all($rows[];
      . as $fact |
      keys == ["byte", "id", "kind", "start", "view"] and
      (.id | type == "string" and test("^[A-Za-z_][A-Za-z0-9_]*$")) and
      .kind == "filled_suffix" and
      (.byte | type == "number" and . == floor and . >= 0 and . <= 255) and
      $sync.allocation_history != null and
      any($sync.captures[];
        .id == $fact.view and .mode == "native_view" and
        .projection.authority.lifetime == "allocation" and
        (.projection.base.kind == "register" or .projection.base.kind == "stack") and .projection.base.width == 32 and
        .projection.extent == {kind: "origin_remainder"} and
        .projection.requested_extent == {kind: "constant", value: 1, width: 32} and
        (.encoding.access == "read" or .encoding.access == "read_write")) and
      (if .start.op == "const" then
        (.start | keys == ["op", "value", "width"] and
          (.width == 1 or .width == 8 or .width == 16 or .width == 32) and
          (.value | type == "number" and . == floor and . >= 0) and .value < pow(2; .width))
       elif .start.op == "state_input" then
        (.start | keys == ["name", "op"]) and
        any($sync.captures[];
          .id == $fact.start.name and .kind == "source_state" and .mode == "machine_codec" and
          (.projection.kind == "register" or .projection.kind == "stack") and .projection.width == 32 and
          .encoding == $fact.start and .decoding == {op: "projected_value"})
       else false end))) and
  (if ($facts | length) == 0 then (has("memory_fact_policy") | not)
   else .memory_fact_policy == "allocation-current-filled-suffix-v1" end));

def spx_private_stack_scope_model($planned):
  [$planned.source.syncs[] | select(has("private_stack_scope")) | .private_stack_scope] as $scopes |
  all($scopes[];
    type == "object" and keys == ["offset", "register"] and
    (.register as $register | ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"] | index($register)) != null and
    (.offset | type) == "number" and (.offset | floor) == .offset and
    .offset >= -2147483648 and .offset < 2147483648) and
  if ($scopes | length) == 0 then (has("private_stack_scope_policy") | not)
  else .private_stack_scope_policy == "checked-invocation-private-stack-scope-v1" end;

def spx_parameter_slot_frame_model($planned):
  . as $model |
  [$planned.source.syncs[] | select(has("preserved_parameter_slots"))] as $syncs |
  all($syncs[]; . as $sync |
    .private_stack_scope.register == "esp" and
    (.preserved_parameter_slots | type == "array" and length > 0 and . == (sort | unique)) and
    all(.preserved_parameter_slots[]; . as $name |
      type == "string" and
      ([$sync.captures[] | select(.id == $name)] | length) == 1 and
      any($sync.captures[]; .id == $name and .kind == "parameter" and .mode == "machine_codec" and
        (.projection.kind == "view" or .projection.kind == "bytes_view") and
        .projection.base.kind == "stack" and .projection.base.width == 32 and
        (.projection.base.offset | type == "number" and . == floor and . % 4 == 0 and . >= -1024 and . <= 4092))) and
    (if $model.obligation_id == ("sync:" + $sync.id) then
      ($model.required_assertion_descriptions | index("spx-bisimulation-preserved-parameter-slot-writes:" + $sync.id)) != null
     else true end)) and
  (if ($syncs | length) == 0 then (has("parameter_slot_frame_policy") | not)
   else .parameter_slot_frame_policy == "checked-preserved-parameter-slots-v1" end);

def spx_local_view_model($planned):
  [$planned.source.syncs[].captures[] | select(.mode == "native_view")] as $views |
  all($views[];
    (.kind == "source_state" or .kind == "parameter") and .decoding == null and
    (.encoding | keys) == ["access", "nullable", "op"] and .encoding.op == "view" and
    (.encoding.nullable | type) == "boolean" and
    (.encoding.access == "read" or .encoding.access == "write" or .encoding.access == "read_write") and
    .projection.kind == "view" and .projection.at == "entry" and
    (if .kind == "parameter" then .encoding.nullable == true and
       .projection.extent == {kind: "origin_remainder"} and
       .projection.requested_extent.kind == "constant" and .projection.requested_extent.width == 32 and
       (.projection.requested_extent.value | type == "number" and . == floor and . >= 0 and . <= 4294967295) and
       (.projection.base.kind == "constant" or .projection.base.kind == "register" or .projection.base.kind == "stack") and
       .projection.base.width == 32 and (.projection.base.kind == "constant" or .projection.base.at == "entry")
     else true end)) and
  (if any($views[]; .kind == "parameter") then .local_view_cut_policy == "canonical-service-view-cut-v2" else true end) and
  if ($views | length) == 0 then (has("local_view_cut_policy") | not)
  else (.local_view_cut_policy == "canonical-service-view-cut-v1" or
        .local_view_cut_policy == "canonical-service-view-cut-v2") end;

def spx_machine_fact_projection($image):
  type == "object" and .at == "entry" and (.width == 8 or .width == 16 or .width == 32) and
  if .kind == "register" then
    keys == ["at", "kind", "register", "width"] and
    (.register as $register | ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"] | index($register)) != null
  elif .kind == "static_slot" then
    keys == ["at", "kind", "rva", "width"] and
    (.rva | type) == "number" and (.rva | floor) == .rva and
    .rva >= 0 and .rva + .width / 8 <= $image.image_size
  elif .kind == "stack" then
    keys == ["at", "kind", "offset", "width"] and
    (.offset | type) == "number" and (.offset | floor) == .offset and
    .offset >= -4096 and .offset <= 4096
  else false end;

def spx_machine_fact_model($planned; $image):
  [$planned.source.syncs[].derived[] | select(.expression.op == "exact_projection")] as $facts |
  all($facts[];
    (.expression | keys) == ["op", "projection"] and
    (.projection | spx_machine_fact_projection($image)) and
    (.expression.projection | spx_machine_fact_projection($image)) and
    .projection.width == .expression.projection.width) and
  if ($facts | length) == 0 then (has("machine_fact_policy") | not)
  elif any($facts[]; any([.projection, .expression.projection][]; .kind == "stack")) then
    .machine_fact_policy == "checked-current-stack-machine-cut-facts-v2"
  else .machine_fact_policy == "checked-current-machine-cut-facts-v1" end;

def spx_cut_capture_codecs:
  .proof_plan.operations as $operations |
  all(.proof.models.operation_models[];
    . as $operation_model |
    ($operations[] | select(.operation_id == $operation_model.operation_id)) as $planned |
    spx_machine_fact_model($planned; $operation_model.machine_image) and
    spx_private_stack_scope_model($planned) and
    spx_parameter_slot_frame_model($planned) and
    spx_allocation_history_model($planned) and
    spx_memory_fact_model($planned) and
    spx_local_view_model($planned) and
    all($planned.source.syncs[];
      all(.captures[];
        if .kind == "parameter" and .mode != "native_view" then
          . as $capture |
          .mode == "machine_codec" and any(["parameter", "bytes_address", "resource_identity"][];
            $capture.encoding == {op: ., name: $capture.id})
        else true end)) and
    all($operation_model.obligation_models[];
      . as $model |
      [$planned.exact.control_edges[] |
        . as $edge | select(($model.selected_unit_ids | index($edge.source_unit_id)) != null) |
        .target_unit_id] as $targets |
      all($planned.source.syncs[];
        . as $sync |
        if ($targets | index($sync.exact_unit_id)) != null then
          ($model.required_assertion_descriptions | index("spx-bisimulation-sync-alignment:" + $sync.id)) != null
        elif $model.obligation_id != ("sync:" + $sync.id) then
          ($model.required_assertion_descriptions | index("spx-bisimulation-unexpected-sync:" + $sync.id)) != null
        else true end) and
      spx_machine_fact_model($planned; $operation_model.machine_image) and
      spx_private_stack_scope_model($planned) and
      spx_parameter_slot_frame_model($planned) and
      spx_allocation_history_model($planned) and
      spx_memory_fact_model($planned) and
      spx_local_view_model($planned) and
      all($planned.source.syncs[];
        . as $sync |
        all((.memory_facts // [])[];
          . as $fact |
          ((if $model.obligation_id == ("sync:" + $sync.id) then ["construction-order", "input-domain"] else [] end) +
           (if ($targets | index($sync.exact_unit_id)) != null then ["output-domain", "contents"] else [] end)) as $phases |
          all(($phases + (if ($phases | length) > 0 then spx_memory_fact_coordinate_phases($sync; $fact) else [] end))[]; . as $phase |
            ($model.required_assertion_descriptions | index("spx-bisimulation-memory-fact-" +
                $phase + ":" + $sync.id + ":" + $fact.id)) != null))) and
      (if ($planned.source | has("entry_allocation_history")) and
          ($model.obligation_id | startswith("entry:")) then
        all(["input", "admission"][];
          . as $kind | ($model.required_assertion_descriptions |
            index("spx-bisimulation-allocation-entry-" + $kind + ":" + $planned.operation_id)) != null)
       else true end) and
      all($planned.source.syncs[];
        . as $sync |
        [$sync.captures[] | select(.mode == "native_view") | .id] as $native |
        (if ($model.obligation_id == ("sync:" + $sync.id) or
             ($targets | index($sync.exact_unit_id)) != null) and
            any($sync | .. | objects; .op == "byte_read" and
              (.name as $name | ($native | index($name)) != null))
         then ($model.required_assertion_descriptions | index("spx-bisimulation-native-view-byte-access")) != null
         else true end) and
        all(.captures[] | select(.mode == "native_view");
          . as $capture |
          if $model.obligation_id == ("sync:" + $sync.id) then
            ($model.required_assertion_descriptions |
              index("spx-bisimulation-native-view-input:" + $sync.id + ":" + $capture.id)) != null and
            (if $model.local_view_cut_policy == "canonical-service-view-cut-v2" then
               ($model.required_assertion_descriptions |
                 index("spx-bisimulation-native-view-input-owner:" + $sync.id + ":" + $capture.id)) != null
             else true end)
          else true end)) and
      all($planned.source.syncs[];
        . as $sync |
        (if any($planned.source.syncs[]; has("private_stack_scope")) and
            ($targets | index($sync.exact_unit_id)) != null then
          ($model.required_assertion_descriptions | index("spx-bisimulation-private-stack-scope:" + $sync.id)) != null
        else true end) and
        (if has("private_stack_scope") and $model.obligation_id == ("sync:" + $sync.id) then
          ($model.required_assertion_descriptions | index("spx-bisimulation-private-stack-scope-input:" + $sync.id)) != null
        else true end)) and
      all($planned.source.syncs[];
        . as $sync |
        all(.derived[] | select(.expression.op == "exact_projection");
          . as $fact |
          any([.projection, .expression.projection][]; .kind == "static_slot" or .kind == "stack") as $reads |
          any([.projection, .expression.projection][]; .kind == "stack") as $stack |
          (if ($targets | index($sync.exact_unit_id)) != null then
            ($model.required_assertion_descriptions | index("spx-bisimulation-derived:" + $sync.id + ":" + $fact.id)) != null and
            (if $reads then ($model.required_assertion_descriptions | index("spx-bisimulation-exact-output-read")) != null else true end) and
            (if $stack then ($model.required_assertion_descriptions | index("spx-bisimulation-exact-output-stack-range")) != null else true end)
           else true end) and
          (if $reads and $model.obligation_id == ("sync:" + $sync.id) then
            ($model.required_assertion_descriptions | index("spx-bisimulation-exact-input-read")) != null and
            (if $stack then ($model.required_assertion_descriptions | index("spx-bisimulation-exact-input-stack-range")) != null else true end)
           else true end))) and
      all($planned.source.syncs[] | select(has("allocation_history"));
        . as $sync |
        if $model.obligation_id == ("sync:" + $sync.id) then
          ($model.required_assertion_descriptions | index("spx-bisimulation-allocation-history-input:" + $sync.id)) != null
        else true end) and
      all($planned.source.syncs[];
        . as $sync |
        if ($targets | index($sync.exact_unit_id)) != null then
          (($model.required_assertion_descriptions |
            index("spx-bisimulation-allocation-cut-admission:" + $sync.id)) != null) and
          all(.captures[];
            if .kind == "source_state" and .mode == "machine_codec" then
              . as $capture |
              ($model.required_assertion_descriptions |
                index("spx-bisimulation-capture-roundtrip:" + $sync.id + ":" + $capture.id)) != null
            elif .mode == "native_view" then
              . as $capture |
              all(["capture", "resumed-view-admission"][];
                . as $kind | ($model.required_assertion_descriptions |
                  index("spx-bisimulation-" + $kind + ":" + $sync.id + ":" + $capture.id)) != null) and
              (if .kind == "parameter" then ($model.required_assertion_descriptions |
                 index("spx-bisimulation-capture-reference-memory:" + $sync.id + ":" + $capture.id)) != null else true end)
            elif .kind == "parameter" and .mode == "machine_codec" and (.projection.kind == "view" or .projection.kind == "bytes_view") then
              . as $capture |
              (($capture.projection.kind != "view") or
                (($model.required_assertion_descriptions |
                  index("spx-bisimulation-resumed-view-admission:" + $sync.id + ":" + $capture.id)) != null)) and
              (($model.required_assertion_descriptions |
                index("spx-bisimulation-capture-reference-memory:" + $sync.id + ":" + $capture.id)) != null) and
              (($model.required_assertion_descriptions |
                index("spx-bisimulation-capture-methods:" + $sync.id + ":" + $capture.id)) != null) and
              (($model.required_assertion_descriptions |
                index("spx-bisimulation-capture-metadata:" + $sync.id + ":" + $capture.id)) != null) and
              (($model.required_assertion_descriptions |
                index("spx-bisimulation-capture-context:" + $sync.id + ":" + $capture.id)) != null) and
              (($model.required_assertion_descriptions |
                index("spx-bisimulation-capture-extent:" + $sync.id + ":" + $capture.id)) != null)
            else true end)
        else true end)));

def spx_shared_view_inputs:
  (.proof.policy.canonical_borrowed_view_spans == true) and
  all(.proof.models.operation_models[];
    .operation_id as $operation |
    all(.obligation_models[];
      . as $model |
      all(["shared-view-inputs", "source-frame-preservation"][];
        . as $kind | ($model.required_assertion_descriptions |
          index("spx-bisimulation-" + $kind + ":" + $operation + ":" + $model.proof_function)) != null)));

def spx_parameter_exit_model($exits):
  . as $model |
  ($exits | type) == "array" and
  ([$exits[].id] == ([$exits[].id] | sort | unique)) and
  ([$exits[].projection.register] | length) == ([$exits[].projection.register] | unique | length) and
  all($exits[];
    . as $row | (keys | sort) == ["id", "projection"] and
    (.id | type) == "string" and (.id | length) > 0 and
    (.projection | keys | sort) == ["at", "kind", "register", "width"] and
    .projection.kind == "register" and .projection.at == "exit" and .projection.width == 32 and
    (["eax", "ebx", "ecx", "edx", "esi", "edi"] | index($row.projection.register)) != null and
    ($model.required_assertion_descriptions |
      index("spx-bisimulation-exit-observable:" + $model.operation_id + ":parameter:" + $row.id)) != null);

def spx_parameter_exit_transports:
  .proof_plan.operations as $operations |
  all(.proof.models.operation_models[];
    .operation_id as $operation |
    [$operations[] | select(.operation_id == $operation)] as $planned |
    ($planned | length) == 1 and
    all(.obligation_models[]; spx_parameter_exit_model($planned[0].parameter_exit_projections // [])));

def spx_common_continuations:
  .proof_plan.operations as $operations |
  all(.proof.models.operation_models[];
    .operation_id as $operation |
    ($operations[] | select(.operation_id == $operation)) as $plan |
    all(.obligation_models[];
      . as $model |
      .continuation == $plan.continuation and
      (if $plan.continuation != null then
        ((.continuation.unit_ids - .selected_unit_ids) | length) == 0 and
        all(["bound", "implemented", "control", "target", "value", "calls", "atomics", "memory"][];
          . as $kind | ($model.required_assertion_descriptions |
            index("spx-bisimulation-continuation-" + $kind + ":" + $operation + ":" + $model.proof_function)) != null)
       else true end)));

def spx_lifetime_site_effect:
  {id: .contract_id, arity, argument_words: .arity.words, result_register_relations,
   memory_effect, memory_footprints, world_effect, callback_effect,
   out_pointer_relations, out_interface_relations, external_service_protocol} +
  (if .world_effect_argument != null then {world_effect_argument} else {} end) +
  (if .world_effect_release != null then {world_effect_release} else {} end);

def spx_local_allocation_effect:
  .result_register_relations[0] |
  {action: "add_result_range", register, ownership, allocation, nullable,
   minimum_size: (.minimum_size // 0), size_kind: .size.kind,
   size_value: (if .size.kind == "fixed" then .size.byte_count
                elif .size.kind == "argument" then (.size.scale // 1) else 0 end),
   size_argument: (if .size.kind == "argument" then .size.argument
                  elif .size.kind == "product" then .size.left_argument else null end),
   size_right_argument: (if .size.kind == "product" then .size.right_argument else null end)};

def spx_terminated_read_effect($words):
  if any(.result_register_relations[]?; .relation == "terminated_byte_offset") then
    .memory_effect == "readOnly" and .world_effect == "none" and .disposition == "returns" and
    ((has("memory_footprints") | not) or .memory_footprints == []) and
    (.callback_effect == null or .callback_effect == "none") and
    ((has("out_pointer_relations") | not) or .out_pointer_relations == []) and
    ((has("out_interface_relations") | not) or .out_interface_relations == []) and
    .world_effect_argument == null and .world_effect_release == null and
    .external_service_protocol == null and .effect_model == null and
    (.result_register_relations | length == 1) and
    (.result_register_relations[0] |
      keys == ["base_argument", "nullable", "register", "relation"] and .register == "eax" and
      (.nullable | type == "boolean") and (.base_argument | spx_allocation_argument($words)))
  else true end;

def spx_terminated_write_effect($words):
  if any(.result_register_relations[]?; .relation == "written_terminated_byte_count") then
    . as $effect | .result_register_relations[0] as $result |
    (.result_register_relations | length == 1) and
    ($result | keys == ["base_argument", "capacity_argument", "register", "relation"] and
      .register == "eax" and (.base_argument | spx_allocation_argument($words)) and
      (.capacity_argument | spx_allocation_argument($words)) and .base_argument != .capacity_argument) and
    .memory_effect == "argumentRanges" and (.world_effect == "none" or .world_effect == "opaqueResources") and
    .disposition == "returns" and
    .memory_footprints == [{access: "write", base_argument: $result.base_argument, offset: 0,
      size: {kind: "argument", argument: $result.capacity_argument, scale: 1}, nullable: false}] and
    (.callback_effect == null or .callback_effect == "none") and
    ((has("out_pointer_relations") | not) or .out_pointer_relations == []) and
    ((has("out_interface_relations") | not) or .out_interface_relations == []) and
    .world_effect_argument == null and .world_effect_release == null and
    .external_service_protocol == null and .effect_model == null
  else true end;

def spx_typed_external_target_supported:
  if has("target_sampling") and
      (.provider_kind != "external_call" or .captured_target_projection == null or
       (.target_sampling | IN("service_call", "operation_entry") | not)) then false
  elif .provider_kind != "external_call" or .captured_target_projection == null then true
  else .captured_target_projection |
    type == "object" and .at == "entry" and .width == 32 and
    (if .kind == "static_slot" then
      keys == ["at", "kind", "rva", "width"] and
      (.rva | type == "number" and floor == . and . >= 0 and . <= 4294967292)
    elif .kind == "register" then
      keys == ["at", "kind", "register", "width"] and
      (.register | IN("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"))
    else false end)
  end;

def spx_typed_adapter_renderer_inventory:
  any(.adapter_plan[].checked_binding;
      .provider_kind == "external_call" and .captured_target_projection != null) as $targets |
  any(.adapter_plan[].checked_binding.external_effect_contract;
      .memory_effect == "argumentRanges" or
      (.memory_effect == "readOnly" and ((.memory_footprints // []) | length) > 0) or
      ((.argument_domain // []) | length) > 0) as $ranges |
  any(.adapter_plan[].checked_binding.external_effect_contract;
      .world_effect == "dynamicRanges" or .world_effect == "dynamicRangeRelease") as $lifetime |
  any(.adapter_plan[].checked_binding.external_effect_contract.result_register_relations[]?;
      .relation == "terminated_byte_offset" or .relation == "written_terminated_byte_count") as $terminated |
  ["bisimulation_terminated_reads.py", "terminated_reads.py", "bisimulation_image_frame.py"] as $termination_files |
  .renderer |
  ([
    "bisimulation_service_effects.py", "bisimulation_service_preconditions.py",
    "bisimulation_typed_services.py", "contracts.py", "machine_overlay_boundaries_v5.py",
    "machine_overlay_external_v5.py", "machine_overlay_result_views.py",
    "machine_overlay_services_v5.py", "machine_overlay_state_views.py", "machine_overlay_v5.py",
    "range_allocation.py", "range_ownership.py", "range_release.py", "resolved_contract.py"
  ] + (if $lifetime then [
    "bisimulation_lifetime_admission.py", "bisimulation_lifetime_namespace.py",
    "bisimulation_allocation_classes.py", "bisimulation_allocation_namespace.py",
    "bisimulation_allocation_producers.py", "bisimulation_allocation_authority.py",
    "bisimulation_allocation_lifetime.py", "bisimulation_call_allocation.py",
    "bisimulation_call_memory.py", "bisimulation_reference_authority.py",
    "bisimulation_reference_origins.py", "bisimulation_world.py",
    "lifetime_effects.py", "import_sites.py", "object_authority.py", "reference_namespace.py"
  ] else [] end) + (if $ranges then [
    "argument_domains.py", "bisimulation_call_ranges.py", "bisimulation_call_memory.py",
    "bisimulation_world.py", "bisimulation_world_memory.py",
    "bisimulation_reference_authority.py", "bisimulation_reference_origins.py",
    "bisimulation_allocation_lifetime.py", "bisimulation_exact_frame.py",
    "bisimulation_mutable_frame.py", "bisimulation_private_frame.py"
  ] else [] end) + [
    "bisimulation_call_memory.py",
    "bisimulation_world.py", "bisimulation_world_memory.py", "bisimulation_reference_origins.py",
    "bisimulation_allocation_lifetime.py"
  ] + (if $targets then [
    "bisimulation_service_targets.py", "machine_binding.py"
  ] else [] end) + (if $terminated then $termination_files else [] end) | sort | unique) as $required |
  .id == "checked-service-adapter-dual-lowering-v5" and .version == 5 and
  (.implementation_files | type == "array") and
  (([.implementation_files[].path] == $required) or
   ($terminated | not) and ([.implementation_files[].path] == (($required + $termination_files) | sort | unique))) and
  (all(.implementation_files[];
    keys == ["path", "sha256"] and (.sha256 | type == "string" and test("^[0-9a-f]{64}$")))) and
  (.implementation_closure_sha256 | type == "string" and test("^[0-9a-f]{64}$"));

# Local readable certificates remain auxiliary: connected read-only replacement
# is rejected below until the caller composition rule is admitted.
def spx_readonly_digest:
  type == "string" and test("^[0-9a-f]{64}$");

def spx_readonly_identifier:
  gsub("[-.]"; "_");

def spx_shared_memory_policy: . == "fixed-shared-view-service-source-contract-v1";

def spx_shared_selected_services:
  . as $certificate | .interface_intent as $interface |
  if .shared_contract | has("service_contracts") then
    .shared_contract.service_contracts as $services |
    ($services | type == "array" and length > 0) and
    ([$services[].service_id] == ([$interface.services[].id] | sort | unique)) and
    all($services[]; . as $service |
      keys == ["abi_sha256", "external_contract_identity_sha256", "external_effect_contract", "service_id"] and
      (.abi_sha256 | spx_readonly_digest) and (.external_contract_identity_sha256 | spx_readonly_digest) and
      (first($interface.services[] | select(.id == $service.service_id)).signature_id as $signature_id |
       first($interface.schema.signatures[] | select(.id == $signature_id)) as $signature |
       .external_effect_contract as $effect |
       $effect.argument_words == ($signature.parameters | length) and
       $effect.arity == {kind: "fixed", words: ($signature.parameters | length)} and
       $effect.disposition == "returns" and
       ($effect.memory_effect == "none" or $effect.memory_effect == "argumentRanges") and
       ($effect.world_effect == "none" or $effect.world_effect == "opaqueResources") and
       ($effect.callback_effect == null or $effect.callback_effect == "none") and
       $effect.external_service_protocol == null and
       ($effect.result_register_relations == [{register: "eax", relation: "exact"}] or
         (($effect.result_register_relations | length) == 1 and
          $effect.result_register_relations[0].relation == "written_terminated_byte_count" and
          ($signature.results | length) == 1 and $signature.results[0].interpretation == "value" and
          ($effect | spx_terminated_write_effect($signature.parameters | length)))) and
       all(($signature.parameters + $signature.results)[]; . as $value |
         .interpretation == "view" or (.interpretation == "value" and
           any($interface.schema.types[]; .id == $value.type_id and
             .kind == "integer" and .width_bits == 32 and .signed == false))) and
       all(($effect.argument_domain // [])[]; . as $domain |
         keys == ["argument_index", "maximum", "minimum"] and
         (.argument_index | type == "number" and . == floor and . >= 0 and . < ($signature.parameters | length)) and
         $signature.parameters[.argument_index].interpretation == "value" and
         (.minimum | type == "number" and . == floor and . >= 0) and
         (.maximum | type == "number" and . == floor and . >= $domain.minimum and . <= 4294967295)) and
       (if $effect.memory_effect == "none" then ($effect.memory_footprints // []) == [] else
         ($effect.memory_footprints | type == "array" and length > 0) and
         all($effect.memory_footprints[]; . as $footprint | $signature.parameters[.base_argument] as $view |
           keys == ["access", "base_argument", "nullable", "offset", "size"] and
           (.nullable | type == "boolean") and
           (.base_argument | type == "number" and . == floor and . >= 0 and . < ($signature.parameters | length)) and
           $view.interpretation == "view" and $view.extent.kind == "fixed" and $view.nullable == false and
           (.access == "read" or .access == "write" or .access == "read_write") and
           (if .access == "read" then ($view.access == "read" or $view.access == "read_write")
            else $view.access == "read_write" end) and
           (.offset | type == "number" and . == floor and . >= 0 and . <= 4294967295) and
           (if .size.kind == "argument" then
             (.size | keys == ["argument", "kind", "scale"]) and
             (.size.argument | type == "number" and . == floor and . >= 0 and . < ($signature.parameters | length)) and
             $signature.parameters[.size.argument].interpretation == "value" and
             (.size.scale | type == "number" and . == floor and . > 0 and . <= 4294967295)
            else (.size | keys == ["bytes", "kind"]) and .size.kind == "fixed" and
              (.size.bytes | type == "number" and . == floor and . > 0 and . <= 4294967295) end)) end)))
  else true end;

# Auxiliary source evidence only. This does not admit a connected strategy.
def spx_shared_source_boundary:
  . as $certificate | .interface_intent as $interface |
  def scalar:
    . as $value | .interpretation == "value" and .access == "none" and .nullable == false and
    any($interface.schema.types[]; .id == $value.type_id and
      (.kind == "integer" or .kind == "bool" or .kind == "enum"));
  def view:
    . as $value | .interpretation == "view" and .nullable == false and
    (.access == "read" or .access == "read_write") and .extent.kind == "fixed" and
    (.extent.bytes | type == "number" and . == floor and . > 0 and . <= 1073741822) and
    any($interface.schema.types[]; .id == $value.type_id and .kind == "pointer" and
      (.pointee_type_id as $pointee | any($interface.schema.types[];
        .id == $pointee and .kind == "integer" and .width_bits == 8)));
  ($interface.state | length > 0) and ($interface.services | length > 0) and
  all($interface.state[]; .initial == null and (.value | view)) and
  ([$interface.state[].value.extent.bytes] | add) <= 1073741822 and
  all($interface.operations[]; .signature_id as $signature |
    any($interface.schema.signatures[]; .id == $signature and
      all(.parameters[]; scalar) and (.results | length == 1) and (.results[0] | view))) and
  all($interface.services[]; .signature_id as $signature |
    any($interface.schema.signatures[]; .id == $signature and
      (.results | length == 1) and (.results[0] | scalar) and
      all(.parameters[]; scalar or (view and (. as $value |
        [$interface.state[].value | select(.type_id == $value.type_id and
          .extent == $value.extent and .access == $value.access)] | length == 1))))) and
  (.shared_contract | keys == (["relation_intent", "maximum_calls", "maximum_memory_events"] +
    (if has("service_contracts") then ["service_contracts"] else [] end) | sort)) and
  all([.shared_contract.maximum_calls, .shared_contract.maximum_memory_events][];
    type == "number" and . == floor and . > 0 and . <= 64) and
  (.shared_contract.relation_intent |
    .format == "spaghetti-extractor-component-relation-intent-v1" and
    .component_id == $interface.id and .status == "ready_for_check" and .blockers == [] and
    .policy == {checked_evidence_required: true, intent_authorizes: false, tests_authorize: false} and
    (.intent_sha256 | spx_readonly_digest) and
    ([.operations[].operation_id] | sort) == ($certificate.operation_symbols | keys) and
    all(.operations[]; .operation_id as $operation |
      (.requirements | length == 1) and .requirements[0].relation == "normal_exit_postcondition" and
      (.requirements[0].expression |
        . as $post |
        (if .op == "and" then
          keys == ["args", "attributes", "op", "sort"] and .sort == {kind: "bool"} and
          .attributes == {} and (.args | length == 2) and
          (.args[1] | keys == ["args", "attributes", "op", "sort"] and
            .op == "view_has_zero" and .sort == {kind: "bool"} and .attributes == {} and
            .args == [$post.args[0].args[] | select(.attributes.path.root == "result")])
         else true end) and
        ((if .op == "and" then .args[0] else . end) |
        .op == "eq" and .sort == {kind: "bool"} and .attributes == {} and
        (.args | length == 2) and ([.args[].attributes.path.root] | sort) == ["result", "state"] and
        all(.args[]; . as $term |
          .op == "logical" and .args == [] and .sort.kind == "view" and .attributes.path.fields == [] and
          (if .attributes.path.root == "state" then
            any($interface.state[].value; .id == $term.attributes.path.id and .type_id == $term.sort.type_id)
           else any($interface.operations[]; .id == $operation and
             (.signature_id as $signature | any($interface.schema.signatures[]; .id == $signature and
               any(.results[]; .id == $term.attributes.path.id and .type_id == $term.sort.type_id)))) end)))))) and
  spx_shared_selected_services and
  .checks[0].interface_sha256 == .interface_sha256 and
  .checks[0].context_tag == ("tag-spx_" + ($interface.id | spx_readonly_identifier) + "_context_v5") and
  .checks[0].state_views == ([$interface.state[].value.id | spx_readonly_identifier] | sort) and
  .checks[0].service_arities == ([$interface.services[] | . as $service |
    $interface.schema.signatures[] | select(.id == $service.signature_id) |
    {key: ($service.id | spx_readonly_identifier), value: (1 + (.parameters | length))}] | from_entries);

def spx_memory_commands($mutable):
  . as $certificate |
  (.policy | spx_shared_memory_policy) as $shared |
  (.operation_symbols | keys) as $operations |
  [.source_package.files[] | select(.path | endswith(".c")) | "inputs/" + .path] as $sources |
  ["--i386-win32", "-nostdinc", "-I", "include", "-I", "inputs"] as $prefix |
  ([range(0; $sources | length) as $index |
    {step: ("authored-" + (("0000" + ($index | tostring))[-4:]) + "-dependencies"),
     arguments: ($prefix + ["-M", "-MT", "spx_readonly_dependencies", $sources[$index]])}] +
   [{step: "authored-compile", arguments: ($prefix + $sources + ["--function", .operation_symbols[$operations[0]], "-o", "authored.goto"])}] +
   [(["authored"] + [$operations[] | spx_readonly_identifier as $operation |
       ["frame", "input_dependence"][] | $operation + "-" + .])[] as $model |
     ["functions", "loops"][] as $kind |
     {step: ($model + "-" + $kind), arguments: [
       (if $kind == "functions" then "--show-goto-functions" else "--show-loops" end), "--json-ui", $model + ".goto"]}] +
   [$operations[] as $operation | ["frame", "input_dependence"][] as $kind |
     ($operation | spx_readonly_identifier) as $identifier |
     ($identifier + "-" + $kind) as $model |
     ((if $shared then "spx_shared_" elif $mutable then "spx_mutable_" else "spx_readonly_" end) + $kind + "_" + $identifier) as $entry |
     {step: ($model + "-compile"), arguments: ($prefix + [$model + ".c"] + $sources + ["--function", $entry, "-o", $model + ".goto"])},
     (if $kind == "frame" then {step: ($model + "-instrument"), arguments:
       ["--dfcc", $entry, "--enforce-contract", $certificate.operation_symbols[$operation], $model + ".goto", $model + "-checked.goto"]} else empty end),
     {step: ($model + "-check"), arguments: ([$model + (if $kind == "frame" then "-checked.goto" else ".goto" end),
       "--function", $entry] + $certificate.checker_options)}]) as $expected |
  ([.commands[] | {step, arguments: .command[1:]}] | sort_by(.step)) == ($expected | sort_by(.step)) and
  all(.checks[1:][];
    . as $check |
    any($certificate.commands[]; .step == (($check.operation_id | spx_readonly_identifier) + "-" + $check.kind + "-check")
      and .output_sha256 == $check.output_sha256));

def spx_readonly_commands: spx_memory_commands(false);

def spx_composed_memory_policy:
  . == "fixed-readable-source-contract-dependencies-v2" or . == "fixed-mutable-source-contract-dependencies-v2";
def spx_mutable_memory_policy:
  . == "fixed-mutable-source-contract-experiment-v1" or . == "fixed-mutable-source-contract-dependencies-v2";
def spx_readable_memory_policy:
  . == "fixed-readable-source-contract-experiment-v1" or . == "fixed-readable-source-contract-dependencies-v2";

def spx_memory_certificate($mutable; $ancestors):
  . as $certificate |
  (.policy | spx_composed_memory_policy) as $composed |
  (.policy | spx_shared_memory_policy) as $shared |
  (.operation_symbols | keys) as $operations |
  [.source_package.files[] | select(.path | endswith(".c")) | "inputs/" + .path] as $sources |
  ["--i386-win32", "-nostdinc", "-I", "include", "-I", "inputs"] as $prefix |
  keys == (["status", "authorizing", "policy", "model_policy", "checker_options",
    "interface_sha256", "interface_intent", "authored_goto_sha256", "source_package",
    "source_profile", "operation_symbols", "source_dependencies", "headers_sha256",
    "support_headers", "tools", "checks", "models", "inventories", "commands", "receipt_sha256"] +
    (if $shared then ["shared_contract"] elif $composed then ["summary_dependencies"] else [] end) | sort) and
  .status == "satisfied" and .authorizing == false and
  (.policy | if $mutable then spx_mutable_memory_policy or spx_shared_memory_policy else spx_readable_memory_policy end) and
  .model_policy == (if $shared then "fixed-shared-view-paired-service-trace-v1" elif $composed then
      (if $mutable then "fixed-mutable-paired-functional-dependencies-v2" else "fixed-readable-paired-functional-dependencies-v2" end)
    else (if $mutable then "fixed-mutable-view-paired-bytes-write-frame-v1" else "fixed-readable-view-paired-input-empty-frame-v1" end) end) and
  ($ancestors | index($certificate.interface_intent.id)) == null and
  (if $composed then
    (.summary_dependencies | type == "array" and length > 0) and
    ([.summary_dependencies[].symbol] == ([.summary_dependencies[].symbol] | sort | unique)) and
    all(.summary_dependencies[]; . as $dependency |
      keys == ["certificate", "operation_id", "symbol"] and
      .symbol == ("spx_component_logical_" + (.certificate.interface_intent.id | spx_readonly_identifier) + "_" + (.operation_id | spx_readonly_identifier)) and
      (.certificate.operation_symbols | has($dependency.operation_id)) and
      (.certificate | spx_memory_certificate((.policy | spx_mutable_memory_policy); $ancestors + [$certificate.interface_intent.id])))
   else true end) and
  ($operations | length > 0) and ($sources | length > 0) and
  (.checker_options[8] | type == "string" and test("^[0-9]+$") and (tonumber >= 2)) and
  .checker_options == (["--json-ui", "--trace", "--bounds-check", "--pointer-check",
    "--signed-overflow-check", "--undefined-shift-check", "--div-by-zero-check",
    "--unwind", .checker_options[8], "--unwinding-assertions", "--no-self-loops-to-assumptions",
    "--sat-solver", "cadical"] + (if $mutable then ["--object-bits", "9"] else [] end)) and
  all([.interface_sha256, .authored_goto_sha256, .headers_sha256, .receipt_sha256,
       .tools.goto_cc, .tools.goto_instrument, .tools.cbmc][]; spx_readonly_digest) and
  (.tools | keys == ["cbmc", "goto_cc", "goto_instrument"]) and
  .source_package.format == "spaghetti-extractor-component-source-package-v3" and
  .source_package.operation_symbols == .operation_symbols and
  .source_package.lift_unit_id == .interface_intent.id and
  .interface_intent.format == "spaghetti-extractor-component-interface-intent-v1" and
  .interface_intent.protocol.states == [.interface_intent.protocol.initial_state] and
  ([.interface_intent.operations[].id] | sort) == $operations and
  (if $shared then spx_shared_source_boundary else
  .interface_intent.state == [] and .interface_intent.effects == [] and .interface_intent.services == [] and
  all(.interface_intent.schema.signatures[] | .id as $signature |
    select(any($certificate.interface_intent.operations[]; .signature_id == $signature)) | .parameters[];
    .nullable == false and
    (if .interpretation == "view" then (.access == "read" or ($mutable and .access == "read_write")) and .extent.kind == "fixed" and
      (.extent.bytes | type == "number" and . == floor and . > 0 and . <= 4294967296)
     else .interpretation == "value" and .access == "none" end)) and
  any(.interface_intent.schema.signatures[] | .id as $signature |
    select(any($certificate.interface_intent.operations[]; .signature_id == $signature)) | .parameters[]; .interpretation == "view") and
  (if $mutable then
    any(.interface_intent.schema.signatures[] | .id as $signature |
      select(any($certificate.interface_intent.operations[]; .signature_id == $signature)) | .parameters[];
      .interpretation == "view" and .access == "read_write") and
    all(.interface_intent.operations[]; .signature_id as $signature |
      any($certificate.interface_intent.schema.signatures[];
        .id == $signature and any(.parameters[]; .interpretation == "view") and
        ([.parameters[] | select(.interpretation == "view") | .extent.bytes] | add) <= 1073741822))
   else true end) end) and
  .source_profile.status == "satisfied" and .source_profile.issues == [] and
  .source_profile.component_id == .interface_intent.id and
  .source_profile.profile_id == "portable-component-c11-cbmc-v1" and
  .source_profile.bindings.implementation_sha256 == .source_package.implementation_sha256 and
  .source_profile.policy == {compiler_semantics_assumed_correct: true, raw_machine_addresses_forbidden: true,
    undeclared_mutable_globals_forbidden: true, operator_behavior_examples_used: false} and
  (.source_profile.receipt_sha256 | spx_readonly_digest) and
  ([.source_dependencies[].source] | sort) == ($sources | sort) and
  all(.source_dependencies[];
    . as $dependency |
    ([.inputs[].path] == ([.inputs[].path] | sort | unique)) and
    any(.inputs[]; .path == $dependency.source) and
    all(.inputs[];
      . as $input |
      if .path | startswith("include/") then
        .sha256 == $certificate.support_headers[.path | ltrimstr("include/")]
      elif .path | startswith("inputs/") then
        any(($certificate.source_package.files + $certificate.source_package.shared_inputs)[];
          ("inputs/" + .path) == $input.path and .sha256 == $input.sha256)
      else false end)) and
  .checks[0].kind == "source_opacity" and .checks[0].status == "satisfied" and
  .checks[0].authorizing == false and .checks[0].policy == (if $shared then "typed-goto-opaque-shared-state-services-v1" elif $composed then "typed-goto-opaque-memory-dependencies-v2"
    else (if $mutable then "typed-goto-opaque-mutable-view-transport-v1" else "typed-goto-opaque-view-transport-v1" end) end) and
  (if $composed then .checks[0].dependency_symbols == [.summary_dependencies[].symbol] else true end) and
  .checks[0].issues == [] and .checks[0].operation_symbols == ([.operation_symbols[]] | sort) and
  ([.checks[1:][] | [.operation_id, .kind]] | sort) ==
    ([$operations[] as $operation | ["frame", "input_dependence"][] | [$operation, .]] | sort) and
  ([.models[] | [.operation_id, .kind]] | sort) ==
    ([$operations[] as $operation | ["frame", "input_dependence"][] | [$operation, .]] | sort) and
  all(.models[];
    . as $model |
    keys == ["checked_goto_sha256", "entry", "kind", "operation_id", "raw_goto_sha256", "source_sha256"] and
    .entry == ((if $shared then "spx_shared_" elif $mutable then "spx_mutable_" else "spx_readonly_" end) + .kind + "_" + (.operation_id | spx_readonly_identifier)) and
    all([.raw_goto_sha256, .checked_goto_sha256, .source_sha256][]; spx_readonly_digest) and
    (.kind == "frame" or .raw_goto_sha256 == .checked_goto_sha256) and
    any($certificate.checks[];
      .operation_id == $model.operation_id and .kind == $model.kind and .status == "satisfied" and
      .code == "cbmc_properties_satisfied" and (.properties == (.property_ids | length)) and
      (.property_ids == (.property_ids | sort | unique)) and
      ((.property_ids | index($model.entry + ".assertion.1")) != null) and
      (if $mutable and $model.kind == "input_dependence" then
        (.property_ids | index($model.entry + ".assertion.2")) != null else true end) and
      (if $shared then .property_ids as $ids |
        all((if $model.kind == "frame" then [2] else [3, 4] end)[]; . as $index |
          ($ids | index($model.entry + ".assertion." + ($index | tostring))) != null) and
        (if any($certificate.shared_contract.relation_intent.operations[];
            .operation_id == $model.operation_id and .requirements[0].expression.op == "and") then
          all((if $model.kind == "frame" then [3] else [5, 6] end)[]; . as $index |
            ($ids | index($model.entry + ".assertion." + ($index | tostring))) != null)
         else true end)
       else true end) and
      (.output_sha256 | spx_readonly_digest))) and
  ([.inventories[].step] | sort) == (["authored-functions", "authored-loops"] +
    [$operations[] | spx_readonly_identifier as $operation | ["frame", "input_dependence"][] as $kind |
      ["functions", "loops"][] | $operation + "-" + $kind + "-" + .] | sort) and
  all(.inventories[];
    keys == ["kind", "rows", "sha256", "step"] and
    (.sha256 | spx_readonly_digest) and (.rows | type == "array") and
    (.kind as $kind | .step | endswith("-" + $kind))) and
  any(.inventories[]; .step == "authored-functions" and .sha256 == $certificate.checks[0].inventory_sha256) and
  all(.commands[]; .cwd == "$MODEL_ROOT" and (.command | type == "array" and length > 0) and
    (.command[0] | type == "string") and
    (.output_sha256 | spx_readonly_digest) and
    (if .step | endswith("-check") then
      keys == ["command", "cwd", "output_sha256", "step"]
     else keys == ["command", "cwd", "exit_code", "output_sha256", "step"] and .exit_code == 0 end)) and
  spx_memory_commands($mutable);

def spx_memory_certificate($mutable): spx_memory_certificate($mutable; []);
def spx_readonly_certificate: spx_memory_certificate(false);
def spx_mutable_certificate: (.policy | spx_mutable_memory_policy) and spx_memory_certificate(true);
def spx_shared_certificate: (.policy | spx_shared_memory_policy) and spx_memory_certificate(true);

def spx_physical_memory_frames($field; $policy; $guard; $description; $entry):
  ($guard + ".assertion.1") as $property |
  .proof as $proof |
  all($proof.shards[];
    . as $shard |
    if has($field) then
      .[$field] as $frame |
      [$proof.models.operation_models[] | select(.operation_id == $shard.operation_id) |
        .obligation_models[] | select(.obligation_id == $shard.obligation_id)] as $models |
      ($models | length) == 1 and
      ($frame | keys == ["authorizing", "bindings", "command", "policy", "proof_function", "receipt_sha256", "result", "tools"]) and
      $frame.policy == $policy and $frame.authorizing == false and
      $shard.status == "satisfied" and $shard.nonvacuity.status == "satisfied" and
      $frame.proof_function == $models[0].proof_function and
      $frame.bindings == {proof_model_sha256: $models[0].proof_model_sha256,
        goto_model_sha256: $models[0].goto_model_sha256,
        property_checker_command_sha256: $models[0].property_checker_command_sha256} and
      $frame.tools == {cbmc_sha256: $proof.checker.cbmc_sha256, goto_cc_sha256: $proof.checker.goto_cc_sha256} and
      ($frame.receipt_sha256 | spx_readonly_digest) and
      $frame.command == (["$CBMC", "$GOTO_MODEL"] + [$models[0].property_checker_command.assertion_arguments[] |
        if . == "$PROPERTY_ID" then $property
        elif . == "$PROPERTY_FUNCTION" then $entry + $models[0].proof_function
        else . end]) and
      ([ $shard.partitioned_evidence.assertions[] |
        select(.description == $description) ] | length) == 1 and
      any($shard.partitioned_evidence.assertions[];
        .description == $description and
        .property_id == $property and
        .source_function == $guard) and
      ($frame.result.output_sha256 | spx_readonly_digest) and
      (if $frame.result.status == "satisfied" then
        $frame.result == {status: "satisfied", code: "cbmc_properties_satisfied", properties: 1,
          property_ids: [$property],
          output_sha256: $frame.result.output_sha256}
       else $frame.result.status == "violated" or $frame.result.status == "incomplete" end)
    else true end);

def spx_exact_memory_frames:
  spx_physical_memory_frames("exact_memory_frame"; "original-physical-empty-write-frame-v1";
    "__CPROVER_spx_exact_empty_memory_frame"; "spx-bisimulation-exact-empty-memory-frame";
    "__CPROVER_spx_exact_frame_");

def spx_exact_mutable_memory_frames:
  spx_physical_memory_frames("exact_mutable_memory_frame"; "original-physical-view-write-frame-v1";
    "__CPROVER_spx_exact_view_memory_frame"; "spx-bisimulation-exact-view-memory-frame";
    "__CPROVER_spx_exact_mutable_frame_");

def spx_exact_mutable_cut_frames:
  spx_physical_memory_frames("exact_mutable_cut_frame"; "original-fixed-writable-cut-transport-v1";
    "__CPROVER_spx_exact_writable_cut_frame"; "spx-bisimulation-exact-writable-cut-frame";
    "__CPROVER_spx_exact_mutable_cut_frame_");

def spx_mutable_machine_frame($field; $policy; $guard; $description; $entry):
  .proof as $proof |
  spx_physical_memory_frames($field; $policy; $guard; $description; $entry) and
  all($proof.shards[] | select(has($field));
    . as $shard |
    .mutable_entry_contract.result.status == "satisfied" and
    any($proof.models.operation_models[] | select(.operation_id == $shard.operation_id) |
        .obligation_models[]; .obligation_id == $shard.obligation_id and
      (.required_assertion_descriptions | index($description)) != null));

def spx_mutable_machine_frames:
  spx_mutable_machine_frame("exact_mutable_cut_machine_frame"; "original-identity-cut-machine-frame-wide-v1";
    "__CPROVER_spx_mutable_cut_machine_frame"; "spx-bisimulation-mutable-cut-machine-frame";
    "__CPROVER_spx_mutable_cut_machine_probe_") and
  spx_mutable_machine_frame("exact_mutable_exit_machine_frame"; "original-adapter-exit-machine-frame-wide-v1";
    "__CPROVER_spx_mutable_exit_machine_frame"; "spx-bisimulation-mutable-exit-machine-frame";
    "__CPROVER_spx_mutable_exit_machine_probe_");

def spx_clobber_fields:
  type == "array" and . == (sort | unique) and
  all(.[]; type == "string" and test("^(eax|ebx|ecx|edx|esi|edi|ebp|cf|zf|sf|of|pf|df|eflags)$"));

def spx_clobber_machine_frames:
  . as $root |
  all(.proof.models.operation_models[];
    . as $model | .operation_id as $operation |
    (.machine_clobbers // []) as $clobbers |
    (.machine_result_registers // []) as $results |
    [$root.proof_plan.operations[] | select(.operation_id == $operation)] as $planned |
    ($planned | length) == 1 and $clobbers == ($planned[0].machine_clobbers // []) and
    all(.obligation_models[]; .machine_clobbers == $model.machine_clobbers and
      .machine_result_registers == $model.machine_result_registers) and
    if ($clobbers | length) == 0 then
      all($root.proof.shards[] | select(.operation_id == $operation);
        (has("exact_mutable_cut_clobber_frame") or has("exact_mutable_exit_clobber_frame")) | not)
    else
      (($clobbers | join("_")) + "__result_" + (if ($results | length) == 0 then "none" else $results | join("_") end)) as $suffix |
      ($clobbers | spx_clobber_fields) and ($results | spx_clobber_fields) and
      all($results[]; test("^(eax|ebx|ecx|edx|esi|edi|ebp)$")) and
      (($clobbers - $results) == $clobbers) and
      all(["cut", "exit"][];
        . as $kind |
        ($root | .proof.shards |= map(select(.operation_id == $operation)) |
          spx_mutable_machine_frame("exact_mutable_" + $kind + "_clobber_frame";
            "original-declared-" + $kind + "-clobber-frame-wide-v1";
            "__CPROVER_spx_" + $kind + "_clobber_" + $suffix;
            "spx-bisimulation-mutable-" + $kind + "-clobber-frame:" + $suffix;
            "__CPROVER_spx_" + $kind + "_clobber_probe_" + $suffix + "_")))
    end);

def spx_has_clobber_frame($proof; $operation):
  ($operation.machine_clobbers // [] | length) > 0 and
  ($operation.obligation_models | length) > 0 and
  all($operation.obligation_models[]; .obligation_id as $id |
    any($proof.shards[]; .operation_id == $operation.operation_id and .obligation_id == $id and
      .exact_mutable_cut_clobber_frame.result.status == "satisfied" and
      .exact_mutable_exit_clobber_frame.result.status == "satisfied"));

def spx_private_ranges:
  . as $ranges | type == "array" and
  all(.[]; type == "object" and keys == ["bytes", "offset"] and
    (.offset | type == "number" and . == floor) and (.bytes | type == "number" and . == floor) and
    .bytes > 0 and .offset >= -1024 and .offset + .bytes <= 4096) and
  all(range(1; length); . as $i | $ranges[$i].offset >= $ranges[$i - 1].offset + $ranges[$i - 1].bytes);

def spx_private_suffix:
  map((if .offset < 0 then "m" + (-.offset | tostring) else "p" + (.offset | tostring) end) + "n" + (.bytes | tostring)) | join("_");

def spx_reference_origin_capacity:
  . as $root |
  all(.proof.models.operation_models[];
    . as $operation | has("reference_origin_capacity") as $present |
    .reference_origin_capacity as $capacity |
    [$root.proof_plan.operations[] | select(.operation_id == $operation.operation_id)] as $planned |
    ($planned | length) == 1 and
    (if $present then ($capacity | type == "number" and . == floor and . > 0 and . <= 4294967295) else true end) and
    all(($planned + .obligation_models)[];
      has("reference_origin_capacity") == $present and .reference_origin_capacity == $capacity) and
    (if $present then all(.obligation_models[];
      .required_assertion_descriptions | index("spx-bisimulation-reference-capacity:" + ($capacity | tostring)) != null)
     else true end));

def spx_image_private_access_frames:
  . as $root |
  all(.proof.models.operation_models[];
    . as $model | .operation_id as $operation | .private_stack_accesses as $ranges |
    [$root.proof_plan.operations[] | select(.operation_id == $operation)] as $planned |
    ($planned | length) == 1 and
    (has("private_stack_accesses") == ($planned[0] | has("private_stack_accesses"))) and
    $ranges == $planned[0].private_stack_accesses and
    (if has("private_stack_accesses") then ($ranges | spx_private_ranges) else true end) and
    all(.obligation_models[];
      has("private_stack_accesses") == ($model | has("private_stack_accesses")) and
      .private_stack_accesses == $ranges) and
    ($root | .proof.shards |= map(select(.operation_id == $operation)) |
      spx_mutable_machine_frame("image_private_access_frame";
        (if $ranges == null then "paired-image-private-access-frame-wide-v1"
         else "paired-image-private-access-footprint-v1" end);
        "__CPROVER_spx_image_private_access";
        ("spx-bisimulation-image-private-access-frame" +
          (if $ranges == null then "" elif ($ranges | length) == 0 then ":empty"
           else ":" + ($ranges | spx_private_suffix) end));
        "__CPROVER_spx_image_private_access_probe_")));

def spx_entry_domain($below):
  {minimum_esp: ([4, $below] | max), image_exclusion_below_esp: $below,
   image_exclusion_above_esp: "original-private-high-offset", private_low: "saturating-original-window",
   nonvacuity: "ordinary-domain-inclusion-v1"};

def spx_private_stack_frames:
  . as $root |
  all(.proof.models.operation_models[];
    . as $model | .operation_id as $operation | (.private_stack_writes // []) as $ranges |
    [$root.proof_plan.operations[] | select(.operation_id == $operation)] as $planned |
    ($planned | length) == 1 and $ranges == ($planned[0].private_stack_writes // []) and
    ($ranges | spx_private_ranges) and
    all(.obligation_models[]; .private_stack_writes == $model.private_stack_writes) and
    if ($ranges | length) == 0 then
      all($root.proof.shards[] | select(.operation_id == $operation);
        (has("exact_private_write_frame") or has("exact_private_cut_frame")) | not)
    else
      ($ranges | spx_private_suffix) as $suffix |
      all(["write", "cut"][]; . as $kind |
        ($root | .proof.shards |= map(select(.operation_id == $operation)) |
          spx_physical_memory_frames("exact_private_" + $kind + "_frame";
            "original-private-stack-" + $kind + "-frame-v1";
            "__CPROVER_spx_private_" + $kind + "_" + $suffix;
            "spx-bisimulation-private-" + $kind + "-frame:" + $suffix;
            "__CPROVER_spx_private_" + $kind + "_probe_" + $suffix + "_")))
    end);

def spx_has_private_frame($proof; $operation):
  ($operation.private_stack_writes // [] | length) > 0 and
  ($operation.obligation_models | length) > 0 and
  all($operation.obligation_models[]; .obligation_id as $id |
    any($proof.shards[]; .operation_id == $operation.operation_id and .obligation_id == $id and
      .mutable_entry_contract.policy == "paired-mutable-entry-private-write-frame-v1" and
      .mutable_entry_contract.result.status == "satisfied" and
      .exact_private_write_frame.result.status == "satisfied" and
      .exact_private_cut_frame.result.status == "satisfied"));

def spx_memory_entry_contracts($field; $policy; $prefix; $frames; $properties; $domain):
  .proof as $proof |
  all($proof.shards[];
    . as $shard |
    if has($field) then
      .[$field] as $entry |
      [$proof.models.operation_models[] | select(.operation_id == $shard.operation_id) |
        .obligation_models[] | select(.obligation_id == $shard.obligation_id)] as $models |
      ($models | length == 1) and ($models[0] as $model |
      ($entry | keys == ["authorizing", "bindings", "command", "domain", "policy", "proof_function", "receipt_sha256", "result", "tools"]) and
      ($entry.policy == $policy and $entry.authorizing == false) and
      ($entry.domain == $domain) and
      ($shard.status == "satisfied" and $shard.nonvacuity.status == "satisfied" and
        all($frames[]; . as $frame | $shard[$frame].result.status == "satisfied")) and
      ($entry.proof_function == $model.proof_function) and
      ($entry.bindings == {proof_model_sha256: $model.proof_model_sha256,
        goto_model_sha256: $model.goto_model_sha256,
        property_checker_command_sha256: $model.property_checker_command_sha256}) and
      ($entry.tools == {cbmc_sha256: $proof.checker.cbmc_sha256, goto_cc_sha256: $proof.checker.goto_cc_sha256}) and
      ($entry.command == (["$CBMC", "$GOTO_MODEL"] +
        [$model.property_checker_command.assertion_arguments[0:-2][] |
          select(. != "--no-standard-checks") |
          if . == "$PROPERTY_FUNCTION" then $prefix + $model.proof_function else . end] +
        ["--no-self-loops-to-assumptions"])) and
      ($entry.result.output_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      ($entry.receipt_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      (if $entry.result.status == "satisfied" then
        ($entry.result | keys == ["code", "output_sha256", "properties", "property_ids", "status"]) and
        ($entry.result.code == "cbmc_properties_satisfied") and
        ($entry.result.property_ids | type == "array") and
        ($entry.result.property_ids == ($entry.result.property_ids | sort | unique)) and
        (all($entry.result.property_ids[]; type == "string")) and
        ($entry.result.properties == ($entry.result.property_ids | length)) and
        (all($properties[]; . as $property | $entry.result.property_ids | index($property) != null)) and
        (all($shard.partitioned_evidence.assertions[]; .property_id as $id | $entry.result.property_ids | index($id) != null))
      else $entry.result.status == "violated" or $entry.result.status == "incomplete" end))
    else true end);

def spx_readable_entry_contracts:
  spx_memory_entry_contracts("readable_entry_contract"; "paired-readable-entry-empty-frame-v1";
    "__CPROVER_spx_readable_entry_"; ["exact_memory_frame"]; ["__CPROVER_spx_exact_empty_memory_frame.assertion.1"]; spx_entry_domain(0));

def spx_mutable_entry_contracts:
  . as $root | all(.proof.models.operation_models[];
    .operation_id as $operation | (.private_stack_writes // []) as $ranges |
    if ($ranges | length) == 0 then
      ($root | .proof.shards |= map(select(.operation_id == $operation)) |
        spx_memory_entry_contracts("mutable_entry_contract"; "paired-mutable-entry-fixed-write-frame-v1";
          "__CPROVER_spx_mutable_entry_"; ["exact_mutable_memory_frame", "exact_mutable_cut_frame"];
          ["__CPROVER_spx_exact_view_memory_frame.assertion.1", "__CPROVER_spx_exact_writable_cut_frame.assertion.1"]; spx_entry_domain(0)))
    else
      ($ranges | spx_private_suffix) as $suffix |
      ([0, -($ranges | map(.offset) | min)] | max) as $below |
      ($root | .proof.shards |= map(select(.operation_id == $operation)) |
        spx_memory_entry_contracts("mutable_entry_contract"; "paired-mutable-entry-private-write-frame-v1";
          "__CPROVER_spx_private_entry_" + $suffix + "_";
          ["exact_private_write_frame", "exact_mutable_cut_frame", "exact_private_cut_frame"];
          ["__CPROVER_spx_private_write_" + $suffix + ".assertion.1", "__CPROVER_spx_exact_writable_cut_frame.assertion.1",
           "__CPROVER_spx_private_cut_" + $suffix + ".assertion.1"]; spx_entry_domain($below)))
    end);

# Entry domains are derived from a checked leaf supplier. This stack premise
# does not establish reference transport, heap preservation, or activation.
def spx_entry_storage:
  if .kind == "view" or .kind == "bytes_view" then .base | spx_entry_storage
  elif .kind == "reference" or .kind == "resource" or .kind == "callback_handle" or .kind == "atomic_object" then
    .source | spx_entry_storage
  elif .kind == "service_output" then .fallback | spx_entry_storage
  else . end;
def spx_entry_stack_ends:
  if . == null then empty
  elif .kind == "record_view" then
    if (.fields | type == "array" and length > 0) then .fields[].projection | spx_entry_stack_ends
    else error("empty entry record") end
  else spx_entry_storage |
    if .kind != "stack" then empty
    elif (.offset | type == "number" and floor == . and . >= 0 and . <= 4096) and
         ((.width // 32) as $width | [8,16,32] | index($width)) != null then .offset + ((.width // 32) / 8) |
      if . <= 4096 then . else error("entry stack extent") end
    else error("entry stack storage") end
  end;
def spx_qualified_source_dependencies:
  . as $proof | .models.source_summary_contracts.certificate as $certificate |
  if ($certificate.policy | spx_composed_memory_policy) then
    ([.models.connected_components[].component_id] | length == (unique | length)) and
    all($certificate.summary_dependencies[]; . as $dependency |
      any($proof.models.connected_components[];
        .component_id == $dependency.certificate.interface_intent.id and
        (.summary_strategy == "image-readable-body-free-v1" or .summary_strategy == "image-mutable-body-free-v1") and
        .entry_contract.proof_system.proof.status == "satisfied" and
        .entry_contract.proof_system.proof.receipt_sha256 == .proof_receipt_sha256 and
        .entry_contract.proof_system.proof.models.source_summary_contracts.certificate == $dependency.certificate))
  else true end;

def spx_memory_dependency_tree($ancestors):
  . as $proof |
  ($ancestors | index($proof.component_id)) == null and
  (if (.models.connected_components | length) > 0 then
    (.models.source_summary_contracts.certificate.policy | spx_composed_memory_policy) and
    spx_qualified_source_dependencies and
    all(.models.connected_components[];
      (.summary_strategy == "image-readable-body-free-v1" or .summary_strategy == "image-mutable-body-free-v1") and
      .entry_contract.proof_system.proof.component_id == .component_id and
      (.entry_contract.proof_system.proof | spx_memory_dependency_tree($ancestors + [$proof.component_id])))
   else true end);

def spx_call_entry_contracts(validate):
  .proof as $parent |
  (all($parent.models.connected_components[];
    .summary_strategy != "connected-replay-v1" or .entry_contract != null)) as $replay_premises |
  ([$parent.models.connected_components[] | select(.entry_contract != null) |
      .entry_contract as $entry |
      .component_id as $component | .summary_strategy as $strategy | .entry_contract.operations[] | .operation_id as $operation |
      ((if $strategy == "connected-replay-v1" then "stack-entry", "machine-state" else "stack-entry" end),
       (if $entry.policy == "checked-mutable-callee-stack-entry-v1" and
          any($entry.proof_system.proof.models.operation_models[]; .operation_id == $operation and
            spx_has_clobber_frame($entry.proof_system.proof; .)) then "clobber-state" else empty end),
       (if $entry.policy == "checked-mutable-callee-stack-entry-v1" and
          any($entry.proof_system.proof.models.operation_models[]; .operation_id == $operation and
            spx_has_private_frame($entry.proof_system.proof; .)) then "private-poststate" else empty end)) |
      "spx-bisimulation-connected-callee-" + . + ":" + $component + ":" + $operation] | sort | unique) as $guards |
  $replay_premises and all($parent.models.operation_models[].obligation_models[];
    ([.required_assertion_descriptions[] | select(startswith("spx-bisimulation-connected-callee-stack-entry:") or
      startswith("spx-bisimulation-connected-callee-machine-state:") or
      startswith("spx-bisimulation-connected-callee-clobber-state:") or
      startswith("spx-bisimulation-connected-callee-private-poststate:"))] | sort | unique) == $guards) and
  all($parent.models.connected_components[] | select(.entry_contract != null);
    . as $connected | .entry_contract as $entry |
    $entry.proof_system.proof as $child |
    $entry.binding_intent as $binding |
    ($child.models.source_summary_contracts.certificate.policy | spx_mutable_memory_policy or spx_shared_memory_policy) as $mutable |
    ($entry | type == "object" and keys == ["authorizing", "binding_intent", "operations", "policy", "proof_system", "receipt_sha256"]) and
    ($child.models.source_summary_contracts.certificate.policy as $policy |
      (($policy | spx_readable_memory_policy) and $entry.policy == "checked-readable-callee-stack-entry-v1") or
      (($policy | spx_mutable_memory_policy or spx_shared_memory_policy) and $entry.policy == "checked-mutable-callee-stack-entry-v1")) and
    $entry.authorizing == false and
    ($entry.receipt_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    ($entry.proof_system | type == "object" and keys == ["exact_c_slice", "proof", "proof_plan"]) and
    ($child | spx_memory_dependency_tree([])) and
    (if ($child.models.connected_components | length) > 0 then
      ($connected.summary_strategy == "image-readable-body-free-v1" or $connected.summary_strategy == "image-mutable-body-free-v1") and
      ([$child | recurse(.models.connected_components[]?.entry_contract.proof_system.proof) | select(. != null) |
        {component_id, receipt_sha256}] | group_by(.component_id) | all(.[]; ([.[].receipt_sha256] | unique | length) == 1))
     else true end) and
    ($entry.proof_system | validate) and
    $child.status == "satisfied" and $child.activation_authorized == true and
    $binding.component_id == $child.component_id and $child.component_id == $connected.component_id and
    $binding.intent_sha256 == $child.world.bindings.binding_intent_sha256 and
    $binding.intent_sha256 == $connected.binding_intent_sha256 and
    $child.receipt_sha256 == $connected.proof_receipt_sha256 and
    (all(["implementation_sha256", "source_profile_sha256", "machine_overlay_sha256", "proof_overlay_sha256"][];
      . as $key | $child.models[$key] == $connected[$key])) and
    ([$binding.operations[].id] | sort) == ([$child.models.operation_models[].operation_id] | sort) and
    all($binding.operations[]; . as $operation |
      all($child.models.operation_models[] | select(.operation_id == $operation.id and (.machine_clobbers // [] | length) > 0);
        .machine_result_registers == ([$operation.machine_projection.operation.results[].projection |
          (if .kind == "view" and .at == "exit" then .base else . end) |
          if .kind == "register" and .width == 32 and .at == "exit" and
            (.register | test("^(eax|ebx|ecx|edx|esi|edi|ebp)$")) then .register else error("clobber result projection") end] | sort | unique))) and
    $entry.operations == [ $binding.operations[] | . as $operation |
      ($child.models.operation_models[] | select(.operation_id == $operation.id)) as $model |
      (if ($model.obligation_models | length) == 0 then error("empty supplier segments") else
        all($model.obligation_models[]; .obligation_id as $id |
          any($child.shards[]; .operation_id == $operation.id and .obligation_id == $id and
            (if $mutable then .mutable_entry_contract else .readable_entry_contract end).result.status == "satisfied")) end) as $wide |
      {operation_id: $operation.id, entry_rvas: $operation.entry_rvas,
       domain: (if $wide then (if $mutable then "mutable-wide" else "readable-wide" end) else "ordinary" end),
       private_high_offset: ([4096, ($operation.machine_projection.operation |
         (.parameters[].projection, .state[].entry) | spx_entry_stack_ends)] | max),
       machine_image: $model.machine_image} ] and
    (all($entry.operations[]; .operation_id as $id |
      all($parent.models.operation_models[].obligation_models[];
        (.required_assertion_descriptions | index(
          "spx-bisimulation-connected-callee-stack-entry:" + $connected.component_id + ":" + $id)) != null)))
  );

def spx_connected_readable_transports:
  .proof as $proof |
  ([$proof.models.connected_components[] | select(.readable_transport_policy != null) |
    .component_id as $component | .entry_contract.operations[] |
    .operation_id as $operation |
    "spx-bisimulation-connected-summary-readable-runtime",
    (("view", "domain", "transport") | "spx-bisimulation-connected-summary-readable-" + . + ":" + $component + ":" + $operation)
  ] + (if any($proof.models.connected_components[]; .summary_strategy == "image-readable-body-free-v1")
        then ["spx-bisimulation-connected-summary-readable-empty-allocation-world"] else [] end) | sort | unique) as $guards |
  (all($proof.models.connected_components[];
    .readable_transport_policy == null or
    (.readable_transport_policy == "canonical-readable-callee-transport-v1" and .entry_contract != null))) and
  (all($proof.models.connected_components[] | select(.readable_transport_policy != null);
    .proof_overlay_sha256 as $overlay |
    all($proof.models.operation_models[].obligation_models[];
      ([.proof_inputs[] | select(.role == "connected_provider_c" and .sha256 == $overlay)] | length) == 1))) and
  all($proof.models.operation_models[].obligation_models[];
    ([.required_assertion_descriptions[] | select(startswith("spx-bisimulation-connected-summary-readable-"))] | sort | unique) == $guards);

def spx_connected_mutable_transports:
  .proof as $proof |
  (all($proof.models.connected_components[];
    if .entry_contract.policy == "checked-mutable-callee-stack-entry-v1" then
      .mutable_transport_policy == "canonical-mutable-callee-transport-v1" and .readable_transport_policy == null
    else .mutable_transport_policy == null end)) as $policies |
  ([$proof.models.connected_components[] | select(.mutable_transport_policy != null) |
    .component_id as $component | .summary_strategy as $strategy | .entry_contract.operations[] | .operation_id as $operation |
    (if $strategy == "image-shared-framed-body-free-v1" then "spx-bisimulation-connected-summary-framed-runtime"
     else "spx-bisimulation-connected-summary-mutable-runtime" end),
    (if $strategy == "image-mutable-body-free-v1" then "spx-bisimulation-connected-summary-mutable-empty-allocation-world",
      ("spx-bisimulation-connected-summary-mutable-post-memory:" + $component + ":" + $operation)
     elif $strategy == "image-shared-body-free-v1" then "spx-bisimulation-connected-summary-mutable-empty-allocation-world" else empty end),
    (("view", "domain", "transport") | "spx-bisimulation-connected-summary-mutable-" + . + ":" + $component + ":" + $operation)
  ] | sort | unique) as $guards |
  $policies and
  (all($proof.models.connected_components[] | select(.mutable_transport_policy != null);
    .proof_overlay_sha256 as $overlay |
    all($proof.models.operation_models[].obligation_models[];
      ([.proof_inputs[] | select(.role == "connected_provider_c" and .sha256 == $overlay)] | length) == 1))) and
  all($proof.models.operation_models[].obligation_models[];
    ([.required_assertion_descriptions[] | select(startswith("spx-bisimulation-connected-summary-mutable-"))] | sort | unique) == $guards);

def spx_image_memory_composition($mutable):
  (if $mutable then "mutable" else "readable" end) as $flavor |
  ("image-" + $flavor + "-body-free-v1") as $strategy |
  ("spx-bisimulation-connected-" + $flavor + "-entry:") as $prefix |
  .proof.models as $parent |
  ([$parent.connected_components[] | select(.summary_strategy == $strategy) |
    .component_id as $component | .entry_contract.operations[] |
    $prefix + $component + ":" + .operation_id] | sort | unique) as $guards |
  all($parent.operation_models[].obligation_models[];
    ([.required_assertion_descriptions[] | select(startswith($prefix))] | sort | unique) == $guards) and
  all($parent.connected_components[] | select(.summary_strategy == $strategy);
    . as $connected | .entry_contract as $entry | $entry.proof_system.proof as $child |
    $child.models as $models | $models.reference_authority as $authority |
    $models.source_summary_contracts.certificate as $certificate |
    .source_summary_certificate == null and
    (if $mutable then .mutable_transport_policy == "canonical-mutable-callee-transport-v1" else .readable_transport_policy == "canonical-readable-callee-transport-v1" end) and
    $authority == $parent.reference_authority and ($authority.rules | length) > 0 and
    $authority.data_export_anchors == [] and
    all($authority.rules[]; .kind == "image" and .lifetime == "image" and .locator.kind == "image_rva" and (.extent_mode // "fixed") == "fixed") and
    all(($models, $parent); .reference_allocation_requirements == null and .reference_runtime_inventory == null) and
    ($certificate.policy | if $flavor == "mutable" then spx_mutable_memory_policy else spx_readable_memory_policy end) and $certificate.status == "satisfied" and
    ($certificate | spx_memory_certificate($mutable)) and
    all($entry.operations[]; .domain == ($flavor + "-wide")) and
    all($models.operation_models[];
      . as $operation |
      ($mutable and spx_has_clobber_frame($child; $operation)) as $clobbered |
      all($parent.operation_models[]; .machine_image == $operation.machine_image) and
      all(.obligation_models[]; . as $segment |
        .finite_control_route_inventory_sha256 == null and
        all((if $clobbered then empty elif $mutable then "spx-bisimulation-mutable-cut-machine-frame", "spx-bisimulation-mutable-exit-machine-frame"
             else "spx-bisimulation-readable-machine-state", "spx-bisimulation-readable-cut-machine-state" end);
          . as $guard | ($segment.required_assertion_descriptions | index($guard)) != null) and
        any($child.shards[]; .operation_id == $operation.operation_id and .obligation_id == $segment.obligation_id and
          (if $mutable then
            .mutable_entry_contract.result.status == "satisfied" and
            (if $clobbered then true else .exact_mutable_cut_machine_frame.result.status == "satisfied" and
            .exact_mutable_exit_machine_frame.result.status == "satisfied" end)
          else
            .readable_entry_contract.result.status == "satisfied" and
            (.readable_entry_contract.result.property_ids as $ids |
              all(("__CPROVER_spx_readable_machine_state.assertion.1", "__CPROVER_spx_readable_cut_machine_state.assertion.1");
                . as $id | ($ids | index($id)) != null)) and
            (.partitioned_evidence.assertions as $assertions |
              all((["__CPROVER_spx_readable_machine_state", "spx-bisimulation-readable-machine-state"],
                   ["__CPROVER_spx_readable_cut_machine_state", "spx-bisimulation-readable-cut-machine-state"]);
                . as $guard | any($assertions[]; .property_id == ($guard[0] + ".assertion.1") and
                  .source_function == $guard[0] and .description == $guard[1])))
          end)))) and
    all($entry.binding_intent.operations[]; . as $binding |
      ($certificate.interface_intent.operations[] | select(.id == $binding.id)) as $operation |
      ($certificate.interface_intent.schema.signatures[] | select(.id == $operation.signature_id)) as $signature |
      all($signature.parameters[] | select(.interpretation == "view"); . as $value |
        (.access == "read" or ($mutable and .access == "read_write")) and .nullable == false and .extent.kind == "fixed" and .extent.bytes > 0 and .extent.bytes <= 4294967295 and
        any($binding.machine_projection.operation.parameters[]; .id == $value.id and .projection.kind == "view" and
          .projection.requested_extent.kind == "constant" and .projection.requested_extent.value == $value.extent.bytes and
          .projection.extent.kind == "constant" and .projection.extent.value == $value.extent.bytes and
          (.projection.authority.id as $origin |
            ([$binding.object_authority_selectors[] | select(.authority_id == $origin) | .rule_id]) as $selectors |
            (if ($selectors | length) == 0 and ($authority.rules | length) == 1 then $authority.rules[0].id
             elif ($selectors | length) == 1 then $selectors[0] else null end) as $selector |
            any($authority.rules[]; .id == $selector and (if $mutable and $value.access == "read_write" then (.permissions % 4) == 3 else (.permissions % 2) == 1 end)))))));

def spx_image_readable_composition: spx_image_memory_composition(false) and spx_image_memory_composition(true);

def spx_shared_state_binding($value):
  .entry.kind == "view" and .entry.at == "entry" and .exit == (.entry + {at: "exit"}) and
  .entry.extent == {kind: "constant", width: 32, value: $value.extent.bytes} and
  .entry.requested_extent == .entry.extent and .entry.base.kind == "constant" and .entry.base.width == 32 and
  (.entry.base.value | type == "number" and . == floor and . > 0 and . <= (4294967296 - $value.extent.bytes)) and
  .entry.authority.kind == "image" and .entry.authority.lifetime == "image";

def spx_shared_result_binding($interface; $binding):
  . as $post |
  (if $post.op == "and" then $post.args[0].args else $post.args end) as $terms |
  first($terms[] | select(.attributes.path.root == "state")).attributes.path.id as $state_id |
  first($terms[] | select(.attributes.path.root == "result")).attributes.path.id as $result_id |
  first($binding.machine_projection.operation.state[] | select(.id == $state_id)) as $state |
  first($binding.machine_projection.operation.results[] | select(.id == $result_id)).projection as $result |
  (if $post.op == "and" then any($interface.state[].value;
    .id == $state_id and .access == "read_write") else true end) and
  $result == ($state.entry + {at: "exit", base: {kind: "register", register: "eax", width: 32, at: "exit"}});

def spx_image_authority_extension($supplier; $parent):
  ($parent | type == "object") and $parent.data_export_anchors == [] and
  all(["format", "machine_backend", "bindings"][]; . as $key | $parent[$key] == $supplier[$key]) and
  all($supplier.rules[]; . as $rule | any($parent.rules[]; . == $rule)) and
  all($parent.rules[]; . as $rule |
    if any($supplier.rules[]; .id == $rule.id) then true else
      .kind == "external" and .lifetime == "allocation" and .locator.kind == "external_allocation" and
      all($supplier.rules[]; .domain != $rule.domain or .object != $rule.object)
    end);

def spx_shared_strategy:
  . == "image-shared-body-free-v1" or . == "image-shared-framed-body-free-v1";

def spx_image_shared_composition:
  .proof.models as $parent |
  ([$parent.connected_components[] | select(.summary_strategy | spx_shared_strategy) |
    .component_id as $component | .entry_contract.operations[] |
    "spx-bisimulation-connected-shared-entry:" + $component + ":" + .operation_id] | sort | unique) as $guards |
  all($parent.operation_models[].obligation_models[];
    ([.required_assertion_descriptions[] | select(startswith("spx-bisimulation-connected-shared-entry:"))] | sort | unique) == $guards) and
  all($parent.connected_components[] | select(.summary_strategy | spx_shared_strategy);
    . as $connected | .entry_contract as $entry | $entry.proof_system.proof as $child |
    ($connected.summary_strategy == "image-shared-framed-body-free-v1") as $framed |
    $child.models as $models | $models.reference_authority as $authority |
    $models.source_summary_contracts.certificate as $certificate |
    $certificate.interface_intent as $interface |
    .source_summary_certificate == null and .mutable_transport_policy == "canonical-mutable-callee-transport-v1" and
    $models.connected_components == [] and ($certificate | spx_shared_certificate) and
    ($parent.operation_models | length) > 0 and
    $certificate.interface_sha256 == $child.world.bindings.interface_sha256 and
    $interface.schema.schema_sha256 == $child.world.bindings.schema_sha256 and
    (if $framed then spx_image_authority_extension($authority; $parent.reference_authority)
     else $authority == $parent.reference_authority end) and
    ($authority.rules | length) > 0 and $authority.data_export_anchors == [] and
    all($authority.rules[]; .kind == "image" and .lifetime == "image" and .locator.kind == "image_rva" and (.extent_mode // "fixed") == "fixed") and
    $models.reference_allocation_requirements == null and $models.reference_runtime_inventory == null and
    $parent.reference_runtime_inventory == null and ($framed or $parent.reference_allocation_requirements == null) and
    ($parent.reference_allocation_requirements == null or ($parent.reference_allocation_requirements | type == "array")) and
    $models.trusted_adapter_lowering.status == "complete" and
    $certificate.shared_contract.service_contracts == ([$models.trusted_adapter_lowering.adapter_plan[].checked_binding |
      {service_id, abi_sha256, external_contract_identity_sha256, external_effect_contract}] | sort_by(.service_id) | unique) and
    all($entry.operations[]; .domain == "mutable-wide") and
    all($models.operation_models[]; . as $operation |
      (if $framed and has("private_stack_accesses") then (.obligation_models | length) == 1 else true end) and
      all($parent.operation_models[]; .machine_image == $operation.machine_image) and
      (spx_has_clobber_frame($child; .) or
        all(.obligation_models[]; .obligation_id as $id |
          any($child.shards[]; .operation_id == $operation.operation_id and .obligation_id == $id and
            .exact_mutable_cut_machine_frame.result.status == "satisfied" and
            .exact_mutable_exit_machine_frame.result.status == "satisfied"))) and
      all(.obligation_models[]; . as $segment | .finite_control_route_inventory_sha256 == null and
        any($child.shards[]; .operation_id == $operation.operation_id and .obligation_id == $segment.obligation_id and
          .mutable_entry_contract.result.status == "satisfied" and
          (if $framed then .image_private_access_frame.result.status == "satisfied" else true end)))) and
    all($entry.binding_intent.operations[]; . as $binding |
      first($models.operation_models[] | select(.operation_id == $binding.id)).machine_image.preferred_base as $image_base |
      all($interface.state[].value; . as $value |
        any($binding.machine_projection.operation.state[]; . as $state |
          .id == $value.id and spx_shared_state_binding($value) and
          (.entry.authority.id as $origin |
            ([$binding.object_authority_selectors[] | select(.authority_id == $origin) | .rule_id]) as $selectors |
            (if ($selectors | length) == 0 and ($authority.rules | length) == 1 then $authority.rules[0].id
             elif ($selectors | length) == 1 then $selectors[0] else null end) as $selector |
            any($authority.rules[]; ($image_base + .locator.rva) as $base | .id == $selector and
              (if $value.access == "read_write" then (.permissions % 4) == 3 else (.permissions % 2) == 1 end) and
              $state.entry.base.value >= $base and $state.entry.base.value + $value.extent.bytes <= $base + .extent and
              ($state.entry.base.value == $base or .interior_pointers == true))))) and
      all($certificate.shared_contract.relation_intent.operations[] | select(.operation_id == $binding.id);
        .requirements[0].expression | spx_shared_result_binding($interface; $binding))));

# This projection grants no supplier authority. The recursive entry reader and
# physical-frame readers still bind the complete retained evidence.
def spx_allocation_preserving_dependencies($models):
  all(($models.connected_components // [])[];
    .summary_strategy == "scalar-body-free-v1" or .summary_strategy == "image-shared-framed-body-free-v1") and
  (if any(($models.connected_components // [])[]; .summary_strategy == "image-shared-framed-body-free-v1") then
    ({proof: {models: $models}} | spx_image_shared_composition) and
    all($models.connected_components[] | select(.summary_strategy == "image-shared-framed-body-free-v1");
      .entry_contract as $entry |
      $entry.binding_intent.intent_sha256 == $entry.proof_system.proof.world.bindings.binding_intent_sha256 and
      ($entry.proof_system | spx_image_private_access_frames))
   else true end);

def spx_local_lifetime_adapter($models):
  .checked_binding as $binding |
  $binding.external_effect_contract as $effect |
  ($binding.argument_offsets | length) as $words |
  ($models.reference_allocation_requirements | type) == "array" and
  spx_allocation_preserving_dependencies($models) and
  $effect.memory_effect == "none" and $effect.memory_footprints == [] and
  $effect.callback_effect == "none" and $effect.external_service_protocol == null and
  $effect.out_pointer_relations == [] and $effect.out_interface_relations == [] and
  ($words > 0 and $words <= 32) and
  (.proof_call_specs | type == "array" and length > 0) and
  all(.proof_call_specs[];
    . as $spec | .checked_external_contract as $site |
    .event_kind == "SPX_CALL_EXTERNAL_IMPORT" and .compare_target == false and
    .external_effect_contract == $effect and
    .external_contract_identity_sha256 == $binding.external_contract_identity_sha256 and
    .offsets == $binding.argument_offsets and .raw_indices == [range(0; $words)] and
    .cell_inputs == [] and .outputs == [] and
    .callee_cleanup == (if $binding.abi_template == "pe32-stdcall-v1" then 4 * $words else 0 end) and
    $site.format == "spaghetti-extractor-candidate-external-site-contract-v3" and
    $site.identity.kind == "import" and $site.transfer_kind == "call" and
    $site.disposition == "returns_here" and $site.profile_disposition == "returns" and
    $site.callback_adapter == null and $site.argument_base_offset == 0 and
    $site.abi_template == $binding.abi_template and
    ($site.abi_template == "pe32-stdcall-v1" or $site.abi_template == "pe32-cdecl-v1") and
    $site.arity == {kind: "fixed", words: $words} and
    ($site.arguments | type == "array" and length == $words) and
    $site.stack_arguments == [range(0; $words) | . as $index |
      {index: $index, offset: $spec.offsets[$index], width: 4, value: $site.arguments[$index]}] and
    ($site | spx_lifetime_site_effect) == $effect and
    any($binding.events[]; .instruction_rva == $spec.instruction_rva and
      .event_index == $spec.event_index and .return_rva == $spec.return_rva and
      .checked_external_contract == $site)) and
  (if $effect.world_effect == "dynamicRanges" then
    ($effect | spx_local_allocation_effect) as $allocation |
    ($effect.result_register_relations | length) == 1 and
    $effect.result_register_relations[0].relation == "dynamic_range_base" and
    $effect.world_effect_argument == null and $effect.world_effect_release == null and
    ($allocation | spx_allocation_effect($words)) and
    ([$models.reference_allocation_requirements[] |
      select(.contract_identity_sha256 == $binding.external_contract_identity_sha256 and
             .argument_words == $words and .effect == $allocation)] | length) == 1
   elif $effect.world_effect == "dynamicRangeRelease" then
    ($effect.world_effect_argument | spx_allocation_argument($words)) and
    ($effect.result_register_relations == [] or
     $effect.result_register_relations == [{register: "eax", relation: "related_word"}]) and
    ($effect.world_effect_release | . as $release |
      keys == ["argument_equals", "ownership", "success"] and
      (.success == "always" or .success == "eax_zero" or .success == "eax_nonzero") and
      (.ownership | keys == ["family", "owner_argument"] and
        (.owner_argument == null or (.owner_argument | spx_allocation_argument($words)))) and
      (.argument_equals | type == "array") and
      ([.argument_equals[].argument_index] == ([.argument_equals[].argument_index] | sort | unique)) and
      all(.argument_equals[]; keys == ["argument_index", "value"] and
        (.argument_index | spx_allocation_argument($words)) and (.value | spx_allocation_u32)) and
      any($models.reference_allocation_requirements[]; .effect.ownership.family == $release.ownership.family))
   else false end);

def spx_readable_range_word:
  type == "number" and floor == . and . >= 0 and . <= 4294967295;

def spx_readable_range_guards($models):
  .checked_binding.external_effect_contract as $effect |
  if $effect.memory_effect != "readOnly" or
      ($effect | has("memory_footprints") | not) or $effect.memory_footprints == [] then true
  else
    ($effect.memory_footprints | type == "array" and length > 0) and
    ($effect.world_effect == "none" or $effect.world_effect == "opaqueResources") and
    ($models.operation_models | type == "array" and length > 0) and
    (.proof_call_specs | type == "array" and length > 0) and
    all(.proof_call_specs[]; . as $spec |
      .external_effect_contract == $effect and .outputs == [] and .cell_inputs == [] and
      all($effect.memory_footprints | to_entries[]; .key as $index | .value as $range |
        ($range | keys == ["access", "base_argument", "nullable", "offset", "size"] and
          .access == "read" and (.nullable | type == "boolean") and
          (.offset | spx_readable_range_word) and (.base_argument | spx_readable_range_word)) and
        ($spec.raw_indices | index($range.base_argument)) != null and
        ($range.size |
          if .kind == "fixed" then
            keys == ["bytes", "kind"] and (.bytes | spx_readable_range_word and . > 0)
          elif .kind == "argument" then
            keys == ["argument", "kind", "scale"] and
            (.argument | spx_readable_range_word) and (.scale | spx_readable_range_word and . > 0) and
            (.argument as $argument | ($spec.raw_indices | index($argument)) != null)
          elif .kind == "bounded_terminated" then
            keys == ["kind", "max_units", "sentinel", "source_argument", "source_offset", "unit_bytes"] and
            .unit_bytes == 1 and .sentinel == [0] and
            (.source_offset | spx_readable_range_word) and (.max_units | spx_readable_range_word and . > 0) and
            (.source_argument | spx_readable_range_word) and
            (.source_argument as $argument | ($spec.raw_indices | index($argument)) != null)
          else false end) and
        ("spx-bisimulation-call-readable-range:\($spec.spec_id):\($index)" as $description |
          all($models.operation_models[];
            (.obligation_models | type == "array" and length > 0) and
            all(.obligation_models[];
              (.required_assertion_descriptions | type == "array") and
              (.required_assertion_descriptions | index($description)) != null)))))
  end;

def spx_declared_external_range_effects($models):
  if .provider_kind != .checked_binding.provider_kind then false
  elif .provider_kind != "external_call" then true else
    .checked_binding.external_effect_contract as $effect |
    .checked_binding.external_contract_identity_sha256 as $identity |
    (.checked_binding.argument_offsets | length) as $words |
    (.checked_binding | spx_typed_external_target_supported) and
    spx_readable_range_guards($models) and
    ($effect | spx_terminated_read_effect($words)) and
    ($effect | spx_terminated_write_effect($words)) and
    ($identity | type == "string" and test("^[0-9a-f]{64}$")) and
    (all(.proof_call_specs[]; .external_contract_identity_sha256 == $identity)) and
    ($effect | type) == "object" and
    ($effect.memory_effect | type) == "string" and
    ($effect.memory_effect | test("\\S")) and
    ($effect.world_effect | type) == "string" and
    ($effect.world_effect | test("\\S")) and
    (if $effect.world_effect == "dynamicRanges" or $effect.world_effect == "dynamicRangeRelease" then
      spx_local_lifetime_adapter($models)
    else
    ($effect.world_effect != "dynamicRanges") and
    ($effect.world_effect != "dynamicRangeRelease") and
    ($effect.world_effect_argument == null) and
    ($effect.world_effect_release == null) and
    (($effect | has("out_pointer_relations") | not) or $effect.out_pointer_relations == []) and
    (($effect | has("result_register_relations") | not) or
      ($effect.result_register_relations | type) == "array") and
    (all(($effect.result_register_relations // [])[];
      type == "object" and .relation != "dynamic_range_base" and .ownership == null)) and
    (all(.proof_call_specs[]; .external_effect_contract == $effect)) end)
  end;

def spx_consumed_scalar_dependency:
  {component_id, binding_intent_sha256, summary_strategy, machine_overlay_sha256,
   proof_overlay_sha256, trusted_adapter_lowering_receipt_sha256, machine_overlay_entries_sha256,
   source_contract: (.source_summary_certificate |
     {strategy, interface_sha256, headers_sha256, operation_symbols,
      postconditions: [.postconditions[] | {operation_id, id, signature, expression}]})};

def spx_reusable_proof_inputs($checker):
  . as $models |
  if has("reusable_inputs") then
    .reusable_inputs as $record |
    ($record | type == "object" and keys == ["artifacts", "input_sha256", "inputs", "policy"]) and
    $record.policy == "unchanged-local-inputs-scalar-contract-proof-reuse-v1" and
    ($record.input_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    ($record.inputs | type == "object" and keys == ["caller", "dependencies", "extra", "generator_sha256"]) and
    ($record.inputs.generator_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    ($record.inputs.extra | type == "object") and
    (all(["cbmc_sha256", "goto_cc_sha256", "smt_solver"][]; . as $key |
      $record.inputs.extra[$key] == $checker[$key])) and
    $record.inputs.caller == ($models | {interface_sha256, semantic_contract_sha256,
      source_profile_sha256, implementation_sha256, bisimulation_intent_sha256,
      exact_c_slice_sha256, machine_overlay_sha256, proof_overlay_sha256,
      trusted_adapter_lowering, reference_authority}) and
    (all($models.connected_components[]; .summary_strategy == "scalar-body-free-v1" and
      .entry_contract == null and .readable_transport_policy == null and
      (has("assurance") or has("mutable_transport_policy") | not))) and
    $record.inputs.dependencies == [$models.connected_components[] | spx_consumed_scalar_dependency] and
    ($record.artifacts | type == "object" and length > 0 and
      all(to_entries[]; (.key | test("^[^/]+(/[^/]+)*$") and
        (split("/") | all(. != "." and . != ".."))) and
        (.value | type == "string" and test("^[0-9a-f]{64}$")))) and
    $record.artifacts["proof-reuse-inputs.json"] == $record.input_sha256 and
    all($models.operation_models[].obligation_models[];
      [.proof_inputs[] | select(.role == "proof_reuse_inputs")] ==
        [{role: "proof_reuse_inputs", sha256: $record.input_sha256}])
  else all($models.operation_models[].obligation_models[].proof_inputs[]; .role != "proof_reuse_inputs") end;

def spx_completion_sat_arguments:
  . as $args | (index("--external-smt2-solver")) as $solver |
  if $solver == null then . else
    [to_entries[] | select(.key != $solver and .key != ($solver + 1)) | .value |
      select(. != "--smt2" and . != "--z3" and . != "--no-array-field-sensitivity")] +
    ["--sat-solver", "cadical"] end;

def spx_call_completion_lemmas:
  try (
    .proof_plan.operations as $plans | .proof.models.connected_components as $suppliers |
    all(.proof.models.operation_models[];
      . as $operation |
      [$plans[] | select(.operation_id == $operation.operation_id)][0].source as $source |
      (if $source | has("call_completion_lemmas") then $source.call_completion_lemmas else [] end) as $lemmas |
      ([$source.syncs[].id]) as $syncs |
      ($lemmas | type == "array") and
      ([$lemmas[].id] == ([$lemmas[].id] | unique)) and
      all($lemmas[];
        . as $lemma |
        keys == ["completed_calls", "component_id", "id", "operation_id", "start_sync", "target_sync"] and
        (.id | type == "string" and length <= 256 and test("^[A-Za-z][A-Za-z0-9_]*$")) and
        all((.start_sync, .target_sync, .component_id, .operation_id);
          type == "string" and test("^[A-Za-z][A-Za-z0-9_.:-]{0,255}$")) and
        ($syncs | index($lemma.start_sync) != null and index($lemma.target_sync) != null) and
        (.completed_calls | type == "number" and . == floor and . > 0 and . < 4294967296) and
        ([$suppliers[] | select(.component_id == $lemma.component_id)] as $matches |
          ($matches | length) == 1 and $matches[0].summary_strategy == "scalar-body-free-v1" and
          $matches[0].entry_contract == null and ($matches[0] | has("assurance") | not) and
          ($matches[0].source_summary_certificate.operation_symbols | has($lemma.operation_id)))) and
      all((., .obligation_models[]);
        if ($lemmas | length) > 0 then .call_completion_policy == "checked-exact-prefix-scalar-call-completion-v1"
        else has("call_completion_policy") | not end) and
      all(.obligation_models[];
        . as $model |
        [$lemmas[] | select($model.obligation_id == ("sync:" + .start_sync))] as $active |
        ([$active[] | "spx-bisimulation-call-completion:" + .id] | sort) as $expected |
        ([.required_assertion_descriptions[] | select(startswith("spx-bisimulation-call-completion:"))] | sort) == $expected and
        (if ($active | length) > 0 then
          .property_checker_command.completion_assertion_arguments ==
            (.property_checker_command.assertion_arguments | spx_completion_sat_arguments)
         else (.property_checker_command | has("completion_assertion_arguments") | not) end))) and
    all(.proof.shards[].partitioned_evidence.assertions[]?;
      if .description | startswith("spx-bisimulation-call-completion:") then
        ("spx_proof_call_completion_" + (.description | ltrimstr("spx-bisimulation-call-completion:"))) as $symbol |
        .source_function == $symbol and .property_id == ($symbol + ".assertion.1")
      else true end)
  ) catch false;

def spx_contextual_proof_system:
  .proof_plan.operations as $operations |
  .proof as $proof |
  ($proof.models | spx_reusable_proof_inputs($proof.checker)) and
  ($proof.format == "spaghetti-extractor-contextual-refinement-v2") and
  ($proof | has("assurance") | not) and
  (($proof | spx_assertion_option) != null) and
  spx_source_unwind_commands and
  spx_call_completion_lemmas and
  spx_exact_memory_frames and
  spx_exact_mutable_memory_frames and
  spx_exact_mutable_cut_frames and
  spx_mutable_machine_frames and
  spx_image_private_access_frames and spx_reference_origin_capacity and
  spx_clobber_machine_frames and
  spx_private_stack_frames and
  spx_readable_entry_contracts and
  spx_mutable_entry_contracts and
  spx_connected_readable_transports and
  spx_connected_mutable_transports and
  spx_image_readable_composition and
  spx_image_shared_composition and
  spx_call_entry_contracts(spx_contextual_proof_system) and
  (if $proof.models | has("source_summary_contracts") then
    $proof.models.source_summary_contracts as $summary |
    ($summary | type == "object" and keys == ["certificate", "implementation_sha256", "proof_interface_sha256", "source_profile_sha256"]) and
    $summary.implementation_sha256 == $proof.models.implementation_sha256 and
    $summary.source_profile_sha256 == $proof.models.source_profile_sha256 and
    $summary.proof_interface_sha256 == $proof.models.interface_sha256 and
    (if ($summary.certificate.policy | spx_readable_memory_policy or spx_mutable_memory_policy or spx_shared_memory_policy) then
      ($summary.certificate | if (.policy | spx_shared_memory_policy) then spx_shared_certificate
        elif (.policy | spx_mutable_memory_policy)
        then spx_mutable_certificate else spx_readonly_certificate end) and
      (if ($summary.certificate.policy | spx_shared_memory_policy)
       then $proof.models.connected_components == [] else true end) and
      ($proof | spx_qualified_source_dependencies) and
      $summary.certificate.source_package.implementation_sha256 == $summary.implementation_sha256 and
      $summary.certificate.source_profile.receipt_sha256 == $summary.source_profile_sha256 and
      $summary.certificate.interface_intent.id == .proof_plan.component_id
     else
      $summary.certificate |
      type == "object" and
      keys == ["authorizing", "checker_options", "checks", "commands", "headers_sha256", "inputs",
        "interface_sha256", "models", "operation_symbols", "postconditions", "receipt_sha256", "status", "strategy", "tools"] and
      .strategy == "scalar-result-empty-frame-context-independence-v1" and
      (.status == "satisfied" or .status == "incomplete") and .authorizing == false
     end)
   else true end) and
  ($proof.policy.compiler_trusted == true) and
  ($proof.policy.private_stack_disjoint_checked_image == true) and
  ($proof.policy.cutpoint_public_memory_checked == true) and
  ($proof.policy.exit_public_memory_checked == true) and
  ($proof.policy.source_cut_storage_overapproximated == true) and
  ($proof.policy.source_cut_parameter_bindings_checked == true) and
  ($proof.policy.normal_exit_results_checked == true) and
  ($proof.policy.intra_function_continuation_state_checked == true) and
  ($proof.policy.call_public_memory_snapshots_checked == true) and
  ($proof.policy.call_allocation_lifetimes_checked == true) and
  ($proof.policy.machine_import_effect_categories_explicit == true) and
  ($proof.policy.declared_external_range_effects_checked == true) and
  ($proof.policy.typed_service_borrowed_inputs_checked == true) and
  (all($proof.models.operation_models[].obligation_models[];
    .required_assertion_descriptions as $required |
    all($required[] | select(startswith("spx-bisimulation-typed-call-fields:"));
      sub("spx-bisimulation-typed-call-fields:"; "spx-bisimulation-typed-call-public-memory:") as $memory |
      ($required | index($memory)) != null))) and
  (all($proof.models.operation_models[];
    .operation_id as $operation |
    all(.obligation_models[];
      . as $model | ($model.required_assertion_descriptions |
        index("spx-bisimulation-exit-continuation-state:" + $operation + ":" + $model.proof_function)) != null))) and
  ($proof.policy.logical_view_contracts_separated == true) and
  spx_shared_view_inputs and
  spx_parameter_exit_transports and
  spx_common_continuations and
  spx_cut_capture_codecs and
  (all($proof.models.operation_models[];
    .operation_id as $operation |
    (any($operations[]; .operation_id == $operation and (.source.syncs | length) > 0)) as $has_cuts |
    all(.obligation_models[];
      ([.proof_inputs[] | select(.role == "source_parameter_binding_inventory")] | length) ==
        (if $has_cuts then 1 else 0 end) and
      ([.proof_inputs[] | select(.role == "source_cut_storage_inventory")] | length) ==
        (if $has_cuts then 1 else 0 end)))) and
  ($proof.world.policy.checked_component_summaries_used ==
    (any($proof.models.connected_components[];
      (.summary_strategy == "scalar-body-free-v1" or .summary_strategy == "image-readable-body-free-v1" or .summary_strategy == "image-mutable-body-free-v1" or (.summary_strategy | spx_shared_strategy))))) and
  (all($proof.models.connected_components[];
    if .summary_strategy == "connected-replay-v1" then
      .source_summary_certificate == null
    elif (.summary_strategy == "image-readable-body-free-v1" or .summary_strategy == "image-mutable-body-free-v1" or (.summary_strategy | spx_shared_strategy)) then .source_summary_certificate == null
    elif .summary_strategy == "scalar-body-free-v1" then
      .source_summary_certificate |
      .status == "satisfied" and .authorizing == false and
      .strategy == "scalar-result-empty-frame-context-independence-v1" and
      (.postconditions | type) == "array" and
      (all(.postconditions[];
        .check.status == "satisfied" and
        (.signature | type) == "object" and
        (.compile_command | type) == "array" and
        (.checker_command | type) == "array")) and
      ([.checks[].kind] | unique) == ["context_independence", "frame"] and
      (all(.checks[]; .status == "satisfied")) and
      (.checks | length) == (2 * (.operation_symbols | length))
    else false end)) and
  ($proof.policy.cutpoint_connected_call_pairing_checked == true) and
  ($proof.policy.reference_realization_checks_issued_origins == true) and
  ($proof.policy.native_reference_authority_bound == true) and
  ($proof | spx_allocation_class_inputs) and
  ($proof.policy.native_cut_reference_decoding == true) and
  ($proof.models.reference_authority as $authority |
    ($authority | type) == "object" and
    $authority.format == "spaghetti-extractor-machine-object-authority-v2" and
    ($authority.rules | type) == "array" and
    ($authority | spx_reference_authority_extents) and
    ($authority.bindings | type) == "object" and
    ($authority.data_export_anchors | type) == "array" and
    ($authority.authority_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    $authority.authority_sha256 == $proof.world.bindings.machine_object_authority_sha256 and
    (all($proof.models.operation_models[].obligation_models[];
      [.proof_inputs[] | select(.role == "reference_authority")] ==
        [{role: "reference_authority", sha256: $authority.authority_sha256}]))
  ) and
  ($proof.policy.nul_origin_metadata_shared_between_worlds == true) and
  ($proof.policy.proof_overlay_rewrites_used == false) and
  ($proof.policy.obligation_local_exact_c_slices == true) and
  ($proof.policy.path_enumeration_authorizes == false) and
  ($proof.policy.partial_authority == false) and
  ($proof.policy.tests_authorize == false) and
  ($proof.policy.nonvacuity_witness_required_per_shard == true) and
  ($proof.policy.one_goto_model_per_obligation == true) and
  ($proof.policy.one_property_goto_model_per_obligation == true) and
  ($proof.policy.distinct_nonvacuity_goto_model_per_obligation == false) and
  ($proof.policy.relation_inhabitation_query_shares_property_model == true) and
  ($proof.policy.relation_inhabitation_uses_unrestricted_domain == true) and
  ($proof.policy.nonvacuity_executes_paired_exact_and_source_suffixes == false) and
  ($proof.policy.one_relation_inhabitation_witness_per_ordinary_shard == true) and
  ($proof.policy.nonvacuity_world_capacity_claimed == false) and
  ($proof.policy.ordinary_branch_feasibility_claimed == false) and
  ($proof.policy.ordinary_terminal_feasibility_claimed == false) and
  ($proof.policy.property_counterexample_proves_model_inhabited == true) and
  ($proof.policy.nonvacuity_domain_restricts_property_model == false) and
  ($proof.policy.small_goal_nonvacuity_uses_per_goal_formula_slicing == true) and
  ($proof.policy.large_goal_nonvacuity_uses_aggregate_formula_slicing == true) and
  ($proof.policy.finite_control_domain_witness_required_per_route == true) and
  ($proof.policy.finite_control_image_bytes_bound_pre_execution == true) and
  ($proof.policy.finite_control_post_result_assumptions == false) and
  ($proof.policy.localized_model_validity_assertions_fail_closed == true) and
  ($proof.policy.typed_service_fields_use_single_call_boundary_assertion == true) and
  ($proof.policy.assertion_inventory_is_entry_reachability_sliced == true) and
  ($proof.policy.experimental_full_slicing_used == false) and
  ($proof.policy.exact_stack_cache_derived_from_generated_affine_accesses == true) and
  ($proof.policy.exact_stack_cache_mirrors_every_exact_private_write == true) and
  ($proof.policy.exact_stack_cache_partial_overlaps_invalidate == true) and
  ($proof.policy.language_safety_checked_separately == true) and
  ($proof.policy.language_safety_uses_paired_obligation_entry == true) and
  ($proof.policy.language_safety_shares_exact_response_transcript == true) and
  (
    (
      ($proof.policy.production_machine_overlay_executed == true) and
      ($proof.policy.trusted_typed_adapter_lowering_used == false) and
      ($proof.policy.private_service_outputs_abstracted_at_typed_barriers == false) and
      ($proof.policy.external_interface_storage_disjoint_private_stack == false) and
      ($proof.models.machine_overlay_sha256 == $proof.models.proof_overlay_sha256) and
      ($proof.models.trusted_adapter_lowering == null)
    ) or (
      ($proof.policy.production_machine_overlay_executed == false) and
      ($proof.policy.trusted_typed_adapter_lowering_used == true) and
      ($proof.policy.private_service_outputs_abstracted_at_typed_barriers == true) and
      ($proof.policy.external_interface_storage_disjoint_private_stack == true) and
      ($proof.models.machine_overlay_sha256 != $proof.models.proof_overlay_sha256) and
      ($proof.models.trusted_adapter_lowering.format ==
        "spaghetti-extractor-trusted-adapter-lowering-v1") and
      ($proof.models.trusted_adapter_lowering.status == "complete") and
      ($proof.models.trusted_adapter_lowering.trust_basis ==
        "trusted_c_compiler_over_single_checked_adapter_plan") and
      ($proof.models.trusted_adapter_lowering.production_overlay_sha256 ==
        $proof.models.machine_overlay_sha256) and
      ($proof.models.trusted_adapter_lowering.proof_overlay_sha256 ==
        $proof.models.proof_overlay_sha256) and
      ($proof.models.trusted_adapter_lowering | spx_typed_adapter_renderer_inventory) and
      (($proof.models.trusted_adapter_lowering.adapter_plan | length) > 0) and
      (all($proof.models.trusted_adapter_lowering.adapter_plan[];
        spx_declared_external_range_effects($proof.models))) and
      (($proof.models.trusted_adapter_lowering.receipt_sha256 | length) == 64)
    )
  ) and
  ($proof | spx_solver_binding_and_commands) and
  ($proof.checker.options == [
    "source-cuts=matched-terminal-v1",
    "object-bits=12",
    "symex-cache-dereferences",
    (if $proof.checker | has("smt_solver") then "smt-solver=z3" else "sat-solver=cadical" end),
    "unwind=2",
    "unwinding-assertions",
    "reachability-slice-fb",
    "slice-formula",
    "stop-on-fail",
    ($proof | spx_assertion_option),
    "assertion-inventory=entry-reachability-sliced",
    "typed-service-fields=single-call-boundary-safe-prefix",
    "exact-stack=affine-word-cache-with-partial-overlap-invalidation",
    "language-safety=inventory-partitioned-paired-obligation-entry",
    "small-goal-nonvacuity=per-goal-formula-sliced",
    "large-goal-nonvacuity=aggregate-formula-sliced"
  ]) and
  ($proof.checker.model_bounds.maximum_exact_stack_cached_accesses >= 0) and
  ($proof.checker.model_bounds.maximum_exact_stack_cached_bytes >= 0) and
  ($proof.checker.model_bounds.localized_model_validity_assertions_fail_closed == true) and
  ($proof.checker.model_bounds.public_capacity == "paired_local_capacity_assertions") and
  ($proof | spx_entry_unwinding_commands) and
  ($proof | spx_supported_slicing_commands) and
  ($proof | spx_nonvacuity_goal_selection) and
  ($proof | spx_reference_unwind_commands) and
  ($proof.checker.maximum_parallel_shards == 1) and
  ($proof.checker.maximum_parallel_solver_processes == 4) and
  ($proof.checker.nested_solver_parallelism == false) and
  ([
    $proof.shards[] | . as $shard |
    select(
      has("assurance") or
      (.proof_model_sha256 | length) != 64 or
      (.nonvacuity_proof_model_sha256 | length) != 64 or
      .proof_model_sha256 != .nonvacuity_proof_model_sha256 or
      (.goto_model_sha256 | length) != 64 or
      (.nonvacuity_goto_model_sha256 | length) != 64 or
      .goto_model_sha256 != .nonvacuity_goto_model_sha256 or
      (.property_checker_command_sha256 | length) != 64 or
      (.nonvacuity_checker_command_sha256 | length) != 64 or
      (.execution_binding_sha256 | length) != 64 or
      ([$proof.models.operation_models[].obligation_models[].property_checker_command.strategy] | unique) !=
        [.partitioned_evidence.strategy] or
      (.partitioned_evidence | spx_selected_safety_queries($shard.status != "incomplete") | not) or
      (.partitioned_evidence | spx_selected_authored_queries | not) or
      (.status == "satisfied" and any(.partitioned_evidence.queries[]; .status != "satisfied")) or
      (.partitioned_evidence.required_assertion_descriptions_sha256 | length) != 64 or
      (.partitioned_evidence.language_safety_inventory_output_sha256 | length) != 64 or
      (.partitioned_evidence.language_safety_baseline_inventory_output_sha256 | length) != 64 or
      (.partitioned_evidence.loop_inventory_output_sha256 | length) != 64 or
      .partitioned_evidence.queries[0].kind != "language_safety" or
      (
        ([.partitioned_evidence.queries[] |
          select(.kind == "language_safety")] | length) <= 0
      ) or
      (
        ([.partitioned_evidence.queries[] |
          select(
            .kind == "language_safety" and
            .status == "satisfied" and
            (
              .properties != (.property_ids | length)
            )
          )] | length) != 0
      ) or
      (
        .partitioned_evidence.language_safety_properties <= 0
      ) or
      (
        ([.partitioned_evidence.queries[] |
          select(
            .kind == "language_safety" and
            .status != "satisfied" and
            .status != "incomplete" and
            .status != "violated"
          )] | length) != 0
      ) or
      (.partitioned_evidence.assertions | length) <= 0 or
      ([.partitioned_evidence.assertions[] | select(
        (.property_id | length) == 0 or
        (.description | length) == 0 or
        (.source_function | length) == 0 or
        (.entry_function | length) == 0
      )] | length) != 0
    )
  ] | length) == 0;

def spx_strong_contextual_proof:
  (.proof.models | has("diagnostic_selection") | not) and
  (.proof.activation_authorized == true) and
  (.proof.status == "satisfied") and
  (all(.proof.shards[]; .status == "satisfied")) and
  spx_unconditional_operation_entries and
  spx_contextual_proof_system and
  ([.proof.shards[].partitioned_evidence.queries[] |
    select(.kind == "language_safety" and .status != "satisfied")] |
    length) == 0;

def spx_strong_cutpoint_plan:
  .format == "spaghetti-extractor-component-proof-plan-v1" and
  .policy == {
    unsegmented_acyclic_operations_use_single_entry_obligation: true,
    arbitrary_shared_world: true,
    compiler_trusted: true,
    finite_unwinding_authorizes: false,
    every_exact_cycle_cut: true,
    acyclic_and_cyclic_syncs_checked: true,
    path_enumeration_authorizes: false,
    proof_form: "strong_cutpoint_bisimulation"
  } and
  .cost.materialized_paths == 0 and
  (.plan_sha256 | length) == 64;

def spx_contextual_exact_c_slice:
  .format == "spaghetti-extractor-component-exact-c-slice-v1" and
  .policy.forced_labels_are_step_barriers == true and
  (.slice_sha256 | length) == 64;
