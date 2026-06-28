PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS labels (
  label TEXT PRIMARY KEY,
  entity_type TEXT NOT NULL,
  display_name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  private INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS binaries (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  path TEXT NOT NULL,
  filename TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  kind TEXT NOT NULL,
  machine TEXT NOT NULL,
  timestamp INTEGER,
  image_base INTEGER,
  entrypoint_rva INTEGER,
  size_of_image INTEGER,
  subsystem TEXT,
  linker_version TEXT,
  pe_checksum INTEGER,
  role TEXT NOT NULL,
  scope TEXT NOT NULL,
  role_reason TEXT NOT NULL,
  source_root TEXT NOT NULL,
  catalog_version TEXT NOT NULL,
  discovered_at TEXT NOT NULL,
  UNIQUE(path, sha256)
);

CREATE INDEX IF NOT EXISTS idx_binaries_sha256 ON binaries(sha256);
CREATE INDEX IF NOT EXISTS idx_binaries_scope ON binaries(scope);
CREATE INDEX IF NOT EXISTS idx_binaries_filename ON binaries(filename);

CREATE TABLE IF NOT EXISTS sections (
  id INTEGER PRIMARY KEY,
  binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  virtual_address INTEGER NOT NULL,
  virtual_size INTEGER NOT NULL,
  raw_pointer INTEGER NOT NULL,
  raw_size INTEGER NOT NULL,
  characteristics INTEGER NOT NULL,
  flags TEXT NOT NULL,
  sha256 TEXT,
  entropy REAL
);

CREATE TABLE IF NOT EXISTS imports (
  id INTEGER PRIMARY KEY,
  binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
  dll TEXT NOT NULL,
  symbol TEXT,
  ordinal INTEGER,
  hint INTEGER,
  thunk_rva INTEGER
);

CREATE INDEX IF NOT EXISTS idx_imports_dll ON imports(lower(dll));

CREATE TABLE IF NOT EXISTS exports (
  id INTEGER PRIMARY KEY,
  binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
  symbol TEXT,
  ordinal INTEGER NOT NULL,
  rva INTEGER NOT NULL,
  forwarder TEXT
);

CREATE TABLE IF NOT EXISTS resources (
  id INTEGER PRIMARY KEY,
  binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
  type_name TEXT NOT NULL,
  name TEXT NOT NULL,
  language TEXT NOT NULL,
  rva INTEGER NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT
);

CREATE TABLE IF NOT EXISTS executable_ranges (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
  rva_start INTEGER NOT NULL,
  rva_end INTEGER NOT NULL,
  file_offset_start INTEGER,
  file_offset_end INTEGER,
  classification TEXT NOT NULL,
  evidence TEXT NOT NULL,
  UNIQUE(binary_id, rva_start, rva_end, classification)
);

CREATE TABLE IF NOT EXISTS executable_byte_classes (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
  executable_range_id INTEGER REFERENCES executable_ranges(id) ON DELETE CASCADE,
  rva_start INTEGER NOT NULL,
  rva_end INTEGER NOT NULL,
  classification TEXT NOT NULL,
  source TEXT NOT NULL,
  evidence TEXT NOT NULL,
  confidence TEXT NOT NULL DEFAULT 'low',
  UNIQUE(binary_id, rva_start, rva_end, classification, source)
);

CREATE INDEX IF NOT EXISTS idx_executable_byte_classes_binary_rva
ON executable_byte_classes(binary_id, rva_start, rva_end);

CREATE TABLE IF NOT EXISTS functions (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
  rva INTEGER NOT NULL,
  name TEXT NOT NULL,
  source TEXT NOT NULL,
  calling_convention TEXT NOT NULL DEFAULT 'unknown',
  signature TEXT NOT NULL DEFAULT 'unknown',
  subsystem TEXT NOT NULL DEFAULT 'unknown',
  purity TEXT NOT NULL DEFAULT 'unknown',
  side_effects TEXT NOT NULL DEFAULT 'unknown',
  confidence TEXT NOT NULL DEFAULT 'low',
  test_status TEXT NOT NULL DEFAULT 'untested',
  clean_room_status TEXT NOT NULL DEFAULT 'needs-spec',
  UNIQUE(binary_id, rva, name, source)
);

CREATE INDEX IF NOT EXISTS idx_functions_binary_rva ON functions(binary_id, rva);

CREATE TABLE IF NOT EXISTS function_semantics (
  function_id INTEGER PRIMARY KEY REFERENCES functions(id) ON DELETE CASCADE,
  binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
  rva_start INTEGER NOT NULL,
  rva_end INTEGER,
  source TEXT NOT NULL,
  decompiler_status TEXT NOT NULL DEFAULT 'not_available',
  decompiler_error TEXT NOT NULL DEFAULT '',
  decompiled_c TEXT NOT NULL DEFAULT '',
  variables_json TEXT NOT NULL DEFAULT '[]',
  inferred_types_json TEXT NOT NULL DEFAULT '{}',
  stack_refs_json TEXT NOT NULL DEFAULT '[]',
  global_refs_json TEXT NOT NULL DEFAULT '[]',
  strings_json TEXT NOT NULL DEFAULT '[]',
  callsites_json TEXT NOT NULL DEFAULT '[]',
  instructions_json TEXT NOT NULL DEFAULT '[]',
  pcode_json TEXT NOT NULL DEFAULT '[]',
  source_json TEXT NOT NULL DEFAULT '{}',
  imported_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_function_semantics_binary_rva
ON function_semantics(binary_id, rva_start);

CREATE TABLE IF NOT EXISTS internal_routine_contracts (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  function_id INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
  public_name TEXT NOT NULL,
  purpose_summary TEXT NOT NULL,
  calling_convention TEXT NOT NULL,
  signature TEXT NOT NULL,
  input_shape_json TEXT NOT NULL DEFAULT '{}',
  output_shape_json TEXT NOT NULL DEFAULT '{}',
  preconditions_json TEXT NOT NULL DEFAULT '[]',
  postconditions_json TEXT NOT NULL DEFAULT '[]',
  side_effects_json TEXT NOT NULL DEFAULT '[]',
  state_transitions_json TEXT NOT NULL DEFAULT '[]',
  fixtures_json TEXT NOT NULL DEFAULT '[]',
  evidence_labels_json TEXT NOT NULL DEFAULT '[]',
  evidence_source TEXT NOT NULL,
  confidence TEXT NOT NULL,
  taint_level TEXT NOT NULL,
  review_status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(function_id, public_name)
);

CREATE INDEX IF NOT EXISTS idx_internal_routine_contracts_function
ON internal_routine_contracts(function_id);

CREATE TABLE IF NOT EXISTS basic_blocks (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
  function_id INTEGER REFERENCES functions(id) ON DELETE SET NULL,
  rva_start INTEGER NOT NULL,
  rva_end INTEGER NOT NULL,
  size INTEGER NOT NULL,
  source TEXT NOT NULL,
  classification TEXT NOT NULL,
  confidence TEXT NOT NULL DEFAULT 'low',
  UNIQUE(binary_id, rva_start, rva_end, source)
);

CREATE INDEX IF NOT EXISTS idx_basic_blocks_binary_rva ON basic_blocks(binary_id, rva_start, rva_end);

CREATE TABLE IF NOT EXISTS block_semantics (
  basic_block_id INTEGER PRIMARY KEY REFERENCES basic_blocks(id) ON DELETE CASCADE,
  binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
  function_id INTEGER REFERENCES functions(id) ON DELETE SET NULL,
  rva_start INTEGER NOT NULL,
  rva_end INTEGER NOT NULL,
  source TEXT NOT NULL,
  instructions_json TEXT NOT NULL DEFAULT '[]',
  pcode_json TEXT NOT NULL DEFAULT '[]',
  data_flow_json TEXT NOT NULL DEFAULT '{}',
  xrefs_json TEXT NOT NULL DEFAULT '{}',
  semantic_summary TEXT NOT NULL DEFAULT '',
  decompiler_status_json TEXT NOT NULL DEFAULT '{}',
  imported_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_block_semantics_binary_rva
ON block_semantics(binary_id, rva_start, rva_end);

CREATE TABLE IF NOT EXISTS cfg_edges (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
  function_id INTEGER REFERENCES functions(id) ON DELETE SET NULL,
  from_rva INTEGER NOT NULL,
  to_rva INTEGER NOT NULL,
  edge_type TEXT NOT NULL,
  source TEXT NOT NULL,
  confidence TEXT NOT NULL DEFAULT 'low',
  UNIQUE(binary_id, from_rva, to_rva, edge_type, source)
);

CREATE TABLE IF NOT EXISTS call_edges (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
  caller_rva INTEGER NOT NULL,
  callee_binary_id INTEGER REFERENCES binaries(id) ON DELETE SET NULL,
  callee_rva INTEGER,
  callee_symbol TEXT,
  call_type TEXT NOT NULL,
  source TEXT NOT NULL,
  confidence TEXT NOT NULL DEFAULT 'low',
  UNIQUE(binary_id, caller_rva, callee_binary_id, callee_rva, callee_symbol, call_type, source)
);

CREATE TABLE IF NOT EXISTS data_refs (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
  from_rva INTEGER NOT NULL,
  to_rva INTEGER NOT NULL,
  ref_type TEXT NOT NULL,
  source TEXT NOT NULL,
  confidence TEXT NOT NULL DEFAULT 'low',
  UNIQUE(binary_id, from_rva, to_rva, ref_type, source)
);

CREATE TABLE IF NOT EXISTS waivers (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
  rva_start INTEGER NOT NULL,
  rva_end INTEGER NOT NULL,
  category TEXT NOT NULL,
  reason TEXT NOT NULL,
  evidence TEXT NOT NULL,
  reviewer TEXT NOT NULL,
  revalidation_trigger TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(binary_id, rva_start, rva_end, category, reason)
);

CREATE TABLE IF NOT EXISTS test_runs (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  test_id TEXT NOT NULL,
  suite TEXT NOT NULL,
  command TEXT,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  tool_versions_json TEXT NOT NULL DEFAULT '{}',
  provenance_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS observed_modules (
  id INTEGER PRIMARY KEY,
  test_run_id INTEGER NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
  drcov_module_id INTEGER NOT NULL,
  path TEXT NOT NULL,
  base INTEGER,
  end INTEGER,
  entry INTEGER,
  preferred_base INTEGER,
  sha256 TEXT,
  binary_id INTEGER REFERENCES binaries(id) ON DELETE SET NULL,
  UNIQUE(test_run_id, drcov_module_id)
);

CREATE TABLE IF NOT EXISTS coverage_blocks (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  test_run_id INTEGER NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
  observed_module_id INTEGER NOT NULL REFERENCES observed_modules(id) ON DELETE CASCADE,
  binary_id INTEGER REFERENCES binaries(id) ON DELETE SET NULL,
  rva_start INTEGER NOT NULL,
  rva_end INTEGER NOT NULL,
  size INTEGER NOT NULL,
  source_log TEXT NOT NULL,
  UNIQUE(test_run_id, observed_module_id, rva_start, rva_end)
);

CREATE INDEX IF NOT EXISTS idx_coverage_blocks_binary_rva ON coverage_blocks(binary_id, rva_start, rva_end);

CREATE TABLE IF NOT EXISTS coverage_edges (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  test_run_id INTEGER NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
  observed_module_id INTEGER NOT NULL REFERENCES observed_modules(id) ON DELETE CASCADE,
  binary_id INTEGER REFERENCES binaries(id) ON DELETE SET NULL,
  from_rva INTEGER NOT NULL,
  to_rva INTEGER NOT NULL,
  source_log TEXT NOT NULL,
  UNIQUE(test_run_id, observed_module_id, from_rva, to_rva)
);

CREATE TABLE IF NOT EXISTS coverage_call_edges (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  test_run_id INTEGER NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
  observed_module_id INTEGER NOT NULL REFERENCES observed_modules(id) ON DELETE CASCADE,
  binary_id INTEGER REFERENCES binaries(id) ON DELETE SET NULL,
  caller_rva INTEGER NOT NULL,
  callee_binary_id INTEGER REFERENCES binaries(id) ON DELETE SET NULL,
  callee_rva INTEGER,
  callee_symbol TEXT,
  source_log TEXT NOT NULL,
  UNIQUE(test_run_id, observed_module_id, caller_rva, callee_binary_id, callee_rva, callee_symbol)
);

CREATE TABLE IF NOT EXISTS trace_probe_results (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  probe_id TEXT NOT NULL,
  probe_kind TEXT NOT NULL,
  command TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  trace_log TEXT,
  expected_filename TEXT,
  expected_sha256 TEXT,
  returncode INTEGER,
  timed_out INTEGER NOT NULL DEFAULT 0,
  raw_trace_json TEXT NOT NULL DEFAULT '{}',
  mapped_json TEXT NOT NULL DEFAULT '{}',
  failures_json TEXT NOT NULL DEFAULT '[]',
  stdout TEXT NOT NULL DEFAULT '',
  stderr TEXT NOT NULL DEFAULT '',
  tool_versions_json TEXT NOT NULL DEFAULT '{}',
  provenance_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_trace_probe_results_probe_kind
ON trace_probe_results(probe_kind, status, started_at);

CREATE TABLE IF NOT EXISTS value_traces (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  test_id TEXT NOT NULL,
  module_sha256 TEXT NOT NULL,
  routine_label TEXT,
  block_label TEXT,
  values_json TEXT NOT NULL DEFAULT '{}',
  provenance_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  UNIQUE(test_id, module_sha256, routine_label, block_label)
);

CREATE INDEX IF NOT EXISTS idx_value_traces_identity
ON value_traces(test_id, module_sha256, routine_label, block_label);

CREATE TABLE IF NOT EXISTS private_artifact_bundles (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  artifact_set_id TEXT NOT NULL,
  root_path TEXT NOT NULL,
  format_version TEXT NOT NULL,
  scopes_json TEXT NOT NULL DEFAULT '[]',
  generator_version TEXT NOT NULL,
  created_at TEXT NOT NULL,
  content_manifest_json TEXT NOT NULL DEFAULT '{}',
  summary_json TEXT NOT NULL DEFAULT '{}',
  taint_policy_json TEXT NOT NULL DEFAULT '{}',
  UNIQUE(artifact_set_id, root_path)
);

CREATE TABLE IF NOT EXISTS private_artifacts (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  bundle_id INTEGER NOT NULL REFERENCES private_artifact_bundles(id) ON DELETE CASCADE,
  artifact_kind TEXT NOT NULL,
  entity_label TEXT,
  entity_type TEXT NOT NULL,
  binary_id INTEGER REFERENCES binaries(id) ON DELETE SET NULL,
  module_sha256 TEXT,
  rva_start INTEGER,
  rva_end INTEGER,
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  taint_level TEXT NOT NULL,
  source_tool TEXT NOT NULL,
  source_detail_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  UNIQUE(bundle_id, path)
);

CREATE INDEX IF NOT EXISTS idx_private_artifacts_bundle_kind
ON private_artifacts(bundle_id, artifact_kind);

CREATE INDEX IF NOT EXISTS idx_private_artifacts_binary_rva
ON private_artifacts(binary_id, rva_start, rva_end);

CREATE TABLE IF NOT EXISTS oracle_mappings (
  label TEXT PRIMARY KEY REFERENCES labels(label) ON DELETE CASCADE,
  entity_type TEXT NOT NULL,
  binary_id INTEGER REFERENCES binaries(id) ON DELETE CASCADE,
  module_sha256 TEXT,
  rva_start INTEGER,
  rva_end INTEGER,
  private_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_oracle_mappings_binary_entity_rva
ON oracle_mappings(binary_id, entity_type, rva_start, rva_end);

CREATE TABLE IF NOT EXISTS oracle_test_cases (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  suite_id TEXT NOT NULL,
  test_id TEXT NOT NULL,
  case_kind TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'planned',
  evidence TEXT NOT NULL DEFAULT '',
  command TEXT,
  fixture_path TEXT,
  trace_log TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(suite_id, test_id, case_kind)
);

CREATE TABLE IF NOT EXISTS internal_harnesses (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  target_label TEXT NOT NULL REFERENCES labels(label) ON DELETE RESTRICT,
  harness_id TEXT NOT NULL,
  harness_kind TEXT NOT NULL,
  command_template TEXT NOT NULL DEFAULT '',
  input_contract TEXT NOT NULL DEFAULT '',
  expected_observation TEXT NOT NULL DEFAULT '',
  risk TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  UNIQUE(target_label, harness_id)
);

CREATE TABLE IF NOT EXISTS internal_harness_runs (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  internal_harness_id INTEGER NOT NULL REFERENCES internal_harnesses(id) ON DELETE CASCADE,
  test_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'planned',
  command TEXT,
  evidence TEXT NOT NULL DEFAULT '',
  fixture_path TEXT,
  trace_log TEXT,
  returncode INTEGER,
  created_at TEXT NOT NULL,
  UNIQUE(internal_harness_id, test_id)
);

CREATE TABLE IF NOT EXISTS mutation_test_cases (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  mutation_kind TEXT NOT NULL,
  target_label TEXT,
  test_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'planned',
  evidence TEXT NOT NULL DEFAULT '',
  command TEXT,
  fixture_path TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS behavior_contracts (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  contract_id TEXT NOT NULL,
  title TEXT NOT NULL,
  scope TEXT NOT NULL,
  version TEXT NOT NULL,
  contract_json TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  UNIQUE(contract_id, version)
);

CREATE TABLE IF NOT EXISTS behavior_observations (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  behavior_contract_id INTEGER NOT NULL REFERENCES behavior_contracts(id) ON DELETE CASCADE,
  test_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pass',
  command TEXT,
  input_json TEXT NOT NULL DEFAULT '{}',
  observed_json TEXT NOT NULL DEFAULT '{}',
  observed_sha256 TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '',
  fixture_path TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(behavior_contract_id, test_id)
);

CREATE TABLE IF NOT EXISTS process_behavior_observations (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  behavior_contract_id INTEGER NOT NULL REFERENCES behavior_contracts(id) ON DELETE CASCADE,
  test_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pass',
  command TEXT,
  input_json TEXT NOT NULL DEFAULT '{}',
  observed_json TEXT NOT NULL DEFAULT '{}',
  observed_sha256 TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '',
  fixture_path TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(behavior_contract_id, test_id)
);

CREATE TABLE IF NOT EXISTS platform_endpoints (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  dll TEXT NOT NULL,
  symbol TEXT,
  ordinal INTEGER,
  endpoint_kind TEXT NOT NULL DEFAULT 'import',
  subsystem TEXT NOT NULL DEFAULT 'unknown',
  mock_status TEXT NOT NULL DEFAULT 'missing',
  test_status TEXT NOT NULL DEFAULT 'untested'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_platform_endpoints_identity
ON platform_endpoints(lower(dll), COALESCE(symbol, ''), COALESCE(ordinal, -1));

CREATE TABLE IF NOT EXISTS binary_platform_endpoints (
  binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
  endpoint_id INTEGER NOT NULL REFERENCES platform_endpoints(id) ON DELETE CASCADE,
  thunk_rva INTEGER,
  PRIMARY KEY(binary_id, endpoint_id, thunk_rva)
);

CREATE TABLE IF NOT EXISTS interface_test_cases (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  endpoint_id INTEGER NOT NULL REFERENCES platform_endpoints(id) ON DELETE CASCADE,
  case_kind TEXT NOT NULL,
  test_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'planned',
  evidence TEXT NOT NULL DEFAULT '',
  fixture_path TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(endpoint_id, case_kind, test_id)
);

CREATE TABLE IF NOT EXISTS data_structures (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  name TEXT NOT NULL,
  structure_kind TEXT NOT NULL,
  spec_status TEXT NOT NULL DEFAULT 'unknown',
  fixture_status TEXT NOT NULL DEFAULT 'missing',
  description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS data_state_test_cases (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  data_structure_id INTEGER NOT NULL REFERENCES data_structures(id) ON DELETE CASCADE,
  case_kind TEXT NOT NULL,
  test_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'planned',
  evidence TEXT NOT NULL DEFAULT '',
  fixture_path TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(data_structure_id, case_kind, test_id)
);

CREATE TABLE IF NOT EXISTS globals (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
  rva INTEGER NOT NULL,
  name TEXT NOT NULL,
  data_type TEXT NOT NULL DEFAULT 'unknown',
  subsystem TEXT NOT NULL DEFAULT 'unknown',
  confidence TEXT NOT NULL DEFAULT 'low',
  UNIQUE(binary_id, rva, name)
);

CREATE TABLE IF NOT EXISTS static_cross_checks (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL UNIQUE REFERENCES labels(label) ON DELETE RESTRICT,
  binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
  tool TEXT NOT NULL,
  status TEXT NOT NULL,
  checked_at TEXT NOT NULL,
  command TEXT NOT NULL,
  section_count INTEGER NOT NULL DEFAULT 0,
  executable_section_count INTEGER NOT NULL DEFAULT 0,
  evidence_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_static_cross_checks_binary_tool
ON static_cross_checks(binary_id, tool, status);
