PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS binaries (
  id INTEGER PRIMARY KEY,
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
  binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
  rva_start INTEGER NOT NULL,
  rva_end INTEGER NOT NULL,
  file_offset_start INTEGER,
  file_offset_end INTEGER,
  classification TEXT NOT NULL,
  evidence TEXT NOT NULL,
  UNIQUE(binary_id, rva_start, rva_end, classification)
);

CREATE TABLE IF NOT EXISTS functions (
  id INTEGER PRIMARY KEY,
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

CREATE TABLE IF NOT EXISTS basic_blocks (
  id INTEGER PRIMARY KEY,
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

CREATE TABLE IF NOT EXISTS cfg_edges (
  id INTEGER PRIMARY KEY,
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
  test_run_id INTEGER NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
  observed_module_id INTEGER NOT NULL REFERENCES observed_modules(id) ON DELETE CASCADE,
  binary_id INTEGER REFERENCES binaries(id) ON DELETE SET NULL,
  from_rva INTEGER NOT NULL,
  to_rva INTEGER NOT NULL,
  source_log TEXT NOT NULL,
  UNIQUE(test_run_id, observed_module_id, from_rva, to_rva)
);
