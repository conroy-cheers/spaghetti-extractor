use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use iced_x86::{Decoder, DecoderOptions, Instruction as IcedInstruction};
use indexmap::IndexMap;
use object::{Object, ObjectSection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const SUITE_FORMAT: &str = "wincr-block-conformance-suite-v2";
const RECOVERY_FORMAT: &str = "wincr-block-recovery-v2";
const COVERAGE_FORMAT: &str = "wincr-block-coverage-report-v1";
const SIDE_EFFECT_FORMAT: &str = "wincr-block-side-effect-model-v1";
const VALIDATION_FORMAT: &str = "wincr-block-candidate-validation-v3";
const CONFORMANCE_FORMAT: &str = "wincr-block-candidate-conformance-v1";

#[derive(Clone, Debug, Serialize)]
pub struct PeImage {
    pub path: PathBuf,
    pub object_format: String,
    pub architecture: String,
    pub machine: u16,
    pub bitness: u32,
    pub is_pe64: bool,
    pub image_base: u64,
    pub entry_rva: u32,
    pub sections: Vec<PeSection>,
    #[serde(skip_serializing)]
    data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PeSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_pointer: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    pub executable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BlockInstruction {
    pub rva: u32,
    pub len: u32,
    pub bytes: String,
    pub mnemonic: String,
    pub flow_control: String,
    pub terminator: Terminator,
    pub target: Option<u32>,
    pub valid: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Terminator {
    None,
    Ret,
    Jump,
    ConditionalJump,
    IndirectJump,
    Call,
    IndirectCall,
    Trap,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BasicBlock {
    pub label: String,
    pub rva_start: u32,
    pub rva_end: u32,
    pub size: u32,
    pub instruction_count: usize,
    pub classification: String,
    pub instructions: Vec<BlockInstruction>,
    pub successors: Vec<u32>,
    pub terminator: Terminator,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveryIssue {
    pub severity: String,
    pub rva_start: u32,
    pub rva_end: u32,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Recovery {
    pub format: &'static str,
    pub image: PeImage,
    pub executable_bytes: u64,
    pub recovered_instruction_bytes: u64,
    pub unknown_bytes: u64,
    pub blocks: Vec<BasicBlock>,
    pub issues: Vec<RecoveryIssue>,
}

#[derive(Clone, Debug, Default)]
pub struct SuiteOptions {
    pub traces: Vec<PathBuf>,
    pub max_cases_per_block: Option<usize>,
}

#[derive(Clone, Debug, Default)]
pub struct CandidateValidationOptions {
    pub allow_incomplete_characterization: bool,
    pub allow_incomplete_side_effects: bool,
    pub waivers: Option<PathBuf>,
    pub candidate_trace: Option<PathBuf>,
}

#[derive(Clone, Debug, Default)]
pub struct CoverageOptions {
    pub waivers: Option<PathBuf>,
    pub allow_incomplete_side_effects: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct CoverageReport {
    pub format: &'static str,
    pub status: String,
    pub required_blocks: usize,
    pub characterized_blocks: usize,
    pub waived_blocks: usize,
    pub uncovered_blocks: Vec<String>,
    pub side_effect_incomplete_blocks: Vec<String>,
    pub complete_cases: usize,
    pub pending_cases: usize,
    pub waiver_issues: Vec<String>,
    pub issues: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CandidateValidationReport {
    pub format: &'static str,
    pub status: String,
    pub required_blocks: usize,
    pub mapped_blocks: usize,
    pub waived_blocks: usize,
    pub missing_blocks: Vec<String>,
    pub invalid_mappings: Vec<String>,
    pub complete_cases: usize,
    pub pending_cases: usize,
    pub uncharacterized_blocks: Vec<String>,
    pub side_effect_incomplete_blocks: Vec<String>,
    pub candidate_results: Option<CandidateConformanceReport>,
    pub issues: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct SuiteManifest {
    format: &'static str,
    artifact_role: &'static str,
    taint_level: &'static str,
    binary: String,
    object_format: String,
    architecture: String,
    machine: String,
    entry_rva: String,
    block_count: usize,
    executable_bytes: u64,
    recovered_instruction_bytes: u64,
    unknown_bytes: u64,
    trace_records: usize,
    complete_cases: usize,
    pending_cases: usize,
    characterized_blocks: usize,
    side_effect_complete_blocks: usize,
    trace_issues: Vec<String>,
    coverage_report: &'static str,
    waiver_schema: &'static str,
    candidate_mapping: &'static str,
    candidate_scaffold: &'static str,
    conformance_policy: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct BlockObligation<'a> {
    format: &'static str,
    artifact_role: &'static str,
    taint_level: &'static str,
    block_label: &'a str,
    rva_start: String,
    rva_end: String,
    size: u32,
    classification: &'a str,
    terminator: Terminator,
    successors: Vec<String>,
    instructions: &'a [BlockInstruction],
    candidate_requirement: CandidateRequirement,
}

#[derive(Clone, Debug, Serialize)]
struct CandidateRequirement {
    distinct_semantic_point: bool,
    pre_state_adapter: bool,
    post_state_adapter: bool,
    side_effect_adapter: bool,
}

#[derive(Clone, Debug, Serialize)]
struct StateSchema<'a> {
    format: &'static str,
    artifact_role: &'static str,
    block_label: &'a str,
    evidence_level: &'static str,
    complete_cases: usize,
    pending_cases: usize,
    required_inputs: Vec<&'static str>,
    required_outputs: Vec<&'static str>,
    fuzz_policy: &'static str,
    conformance_status: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct SideEffectModel<'a> {
    format: &'static str,
    artifact_role: &'static str,
    block_label: &'a str,
    status: String,
    complete_cases: usize,
    complete_side_effect_cases: usize,
    incomplete_side_effect_cases: usize,
    observed_effect_classes: Vec<String>,
    capture_status_counts: BTreeMap<String, usize>,
    limitations: Vec<String>,
    missing_effect_classes: Vec<&'static str>,
    comparison_policy: SideEffectComparisonPolicy,
}

#[derive(Clone, Debug, Serialize)]
struct ConformanceCase<'a> {
    format: &'static str,
    case_id: String,
    block_label: &'a str,
    origin: &'static str,
    status: &'static str,
    pre_state: Value,
    expected: Option<ExpectedState>,
    trace_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct ExpectedState {
    post_state: Value,
    successor_rva: Option<String>,
    side_effects: Value,
}

#[derive(Clone, Debug)]
struct TraceEvent {
    kind: TraceEventKind,
    source: String,
    line_number: usize,
    test_id: String,
    rva: u32,
    block_label: Option<String>,
    state: Value,
    successor_rva: Option<u32>,
    side_effects: Value,
    raw: Value,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum TraceEventKind {
    Entry,
    Exit,
}

#[derive(Clone, Debug, Default)]
struct Characterization {
    cases_by_block: BTreeMap<String, Vec<OwnedCase>>,
    trace_records: usize,
    complete_cases: usize,
    pending_cases: usize,
    issues: Vec<String>,
}

#[derive(Clone, Debug)]
struct OwnedCase {
    case_id: String,
    origin: &'static str,
    status: &'static str,
    pre_state: Value,
    expected: Option<ExpectedState>,
    trace_refs: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct BlockCaseSummary {
    complete_cases: usize,
    pending_cases: usize,
    complete_side_effect_cases: usize,
    incomplete_side_effect_cases: usize,
}

#[derive(Clone, Debug, Serialize)]
struct BlockCoverage {
    format: &'static str,
    artifact_role: &'static str,
    block_label: String,
    status: String,
    complete_cases: usize,
    pending_cases: usize,
    side_effect_status: String,
    waiver: Option<BlockWaiver>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CoverageWaiverFile {
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    waivers: IndexMap<String, BlockWaiver>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct BlockWaiver {
    reason: String,
    evidence: String,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    reviewer: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct SideEffectComparisonPolicy {
    exact_memory_writes: bool,
    exact_api_calls: bool,
    exact_external_events: bool,
    ignored_fields: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CandidateConformanceReport {
    pub format: &'static str,
    pub status: String,
    pub expected_cases: usize,
    pub observed_cases: usize,
    pub passed_cases: usize,
    pub failed_cases: usize,
    pub missing_cases: Vec<String>,
    pub unexpected_cases: Vec<String>,
    pub mismatches: Vec<CandidateMismatch>,
    pub issues: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CandidateMismatch {
    pub case_id: String,
    pub block_label: String,
    pub field: String,
    pub expected: Value,
    pub actual: Value,
}

#[derive(Clone, Debug)]
struct CandidateCaseResult {
    block_label: String,
    post_state: Value,
    side_effects: Value,
    successor_rva: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CandidateMapping {
    blocks: IndexMap<String, CandidateBlockMapping>,
}

#[derive(Debug, Deserialize)]
struct CandidateBlockMapping {
    semantic_point: Option<String>,
    source: Option<String>,
    state_adapter: Option<String>,
    side_effect_adapter: Option<String>,
}

const ALIGNMENT_PADDING_CLASSIFICATION: &str = "alignment_padding";

pub fn recover_blocks_from_path(path: &Path) -> Result<Recovery, String> {
    let image = PeImage::parse(path)?;
    Ok(recover_blocks(image))
}

pub fn emit_recovery_report(recovery: &Recovery, out: &Path) -> Result<(), String> {
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create {}: {err}", parent.display()))?;
    }
    let mut file = File::create(out).map_err(|err| format!("create {}: {err}", out.display()))?;
    serde_json::to_writer_pretty(&mut file, recovery)
        .map_err(|err| format!("serialize {}: {err}", out.display()))?;
    file.write_all(b"\n")
        .map_err(|err| format!("write {}: {err}", out.display()))
}

pub fn emit_suite(binary: &Path, out: &Path, options: &SuiteOptions) -> Result<(), String> {
    let recovery = recover_blocks_from_path(binary)?;
    if out.exists() {
        if !out.is_dir() {
            return Err(format!(
                "suite output exists and is not a directory: {}",
                out.display()
            ));
        }
    } else {
        fs::create_dir_all(out).map_err(|err| format!("create {}: {err}", out.display()))?;
    }

    let characterization = characterize_traces(&options.traces, &recovery.blocks, options)?;
    let summaries = block_case_summaries(&recovery.blocks, &characterization);
    let characterized_blocks = summaries
        .values()
        .filter(|summary| summary.complete_cases > 0)
        .count();
    let side_effect_complete_blocks = summaries
        .values()
        .filter(|summary| summary.complete_side_effect_cases > 0)
        .count();

    write_json(
        out.join("manifest.json"),
        &SuiteManifest {
            format: SUITE_FORMAT,
            artifact_role: "private_block_conformance_suite",
            taint_level: "private_high_taint",
            binary: recovery.image.path.display().to_string(),
            object_format: recovery.image.object_format.clone(),
            architecture: recovery.image.architecture.clone(),
            machine: hex_u16(recovery.image.machine),
            entry_rva: hex_u32(recovery.image.entry_rva),
            block_count: recovery.blocks.len(),
            executable_bytes: recovery.executable_bytes,
            recovered_instruction_bytes: recovery.recovered_instruction_bytes,
            unknown_bytes: recovery.unknown_bytes,
            trace_records: characterization.trace_records,
            complete_cases: characterization.complete_cases,
            pending_cases: characterization.pending_cases,
            characterized_blocks,
            side_effect_complete_blocks,
            trace_issues: characterization.issues.clone(),
            coverage_report: "coverage.json",
            waiver_schema: "waivers.schema.json",
            candidate_mapping: "candidate/schema.json",
            candidate_scaffold: "candidate/wincr_block_verify.hpp",
            conformance_policy: "fail_closed_without_complete_pre_post_side_effect_cases_or_reviewed_waivers_for_every_block",
        },
    )?;
    write_json(out.join("recovery.json"), &recovery)?;
    write_candidate_schema(out)?;
    write_waiver_schema(out)?;

    let blocks_root = out.join("blocks");
    fs::create_dir_all(&blocks_root)
        .map_err(|err| format!("create {}: {err}", blocks_root.display()))?;
    for block in &recovery.blocks {
        let block_root = blocks_root.join(&block.label);
        fs::create_dir_all(&block_root)
            .map_err(|err| format!("create {}: {err}", block_root.display()))?;
        let cases = characterization
            .cases_by_block
            .get(&block.label)
            .cloned()
            .unwrap_or_default();
        let summary = summaries.get(&block.label).cloned().unwrap_or_default();
        write_json(block_root.join("obligation.json"), &block_obligation(block))?;
        write_json(
            block_root.join("state-schema.json"),
            &state_schema(block, summary.complete_cases, summary.pending_cases),
        )?;
        write_cases_jsonl(block_root.join("cases.jsonl"), block, &cases)?;
        write_json(
            block_root.join("side-effects.json"),
            &side_effects(block, &cases),
        )?;
        write_json(
            block_root.join("coverage.json"),
            &block_coverage(block, &summary, None),
        )?;
    }
    let coverage = coverage_report_for_suite(out, &CoverageOptions::default())?;
    write_json(out.join("coverage.json"), &coverage)?;

    Ok(())
}

pub fn validate_candidate_mapping(
    suite: &Path,
    mapping: &Path,
    options: &CandidateValidationOptions,
) -> Result<CandidateValidationReport, String> {
    let all_block_labels = suite_block_labels(suite)?;
    let block_labels = suite_required_block_labels(suite)?;
    let waivers = load_waivers(options.waivers.as_deref(), &all_block_labels)?;
    let mapping_text =
        fs::read_to_string(mapping).map_err(|err| format!("read {}: {err}", mapping.display()))?;
    let candidate: CandidateMapping = serde_json::from_str(&mapping_text)
        .map_err(|err| format!("parse candidate mapping {}: {err}", mapping.display()))?;

    let mut missing_blocks = Vec::new();
    let mut invalid_mappings = Vec::new();
    for label in &block_labels {
        if waivers.waivers.contains_key(label) {
            continue;
        }
        match candidate.blocks.get(label) {
            Some(block) => {
                for (field, value) in [
                    ("semantic_point", &block.semantic_point),
                    ("source", &block.source),
                    ("state_adapter", &block.state_adapter),
                    ("side_effect_adapter", &block.side_effect_adapter),
                ] {
                    if value.as_deref().unwrap_or("").trim().is_empty() {
                        invalid_mappings.push(format!("{label}.{field} is missing or empty"));
                    }
                }
            }
            None => missing_blocks.push(label.clone()),
        }
    }

    let mut complete_cases = 0usize;
    let mut pending_cases = 0usize;
    let mut uncharacterized_blocks = Vec::new();
    let mut side_effect_incomplete_blocks = Vec::new();
    for label in &block_labels {
        if waivers.waivers.contains_key(label) {
            continue;
        }
        let path = suite.join("blocks").join(label).join("cases.jsonl");
        let mut block_complete = 0usize;
        let mut block_side_effect_complete = 0usize;
        for value in read_jsonl_values(&path)? {
            match value.get("status").and_then(Value::as_str) {
                Some("complete") => {
                    complete_cases += 1;
                    block_complete += 1;
                    if case_has_complete_side_effects(&value) {
                        block_side_effect_complete += 1;
                    }
                }
                _ => pending_cases += 1,
            }
        }
        if block_complete == 0 {
            uncharacterized_blocks.push(label.clone());
        }
        if block_complete > 0 && block_side_effect_complete == 0 {
            side_effect_incomplete_blocks.push(label.clone());
        }
    }

    let mut issues = Vec::new();
    issues.extend(waivers.issues.clone());
    if !missing_blocks.is_empty() {
        issues.push(format!(
            "{} block obligations are not mapped",
            missing_blocks.len()
        ));
    }
    if !invalid_mappings.is_empty() {
        issues.push(format!(
            "{} candidate mapping entries are invalid",
            invalid_mappings.len()
        ));
    }
    if !uncharacterized_blocks.is_empty() && !options.allow_incomplete_characterization {
        issues.push(format!(
            "{} block obligations have no complete original pre/post characterization case",
            uncharacterized_blocks.len()
        ));
    }
    if !side_effect_incomplete_blocks.is_empty() && !options.allow_incomplete_side_effects {
        issues.push(format!(
            "{} block obligations have no complete side-effect characterization case",
            side_effect_incomplete_blocks.len()
        ));
    }

    let candidate_results = match &options.candidate_trace {
        Some(path) => Some(validate_candidate_trace(
            suite,
            path,
            &block_labels,
            &waivers.waivers,
            options.allow_incomplete_side_effects,
        )?),
        None => None,
    };
    if let Some(report) = &candidate_results {
        if report.status != "pass" {
            issues.push(format!(
                "candidate conformance trace failed: {} failed, {} missing",
                report.failed_cases,
                report.missing_cases.len()
            ));
        }
    }

    Ok(CandidateValidationReport {
        format: VALIDATION_FORMAT,
        status: if issues.is_empty() { "pass" } else { "fail" }.to_string(),
        required_blocks: block_labels
            .len()
            .saturating_sub(required_waiver_count(&block_labels, &waivers.waivers)),
        mapped_blocks: block_labels.len().saturating_sub(missing_blocks.len()),
        waived_blocks: required_waiver_count(&block_labels, &waivers.waivers),
        missing_blocks,
        invalid_mappings,
        complete_cases,
        pending_cases,
        uncharacterized_blocks,
        side_effect_incomplete_blocks,
        candidate_results,
        issues,
    })
}

pub fn coverage_report_for_suite(
    suite: &Path,
    options: &CoverageOptions,
) -> Result<CoverageReport, String> {
    let all_block_labels = suite_block_labels(suite)?;
    let block_labels = suite_required_block_labels(suite)?;
    let waivers = load_waivers(options.waivers.as_deref(), &all_block_labels)?;
    let mut characterized_blocks = 0usize;
    let mut uncovered_blocks = Vec::new();
    let mut side_effect_incomplete_blocks = Vec::new();
    let mut complete_cases = 0usize;
    let mut pending_cases = 0usize;

    for label in &block_labels {
        if waivers.waivers.contains_key(label) {
            continue;
        }
        let path = suite.join("blocks").join(label).join("cases.jsonl");
        let mut block_complete = 0usize;
        let mut block_side_effect_complete = 0usize;
        for value in read_jsonl_values(&path)? {
            match value.get("status").and_then(Value::as_str) {
                Some("complete") => {
                    complete_cases += 1;
                    block_complete += 1;
                    if case_has_complete_side_effects(&value) {
                        block_side_effect_complete += 1;
                    }
                }
                _ => pending_cases += 1,
            }
        }
        if block_complete == 0 {
            uncovered_blocks.push(label.clone());
        } else {
            characterized_blocks += 1;
            if block_side_effect_complete == 0 {
                side_effect_incomplete_blocks.push(label.clone());
            }
        }
    }

    let mut issues = waivers.issues.clone();
    if !uncovered_blocks.is_empty() {
        issues.push(format!(
            "{} block obligations are uncovered and unwaived",
            uncovered_blocks.len()
        ));
    }
    if !side_effect_incomplete_blocks.is_empty() && !options.allow_incomplete_side_effects {
        issues.push(format!(
            "{} block obligations lack complete side-effect evidence",
            side_effect_incomplete_blocks.len()
        ));
    }

    Ok(CoverageReport {
        format: COVERAGE_FORMAT,
        status: if issues.is_empty() { "pass" } else { "fail" }.to_string(),
        required_blocks: block_labels
            .len()
            .saturating_sub(required_waiver_count(&block_labels, &waivers.waivers)),
        characterized_blocks,
        waived_blocks: required_waiver_count(&block_labels, &waivers.waivers),
        uncovered_blocks,
        side_effect_incomplete_blocks,
        complete_cases,
        pending_cases,
        waiver_issues: waivers.issues,
        issues,
    })
}

impl PeImage {
    pub fn parse(path: &Path) -> Result<Self, String> {
        let data = fs::read(path).map_err(|err| format!("read {}: {err}", path.display()))?;
        if data.len() < 0x40 {
            return Err(format!("{} is too small to be a PE image", path.display()));
        }
        let object_file = object::File::parse(data.as_slice())
            .map_err(|err| format!("parse PE object: {err}"))?;
        let object_format = format!("{:?}", object_file.format());
        let architecture = format!("{:?}", object_file.architecture());
        let object_sections = object_file
            .sections()
            .filter_map(|section| {
                let name = section.name().ok()?.to_string();
                Some((section.address() as u32, name))
            })
            .collect::<BTreeMap<_, _>>();

        if data.get(0..2) != Some(b"MZ") {
            return Err(format!("{} is missing MZ header", path.display()));
        }
        let pe_offset = read_u32(&data, 0x3c)? as usize;
        if data.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0") {
            return Err(format!("{} is missing PE signature", path.display()));
        }

        let coff = pe_offset + 4;
        let machine = read_u16(&data, coff)?;
        let section_count = read_u16(&data, coff + 2)? as usize;
        let optional_size = read_u16(&data, coff + 16)? as usize;
        let optional = coff + 20;
        let magic = read_u16(&data, optional)?;
        let is_pe64 = match magic {
            0x10b => false,
            0x20b => true,
            _ => {
                return Err(format!(
                    "{} has unsupported optional header magic 0x{magic:04x}",
                    path.display()
                ))
            }
        };
        let bitness = if is_pe64 || machine == 0x8664 { 64 } else { 32 };
        let entry_rva = read_u32(&data, optional + 16)?;
        let image_base = if is_pe64 {
            read_u64(&data, optional + 24)?
        } else {
            read_u32(&data, optional + 28)? as u64
        };

        let section_table = optional + optional_size;
        let mut sections = Vec::with_capacity(section_count);
        for index in 0..section_count {
            let base = section_table + index * 40;
            if base + 40 > data.len() {
                return Err(format!("{} has truncated section table", path.display()));
            }
            let name_bytes = &data[base..base + 8];
            let name_len = name_bytes.iter().position(|byte| *byte == 0).unwrap_or(8);
            let mut name = String::from_utf8_lossy(&name_bytes[..name_len]).to_string();
            let virtual_size = read_u32(&data, base + 8)?;
            let virtual_address = read_u32(&data, base + 12)?;
            if name.is_empty() {
                if let Some(object_name) = object_sections.get(&virtual_address) {
                    name = object_name.clone();
                }
            }
            let characteristics = read_u32(&data, base + 36)?;
            sections.push(PeSection {
                name,
                virtual_size,
                virtual_address,
                raw_size: read_u32(&data, base + 16)?,
                raw_pointer: read_u32(&data, base + 20)?,
                executable: characteristics & 0x2000_0000 != 0,
                characteristics,
            });
        }

        Ok(Self {
            path: path.to_path_buf(),
            object_format,
            architecture,
            machine,
            bitness,
            is_pe64,
            image_base,
            entry_rva,
            sections,
            data,
        })
    }

    pub fn executable_sections(&self) -> impl Iterator<Item = &PeSection> {
        self.sections.iter().filter(|section| section.executable)
    }

    fn section_bytes(&self, section: &PeSection) -> &[u8] {
        let start = section.raw_pointer as usize;
        let size = section.decoded_file_size() as usize;
        if start >= self.data.len() {
            return &[];
        }
        let end = start.saturating_add(size).min(self.data.len());
        &self.data[start..end]
    }

    fn contains_executable_rva(&self, rva: u32) -> bool {
        self.executable_sections()
            .any(|section| section.contains_rva(rva))
    }
}

impl PeSection {
    pub fn effective_virtual_size(&self) -> u32 {
        if self.virtual_size == 0 {
            self.raw_size
        } else {
            self.virtual_size
        }
    }

    pub fn decoded_file_size(&self) -> u32 {
        if self.virtual_size == 0 {
            self.raw_size
        } else {
            self.raw_size.min(self.virtual_size)
        }
    }

    pub fn contains_rva(&self, rva: u32) -> bool {
        let start = self.virtual_address;
        let end = start.saturating_add(self.effective_virtual_size());
        rva >= start && rva < end
    }
}

impl Terminator {
    fn ends_block(self) -> bool {
        matches!(
            self,
            Terminator::Ret
                | Terminator::Jump
                | Terminator::ConditionalJump
                | Terminator::IndirectJump
                | Terminator::Call
                | Terminator::IndirectCall
                | Terminator::Trap
        )
    }
}

fn recover_blocks(image: PeImage) -> Recovery {
    let mut all_instructions = Vec::new();
    let mut issues = Vec::new();
    let mut executable_bytes = 0u64;
    let mut recovered_instruction_bytes = 0u64;
    let mut unknown_bytes = 0u64;

    for section in image.executable_sections() {
        executable_bytes += section.effective_virtual_size() as u64;
        let bytes = image.section_bytes(section);
        let section_instructions = decode_section(bytes, section.virtual_address, image.bitness);
        for instr in &section_instructions {
            recovered_instruction_bytes += instr.len as u64;
            if !instr.valid {
                unknown_bytes += instr.len as u64;
                issues.push(RecoveryIssue {
                    severity: "error".to_string(),
                    rva_start: instr.rva,
                    rva_end: instr.rva.saturating_add(instr.len),
                    message: "invalid or undecodable instruction byte in executable section"
                        .to_string(),
                });
            }
        }
        all_instructions.extend(section_instructions);
    }
    all_instructions.sort_by_key(|instr| instr.rva);

    let mut leaders = BTreeSet::new();
    for section in image.executable_sections() {
        leaders.insert(section.virtual_address);
    }
    if image.contains_executable_rva(image.entry_rva) {
        leaders.insert(image.entry_rva);
    }
    for instr in &all_instructions {
        let next = instr.rva.saturating_add(instr.len);
        if !instr.valid {
            leaders.insert(instr.rva);
            if image.contains_executable_rva(next) {
                leaders.insert(next);
            }
            continue;
        }
        if let Some(target) = instr.target {
            if image.contains_executable_rva(target) {
                leaders.insert(target);
            }
        }
        if instr.terminator.ends_block() && image.contains_executable_rva(next) {
            leaders.insert(next);
        }
    }

    let mut blocks = Vec::new();
    let mut current = Vec::new();
    for (index, instr) in all_instructions.iter().enumerate() {
        if leaders.contains(&instr.rva) && !current.is_empty() {
            push_block(&mut blocks, &current, &image);
            current.clear();
        }
        current.push(instr.clone());
        let next_is_leader = all_instructions
            .get(index + 1)
            .map(|next| leaders.contains(&next.rva))
            .unwrap_or(false);
        if instr.terminator.ends_block() || next_is_leader {
            push_block(&mut blocks, &current, &image);
            current.clear();
        }
    }
    if !current.is_empty() {
        push_block(&mut blocks, &current, &image);
    }
    blocks.sort_by_key(|block| block.rva_start);
    classify_alignment_padding(&mut blocks, image.entry_rva);

    Recovery {
        format: RECOVERY_FORMAT,
        image,
        executable_bytes,
        recovered_instruction_bytes,
        unknown_bytes,
        blocks,
        issues,
    }
}

fn classify_alignment_padding(blocks: &mut [BasicBlock], entry_rva: u32) {
    let mut incoming = BTreeMap::<u32, usize>::new();
    for block in blocks.iter() {
        for successor in &block.successors {
            *incoming.entry(*successor).or_insert(0) += 1;
        }
    }

    for block in blocks {
        let has_incoming = incoming.get(&block.rva_start).copied().unwrap_or(0) > 0;
        if block.rva_start != entry_rva
            && !has_incoming
            && block
                .instructions
                .iter()
                .all(is_alignment_padding_instruction)
        {
            block.classification = ALIGNMENT_PADDING_CLASSIFICATION.to_string();
        }
    }
}

fn is_alignment_padding_instruction(instruction: &BlockInstruction) -> bool {
    instruction.valid && instruction.mnemonic == "nop"
}

fn decode_section(bytes: &[u8], base_rva: u32, bitness: u32) -> Vec<BlockInstruction> {
    let mut decoder = Decoder::with_ip(bitness, bytes, base_rva as u64, DecoderOptions::NONE);
    let end_ip = base_rva as u64 + bytes.len() as u64;
    let mut instructions = Vec::new();
    while decoder.can_decode() && decoder.ip() < end_ip {
        let instr = decoder.decode();
        let len = instr.len().max(1) as u32;
        let rva = instr.ip() as u32;
        let offset = rva.saturating_sub(base_rva) as usize;
        let instr_bytes = bytes
            .get(offset..offset.saturating_add(len as usize))
            .map(hex_bytes)
            .unwrap_or_default();
        instructions.push(block_instruction(&instr, rva, len, instr_bytes));
    }
    instructions
}

fn block_instruction(
    instr: &IcedInstruction,
    rva: u32,
    len: u32,
    bytes: String,
) -> BlockInstruction {
    let flow_control = format!("{:?}", instr.flow_control());
    let terminator = match flow_control.as_str() {
        "Return" => Terminator::Ret,
        "UnconditionalBranch" => Terminator::Jump,
        "IndirectBranch" => Terminator::IndirectJump,
        "ConditionalBranch" | "Xbegin" => Terminator::ConditionalJump,
        "Call" => Terminator::Call,
        "IndirectCall" => Terminator::IndirectCall,
        "Interrupt" | "Exception" | "Xabort" => Terminator::Trap,
        _ => Terminator::None,
    };
    let target = match terminator {
        Terminator::Jump | Terminator::ConditionalJump | Terminator::Call => {
            let target = instr.near_branch_target();
            u32::try_from(target).ok()
        }
        _ => None,
    };
    let valid = !instr.is_invalid();
    BlockInstruction {
        rva,
        len,
        bytes,
        mnemonic: format!("{:?}", instr.mnemonic()).to_ascii_lowercase(),
        flow_control,
        terminator,
        target,
        valid,
    }
}

fn push_block(blocks: &mut Vec<BasicBlock>, instructions: &[BlockInstruction], image: &PeImage) {
    if instructions.is_empty() {
        return;
    }
    let first = instructions.first().unwrap();
    let last = instructions.last().unwrap();
    let rva_start = first.rva;
    let rva_end = last.rva.saturating_add(last.len);
    let terminator = last.terminator;
    let mut successors = Vec::new();
    match terminator {
        Terminator::ConditionalJump => {
            if let Some(target) = last.target {
                if image.contains_executable_rva(target) {
                    successors.push(target);
                }
            }
            if image.contains_executable_rva(rva_end) {
                successors.push(rva_end);
            }
        }
        Terminator::Jump => {
            if let Some(target) = last.target {
                if image.contains_executable_rva(target) {
                    successors.push(target);
                }
            }
        }
        Terminator::None | Terminator::Call | Terminator::IndirectCall => {
            if image.contains_executable_rva(rva_end) {
                successors.push(rva_end);
            }
        }
        Terminator::Ret | Terminator::IndirectJump | Terminator::Trap => {}
    }
    successors.sort_unstable();
    successors.dedup();
    let classification = if instructions.iter().all(|instr| instr.valid) {
        "code"
    } else {
        "unknown"
    };
    blocks.push(BasicBlock {
        label: block_label(rva_start, rva_end),
        rva_start,
        rva_end,
        size: rva_end.saturating_sub(rva_start),
        instruction_count: instructions.len(),
        classification: classification.to_string(),
        instructions: instructions.to_vec(),
        successors,
        terminator,
    });
}

fn characterize_traces(
    paths: &[PathBuf],
    blocks: &[BasicBlock],
    options: &SuiteOptions,
) -> Result<Characterization, String> {
    let mut result = Characterization::default();
    let mut open_entries: BTreeMap<(String, String, String), VecDeque<TraceEvent>> =
        BTreeMap::new();
    let mut dropped_cases = 0usize;
    for path in paths {
        characterize_trace_path(
            path,
            blocks,
            options,
            &mut result,
            &mut open_entries,
            &mut dropped_cases,
        )?;
    }

    for ((source, test_id, block_label), entries) in open_entries {
        for (index, entry) in entries.into_iter().enumerate() {
            store_case(
                &mut result,
                &block_label,
                OwnedCase {
                    case_id: format!("{source}:{test_id}:{block_label}:entry_pending:{index}"),
                    origin: "original_trace_v2",
                    status: "entry_only_pending_exit_snapshot",
                    pre_state: entry.state,
                    expected: None,
                    trace_refs: vec![entry.raw.to_string()],
                },
                options,
                &mut dropped_cases,
            );
        }
    }
    add_static_simple_cases_for_uncovered_blocks(blocks, options, &mut result, &mut dropped_cases);
    if dropped_cases > 0 {
        let cap = options
            .max_cases_per_block
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unbounded".to_string());
        result.issues.push(format!(
            "case emission capped by max_cases_per_block={cap}; dropped {dropped_cases} excess cases"
        ));
    }

    Ok(result)
}

fn add_static_simple_cases_for_uncovered_blocks(
    blocks: &[BasicBlock],
    options: &SuiteOptions,
    result: &mut Characterization,
    dropped_cases: &mut usize,
) {
    for block in blocks {
        let has_complete_case = result
            .cases_by_block
            .get(&block.label)
            .is_some_and(|cases| cases.iter().any(|case| case.status == "complete"));
        if has_complete_case {
            continue;
        }
        if let Some(case) = static_simple_x86_32_case(block) {
            store_case(result, &block.label, case, options, dropped_cases);
        }
    }
}

fn static_simple_x86_32_case(block: &BasicBlock) -> Option<OwnedCase> {
    if block.instructions.len() != 3
        || block.instructions[0].bytes != "31c0"
        || block.instructions[1].bytes != "31d2"
        || block.instructions[2].bytes != "c3"
    {
        return None;
    }

    let stack = [0x0040_1000u64, 0x2222_2222, 0x3333_3333, 0x4444_4444];
    let pre_xsp = 0x0010_0000u64;
    let pre_registers = json!({
        "xax": 0x1111_1111u64,
        "xbp": 0x0020_0000u64,
        "xbx": 0x3333_0000u64,
        "xcx": 0x4444_0000u64,
        "xdi": 0x5555_0000u64,
        "xdx": 0x6666_0000u64,
        "xsi": 0x7777_0000u64,
        "xsp": pre_xsp,
    });
    let mut post_registers = pre_registers.clone();
    post_registers["xax"] = json!(0);
    post_registers["xdx"] = json!(0);
    post_registers["xsp"] = json!(pre_xsp + 4);

    Some(OwnedCase {
        case_id: format!("static-x86-32:{}:zero-return", block.label),
        origin: "static_x86_32_block_semantics_v1",
        status: "complete",
        pre_state: json!({
            "flags": {"xflags": 0x202u64},
            "registers": pre_registers,
            "stack_top": stack,
            "synthetic": {
                "kind": "block_local_seed",
                "source": "exact_instruction_pattern",
                "pattern": "31c031d2c3"
            }
        }),
        expected: Some(ExpectedState {
            post_state: json!({
                "flags": {"xflags": 0x246u64},
                "registers": post_registers,
                "stack_top": [stack[1], stack[2], stack[3]],
                "synthetic": {
                    "kind": "block_local_seed",
                    "source": "exact_instruction_pattern",
                    "pattern": "31c031d2c3"
                }
            }),
            successor_rva: Some("0x1000".to_string()),
            side_effects: json!({
                "format": "wincr-block-side-effects-v1",
                "capture_status": "complete",
                "memory_reads": [{
                    "address": pre_xsp,
                    "instr_rva": block.rva_end.saturating_sub(1),
                    "size": 4,
                    "value": "00104000",
                    "read_ok": true,
                    "truncated": false,
                    "region": "synthetic_stack"
                }],
                "memory_writes": [],
                "api_calls": [],
                "api_returns": [],
                "callbacks": [],
                "external_events": [],
                "limitations": [],
                "dropped": {
                    "api_calls": 0,
                    "memory_reads": 0,
                    "memory_writes": 0,
                    "pending_writes": 0,
                    "syscalls": 0
                },
                "memory_aggregates": {
                    "reads": {"count": 0, "sha256": "", "sha256_ok": false},
                    "writes": {"count": 0, "sha256": "", "sha256_ok": false}
                }
            }),
        }),
        trace_refs: vec![json!({
            "kind": "static_x86_32_block_semantics",
            "block_label": block.label,
            "rva": hex_u32(block.rva_start),
            "pattern": "31c031d2c3",
            "semantics": "xor eax,eax; xor edx,edx; ret",
            "limitations": ["static_seed_until_runtime_block_fuzzer_available"]
        })
        .to_string()],
    })
}

fn characterize_trace_path(
    path: &Path,
    blocks: &[BasicBlock],
    options: &SuiteOptions,
    result: &mut Characterization,
    open_entries: &mut BTreeMap<(String, String, String), VecDeque<TraceEvent>>,
    dropped_cases: &mut usize,
) -> Result<(), String> {
    let source = trace_source_id(path);
    let file = File::open(path).map_err(|err| format!("open {}: {err}", path.display()))?;
    let reader = BufReader::new(file);
    for (line_number, line) in reader.lines().enumerate() {
        let line =
            line.map_err(|err| format!("read {}:{}: {err}", path.display(), line_number + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let raw: Value = serde_json::from_str(&line).map_err(|err| {
            format!(
                "parse {}:{} as JSON: {err}",
                path.display(),
                line_number + 1
            )
        })?;
        let kind = raw
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{}:{} missing kind", path.display(), line_number + 1))?;
        let event = match kind {
            "block_entry" => Some(trace_event(
                &raw,
                TraceEventKind::Entry,
                &source,
                line_number + 1,
            )?),
            "block_exit" => Some(trace_event(
                &raw,
                TraceEventKind::Exit,
                &source,
                line_number + 1,
            )?),
            "value_trace" => Some(legacy_value_trace_event(&raw, &source, line_number + 1)?),
            _ => None,
        };
        if let Some(event) = event {
            process_trace_event(event, blocks, options, result, open_entries, dropped_cases);
        }
    }
    Ok(())
}

fn process_trace_event(
    event: TraceEvent,
    blocks: &[BasicBlock],
    options: &SuiteOptions,
    result: &mut Characterization,
    open_entries: &mut BTreeMap<(String, String, String), VecDeque<TraceEvent>>,
    dropped_cases: &mut usize,
) {
    result.trace_records += 1;
    let Some(block_label) = event
        .block_label
        .clone()
        .or_else(|| label_for_rva(blocks, event.rva))
    else {
        result.issues.push(format!(
            "{}:{} references RVA {} outside recovered blocks",
            event.source,
            event.line_number,
            hex_u32(event.rva)
        ));
        return;
    };
    let key = (
        event.source.clone(),
        event.test_id.clone(),
        block_label.clone(),
    );
    match event.kind {
        TraceEventKind::Entry => {
            open_entries.entry(key).or_default().push_back(event);
        }
        TraceEventKind::Exit => {
            let Some(entry) = open_entries.get_mut(&key).and_then(VecDeque::pop_front) else {
                result.issues.push(format!(
                    "block_exit without matching block_entry for {} in test {}",
                    block_label, event.test_id
                ));
                return;
            };
            let case_id = format!(
                "{}:{}:{}:complete:{}",
                event.source, event.test_id, block_label, event.line_number
            );
            store_case(
                result,
                &block_label,
                OwnedCase {
                    case_id,
                    origin: "original_trace_v2",
                    status: "complete",
                    pre_state: entry.state,
                    expected: Some(ExpectedState {
                        post_state: event.state,
                        successor_rva: event.successor_rva.map(hex_u32),
                        side_effects: event.side_effects,
                    }),
                    trace_refs: vec![entry.raw.to_string(), event.raw.to_string()],
                },
                options,
                dropped_cases,
            );
        }
    }
}

fn store_case(
    result: &mut Characterization,
    block_label: &str,
    case: OwnedCase,
    options: &SuiteOptions,
    dropped_cases: &mut usize,
) {
    let is_pending = case.expected.is_none();
    let new_side_effect_complete = case
        .expected
        .as_ref()
        .map(|expected| side_effects_are_complete(&expected.side_effects))
        .unwrap_or(false);
    let cases = result
        .cases_by_block
        .entry(block_label.to_string())
        .or_default();
    if let Some(max_cases) = options.max_cases_per_block {
        if cases.len() >= max_cases {
            if new_side_effect_complete {
                if let Some(index) = cases.iter().position(|existing| {
                    existing
                        .expected
                        .as_ref()
                        .is_some_and(|expected| !side_effects_are_complete(&expected.side_effects))
                }) {
                    cases[index] = case;
                    return;
                }
            }
            *dropped_cases += 1;
            return;
        }
    }
    cases.push(case);
    if is_pending {
        result.pending_cases += 1;
    } else {
        result.complete_cases += 1;
    }
}

fn trace_event(
    raw: &Value,
    kind: TraceEventKind,
    source: &str,
    line_number: usize,
) -> Result<TraceEvent, String> {
    let rva =
        rva_field(raw, "rva").ok_or_else(|| format!("trace line {line_number} missing rva"))?;
    let state = raw.get("state").cloned().unwrap_or_else(|| json!({}));
    Ok(TraceEvent {
        kind,
        source: source.to_string(),
        line_number,
        test_id: string_field(raw, "test_id").unwrap_or_else(|| "unknown-test".to_string()),
        rva,
        block_label: string_field(raw, "block_label"),
        state,
        successor_rva: rva_field(raw, "successor_rva"),
        side_effects: raw
            .get("side_effects")
            .cloned()
            .unwrap_or_else(|| json!({})),
        raw: raw.clone(),
    })
}

fn legacy_value_trace_event(
    raw: &Value,
    source: &str,
    line_number: usize,
) -> Result<TraceEvent, String> {
    let rva =
        rva_field(raw, "rva").ok_or_else(|| format!("trace line {line_number} missing rva"))?;
    Ok(TraceEvent {
        kind: TraceEventKind::Entry,
        source: source.to_string(),
        line_number,
        test_id: string_field(raw, "test_id").unwrap_or_else(|| "legacy-value-trace".to_string()),
        rva,
        block_label: string_field(raw, "block_label"),
        state: raw.get("values").cloned().unwrap_or_else(|| json!({})),
        successor_rva: None,
        side_effects: json!({}),
        raw: raw.clone(),
    })
}

fn block_obligation(block: &BasicBlock) -> BlockObligation<'_> {
    let behavior_required = block_behavior_required(block);
    BlockObligation {
        format: SUITE_FORMAT,
        artifact_role: "block_obligation",
        taint_level: "private_high_taint",
        block_label: &block.label,
        rva_start: hex_u32(block.rva_start),
        rva_end: hex_u32(block.rva_end),
        size: block.size,
        classification: &block.classification,
        terminator: block.terminator,
        successors: block.successors.iter().copied().map(hex_u32).collect(),
        instructions: &block.instructions,
        candidate_requirement: CandidateRequirement {
            distinct_semantic_point: behavior_required,
            pre_state_adapter: behavior_required,
            post_state_adapter: behavior_required,
            side_effect_adapter: behavior_required,
        },
    }
}

fn state_schema(
    block: &BasicBlock,
    complete_cases: usize,
    pending_cases: usize,
) -> StateSchema<'_> {
    let non_behavioral_padding = !block_behavior_required(block);
    StateSchema {
        format: SUITE_FORMAT,
        artifact_role: "block_state_schema",
        block_label: &block.label,
        evidence_level: if non_behavioral_padding {
            "static_non_behavioral_alignment_padding"
        } else if complete_cases > 0 {
            "complete_pre_post_trace"
        } else if pending_cases > 0 {
            "entry_snapshot_only"
        } else {
            "static_only"
        },
        complete_cases,
        pending_cases,
        required_inputs: vec![
            "registers",
            "flags",
            "stack_slice",
            "globals",
            "heap_object_slices",
            "api_environment",
        ],
        required_outputs: vec![
            "register_diff",
            "flag_diff",
            "memory_diff",
            "successor_edge",
            "calls",
            "returns",
            "exceptions",
            "side_effects",
        ],
        fuzz_policy: "snapshot_seeded_only",
        conformance_status: if non_behavioral_padding {
            "not_required_alignment_padding"
        } else if complete_cases > 0 {
            "ready_for_candidate_replay"
        } else {
            "pending_complete_pre_post_snapshots"
        },
    }
}

fn side_effects<'a>(block: &'a BasicBlock, cases: &[OwnedCase]) -> SideEffectModel<'a> {
    let mut observed = BTreeSet::new();
    let mut capture_status_counts = BTreeMap::new();
    let mut limitations = BTreeSet::new();
    let mut complete_cases = 0usize;
    let mut complete_side_effect_cases = 0usize;
    let mut incomplete_side_effect_cases = 0usize;
    for case in cases {
        if case.status != "complete" {
            continue;
        }
        complete_cases += 1;
        let side_effects = case
            .expected
            .as_ref()
            .map(|expected| &expected.side_effects)
            .unwrap_or(&Value::Null);
        collect_observed_effect_classes(side_effects, &mut observed);
        if let Some(status) = side_effects
            .get("capture_status")
            .or_else(|| side_effects.get("status"))
            .and_then(Value::as_str)
        {
            *capture_status_counts.entry(status.to_string()).or_insert(0) += 1;
        }
        collect_side_effect_limitations(side_effects, &mut limitations);
        if side_effects_are_complete(side_effects) {
            complete_side_effect_cases += 1;
        } else {
            incomplete_side_effect_cases += 1;
        }
    }
    let status = if complete_cases == 0 {
        "pending_block_characterization"
    } else if complete_side_effect_cases == complete_cases {
        "complete"
    } else if complete_side_effect_cases > 0 {
        "partial"
    } else {
        "pending_typed_side_effect_capture"
    };
    SideEffectModel {
        format: SIDE_EFFECT_FORMAT,
        artifact_role: "block_side_effect_model",
        block_label: &block.label,
        status: status.to_string(),
        complete_cases,
        complete_side_effect_cases,
        incomplete_side_effect_cases,
        observed_effect_classes: observed.into_iter().collect(),
        capture_status_counts,
        limitations: limitations.into_iter().collect(),
        missing_effect_classes: required_effect_classes(),
        comparison_policy: SideEffectComparisonPolicy {
            exact_memory_writes: true,
            exact_api_calls: true,
            exact_external_events: true,
            ignored_fields: vec!["addresses_normalized_by_adapter"],
        },
    }
}

fn block_case_summaries(
    blocks: &[BasicBlock],
    characterization: &Characterization,
) -> BTreeMap<String, BlockCaseSummary> {
    let mut summaries = BTreeMap::new();
    for block in blocks {
        let mut summary = BlockCaseSummary::default();
        if let Some(cases) = characterization.cases_by_block.get(&block.label) {
            for case in cases {
                if case.status == "complete" {
                    summary.complete_cases += 1;
                    if case
                        .expected
                        .as_ref()
                        .map(|expected| side_effects_are_complete(&expected.side_effects))
                        .unwrap_or(false)
                    {
                        summary.complete_side_effect_cases += 1;
                    } else {
                        summary.incomplete_side_effect_cases += 1;
                    }
                } else {
                    summary.pending_cases += 1;
                }
            }
        }
        summaries.insert(block.label.clone(), summary);
    }
    summaries
}

fn block_coverage(
    block: &BasicBlock,
    summary: &BlockCaseSummary,
    waiver: Option<BlockWaiver>,
) -> BlockCoverage {
    let non_behavioral_padding = !block_behavior_required(block);
    let status = if non_behavioral_padding {
        "non_behavioral_alignment_padding"
    } else if waiver.is_some() {
        "waived"
    } else if summary.complete_cases > 0 {
        "covered"
    } else if summary.pending_cases > 0 {
        "entry_only_pending_exit"
    } else {
        "uncovered"
    };
    let side_effect_status = if non_behavioral_padding {
        "not_applicable_alignment_padding"
    } else if summary.complete_cases == 0 {
        "not_applicable_until_block_covered"
    } else if summary.complete_side_effect_cases == summary.complete_cases {
        "complete"
    } else if summary.complete_side_effect_cases > 0 {
        "partial"
    } else {
        "incomplete"
    };
    BlockCoverage {
        format: COVERAGE_FORMAT,
        artifact_role: "block_coverage",
        block_label: block.label.clone(),
        status: status.to_string(),
        complete_cases: summary.complete_cases,
        pending_cases: summary.pending_cases,
        side_effect_status: side_effect_status.to_string(),
        waiver,
    }
}

fn block_behavior_required(block: &BasicBlock) -> bool {
    block.classification != ALIGNMENT_PADDING_CLASSIFICATION
}

fn required_effect_classes() -> Vec<&'static str> {
    vec![
        "memory_reads",
        "memory_writes",
        "api_calls",
        "api_returns",
        "api_output_buffers",
        "api_resources",
        "callbacks",
        "callback_effects",
        "window_callbacks",
        "timer_callbacks",
        "thread_callbacks",
        "drawing_effects",
        "message_effects",
        "registry_effects",
        "window_effects",
        "window_long_effects",
        "subclass_effects",
        "paint_effects",
        "input_effects",
        "raw_input_effects",
        "audio_effects",
        "audio_output",
        "timer_effects",
        "time_effects",
        "process_effects",
        "dynamic_loading_effects",
        "dynamic_loading",
        "com_vtable_effects",
        "com_vtable",
        "thread_effects",
        "sync_effects",
        "synchronization",
        "gdi_state_effects",
        "class_effects",
        "cursor_effects",
        "external_events",
        "syscalls",
        "last_error",
        "files",
        "network",
        "device_io",
        "vector_io",
        "registry",
        "stdout",
        "stderr",
        "process_exit",
        "window_messages",
        "gdi_calls",
        "time",
        "rng",
        "input_events",
        "threading",
        "exceptions",
    ]
}

fn collect_side_effect_limitations(side_effects: &Value, limitations: &mut BTreeSet<String>) {
    if let Some(items) = side_effects.get("limitations").and_then(Value::as_array) {
        for item in items {
            if let Some(text) = item.as_str() {
                if !text.is_empty() {
                    limitations.insert(text.to_string());
                }
            }
        }
    }
}

fn collect_observed_effect_classes(side_effects: &Value, observed: &mut BTreeSet<String>) {
    for class in required_effect_classes() {
        if let Some(value) = side_effects.get(class) {
            if !value_is_empty_effect(value) {
                observed.insert(class.to_string());
            }
        }
    }
    if let Some(aggregates) = side_effects.get("memory_aggregates") {
        if aggregates
            .get("reads")
            .and_then(|reads| reads.get("count"))
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > 0
        {
            observed.insert("memory_reads".to_string());
        }
        if aggregates
            .get("writes")
            .and_then(|writes| writes.get("count"))
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > 0
        {
            observed.insert("memory_writes".to_string());
        }
    }
    if let Some(events) = side_effects
        .get("external_events")
        .and_then(Value::as_array)
    {
        if !events.is_empty() {
            observed.insert("external_events".to_string());
        }
        for event in events {
            if event.get("kind").and_then(Value::as_str) == Some("syscall") {
                observed.insert("syscalls".to_string());
                if let Some(semantic_class) = event.get("semantic_class").and_then(Value::as_str) {
                    if !semantic_class.is_empty() && semantic_class != "unknown" {
                        observed.insert(format!("syscall:{semantic_class}"));
                        if semantic_class == "network" {
                            observed.insert("network".to_string());
                        }
                        if semantic_class == "device_io" {
                            observed.insert("device_io".to_string());
                        }
                    }
                }
                if let Some(buffers) = event.get("buffers").and_then(Value::as_array) {
                    for buffer in buffers {
                        if matches!(
                            buffer.get("source").and_then(Value::as_str),
                            Some("iovec_data" | "msghdr_iovec_data")
                        ) {
                            observed.insert("vector_io".to_string());
                            observed.insert("syscall:vector_io".to_string());
                        }
                    }
                }
                if let Some(buffers) = event
                    .get("buffer_aggregate")
                    .and_then(|aggregate| aggregate.get("entries"))
                    .and_then(Value::as_array)
                {
                    for buffer in buffers {
                        if matches!(
                            buffer.get("source").and_then(Value::as_str),
                            Some("iovec_data" | "msghdr_iovec_data")
                        ) {
                            observed.insert("vector_io".to_string());
                            observed.insert("syscall:vector_io".to_string());
                        }
                    }
                }
                if let Some(aggregates) = event.get("aggregates").and_then(Value::as_array) {
                    for aggregate in aggregates {
                        if matches!(
                            aggregate.get("source").and_then(Value::as_str),
                            Some("iovec_array" | "mmsghdr_array")
                        ) {
                            observed.insert("vector_io".to_string());
                            observed.insert("syscall:vector_io".to_string());
                        }
                    }
                }
            }
        }
    }
    if let Some(callbacks) = side_effects.get("callbacks").and_then(Value::as_array) {
        if !callbacks.is_empty() {
            observed.insert("callbacks".to_string());
            observed.insert("callback_effects".to_string());
        }
        for callback in callbacks {
            if let Some(operation) = callback.get("operation").and_then(Value::as_str) {
                if !operation.is_empty() {
                    observed.insert(format!("callback:{operation}"));
                    if operation == "wndproc_entry" {
                        observed.insert("window_callbacks".to_string());
                        observed.insert("window_messages".to_string());
                    } else if operation == "timerproc_entry" {
                        observed.insert("timer_callbacks".to_string());
                        observed.insert("timer_effects".to_string());
                    } else if operation == "thread_entry" {
                        observed.insert("thread_callbacks".to_string());
                        observed.insert("thread_effects".to_string());
                        observed.insert("threading".to_string());
                    }
                }
            }
        }
    }
    if let Some(calls) = side_effects.get("api_calls").and_then(Value::as_array) {
        if !calls.is_empty() {
            observed.insert("api_calls".to_string());
        }
        for call in calls {
            if let Some(semantic_class) = call.get("semantic_class").and_then(Value::as_str) {
                if !semantic_class.is_empty() && semantic_class != "unknown" {
                    observed.insert(format!("api:{semantic_class}"));
                }
            }
            if let Some(resource) = call.get("resource") {
                if resource.get("known").and_then(Value::as_bool) == Some(true) {
                    observed.insert("api_resources".to_string());
                    if let Some(kind) = resource.get("kind").and_then(Value::as_str) {
                        if !kind.is_empty() {
                            observed.insert(format!("api_resource:{kind}"));
                        }
                    }
                }
            }
            if let Some(resources) = call.get("resource_refs").and_then(Value::as_array) {
                for resource in resources {
                    if resource.get("known").and_then(Value::as_bool) == Some(true) {
                        observed.insert("api_resources".to_string());
                        if let Some(kind) = resource.get("kind").and_then(Value::as_str) {
                            if !kind.is_empty() {
                                observed.insert(format!("api_resource:{kind}"));
                            }
                        }
                    }
                }
            }
            if let Some(resources) = call
                .get("resource_ref_aggregate")
                .and_then(|aggregate| aggregate.get("entries"))
                .and_then(Value::as_array)
            {
                for resource in resources {
                    if resource.get("known").and_then(Value::as_bool) == Some(true) {
                        observed.insert("api_resources".to_string());
                        if let Some(kind) = resource.get("kind").and_then(Value::as_str) {
                            if !kind.is_empty() {
                                observed.insert(format!("api_resource:{kind}"));
                            }
                        }
                    }
                }
            }
            if call
                .get("output_buffers")
                .and_then(Value::as_array)
                .is_some_and(|buffers| !buffers.is_empty())
                || call
                    .get("output_buffer_aggregate")
                    .and_then(|aggregate| aggregate.get("count"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    > 0
            {
                observed.insert("api_output_buffers".to_string());
            }
            if call
                .get("draw_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("drawing_effects".to_string());
                if let Some(operation) = call
                    .get("draw_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("drawing:{operation}"));
                    }
                }
                if call
                    .get("draw_effect")
                    .and_then(|effect| effect.get("framebuffer_effect"))
                    .and_then(|effect| effect.get("captured"))
                    .and_then(Value::as_bool)
                    == Some(true)
                {
                    observed.insert("framebuffer_effects".to_string());
                    if let Some(kind) = call
                        .get("draw_effect")
                        .and_then(|effect| effect.get("framebuffer_effect"))
                        .and_then(|effect| effect.get("presentation_kind"))
                        .and_then(Value::as_str)
                    {
                        if !kind.is_empty() {
                            observed.insert(format!("framebuffer:{kind}"));
                        }
                    }
                }
            }
            if call
                .get("message_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("message_effects".to_string());
                if let Some(operation) = call
                    .get("message_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("message:{operation}"));
                    }
                }
            }
            if call
                .get("registry_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("registry_effects".to_string());
                if let Some(operation) = call
                    .get("registry_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("registry:{operation}"));
                    }
                }
            }
            if call
                .get("window_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("window_effects".to_string());
                if let Some(operation) = call
                    .get("window_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("window:{operation}"));
                    }
                }
            }
            if call
                .get("window_long_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("window_long_effects".to_string());
                if let Some(operation) = call
                    .get("window_long_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("window_long:{operation}"));
                    }
                }
                if call
                    .get("window_long_effect")
                    .and_then(|effect| effect.get("slot"))
                    .and_then(Value::as_str)
                    == Some("wndproc")
                {
                    observed.insert("subclass_effects".to_string());
                    observed.insert("window_callbacks".to_string());
                }
            }
            if call
                .get("paint_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("paint_effects".to_string());
                if let Some(operation) = call
                    .get("paint_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("paint:{operation}"));
                    }
                }
            }
            if call
                .get("input_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("input_effects".to_string());
                observed.insert("input_events".to_string());
                if let Some(operation) = call
                    .get("input_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("input:{operation}"));
                        if matches!(
                            operation,
                            "register_raw_input_devices" | "get_raw_input_data"
                        ) {
                            observed.insert("raw_input_effects".to_string());
                        }
                    }
                }
            }
            if call
                .get("audio_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("audio_effects".to_string());
                observed.insert("audio_output".to_string());
                if let Some(operation) = call
                    .get("audio_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("audio:{operation}"));
                    }
                }
            }
            if call
                .get("timer_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("timer_effects".to_string());
                if let Some(operation) = call
                    .get("timer_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("timer:{operation}"));
                    }
                }
            }
            if call
                .get("thread_error_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("thread_error_effects".to_string());
                observed.insert("thread_error_state".to_string());
                if let Some(operation) = call
                    .get("thread_error_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("thread_error:{operation}"));
                    }
                }
            }
            if call
                .get("time_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("time_effects".to_string());
                observed.insert("time".to_string());
                if let Some(operation) = call
                    .get("time_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("time:{operation}"));
                    }
                }
            }
            if call
                .get("process_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("process_effects".to_string());
                if let Some(operation) = call
                    .get("process_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("process:{operation}"));
                        if operation == "exit_process" {
                            observed.insert("process_exit".to_string());
                        }
                    }
                }
            }
            if call
                .get("file_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("file_effects".to_string());
                observed.insert("files".to_string());
                if let Some(operation) = call
                    .get("file_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("file:{operation}"));
                    }
                }
            }
            if call
                .get("network_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("network_effects".to_string());
                observed.insert("network".to_string());
                if let Some(operation) = call
                    .get("network_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("network:{operation}"));
                    }
                }
            }
            if call
                .get("memory_api_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("memory_api_effects".to_string());
                observed.insert("memory".to_string());
                if let Some(operation) = call
                    .get("memory_api_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("memory_api:{operation}"));
                    }
                }
            }
            if call
                .get("dynamic_loader_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("dynamic_loading_effects".to_string());
                observed.insert("dynamic_loading".to_string());
                if let Some(operation) = call
                    .get("dynamic_loader_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("dynamic_loading:{operation}"));
                    }
                }
            }
            if call
                .get("com_vtable_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("com_vtable_effects".to_string());
                observed.insert("com_vtable".to_string());
                if let Some(operation) = call
                    .get("com_vtable_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("com_vtable:{operation}"));
                    }
                }
                if let Some(semantic_kind) = call
                    .get("com_vtable_effect")
                    .and_then(|effect| effect.get("semantic_kind"))
                    .and_then(Value::as_str)
                {
                    if !semantic_kind.is_empty() {
                        observed.insert(format!("com_method_semantic:{semantic_kind}"));
                    }
                }
                if call
                    .get("com_vtable_effect")
                    .and_then(|effect| effect.get("interface_known"))
                    .and_then(Value::as_bool)
                    == Some(true)
                {
                    observed.insert("com_interface_known".to_string());
                    if let Some(interface_name) = call
                        .get("com_vtable_effect")
                        .and_then(|effect| effect.get("interface_name"))
                        .and_then(Value::as_str)
                    {
                        if !interface_name.is_empty() {
                            observed.insert(format!("com_interface:{interface_name}"));
                        }
                    }
                }
                if call
                    .get("com_vtable_effect")
                    .and_then(|effect| effect.get("method_exact"))
                    .and_then(Value::as_bool)
                    == Some(true)
                {
                    observed.insert("com_method_exact".to_string());
                    if let Some(method_name) = call
                        .get("com_vtable_effect")
                        .and_then(|effect| effect.get("method_name"))
                        .and_then(Value::as_str)
                    {
                        if !method_name.is_empty() {
                            observed.insert(format!("com_method_exact:{method_name}"));
                        }
                    }
                }
                if let Some(candidates) = call
                    .get("com_vtable_effect")
                    .and_then(|effect| effect.get("method_candidates"))
                    .and_then(Value::as_array)
                {
                    for candidate in candidates {
                        if let Some(candidate) = candidate.as_str() {
                            if !candidate.is_empty() {
                                observed.insert(format!("com_method:{candidate}"));
                            }
                        }
                    }
                }
                if call
                    .get("com_vtable_effect")
                    .and_then(|effect| effect.get("method_buffers"))
                    .and_then(Value::as_array)
                    .is_some_and(|buffers| !buffers.is_empty())
                {
                    observed.insert("com_method_buffer_effects".to_string());
                }
                if let Some(subsystem) = call
                    .get("com_vtable_effect")
                    .and_then(|effect| effect.get("subsystem"))
                    .and_then(Value::as_str)
                {
                    if !subsystem.is_empty() {
                        observed.insert(format!("com_subsystem:{subsystem}"));
                        if subsystem == "audio" {
                            observed.insert("audio_effects".to_string());
                        } else if subsystem == "input" {
                            observed.insert("input_effects".to_string());
                            observed.insert("input_events".to_string());
                        } else if subsystem == "graphics" {
                            observed.insert("gdi_calls".to_string());
                        }
                    }
                }
            }
            if call
                .get("thread_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("thread_effects".to_string());
                observed.insert("threading".to_string());
                if let Some(operation) = call
                    .get("thread_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("thread:{operation}"));
                    }
                }
            }
            if call
                .get("sync_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("sync_effects".to_string());
                observed.insert("synchronization".to_string());
                if let Some(operation) = call
                    .get("sync_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("sync:{operation}"));
                    }
                }
                if let Some(object_type) = call
                    .get("sync_effect")
                    .and_then(|effect| effect.get("object_type"))
                    .and_then(Value::as_str)
                {
                    if !object_type.is_empty() {
                        observed.insert(format!("sync_object:{object_type}"));
                    }
                }
            }
            if call
                .get("gdi_state_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("gdi_state_effects".to_string());
                observed.insert("gdi_calls".to_string());
                if let Some(operation) = call
                    .get("gdi_state_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("gdi_state:{operation}"));
                    }
                }
            }
            if call
                .get("class_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("class_effects".to_string());
                observed.insert("window_class".to_string());
                if let Some(operation) = call
                    .get("class_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("class:{operation}"));
                    }
                }
            }
            if call
                .get("cursor_effect")
                .and_then(|effect| effect.get("captured"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                observed.insert("cursor_effects".to_string());
                observed.insert("window_resources".to_string());
                if let Some(operation) = call
                    .get("cursor_effect")
                    .and_then(|effect| effect.get("operation"))
                    .and_then(Value::as_str)
                {
                    if !operation.is_empty() {
                        observed.insert(format!("cursor:{operation}"));
                    }
                }
            }
        }
    }
}

fn case_has_complete_side_effects(case: &Value) -> bool {
    case.get("expected")
        .and_then(|expected| expected.get("side_effects"))
        .map(side_effects_are_complete)
        .unwrap_or(false)
}

fn side_effects_are_complete(side_effects: &Value) -> bool {
    if side_effects.is_null() {
        return false;
    }
    if let Some(status) = side_effects.get("status").and_then(Value::as_str) {
        if status == "not_captured_yet" {
            return false;
        }
    }
    if let Some(status) = side_effects.get("capture_status").and_then(Value::as_str) {
        if !matches!(
            status,
            "complete" | "typed_complete" | "no_effects_observed"
        ) {
            return false;
        }
    } else {
        return false;
    }
    side_effects
        .get("limitations")
        .map(value_is_empty_effect)
        .unwrap_or(true)
        && nested_api_call_effects_are_complete(side_effects)
}

fn value_is_empty_effect(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(items) => items.is_empty(),
        Value::Object(map) => map.is_empty(),
        Value::String(text) => text.is_empty(),
        _ => false,
    }
}

fn nested_api_call_effects_are_complete(side_effects: &Value) -> bool {
    side_effects
        .get("api_calls")
        .and_then(Value::as_array)
        .map(|calls| calls.iter().all(api_call_effects_are_complete))
        .unwrap_or(true)
}

fn api_call_effects_are_complete(call: &Value) -> bool {
    com_vtable_effect_is_complete(call)
        && gdi_dib_effect_is_complete(call)
        && gdi_bitmap_resource_effect_is_complete(call)
        && gdi_pixel_effect_is_complete(call)
        && framebuffer_effect_is_complete(call)
        && process_effect_is_complete(call)
        && file_effect_is_complete(call)
        && network_effect_is_complete(call)
        && memory_api_effect_is_complete(call)
        && thread_error_effect_is_complete(call)
}

fn network_effect_is_complete(call: &Value) -> bool {
    let Some(symbol) = call.get("callee_symbol").and_then(Value::as_str) else {
        return true;
    };
    if !matches!(
        symbol,
        "WSAStartup"
            | "WSACleanup"
            | "socket"
            | "accept"
            | "closesocket"
            | "connect"
            | "bind"
            | "listen"
            | "shutdown"
            | "send"
            | "recv"
            | "sendto"
            | "recvfrom"
            | "setsockopt"
            | "getsockopt"
            | "ioctlsocket"
            | "getsockname"
            | "getpeername"
    ) {
        return true;
    }
    let Some(effect) = call.get("network_effect") else {
        return false;
    };
    if effect.get("captured").and_then(Value::as_bool) != Some(true)
        || effect
            .get("operation")
            .and_then(Value::as_str)
            .map(str::is_empty)
            .unwrap_or(true)
        || effect.get("succeeded").and_then(Value::as_bool).is_none()
        || !network_mutation_flags_complete(effect)
    {
        return false;
    }
    match symbol {
        "socket" => {
            network_u64_field_complete(effect, "domain")
                && network_u64_field_complete(effect, "type")
                && network_u64_field_complete(effect, "protocol")
                && network_result_resource_complete(effect)
        }
        "WSAStartup" => {
            network_u64_field_complete(effect, "version_requested")
                && effect
                    .get("data_address")
                    .and_then(Value::as_u64)
                    .is_some_and(|address| address != 0)
                && network_u64_field_complete(effect, "data_size")
                && (effect.get("succeeded").and_then(Value::as_bool) != Some(true)
                    || (network_u64_field_complete(effect, "data_version")
                        && network_u64_field_complete(effect, "data_high_version")
                        && api_output_buffer_arg_is_complete(call, 1)))
        }
        "WSACleanup" => true,
        "accept" => {
            network_resource_complete(effect.get("target"))
                && network_result_resource_complete(effect)
                && network_optional_buffer_complete(call, effect, "address_address", 1)
                && network_optional_buffer_complete(call, effect, "address_length_address", 2)
        }
        "closesocket" => network_resource_complete(effect.get("target")),
        "connect" | "bind" => {
            network_resource_complete(effect.get("target"))
                && effect
                    .get("address_address")
                    .and_then(Value::as_u64)
                    .is_some_and(|address| address != 0)
                && network_u64_field_complete(effect, "address_size")
                && api_output_buffer_arg_is_complete(call, 1)
        }
        "listen" => {
            network_resource_complete(effect.get("target"))
                && network_u64_field_complete(effect, "backlog")
        }
        "shutdown" => {
            network_resource_complete(effect.get("target"))
                && network_u64_field_complete(effect, "shutdown_how")
        }
        "send" | "recv" => {
            network_resource_complete(effect.get("target"))
                && effect
                    .get("payload_address")
                    .and_then(Value::as_u64)
                    .is_some_and(|address| address != 0)
                && network_u64_field_complete(effect, "requested_size")
                && network_u64_field_complete(effect, "flags")
                && api_output_buffer_arg_is_complete(call, 1)
                && network_transfer_complete(effect)
        }
        "sendto" => {
            network_resource_complete(effect.get("target"))
                && effect
                    .get("payload_address")
                    .and_then(Value::as_u64)
                    .is_some_and(|address| address != 0)
                && network_u64_field_complete(effect, "requested_size")
                && network_u64_field_complete(effect, "flags")
                && api_output_buffer_arg_is_complete(call, 1)
                && network_optional_buffer_complete(call, effect, "address_address", 4)
                && network_transfer_complete(effect)
        }
        "recvfrom" => {
            network_resource_complete(effect.get("target"))
                && effect
                    .get("payload_address")
                    .and_then(Value::as_u64)
                    .is_some_and(|address| address != 0)
                && network_u64_field_complete(effect, "requested_size")
                && network_u64_field_complete(effect, "flags")
                && api_output_buffer_arg_is_complete(call, 1)
                && network_optional_buffer_complete(call, effect, "address_address", 4)
                && network_optional_buffer_complete(call, effect, "address_length_address", 5)
                && network_transfer_complete(effect)
        }
        "setsockopt" => {
            network_resource_complete(effect.get("target"))
                && network_u64_field_complete(effect, "option_level")
                && network_u64_field_complete(effect, "option_name")
                && network_u64_field_complete(effect, "option_value_address")
                && network_u64_field_complete(effect, "option_value_size")
                && network_optional_buffer_complete(call, effect, "option_value_address", 3)
        }
        "getsockopt" => {
            network_resource_complete(effect.get("target"))
                && network_u64_field_complete(effect, "option_level")
                && network_u64_field_complete(effect, "option_name")
                && network_u64_field_complete(effect, "option_value_address")
                && network_u64_field_complete(effect, "option_value_size")
                && network_optional_buffer_complete(call, effect, "option_value_address", 3)
                && network_optional_buffer_complete(call, effect, "address_length_address", 4)
        }
        "ioctlsocket" => {
            network_resource_complete(effect.get("target"))
                && network_u64_field_complete(effect, "ioctl_command")
                && effect.get("ioctl_command_known").and_then(Value::as_bool) == Some(true)
                && effect
                    .get("ioctl_arg_address")
                    .and_then(Value::as_u64)
                    .is_some_and(|address| address != 0)
                && network_u64_field_complete(effect, "ioctl_arg_before")
                && network_u64_field_complete(effect, "ioctl_arg_after")
                && api_output_buffer_arg_is_complete(call, 2)
        }
        "getsockname" | "getpeername" => {
            network_resource_complete(effect.get("target"))
                && network_optional_buffer_complete(call, effect, "address_address", 1)
                && network_optional_buffer_complete(call, effect, "address_length_address", 2)
        }
        _ => true,
    }
}

fn network_resource_complete(resource: Option<&Value>) -> bool {
    let Some(resource) = resource else {
        return false;
    };
    resource.get("handle").and_then(Value::as_u64).is_some()
        && resource.get("known").and_then(Value::as_bool) == Some(true)
        && resource
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(|kind| !kind.is_empty())
        && resource
            .get("label")
            .and_then(Value::as_str)
            .is_some_and(|label| !label.is_empty())
}

fn network_result_resource_complete(effect: &Value) -> bool {
    let Some(result) = effect.get("result") else {
        return false;
    };
    if result.get("handle").and_then(Value::as_u64).is_none() {
        return false;
    }
    if effect.get("succeeded").and_then(Value::as_bool) != Some(true) {
        return true;
    }
    network_resource_complete(Some(result))
}

fn network_mutation_flags_complete(effect: &Value) -> bool {
    effect.get("mutation_captured").and_then(Value::as_bool) == Some(true)
        && effect
            .get("mutates_socket_state")
            .and_then(Value::as_bool)
            .is_some()
        && effect
            .get("mutates_network")
            .and_then(Value::as_bool)
            .is_some()
        && effect
            .get("mutates_caller_buffer")
            .and_then(Value::as_bool)
            .is_some()
}

fn network_u64_field_complete(effect: &Value, field: &str) -> bool {
    effect.get(field).and_then(Value::as_u64).is_some()
}

fn network_optional_buffer_complete(
    call: &Value,
    effect: &Value,
    address_field: &str,
    arg_index: usize,
) -> bool {
    let Some(address) = effect.get(address_field).and_then(Value::as_u64) else {
        return false;
    };
    address == 0 || api_output_buffer_arg_is_complete(call, arg_index)
}

fn network_transfer_complete(effect: &Value) -> bool {
    effect.get("succeeded").and_then(Value::as_bool) != Some(true)
        || network_u64_field_complete(effect, "transferred")
}

fn thread_error_effect_is_complete(call: &Value) -> bool {
    let Some(symbol) = call.get("callee_symbol").and_then(Value::as_str) else {
        return true;
    };
    if !matches!(
        symbol,
        "GetLastError" | "SetLastError" | "WSAGetLastError" | "WSASetLastError"
    ) {
        return true;
    }
    let Some(effect) = call.get("thread_error_effect") else {
        return false;
    };
    if effect.get("captured").and_then(Value::as_bool) != Some(true)
        || effect
            .get("operation")
            .and_then(Value::as_str)
            .map(str::is_empty)
            .unwrap_or(true)
    {
        return false;
    }
    let before = effect.get("before").and_then(Value::as_u64);
    let after = effect.get("after").and_then(Value::as_u64);
    let (Some(before), Some(after)) = (before, after) else {
        return false;
    };
    let expected_kind = match symbol {
        "WSAGetLastError" | "WSASetLastError" => "winsock_last_error",
        _ => "win32_last_error",
    };
    if effect.get("kind").and_then(Value::as_str) != Some(expected_kind) {
        return false;
    }
    match symbol {
        "GetLastError" | "WSAGetLastError" => {
            effect.get("return_value").and_then(Value::as_u64) == Some(before)
                && after == before
                && effect.get("mutated").and_then(Value::as_bool) == Some(false)
        }
        "SetLastError" | "WSASetLastError" => {
            let Some(requested) = effect.get("requested").and_then(Value::as_u64) else {
                return false;
            };
            after == requested && effect.get("mutated").and_then(Value::as_bool) == Some(true)
        }
        _ => true,
    }
}

fn file_effect_is_complete(call: &Value) -> bool {
    let Some(symbol) = call.get("callee_symbol").and_then(Value::as_str) else {
        return true;
    };
    if !matches!(
        symbol,
        "CreateFileA"
            | "CreateFileW"
            | "GetStdHandle"
            | "ReadFile"
            | "WriteFile"
            | "FlushFileBuffers"
            | "GetFileSize"
            | "GetFileSizeEx"
            | "SetFilePointer"
            | "SetFilePointerEx"
            | "SetEndOfFile"
            | "GetFileInformationByHandle"
            | "GetFileType"
    ) {
        return true;
    }
    let Some(effect) = call.get("file_effect") else {
        return false;
    };
    if effect.get("captured").and_then(Value::as_bool) != Some(true)
        || effect
            .get("operation")
            .and_then(Value::as_str)
            .map(str::is_empty)
            .unwrap_or(true)
        || effect.get("succeeded").and_then(Value::as_bool).is_none()
    {
        return false;
    }
    match symbol {
        "CreateFileA" | "CreateFileW" => {
            file_u64_field_complete(effect, "desired_access")
                && file_u64_field_complete(effect, "share_mode")
                && file_u64_field_complete(effect, "creation_disposition")
                && file_u64_field_complete(effect, "flags_attributes")
                && file_resource_complete(effect.get("result"))
        }
        "GetStdHandle" => {
            file_resource_complete(effect.get("target"))
                && file_resource_complete(effect.get("result"))
        }
        "ReadFile" | "WriteFile" => {
            if !file_resource_complete(effect.get("target"))
                || !file_u64_field_complete(effect, "data_address")
                || !file_u64_field_complete(effect, "requested_size")
                || !file_u64_field_complete(effect, "transferred_address")
                || !file_mutation_complete(effect)
            {
                return false;
            }
            let transferred_address = effect
                .get("transferred_address")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            effect.get("succeeded").and_then(Value::as_bool) != Some(true)
                || transferred_address == 0
                || file_u64_field_complete(effect, "transferred")
        }
        "FlushFileBuffers" | "SetEndOfFile" => {
            file_resource_complete(effect.get("target")) && file_mutation_complete(effect)
        }
        "GetFileSize" | "GetFileSizeEx" => {
            file_resource_complete(effect.get("target"))
                && (effect.get("succeeded").and_then(Value::as_bool) != Some(true)
                    || file_u64_field_complete(effect, "size"))
        }
        "SetFilePointer" | "SetFilePointerEx" => {
            if !file_resource_complete(effect.get("target"))
                || !file_i64_field_complete(effect, "distance")
                || !file_u64_field_complete(effect, "move_method")
                || !file_u64_field_complete(effect, "new_position_address")
                || !file_mutation_complete(effect)
            {
                return false;
            }
            let new_position_address = effect
                .get("new_position_address")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            effect.get("succeeded").and_then(Value::as_bool) != Some(true)
                || new_position_address == 0
                || file_i64_field_complete(effect, "new_position")
        }
        "GetFileInformationByHandle" => {
            file_resource_complete(effect.get("target"))
                && api_output_buffer_arg_complete(call, 1)
                && (effect.get("succeeded").and_then(Value::as_bool) != Some(true)
                    || file_u64_field_complete(effect, "size"))
        }
        "GetFileType" => {
            file_resource_complete(effect.get("target"))
                && file_u64_field_complete(effect, "file_type")
        }
        _ => true,
    }
}

fn file_resource_complete(resource: Option<&Value>) -> bool {
    let Some(resource) = resource else {
        return false;
    };
    resource.get("handle").and_then(Value::as_u64).is_some()
        && resource.get("known").and_then(Value::as_bool) == Some(true)
        && resource
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(|kind| !kind.is_empty())
        && resource
            .get("label")
            .and_then(Value::as_str)
            .is_some_and(|label| !label.is_empty())
}

fn file_mutation_complete(effect: &Value) -> bool {
    effect.get("mutation_captured").and_then(Value::as_bool) == Some(true)
        && effect
            .get("mutates_data")
            .and_then(Value::as_bool)
            .is_some()
        && effect
            .get("mutates_position")
            .and_then(Value::as_bool)
            .is_some()
        && effect
            .get("mutates_size")
            .and_then(Value::as_bool)
            .is_some()
        && effect
            .get("mutates_caller_buffer")
            .and_then(Value::as_bool)
            .is_some()
}

fn file_u64_field_complete(effect: &Value, field: &str) -> bool {
    effect.get(field).and_then(Value::as_u64).is_some()
}

fn file_i64_field_complete(effect: &Value, field: &str) -> bool {
    effect.get(field).and_then(Value::as_i64).is_some()
        || effect.get(field).and_then(Value::as_u64).is_some()
}

fn api_output_buffer_arg_complete(call: &Value, arg_index: u64) -> bool {
    let inline = call
        .get("output_buffers")
        .and_then(Value::as_array)
        .is_some_and(|buffers| {
            buffers.iter().any(|buffer| {
                buffer.get("arg_index").and_then(Value::as_u64) == Some(arg_index)
                    && buffer.get("before_ok").and_then(Value::as_bool) == Some(true)
                    && buffer.get("after_ok").and_then(Value::as_bool) == Some(true)
                    && buffer.get("truncated").and_then(Value::as_bool) != Some(true)
            })
        });
    if inline {
        return true;
    }
    call.get("output_buffer_aggregate")
        .and_then(|aggregate| aggregate.get("entries"))
        .and_then(Value::as_array)
        .is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry.get("arg_index").and_then(Value::as_u64) == Some(arg_index)
                    && entry.get("before_sha256_ok").and_then(Value::as_bool) == Some(true)
                    && entry.get("after_sha256_ok").and_then(Value::as_bool) == Some(true)
                    && entry.get("truncated").and_then(Value::as_bool) != Some(true)
            })
        })
}

fn memory_api_effect_is_complete(call: &Value) -> bool {
    let Some(symbol) = call.get("callee_symbol").and_then(Value::as_str) else {
        return true;
    };
    if !matches!(
        symbol,
        "GetProcessHeap"
            | "HeapAlloc"
            | "HeapReAlloc"
            | "HeapFree"
            | "HeapSize"
            | "VirtualAlloc"
            | "VirtualFree"
            | "VirtualProtect"
            | "malloc"
            | "calloc"
            | "free"
            | "_msize"
            | "LocalAlloc"
            | "LocalReAlloc"
            | "LocalFree"
            | "LocalSize"
            | "LocalLock"
            | "LocalUnlock"
            | "GlobalAlloc"
            | "GlobalReAlloc"
            | "GlobalFree"
            | "GlobalSize"
            | "GlobalLock"
            | "GlobalUnlock"
    ) {
        return true;
    }
    let Some(effect) = call.get("memory_api_effect") else {
        return false;
    };
    if effect.get("captured").and_then(Value::as_bool) != Some(true)
        || effect
            .get("operation")
            .and_then(Value::as_str)
            .map(str::is_empty)
            .unwrap_or(true)
        || effect.get("succeeded").and_then(Value::as_bool).is_none()
    {
        return false;
    }
    match symbol {
        "GetProcessHeap" => effect
            .get("result_address")
            .and_then(Value::as_u64)
            .is_some(),
        "HeapAlloc" => {
            memory_u64_field_complete(effect, "heap")
                && memory_u64_field_complete(effect, "flags")
                && memory_u64_field_complete(effect, "size")
                && memory_u64_field_complete(effect, "result_address")
                && effect.get("mutated").and_then(Value::as_bool).is_some()
        }
        "HeapReAlloc" => {
            memory_u64_field_complete(effect, "heap")
                && memory_u64_field_complete(effect, "flags")
                && memory_u64_field_complete(effect, "address")
                && memory_u64_field_complete(effect, "size")
                && memory_u64_field_complete(effect, "result_address")
                && effect.get("mutated").and_then(Value::as_bool).is_some()
        }
        "HeapFree" => {
            memory_u64_field_complete(effect, "heap")
                && memory_u64_field_complete(effect, "flags")
                && memory_u64_field_complete(effect, "address")
                && effect.get("mutated").and_then(Value::as_bool).is_some()
        }
        "HeapSize" => {
            memory_u64_field_complete(effect, "heap")
                && memory_u64_field_complete(effect, "flags")
                && memory_u64_field_complete(effect, "address")
                && (effect.get("succeeded").and_then(Value::as_bool) != Some(true)
                    || memory_u64_field_complete(effect, "size"))
        }
        "VirtualAlloc" => {
            memory_u64_field_complete(effect, "address")
                && memory_u64_field_complete(effect, "size")
                && memory_u64_field_complete(effect, "allocation_type")
                && memory_u64_field_complete(effect, "protect")
                && memory_u64_field_complete(effect, "result_address")
                && effect.get("mutated").and_then(Value::as_bool).is_some()
        }
        "VirtualFree" => {
            memory_u64_field_complete(effect, "address")
                && memory_u64_field_complete(effect, "size")
                && memory_u64_field_complete(effect, "allocation_type")
                && effect.get("mutated").and_then(Value::as_bool).is_some()
        }
        "VirtualProtect" => {
            if !memory_u64_field_complete(effect, "address")
                || !memory_u64_field_complete(effect, "size")
                || !memory_u64_field_complete(effect, "protect")
                || !memory_u64_field_complete(effect, "old_protect_address")
                || effect.get("mutated").and_then(Value::as_bool).is_none()
            {
                return false;
            }
            if effect.get("succeeded").and_then(Value::as_bool) != Some(true)
                || effect.get("old_protect_address").and_then(Value::as_u64) == Some(0)
            {
                return true;
            }
            memory_u64_field_complete(effect, "old_protect")
        }
        "malloc" => {
            memory_u64_field_complete(effect, "size")
                && memory_u64_field_complete(effect, "result_address")
                && effect.get("mutated").and_then(Value::as_bool).is_some()
        }
        "calloc" => {
            memory_u64_field_complete(effect, "count")
                && memory_u64_field_complete(effect, "element_size")
                && memory_u64_field_complete(effect, "size")
                && effect.get("zeroed").and_then(Value::as_bool) == Some(true)
                && memory_u64_field_complete(effect, "result_address")
                && effect.get("mutated").and_then(Value::as_bool).is_some()
        }
        "free" => {
            memory_u64_field_complete(effect, "address")
                && effect.get("mutated").and_then(Value::as_bool).is_some()
        }
        "_msize" => {
            memory_u64_field_complete(effect, "address")
                && (effect.get("succeeded").and_then(Value::as_bool) != Some(true)
                    || memory_u64_field_complete(effect, "size"))
        }
        "LocalAlloc" | "GlobalAlloc" => {
            memory_u64_field_complete(effect, "flags")
                && memory_u64_field_complete(effect, "size")
                && effect.get("zeroed").and_then(Value::as_bool).is_some()
                && memory_u64_field_complete(effect, "result_address")
                && effect.get("mutated").and_then(Value::as_bool).is_some()
        }
        "LocalReAlloc" | "GlobalReAlloc" => {
            memory_u64_field_complete(effect, "address")
                && memory_u64_field_complete(effect, "size")
                && memory_u64_field_complete(effect, "flags")
                && effect.get("zeroed").and_then(Value::as_bool).is_some()
                && memory_u64_field_complete(effect, "result_address")
                && effect.get("mutated").and_then(Value::as_bool).is_some()
        }
        "LocalFree" | "GlobalFree" => {
            memory_u64_field_complete(effect, "address")
                && effect.get("mutated").and_then(Value::as_bool).is_some()
        }
        "LocalSize" | "GlobalSize" => {
            memory_u64_field_complete(effect, "address")
                && (effect.get("succeeded").and_then(Value::as_bool) != Some(true)
                    || memory_u64_field_complete(effect, "size"))
        }
        "LocalLock" | "GlobalLock" => {
            memory_u64_field_complete(effect, "address")
                && memory_u64_field_complete(effect, "result_address")
                && effect.get("mutated").and_then(Value::as_bool).is_some()
        }
        "LocalUnlock" | "GlobalUnlock" => {
            memory_u64_field_complete(effect, "address")
                && effect.get("mutated").and_then(Value::as_bool).is_some()
        }
        _ => true,
    }
}

fn memory_u64_field_complete(effect: &Value, field: &str) -> bool {
    effect.get(field).and_then(Value::as_u64).is_some()
}

fn framebuffer_effect_is_complete(call: &Value) -> bool {
    let Some(symbol) = call.get("callee_symbol").and_then(Value::as_str) else {
        return true;
    };
    if !matches!(
        symbol,
        "BitBlt" | "StretchBlt" | "PatBlt" | "SwapBuffers" | "SetDIBitsToDevice" | "StretchDIBits"
    ) {
        return true;
    }
    let Some(effect) = call.get("draw_effect") else {
        return false;
    };
    if effect.get("captured").and_then(Value::as_bool) != Some(true) {
        return false;
    }
    let Some(framebuffer) = effect.get("framebuffer_effect") else {
        return false;
    };
    if framebuffer.get("captured").and_then(Value::as_bool) != Some(true) {
        return false;
    }
    if framebuffer
        .get("operation")
        .and_then(Value::as_str)
        .map(str::is_empty)
        .unwrap_or(true)
    {
        return false;
    }
    if !framebuffer_endpoint_is_complete(framebuffer.get("destination"), true) {
        return false;
    }
    match symbol {
        "SwapBuffers" => true,
        "PatBlt" => {
            framebuffer_rect_is_complete(framebuffer.get("destination"))
                && framebuffer
                    .get("raster_op")
                    .and_then(Value::as_u64)
                    .is_some()
                && framebuffer_payload_kind(framebuffer) == Some("raster_pattern")
        }
        "BitBlt" | "StretchBlt" => {
            framebuffer_rect_is_complete(framebuffer.get("destination"))
                && framebuffer_endpoint_is_complete(framebuffer.get("source"), true)
                && framebuffer_rect_is_complete(framebuffer.get("source"))
                && framebuffer
                    .get("raster_op")
                    .and_then(Value::as_u64)
                    .is_some()
                && framebuffer_payload_kind(framebuffer) == Some("source_dc")
        }
        "SetDIBitsToDevice" => {
            framebuffer_rect_is_complete(framebuffer.get("destination"))
                && framebuffer_rect_is_complete(framebuffer.get("source"))
                && framebuffer_dib_payload_is_complete(framebuffer)
        }
        "StretchDIBits" => {
            framebuffer_rect_is_complete(framebuffer.get("destination"))
                && framebuffer_rect_is_complete(framebuffer.get("source"))
                && framebuffer
                    .get("raster_op")
                    .and_then(Value::as_u64)
                    .is_some()
                && framebuffer_dib_payload_is_complete(framebuffer)
        }
        _ => true,
    }
}

fn framebuffer_endpoint_is_complete(endpoint: Option<&Value>, require_target: bool) -> bool {
    let Some(endpoint) = endpoint else {
        return false;
    };
    if !require_target {
        return true;
    }
    endpoint
        .get("target")
        .and_then(|target| target.get("known"))
        .and_then(Value::as_bool)
        == Some(true)
}

fn framebuffer_rect_is_complete(endpoint: Option<&Value>) -> bool {
    let Some(rect) = endpoint.and_then(|endpoint| endpoint.get("rect")) else {
        return false;
    };
    ["x", "y", "width", "height"]
        .iter()
        .all(|field| rect.get(*field).and_then(Value::as_i64).is_some())
}

fn framebuffer_payload_kind(framebuffer: &Value) -> Option<&str> {
    framebuffer
        .get("payload")
        .and_then(|payload| payload.get("kind"))
        .and_then(Value::as_str)
}

fn framebuffer_dib_payload_is_complete(framebuffer: &Value) -> bool {
    if framebuffer_payload_kind(framebuffer) != Some("dib_argument") {
        return false;
    }
    let Some(payload) = framebuffer.get("payload") else {
        return false;
    };
    payload.get("bits_digest_captured").and_then(Value::as_bool) == Some(true)
        && payload
            .get("bitmap_info_digest_captured")
            .and_then(Value::as_bool)
            == Some(true)
}

fn process_effect_is_complete(call: &Value) -> bool {
    let Some(symbol) = call.get("callee_symbol").and_then(Value::as_str) else {
        return true;
    };
    if !matches!(
        symbol,
        "GetCommandLineA"
            | "GetCommandLineW"
            | "GetEnvironmentVariableA"
            | "GetEnvironmentVariableW"
            | "SetEnvironmentVariableA"
            | "SetEnvironmentVariableW"
            | "ExpandEnvironmentStringsA"
            | "ExpandEnvironmentStringsW"
            | "GetCurrentDirectoryA"
            | "GetCurrentDirectoryW"
            | "SetCurrentDirectoryA"
            | "SetCurrentDirectoryW"
            | "GetTempPathA"
            | "GetTempPathW"
            | "CreateProcessA"
            | "CreateProcessW"
            | "WinExec"
            | "ShellExecuteA"
            | "ShellExecuteW"
            | "ExitProcess"
    ) {
        return true;
    }
    let Some(effect) = call.get("process_effect") else {
        return false;
    };
    if effect.get("captured").and_then(Value::as_bool) != Some(true) {
        return false;
    }
    match symbol {
        "ExitProcess" => {
            effect.get("does_not_return").and_then(Value::as_bool) == Some(true)
                && effect.get("exit_code").and_then(Value::as_u64).is_some()
        }
        "GetCommandLineA" | "GetCommandLineW" => {
            effect
                .get("result_pointer")
                .and_then(Value::as_u64)
                .is_some()
                && effect.get("command_line_captured").and_then(Value::as_bool) == Some(true)
                && effect
                    .get("command_line_truncated")
                    .and_then(Value::as_bool)
                    != Some(true)
        }
        "SetEnvironmentVariableA" | "SetEnvironmentVariableW" => {
            process_text_field_complete(effect, "name")
                && process_text_field_complete(effect, "value")
                && effect.get("succeeded").and_then(Value::as_bool).is_some()
                && effect.get("mutated").and_then(Value::as_bool).is_some()
        }
        "SetCurrentDirectoryA" | "SetCurrentDirectoryW" => {
            process_text_field_complete(effect, "directory")
                && effect.get("succeeded").and_then(Value::as_bool).is_some()
                && effect.get("mutated").and_then(Value::as_bool).is_some()
        }
        "GetEnvironmentVariableA" | "GetEnvironmentVariableW" => {
            process_text_field_complete(effect, "name")
                && process_output_shape_complete(effect)
                && process_optional_output_text_complete(effect, "value", false)
        }
        "ExpandEnvironmentStringsA" | "ExpandEnvironmentStringsW" => {
            process_text_field_complete(effect, "name")
                && process_output_shape_complete(effect)
                && process_optional_output_text_complete(effect, "value", true)
        }
        "GetCurrentDirectoryA" | "GetCurrentDirectoryW" | "GetTempPathA" | "GetTempPathW" => {
            process_output_shape_complete(effect)
                && process_optional_output_text_complete(effect, "directory", false)
        }
        "WinExec" => {
            process_required_text_arg_complete(effect, "command_line_address", "command_line")
                && process_u64_field_complete(effect, "show_cmd")
                && process_bool_field_complete(effect, "succeeded")
                && process_bool_field_complete(effect, "spawned")
                && process_bool_field_complete(effect, "mutated")
        }
        "ShellExecuteA" | "ShellExecuteW" => {
            process_optional_text_arg_complete(effect, "value_address", "value")
                && process_required_text_arg_complete(effect, "name_address", "name")
                && process_optional_text_arg_complete(
                    effect,
                    "command_line_address",
                    "command_line",
                )
                && process_optional_text_arg_complete(effect, "directory_address", "directory")
                && process_u64_field_complete(effect, "show_cmd")
                && process_bool_field_complete(effect, "succeeded")
                && process_bool_field_complete(effect, "spawned")
                && process_bool_field_complete(effect, "mutated")
        }
        "CreateProcessA" | "CreateProcessW" => process_create_process_effect_complete(effect),
        _ => true,
    }
}

fn process_create_process_effect_complete(effect: &Value) -> bool {
    if !process_optional_text_arg_complete(effect, "name_address", "name")
        || !process_optional_text_arg_complete(effect, "command_line_address", "command_line")
    {
        return false;
    }
    let name_address = effect
        .get("name_address")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let command_line_address = effect
        .get("command_line_address")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if name_address == 0 && command_line_address == 0 {
        return false;
    }
    if !process_bool_field_complete(effect, "inherit_handles")
        || !process_u64_field_complete(effect, "creation_flags")
        || !process_environment_block_complete(effect)
        || !process_optional_text_arg_complete(effect, "directory_address", "directory")
        || !process_startup_info_complete(effect)
        || !process_u64_field_complete(effect, "process_info_address")
        || !process_bool_field_complete(effect, "succeeded")
        || !process_bool_field_complete(effect, "spawned")
        || !process_bool_field_complete(effect, "mutated")
    {
        return false;
    }
    if effect
        .get("process_info_address")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        == 0
    {
        return false;
    }
    if effect.get("succeeded").and_then(Value::as_bool) != Some(true) {
        return true;
    }
    effect
        .get("process_info_address")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        != 0
        && process_u64_field_complete(effect, "process_handle")
        && process_u64_field_complete(effect, "thread_handle")
        && process_u64_field_complete(effect, "process_id")
        && process_u64_field_complete(effect, "thread_id")
}

fn process_environment_block_complete(effect: &Value) -> bool {
    let Some(address) = effect.get("environment_address").and_then(Value::as_u64) else {
        return false;
    };
    if address == 0 {
        return true;
    }
    process_u64_field_complete(effect, "environment_block_size")
        && effect
            .get("environment_block_sha256_ok")
            .and_then(Value::as_bool)
            == Some(true)
        && effect
            .get("environment_block_sha256")
            .and_then(Value::as_str)
            .is_some_and(|sha| sha.len() == 64)
}

fn process_startup_info_complete(effect: &Value) -> bool {
    let Some(address) = effect.get("startup_info_address").and_then(Value::as_u64) else {
        return false;
    };
    if address == 0 {
        return false;
    }
    process_u64_field_complete(effect, "startup_info_size")
        && effect
            .get("startup_info_sha256_ok")
            .and_then(Value::as_bool)
            == Some(true)
        && effect
            .get("startup_info_sha256")
            .and_then(Value::as_str)
            .is_some_and(|sha| sha.len() == 64)
}

fn process_text_field_complete(effect: &Value, field: &str) -> bool {
    let captured = format!("{field}_captured");
    let truncated = format!("{field}_truncated");
    effect.get(&captured).and_then(Value::as_bool) == Some(true)
        && effect.get(&truncated).and_then(Value::as_bool) != Some(true)
}

fn process_optional_text_arg_complete(effect: &Value, address_field: &str, field: &str) -> bool {
    let Some(address) = effect.get(address_field).and_then(Value::as_u64) else {
        return false;
    };
    address == 0 || process_text_field_complete(effect, field)
}

fn process_required_text_arg_complete(effect: &Value, address_field: &str, field: &str) -> bool {
    effect
        .get(address_field)
        .and_then(Value::as_u64)
        .is_some_and(|address| address != 0)
        && process_text_field_complete(effect, field)
}

fn process_u64_field_complete(effect: &Value, field: &str) -> bool {
    effect.get(field).and_then(Value::as_u64).is_some()
}

fn process_bool_field_complete(effect: &Value, field: &str) -> bool {
    effect.get(field).and_then(Value::as_bool).is_some()
}

fn process_output_shape_complete(effect: &Value) -> bool {
    effect
        .get("output_address")
        .and_then(Value::as_u64)
        .is_some()
        && effect
            .get("output_capacity")
            .and_then(Value::as_u64)
            .is_some()
        && effect
            .get("result_length")
            .and_then(Value::as_u64)
            .is_some()
        && effect.get("succeeded").and_then(Value::as_bool).is_some()
}

fn process_optional_output_text_complete(
    effect: &Value,
    field: &str,
    length_includes_nul: bool,
) -> bool {
    if effect.get("succeeded").and_then(Value::as_bool) != Some(true) {
        return true;
    }
    let output_address = effect
        .get("output_address")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output_capacity = effect
        .get("output_capacity")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let result_length = effect
        .get("result_length")
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX);
    let too_small = if length_includes_nul {
        result_length > output_capacity
    } else {
        result_length >= output_capacity
    };
    if output_address == 0 || output_capacity == 0 || too_small {
        return true;
    }
    process_text_field_complete(effect, field)
}

fn gdi_pixel_effect_is_complete(call: &Value) -> bool {
    let Some(symbol) = call.get("callee_symbol").and_then(Value::as_str) else {
        return true;
    };
    if !matches!(symbol, "SetPixel" | "SetPixelV" | "GetPixel") {
        return true;
    }
    call.get("draw_effect")
        .and_then(|effect| effect.get("captured"))
        .and_then(Value::as_bool)
        == Some(true)
}

fn gdi_bitmap_resource_effect_is_complete(call: &Value) -> bool {
    let Some(symbol) = call.get("callee_symbol").and_then(Value::as_str) else {
        return true;
    };
    if symbol != "CreateDIBSection" {
        return true;
    }
    api_output_buffer_arg_is_complete(call, 1) && api_output_buffer_arg_is_complete(call, 3)
}

fn gdi_dib_effect_is_complete(call: &Value) -> bool {
    let Some(symbol) = call.get("callee_symbol").and_then(Value::as_str) else {
        return true;
    };
    let required_args: &[usize] = match symbol {
        "SetDIBits" => &[5],
        "SetDIBitsToDevice" | "StretchDIBits" => &[9, 10],
        "GetDIBits" => &[5],
        _ => return true,
    };
    if call
        .get("draw_effect")
        .and_then(|effect| effect.get("captured"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return false;
    }
    if !required_args
        .iter()
        .all(|arg_index| api_output_buffer_arg_is_complete(call, *arg_index))
    {
        return false;
    }
    if symbol == "SetDIBits" && stack_arg(call, 4).unwrap_or(0) != 0 {
        return api_output_buffer_arg_is_complete(call, 4);
    }
    if symbol == "GetDIBits" && stack_arg(call, 4).unwrap_or(0) != 0 {
        return api_output_buffer_arg_is_complete(call, 4);
    }
    true
}

fn stack_arg(call: &Value, arg_index: usize) -> Option<u64> {
    call.get("stack_args")
        .and_then(Value::as_array)
        .and_then(|args| args.get(arg_index))
        .and_then(Value::as_u64)
}

fn api_output_buffer_arg_is_complete(call: &Value, arg_index: usize) -> bool {
    if call
        .get("output_buffers")
        .and_then(Value::as_array)
        .map(|buffers| {
            buffers
                .iter()
                .filter(|buffer| {
                    buffer.get("arg_index").and_then(Value::as_u64) == Some(arg_index as u64)
                })
                .any(api_output_buffer_is_complete)
        })
        .unwrap_or(false)
    {
        return true;
    }
    call.get("output_buffer_aggregate")
        .and_then(|aggregate| aggregate.get("entries"))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter(|entry| {
                    entry.get("arg_index").and_then(Value::as_u64) == Some(arg_index as u64)
                })
                .any(api_output_aggregate_entry_is_complete)
        })
        .unwrap_or(false)
}

fn api_output_buffer_is_complete(buffer: &Value) -> bool {
    let truncated = buffer
        .get("truncated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if truncated {
        return buffer.get("before_sha256_ok").and_then(Value::as_bool) == Some(true)
            && buffer.get("after_sha256_ok").and_then(Value::as_bool) == Some(true);
    }
    buffer.get("before_ok").and_then(Value::as_bool) == Some(true)
        && buffer.get("after_ok").and_then(Value::as_bool) == Some(true)
}

fn api_output_aggregate_entry_is_complete(entry: &Value) -> bool {
    entry.get("before_sha256_ok").and_then(Value::as_bool) == Some(true)
        && entry.get("after_sha256_ok").and_then(Value::as_bool) == Some(true)
}

fn com_vtable_effect_is_complete(call: &Value) -> bool {
    let Some(effect) = call.get("com_vtable_effect") else {
        return true;
    };
    if effect.is_null() {
        return true;
    }
    if effect.get("captured").and_then(Value::as_bool) != Some(true) {
        return false;
    }
    if effect
        .get("method_buffer_dropped")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        != 0
    {
        return false;
    }
    let method_buffers = effect
        .get("method_buffers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if effect
        .get("method_name")
        .and_then(Value::as_str)
        .is_some_and(com_method_requires_buffer)
        && method_buffers.is_empty()
    {
        return false;
    }
    method_buffers.iter().all(com_method_buffer_is_complete)
}

fn com_method_buffer_is_complete(buffer: &Value) -> bool {
    let before_captured = buffer
        .get("before_captured")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let after_captured = buffer
        .get("after_captured")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !before_captured && !after_captured {
        return false;
    }
    if before_captured && buffer.get("before_sha256_ok").and_then(Value::as_bool) != Some(true) {
        return false;
    }
    if after_captured && buffer.get("after_sha256_ok").and_then(Value::as_bool) != Some(true) {
        return false;
    }
    true
}

fn com_method_requires_buffer(method_name: &str) -> bool {
    matches!(
        method_name,
        "IDirect3DSurface8::UnlockRect"
            | "IDirect3DVolume8::UnlockBox"
            | "IDirect3DVertexBuffer8::Unlock"
            | "IDirect3DIndexBuffer8::Unlock"
            | "IDirect3DTexture8::UnlockRect"
            | "IDirect3DCubeTexture8::UnlockRect"
            | "IDirect3DVolumeTexture8::UnlockBox"
            | "IDirectDrawSurface::Unlock"
    )
}

fn write_candidate_schema(out: &Path) -> Result<(), String> {
    let candidate = out.join("candidate");
    fs::create_dir_all(&candidate)
        .map_err(|err| format!("create {}: {err}", candidate.display()))?;
    write_json(
        candidate.join("schema.json"),
        &json!({
            "format": "wincr-block-candidate-mapping-v1",
            "artifact_role": "candidate_block_mapping_schema",
            "required_shape": {
                "blocks": {
                    "<block_label>": {
                        "semantic_point": "candidate hook or adapter name",
                        "source": "candidate source file/function reference",
                        "state_adapter": "adapter that captures comparable pre/post state",
                        "side_effect_adapter": "adapter or shim used for API/environment effects"
                    }
                }
            },
            "candidate_trace_result": {
                "kind": "candidate_block_result",
                "case_id": "original case_id from blocks/<label>/cases.jsonl",
                "block_label": "block obligation label",
                "post_state": "candidate post-state JSON captured by adapter",
                "side_effects": "candidate side-effect JSON captured by adapter",
                "successor_rva": "optional normalized successor RVA"
            }
        }),
    )?;
    write_text(
        candidate.join("wincr_block_verify.hpp"),
        candidate_scaffold_header(),
    )
}

fn write_waiver_schema(out: &Path) -> Result<(), String> {
    write_json(
        out.join("waivers.schema.json"),
        &json!({
            "format": "wincr-block-coverage-waivers-v1",
            "artifact_role": "coverage_waiver_schema",
            "required_shape": {
                "waivers": {
                    "<block_label>": {
                        "reason": "why this recovered block cannot or need not be characterized",
                        "evidence": "private evidence supporting the waiver",
                        "category": "optional unreachable|tooling_error|out_of_scope|duplicate",
                        "reviewer": "optional reviewer identity"
                    }
                }
            },
            "policy": "waivers are reviewed exceptions; uncovered blocks without waivers fail coverage and candidate validation"
        }),
    )
}

fn candidate_scaffold_header() -> &'static str {
    concat!(
        "#pragma once\n",
        "#include <cstdio>\n",
        "#include <cstdlib>\n",
        "#include <string>\n",
        "\n",
        "namespace wincr_block_verify {\n",
        "inline FILE* trace_file() {\n",
        "  static FILE* handle = []() -> FILE* {\n",
        "    const char* path = std::getenv(\"WINCR_BLOCK_TRACE_OUT\");\n",
        "    return path ? std::fopen(path, \"ab\") : nullptr;\n",
        "  }();\n",
        "  return handle;\n",
        "}\n",
        "\n",
        "inline void observe(const char* block_label, const char* phase, const std::string& state_json) {\n",
        "  FILE* out = trace_file();\n",
        "  if (!out) return;\n",
        "  std::fprintf(out, \"{\\\"kind\\\":\\\"candidate_block_observation\\\",\\\"block_label\\\":\\\"%s\\\",\\\"phase\\\":\\\"%s\\\",\\\"state\\\":%s}\\n\", block_label, phase, state_json.c_str());\n",
        "  std::fflush(out);\n",
        "}\n",
        "\n",
        "inline void result(const char* block_label, const char* case_id, const std::string& post_state_json, const std::string& side_effects_json, const char* successor_rva_json) {\n",
        "  FILE* out = trace_file();\n",
        "  if (!out) return;\n",
        "  const char* successor = successor_rva_json ? successor_rva_json : \"null\";\n",
        "  std::fprintf(out, \"{\\\"kind\\\":\\\"candidate_block_result\\\",\\\"block_label\\\":\\\"%s\\\",\\\"case_id\\\":\\\"%s\\\",\\\"post_state\\\":%s,\\\"side_effects\\\":%s,\\\"successor_rva\\\":%s}\\n\", block_label, case_id, post_state_json.c_str(), side_effects_json.c_str(), successor);\n",
        "  std::fflush(out);\n",
        "}\n",
        "} // namespace wincr_block_verify\n",
        "\n",
        "#define WINCR_BLOCK_OBSERVE(label, phase, state_json) \\\n",
        "  ::wincr_block_verify::observe((label), (phase), (state_json))\n",
        "#define WINCR_BLOCK_RESULT(label, case_id, post_state_json, side_effects_json, successor_rva_json) \\\n",
        "  ::wincr_block_verify::result((label), (case_id), (post_state_json), (side_effects_json), (successor_rva_json))\n"
    )
}

fn write_cases_jsonl(path: PathBuf, block: &BasicBlock, cases: &[OwnedCase]) -> Result<(), String> {
    let mut file =
        File::create(&path).map_err(|err| format!("create {}: {err}", path.display()))?;
    for case in cases {
        let payload = ConformanceCase {
            format: SUITE_FORMAT,
            case_id: case.case_id.clone(),
            block_label: &block.label,
            origin: case.origin,
            status: case.status,
            pre_state: case.pre_state.clone(),
            expected: case.expected.clone(),
            trace_refs: case.trace_refs.clone(),
        };
        serde_json::to_writer(&mut file, &payload)
            .map_err(|err| format!("serialize case {}: {err}", path.display()))?;
        file.write_all(b"\n")
            .map_err(|err| format!("write {}: {err}", path.display()))?;
    }
    Ok(())
}

#[derive(Clone, Debug, Default)]
struct LoadedWaivers {
    waivers: IndexMap<String, BlockWaiver>,
    issues: Vec<String>,
}

fn load_waivers(path: Option<&Path>, block_labels: &[String]) -> Result<LoadedWaivers, String> {
    let Some(path) = path else {
        return Ok(LoadedWaivers::default());
    };
    let text = fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    let file: CoverageWaiverFile = serde_json::from_str(&text)
        .map_err(|err| format!("parse waiver file {}: {err}", path.display()))?;
    let known = block_labels.iter().cloned().collect::<BTreeSet<_>>();
    let mut loaded = LoadedWaivers::default();
    for (label, waiver) in file.waivers {
        if !known.contains(&label) {
            loaded
                .issues
                .push(format!("waiver references unknown block {label}"));
            continue;
        }
        if waiver.reason.trim().is_empty() {
            loaded
                .issues
                .push(format!("waiver for {label} has an empty reason"));
        }
        if waiver.evidence.trim().is_empty() {
            loaded
                .issues
                .push(format!("waiver for {label} has empty evidence"));
        }
        loaded.waivers.insert(label, waiver);
    }
    Ok(loaded)
}

fn validate_candidate_trace(
    suite: &Path,
    candidate_trace: &Path,
    block_labels: &[String],
    waivers: &IndexMap<String, BlockWaiver>,
    allow_incomplete_side_effects: bool,
) -> Result<CandidateConformanceReport, String> {
    let expected = load_complete_cases(suite, block_labels, waivers)?;
    let observed = parse_candidate_results(candidate_trace)?;
    let mut passed_cases = 0usize;
    let mut missing_cases = Vec::new();
    let mut mismatches = Vec::new();

    for (case_id, case) in &expected {
        let Some(actual) = observed.get(case_id) else {
            missing_cases.push(case_id.clone());
            continue;
        };
        if actual.block_label != case.block_label {
            mismatches.push(CandidateMismatch {
                case_id: case_id.clone(),
                block_label: case.block_label.clone(),
                field: "block_label".to_string(),
                expected: Value::String(case.block_label.clone()),
                actual: Value::String(actual.block_label.clone()),
            });
            continue;
        }
        let mut case_failed = false;
        let expected_post = case
            .expected
            .as_ref()
            .map(|expected| &expected.post_state)
            .unwrap_or(&Value::Null);
        if expected_post != &actual.post_state {
            mismatches.push(CandidateMismatch {
                case_id: case_id.clone(),
                block_label: case.block_label.clone(),
                field: "post_state".to_string(),
                expected: expected_post.clone(),
                actual: actual.post_state.clone(),
            });
            case_failed = true;
        }
        let expected_successor = case
            .expected
            .as_ref()
            .and_then(|expected| expected.successor_rva.clone());
        if expected_successor != actual.successor_rva {
            mismatches.push(CandidateMismatch {
                case_id: case_id.clone(),
                block_label: case.block_label.clone(),
                field: "successor_rva".to_string(),
                expected: expected_successor.map(Value::String).unwrap_or(Value::Null),
                actual: actual
                    .successor_rva
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            });
            case_failed = true;
        }
        let expected_side_effects = case
            .expected
            .as_ref()
            .map(|expected| &expected.side_effects)
            .unwrap_or(&Value::Null);
        if !allow_incomplete_side_effects || side_effects_are_complete(expected_side_effects) {
            if expected_side_effects != &actual.side_effects {
                mismatches.push(CandidateMismatch {
                    case_id: case_id.clone(),
                    block_label: case.block_label.clone(),
                    field: "side_effects".to_string(),
                    expected: expected_side_effects.clone(),
                    actual: actual.side_effects.clone(),
                });
                case_failed = true;
            }
        }
        if !case_failed {
            passed_cases += 1;
        }
    }

    let expected_case_ids = expected.keys().cloned().collect::<BTreeSet<_>>();
    let unexpected_cases = observed
        .keys()
        .filter(|case_id| !expected_case_ids.contains(*case_id))
        .cloned()
        .collect::<Vec<_>>();
    let failed_cases = missing_cases.len() + mismatches.len();
    let mut issues = Vec::new();
    if !missing_cases.is_empty() {
        issues.push(format!(
            "{} expected candidate case results are missing",
            missing_cases.len()
        ));
    }
    if !unexpected_cases.is_empty() {
        issues.push(format!(
            "{} candidate case results do not match any original case",
            unexpected_cases.len()
        ));
    }
    if !mismatches.is_empty() {
        issues.push(format!(
            "{} candidate case fields diverged",
            mismatches.len()
        ));
    }

    Ok(CandidateConformanceReport {
        format: CONFORMANCE_FORMAT,
        status: if issues.is_empty() { "pass" } else { "fail" }.to_string(),
        expected_cases: expected.len(),
        observed_cases: observed.len(),
        passed_cases,
        failed_cases,
        missing_cases,
        unexpected_cases,
        mismatches,
        issues,
    })
}

fn load_complete_cases(
    suite: &Path,
    block_labels: &[String],
    waivers: &IndexMap<String, BlockWaiver>,
) -> Result<IndexMap<String, ConformanceCaseOwned>, String> {
    let mut cases = IndexMap::new();
    for label in block_labels {
        if waivers.contains_key(label) {
            continue;
        }
        let path = suite.join("blocks").join(label).join("cases.jsonl");
        for value in read_jsonl_values(&path)? {
            if value.get("status").and_then(Value::as_str) != Some("complete") {
                continue;
            }
            let case_id = string_field(&value, "case_id")
                .ok_or_else(|| format!("{} has a complete case without case_id", path.display()))?;
            let expected = value.get("expected").cloned().unwrap_or(Value::Null);
            let expected = parse_expected_state_value(&expected, &path, &case_id)?;
            cases.insert(
                case_id.clone(),
                ConformanceCaseOwned {
                    block_label: label.clone(),
                    expected: Some(expected),
                },
            );
        }
    }
    Ok(cases)
}

#[derive(Clone, Debug)]
struct ConformanceCaseOwned {
    block_label: String,
    expected: Option<ExpectedState>,
}

fn parse_expected_state_value(
    value: &Value,
    path: &Path,
    case_id: &str,
) -> Result<ExpectedState, String> {
    let post_state = value.get("post_state").cloned().ok_or_else(|| {
        format!(
            "{} case {case_id} missing expected.post_state",
            path.display()
        )
    })?;
    let successor_rva = value.get("successor_rva").and_then(|value| match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(_) => parse_rva_value(value).map(hex_u32),
        _ => None,
    });
    let side_effects = value.get("side_effects").cloned().unwrap_or(Value::Null);
    Ok(ExpectedState {
        post_state,
        successor_rva,
        side_effects,
    })
}

fn parse_candidate_results(path: &Path) -> Result<IndexMap<String, CandidateCaseResult>, String> {
    let file = File::open(path).map_err(|err| format!("open {}: {err}", path.display()))?;
    let reader = BufReader::new(file);
    let mut results = IndexMap::new();
    for (line_number, line) in reader.lines().enumerate() {
        let line =
            line.map_err(|err| format!("read {}:{}: {err}", path.display(), line_number + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let raw: Value = serde_json::from_str(&line).map_err(|err| {
            format!(
                "parse {}:{} as JSON: {err}",
                path.display(),
                line_number + 1
            )
        })?;
        if raw.get("kind").and_then(Value::as_str) != Some("candidate_block_result") {
            continue;
        }
        let case_id = string_field(&raw, "case_id")
            .ok_or_else(|| format!("{}:{} missing case_id", path.display(), line_number + 1))?;
        let block_label = string_field(&raw, "block_label")
            .ok_or_else(|| format!("{}:{} missing block_label", path.display(), line_number + 1))?;
        let post_state = raw.get("post_state").cloned().unwrap_or(Value::Null);
        let side_effects = raw.get("side_effects").cloned().unwrap_or(Value::Null);
        let successor_rva = raw.get("successor_rva").and_then(|value| match value {
            Value::String(text) => Some(text.clone()),
            Value::Number(_) => parse_rva_value(value).map(hex_u32),
            _ => None,
        });
        results.insert(
            case_id,
            CandidateCaseResult {
                block_label,
                post_state,
                side_effects,
                successor_rva,
            },
        );
    }
    Ok(results)
}

fn suite_block_labels(suite: &Path) -> Result<Vec<String>, String> {
    let blocks = suite.join("blocks");
    let mut labels = Vec::new();
    for entry in fs::read_dir(&blocks).map_err(|err| format!("read {}: {err}", blocks.display()))? {
        let entry = entry.map_err(|err| format!("read {} entry: {err}", blocks.display()))?;
        if entry
            .file_type()
            .map_err(|err| format!("stat {}: {err}", entry.path().display()))?
            .is_dir()
        {
            labels.push(entry.file_name().to_string_lossy().to_string());
        }
    }
    labels.sort();
    Ok(labels)
}

fn suite_required_block_labels(suite: &Path) -> Result<Vec<String>, String> {
    let mut labels = Vec::new();
    for label in suite_block_labels(suite)? {
        let path = suite.join("blocks").join(&label).join("obligation.json");
        let text =
            fs::read_to_string(&path).map_err(|err| format!("read {}: {err}", path.display()))?;
        let value: Value = serde_json::from_str(&text)
            .map_err(|err| format!("parse {} as JSON: {err}", path.display()))?;
        if value.get("classification").and_then(Value::as_str)
            != Some(ALIGNMENT_PADDING_CLASSIFICATION)
        {
            labels.push(label);
        }
    }
    labels.sort();
    Ok(labels)
}

fn required_waiver_count(
    required_block_labels: &[String],
    waivers: &IndexMap<String, BlockWaiver>,
) -> usize {
    required_block_labels
        .iter()
        .filter(|label| waivers.contains_key(*label))
        .count()
}

fn read_jsonl_values(path: &Path) -> Result<Vec<Value>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(path).map_err(|err| format!("open {}: {err}", path.display()))?;
    let reader = BufReader::new(file);
    let mut values = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|err| format!("read {}:{}: {err}", path.display(), index + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        values.push(
            serde_json::from_str(&line)
                .map_err(|err| format!("parse {}:{} as JSON: {err}", path.display(), index + 1))?,
        );
    }
    Ok(values)
}

fn write_json<T: Serialize>(path: PathBuf, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create {}: {err}", parent.display()))?;
    }
    let mut file =
        File::create(&path).map_err(|err| format!("create {}: {err}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, value)
        .map_err(|err| format!("serialize {}: {err}", path.display()))?;
    file.write_all(b"\n")
        .map_err(|err| format!("write {}: {err}", path.display()))
}

fn write_text(path: PathBuf, text: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create {}: {err}", parent.display()))?;
    }
    fs::write(&path, text).map_err(|err| format!("write {}: {err}", path.display()))
}

fn label_for_rva(blocks: &[BasicBlock], rva: u32) -> Option<String> {
    blocks
        .iter()
        .find(|block| rva >= block.rva_start && rva < block.rva_end)
        .map(|block| block.label.clone())
}

fn string_field(raw: &Value, key: &str) -> Option<String> {
    raw.get(key).and_then(Value::as_str).map(str::to_string)
}

fn rva_field(raw: &Value, key: &str) -> Option<u32> {
    parse_rva_value(raw.get(key)?)
}

fn parse_rva_value(value: &Value) -> Option<u32> {
    match value {
        Value::Number(number) => number.as_u64().and_then(|value| u32::try_from(value).ok()),
        Value::String(text) => parse_rva_text(text),
        _ => None,
    }
}

fn parse_rva_text(text: &str) -> Option<u32> {
    if let Some(hex) = text.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()
    } else {
        text.parse::<u32>().ok()
    }
}

fn trace_source_id(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("trace")
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | '.' => ch,
            _ => '_',
        })
        .collect()
}

fn block_label(start: u32, end: u32) -> String {
    format!("bb_{start:08x}_{end:08x}")
}

fn hex_u16(value: u16) -> String {
    format!("0x{value:04x}")
}

fn hex_u32(value: u32) -> String {
    format!("0x{value:x}")
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, String> {
    if offset + 2 > data.len() {
        return Err("unexpected end of file while reading u16".to_string());
    }
    Ok(u16::from_le_bytes(
        data[offset..offset + 2].try_into().unwrap(),
    ))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, String> {
    if offset + 4 > data.len() {
        return Err("unexpected end of file while reading u32".to_string());
    }
    Ok(u32::from_le_bytes(
        data[offset..offset + 4].try_into().unwrap(),
    ))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, String> {
    if offset + 8 > data.len() {
        return Err("unexpected end of file while reading u64".to_string());
    }
    Ok(u64::from_le_bytes(
        data[offset..offset + 8].try_into().unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn recovers_conditional_branch_blocks_with_iced() {
        let code = [0x74, 0x02, 0x31, 0xc0, 0xc3];
        let image = synthetic_image(&code);
        let recovery = recover_blocks(image);
        assert_eq!(recovery.blocks.len(), 3);
        assert_eq!(recovery.blocks[0].rva_start, 0x1000);
        assert_eq!(recovery.blocks[0].terminator, Terminator::ConditionalJump);
        assert_eq!(recovery.blocks[0].successors, vec![0x1002, 0x1004]);
        assert_eq!(recovery.blocks[2].terminator, Terminator::Ret);
    }

    #[test]
    fn parses_minimal_pe_image_and_trims_file_alignment_padding() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("minimal.exe");
        fs::write(&path, minimal_pe(&[0xc3])).unwrap();
        let image = PeImage::parse(&path).unwrap();
        assert_eq!(image.machine, 0x14c);
        assert_eq!(image.entry_rva, 0x1000);
        assert_eq!(image.executable_sections().count(), 1);
        let recovery = recover_blocks_from_path(&path).unwrap();
        assert_eq!(recovery.blocks.len(), 1);
        assert_eq!(recovery.blocks[0].terminator, Terminator::Ret);
    }

    #[test]
    fn alignment_padding_is_preserved_but_not_required_for_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0xc3, 0x90, 0x90])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":null,\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_writes\":[],\"api_calls\":[],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();

        let all_labels = suite_block_labels(&suite).unwrap();
        assert_eq!(all_labels.len(), 2);
        let required_labels = suite_required_block_labels(&suite).unwrap();
        assert_eq!(required_labels, vec!["bb_00001000_00001001"]);
        let padding_obligation: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join("bb_00001001_00001003")
                    .join("obligation.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            padding_obligation["classification"],
            ALIGNMENT_PADDING_CLASSIFICATION
        );
        assert_eq!(
            padding_obligation["candidate_requirement"]["distinct_semantic_point"],
            false
        );

        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.required_blocks, 1);
        assert_eq!(coverage.uncovered_blocks.len(), 0);
    }

    #[test]
    fn exact_zero_return_block_gets_static_block_local_seed() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x31, 0xc0, 0x31, 0xd2, 0xc3])).unwrap();

        emit_suite(&binary, &suite, &SuiteOptions::default()).unwrap();

        let labels = suite_required_block_labels(&suite).unwrap();
        assert_eq!(labels, vec!["bb_00001000_00001005"]);
        let cases = read_jsonl_values(
            &suite
                .join("blocks")
                .join("bb_00001000_00001005")
                .join("cases.jsonl"),
        )
        .unwrap();
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0]["origin"], "static_x86_32_block_semantics_v1");
        assert_eq!(cases[0]["status"], "complete");
        assert_eq!(
            cases[0]["expected"]["side_effects"]["capture_status"],
            "complete"
        );
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
    }

    #[test]
    fn trace_v2_entry_exit_generates_complete_case() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":2}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_writes\":[],\"api_calls\":[],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let labels = suite_block_labels(&suite).unwrap();
        let cases =
            read_jsonl_values(&suite.join("blocks").join(&labels[0]).join("cases.jsonl")).unwrap();
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0]["status"], "complete");
        assert_eq!(cases[0]["expected"]["post_state"]["registers"]["eax"], 2);
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
    }

    #[test]
    fn max_cases_per_block_bounds_output_and_prefers_complete_side_effects() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":2}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_writes\":[],\"api_calls\":[],\"external_events\":[],\"limitations\":[\"api_semantics_decoder_missing\"]}}\n",
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":3}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":4}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_writes\":[],\"api_calls\":[],\"external_events\":[],\"limitations\":[]}}\n",
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":5}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":6}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_writes\":[],\"api_calls\":[],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                max_cases_per_block: Some(1),
            },
        )
        .unwrap();
        let manifest: Value =
            serde_json::from_str(&fs::read_to_string(suite.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["trace_records"], 6);
        assert_eq!(manifest["complete_cases"], 1);
        assert!(manifest["trace_issues"][0]
            .as_str()
            .unwrap()
            .contains("dropped 1 excess cases"));
        let labels = suite_block_labels(&suite).unwrap();
        let cases =
            read_jsonl_values(&suite.join("blocks").join(&labels[0]).join("cases.jsonl")).unwrap();
        assert_eq!(cases.len(), 1);
        assert_eq!(
            cases[0]["expected"]["side_effects"]["capture_status"],
            "complete"
        );
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
    }

    #[test]
    fn partial_side_effect_trace_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":2}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[{\"address\":4096,\"size\":4,\"value\":\"01000000\",\"read_ok\":true,\"truncated\":false}],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"external\":true}],\"limitations\":[\"api_return_values_not_instrumented\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_call_side_effect_trace_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":2}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"external\":false,\"return_captured\":true,\"return_value\":2,\"output_buffers\":[{\"arg_index\":0,\"address\":8192,\"before\":\"00000000\",\"after\":\"02000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}]}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":2}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn complete_api_output_aggregate_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            format!(
                concat!(
                    "{{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{{\"registers\":{{\"eax\":1}}}}}}\n",
                    "{{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{{\"registers\":{{\"eax\":2}}}},\"side_effects\":{{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{{\"caller_rva\":4096,\"callee_module\":\"libc.so.6\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"gettimeofday\",\"semantic_class\":\"time\",\"operation\":\"gettimeofday\",\"external\":true,\"stack_args\":[8192,12288],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{{\"kind\":\"errno\",\"captured\":true,\"before\":0,\"after\":0}},\"output_buffers\":[],\"output_buffer_dropped\":0,\"output_buffer_aggregate\":{{\"count\":2,\"sha256\":\"{digest}\",\"sha256_ok\":true,\"entries\":[{{\"arg_index\":0,\"address\":8192,\"size\":16,\"before_sha256\":\"{digest}\",\"before_sha256_ok\":true,\"after_sha256\":\"{digest}\",\"after_sha256_ok\":true,\"truncated\":false}},{{\"arg_index\":1,\"address\":12288,\"size\":8,\"before_sha256\":\"{digest}\",\"before_sha256_ok\":true,\"after_sha256\":\"{digest}\",\"after_sha256_ok\":true,\"truncated\":false}}]}}}}],\"api_returns\":[{{\"caller_rva\":4096,\"return_value\":0}}],\"external_events\":[],\"limitations\":[]}}}}\n"
                ),
                digest = digest
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("api_output_buffers")));
    }

    #[test]
    fn complete_get_last_error_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":5}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"GetLastError\",\"semantic_class\":\"thread_error_state\",\"operation\":\"GetLastError\",\"external\":true,\"stack_args\":[],\"return_captured\":true,\"return_value\":5,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":5,\"after\":5},\"thread_error_effect\":{\"captured\":true,\"kind\":\"win32_last_error\",\"operation\":\"get_last_error\",\"before\":5,\"after\":5,\"requested\":null,\"return_value\":5,\"mutated\":false},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":5}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("thread_error_effects")));
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("thread_error:get_last_error")));
    }

    #[test]
    fn complete_set_last_error_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":0}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"SetLastError\",\"semantic_class\":\"thread_error_state\",\"operation\":\"SetLastError\",\"external\":true,\"stack_args\":[5],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":5},\"thread_error_effect\":{\"captured\":true,\"kind\":\"win32_last_error\",\"operation\":\"set_last_error\",\"before\":0,\"after\":5,\"requested\":5,\"return_value\":null,\"mutated\":true},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":0}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn complete_winsock_last_error_effects_pass_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":10054}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"ws2_32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"WSAGetLastError\",\"semantic_class\":\"thread_error_state\",\"operation\":\"WSAGetLastError\",\"external\":true,\"stack_args\":[],\"return_captured\":true,\"return_value\":10035,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"thread_error_effect\":{\"captured\":true,\"kind\":\"winsock_last_error\",\"operation\":\"wsa_get_last_error\",\"before\":10035,\"after\":10035,\"requested\":null,\"return_value\":10035,\"mutated\":false},\"output_buffers\":[],\"output_buffer_dropped\":0},{\"caller_rva\":4096,\"callee_module\":\"ws2_32.dll\",\"callee_rva\":1240,\"symbol_resolved\":true,\"callee_symbol\":\"WSASetLastError\",\"semantic_class\":\"thread_error_state\",\"operation\":\"WSASetLastError\",\"external\":true,\"stack_args\":[10054],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"thread_error_effect\":{\"captured\":true,\"kind\":\"winsock_last_error\",\"operation\":\"wsa_set_last_error\",\"before\":10035,\"after\":10054,\"requested\":10054,\"return_value\":null,\"mutated\":true},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":10035},{\"caller_rva\":4096,\"return_value\":0}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("thread_error:wsa_get_last_error")));
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("thread_error:wsa_set_last_error")));
    }

    #[test]
    fn winsock_last_error_with_win32_kind_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":10054}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"ws2_32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"WSASetLastError\",\"semantic_class\":\"thread_error_state\",\"operation\":\"WSASetLastError\",\"external\":true,\"stack_args\":[10054],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"thread_error_effect\":{\"captured\":true,\"kind\":\"win32_last_error\",\"operation\":\"wsa_set_last_error\",\"before\":10035,\"after\":10054,\"requested\":10054,\"return_value\":null,\"mutated\":true},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":0}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn set_last_error_without_thread_error_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":0}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"SetLastError\",\"semantic_class\":\"thread_error_state\",\"operation\":\"SetLastError\",\"external\":true,\"stack_args\":[5],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":5},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":0}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn set_last_error_wrong_after_value_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":0}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"SetLastError\",\"semantic_class\":\"thread_error_state\",\"operation\":\"SetLastError\",\"external\":true,\"stack_args\":[5],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":4},\"thread_error_effect\":{\"captured\":true,\"kind\":\"win32_last_error\",\"operation\":\"set_last_error\",\"before\":0,\"after\":4,\"requested\":5,\"return_value\":null,\"mutated\":true},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":0}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_winsock_socket_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":3}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"ws2_32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"socket\",\"semantic_class\":\"network\",\"operation\":\"socket\",\"external\":true,\"stack_args\":[2,1,6],\"return_captured\":true,\"return_value\":3,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=1,protocol=6\",\"handle\":null,\"handle_result\":3,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"network_effect\":{\"captured\":true,\"operation\":\"socket\",\"succeeded\":true,\"target\":{\"handle\":null,\"known\":false,\"kind\":\"\",\"label\":\"\"},\"result\":{\"handle\":3,\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=1,protocol=6\"},\"domain\":2,\"type\":1,\"protocol\":6,\"backlog\":null,\"shutdown_how\":null,\"option_level\":null,\"option_name\":null,\"option_value_address\":null,\"option_value_size\":null,\"address_address\":null,\"address_size\":null,\"address_length_address\":null,\"address_length\":null,\"payload_address\":null,\"requested_size\":null,\"transferred\":null,\"flags\":null,\"mutation_captured\":true,\"mutates_socket_state\":true,\"mutates_network\":false,\"mutates_caller_buffer\":false},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":3}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("network_effects")));
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("network:socket")));
    }

    #[test]
    fn complete_winsock_startup_cleanup_effects_pass_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            format!(
                concat!(
                    "{{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{{\"registers\":{{\"eax\":1}}}}}}\n",
                    "{{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{{\"registers\":{{\"eax\":0}}}},\"side_effects\":{{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{{\"caller_rva\":4096,\"callee_module\":\"ws2_32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"WSAStartup\",\"semantic_class\":\"network\",\"operation\":\"WSAStartup\",\"external\":true,\"stack_args\":[514,8192],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0}},\"network_effect\":{{\"captured\":true,\"operation\":\"wsa_startup\",\"succeeded\":true,\"target\":{{\"handle\":null,\"known\":false,\"kind\":\"\",\"label\":\"\"}},\"result\":{{\"handle\":null,\"known\":false,\"kind\":\"\",\"label\":\"\"}},\"domain\":null,\"type\":null,\"protocol\":null,\"version_requested\":514,\"data_address\":8192,\"data_size\":400,\"data_version\":514,\"data_high_version\":514,\"backlog\":null,\"shutdown_how\":null,\"option_level\":null,\"option_name\":null,\"option_value_address\":null,\"option_value_size\":null,\"address_address\":null,\"address_size\":null,\"address_length_address\":null,\"address_length\":null,\"payload_address\":null,\"requested_size\":null,\"transferred\":null,\"flags\":null,\"mutation_captured\":true,\"mutates_socket_state\":true,\"mutates_network\":false,\"mutates_caller_buffer\":true}},\"output_buffers\":[{{\"arg_index\":1,\"address\":8192,\"size\":400,\"before_sha256\":\"{digest}\",\"before_sha256_ok\":true,\"after_sha256\":\"{digest}\",\"after_sha256_ok\":true,\"before_ok\":true,\"after_ok\":true,\"truncated\":true}}],\"output_buffer_dropped\":0}},{{\"caller_rva\":4096,\"callee_module\":\"ws2_32.dll\",\"callee_rva\":1240,\"symbol_resolved\":true,\"callee_symbol\":\"WSACleanup\",\"semantic_class\":\"network\",\"operation\":\"WSACleanup\",\"external\":true,\"stack_args\":[],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0}},\"network_effect\":{{\"captured\":true,\"operation\":\"wsa_cleanup\",\"succeeded\":true,\"target\":{{\"handle\":null,\"known\":false,\"kind\":\"\",\"label\":\"\"}},\"result\":{{\"handle\":null,\"known\":false,\"kind\":\"\",\"label\":\"\"}},\"domain\":null,\"type\":null,\"protocol\":null,\"version_requested\":null,\"data_address\":null,\"data_size\":null,\"data_version\":null,\"data_high_version\":null,\"backlog\":null,\"shutdown_how\":null,\"option_level\":null,\"option_name\":null,\"option_value_address\":null,\"option_value_size\":null,\"address_address\":null,\"address_size\":null,\"address_length_address\":null,\"address_length\":null,\"payload_address\":null,\"requested_size\":null,\"transferred\":null,\"flags\":null,\"mutation_captured\":true,\"mutates_socket_state\":true,\"mutates_network\":false,\"mutates_caller_buffer\":false}},\"output_buffers\":[],\"output_buffer_dropped\":0}}],\"api_returns\":[{{\"caller_rva\":4096,\"return_value\":0}},{{\"caller_rva\":4096,\"return_value\":0}}],\"external_events\":[],\"limitations\":[]}}}}\n"
                ),
                digest = digest
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("network:wsa_startup")));
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("network:wsa_cleanup")));
    }

    #[test]
    fn winsock_startup_without_wsadata_evidence_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":0}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"ws2_32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"WSAStartup\",\"semantic_class\":\"network\",\"operation\":\"WSAStartup\",\"external\":true,\"stack_args\":[514,8192],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"network_effect\":{\"captured\":true,\"operation\":\"wsa_startup\",\"succeeded\":true,\"target\":{\"handle\":null,\"known\":false,\"kind\":\"\",\"label\":\"\"},\"result\":{\"handle\":null,\"known\":false,\"kind\":\"\",\"label\":\"\"},\"domain\":null,\"type\":null,\"protocol\":null,\"version_requested\":514,\"data_address\":8192,\"data_size\":400,\"data_version\":514,\"data_high_version\":514,\"backlog\":null,\"shutdown_how\":null,\"option_level\":null,\"option_name\":null,\"option_value_address\":null,\"option_value_size\":null,\"address_address\":null,\"address_size\":null,\"address_length_address\":null,\"address_length\":null,\"payload_address\":null,\"requested_size\":null,\"transferred\":null,\"flags\":null,\"mutation_captured\":true,\"mutates_socket_state\":true,\"mutates_network\":false,\"mutates_caller_buffer\":true},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":0}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_winsock_ioctl_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":0}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"ws2_32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"ioctlsocket\",\"semantic_class\":\"network\",\"operation\":\"ioctlsocket\",\"external\":true,\"stack_args\":[3,2147772030,8192],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=1,protocol=6\",\"handle\":3,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"socket\",\"handle\":3,\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=1,protocol=6\"}],\"resource_ref_dropped\":0,\"network_effect\":{\"captured\":true,\"operation\":\"ioctl_socket\",\"succeeded\":true,\"target\":{\"handle\":3,\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=1,protocol=6\"},\"result\":{\"handle\":null,\"known\":false,\"kind\":\"\",\"label\":\"\"},\"ioctl_command\":2147772030,\"ioctl_command_known\":true,\"ioctl_arg_address\":8192,\"ioctl_arg_before\":1,\"ioctl_arg_after\":1,\"mutation_captured\":true,\"mutates_socket_state\":true,\"mutates_network\":false,\"mutates_caller_buffer\":false},\"output_buffers\":[{\"arg_index\":2,\"address\":8192,\"size\":4,\"before\":\"01000000\",\"after\":\"01000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":0}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("network:ioctl_socket")));
    }

    #[test]
    fn winsock_ioctl_unknown_command_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":0}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"ws2_32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"ioctlsocket\",\"semantic_class\":\"network\",\"operation\":\"ioctlsocket\",\"external\":true,\"stack_args\":[3,3735928559,8192],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=1,protocol=6\",\"handle\":3,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"socket\",\"handle\":3,\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=1,protocol=6\"}],\"resource_ref_dropped\":0,\"network_effect\":{\"captured\":true,\"operation\":\"ioctl_socket\",\"succeeded\":true,\"target\":{\"handle\":3,\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=1,protocol=6\"},\"result\":{\"handle\":null,\"known\":false,\"kind\":\"\",\"label\":\"\"},\"ioctl_command\":3735928559,\"ioctl_command_known\":false,\"ioctl_arg_address\":8192,\"ioctl_arg_before\":1,\"ioctl_arg_after\":1,\"mutation_captured\":true,\"mutates_socket_state\":false,\"mutates_network\":false,\"mutates_caller_buffer\":false},\"output_buffers\":[{\"arg_index\":2,\"address\":8192,\"size\":4,\"before\":\"01000000\",\"after\":\"01000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":0}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_winsock_send_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"ws2_32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"send\",\"semantic_class\":\"network\",\"operation\":\"send\",\"external\":true,\"stack_args\":[3,8192,1,0],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=1,protocol=6\",\"handle\":3,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"socket\",\"handle\":3,\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=1,protocol=6\"}],\"resource_ref_dropped\":0,\"network_effect\":{\"captured\":true,\"operation\":\"send\",\"succeeded\":true,\"target\":{\"handle\":3,\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=1,protocol=6\"},\"result\":{\"handle\":null,\"known\":false,\"kind\":\"\",\"label\":\"\"},\"domain\":null,\"type\":null,\"protocol\":null,\"backlog\":null,\"shutdown_how\":null,\"option_level\":null,\"option_name\":null,\"option_value_address\":null,\"option_value_size\":null,\"address_address\":null,\"address_size\":null,\"address_length_address\":null,\"address_length\":null,\"payload_address\":8192,\"requested_size\":1,\"transferred\":1,\"flags\":0,\"mutation_captured\":true,\"mutates_socket_state\":false,\"mutates_network\":true,\"mutates_caller_buffer\":false},\"output_buffers\":[{\"arg_index\":1,\"address\":8192,\"size\":1,\"before\":\"6e\",\"after\":\"6e\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn winsock_send_without_network_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"ws2_32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"send\",\"semantic_class\":\"network\",\"operation\":\"send\",\"external\":true,\"stack_args\":[3,8192,1,0],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=1,protocol=6\",\"handle\":3,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"socket\",\"handle\":3,\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=1,protocol=6\"}],\"resource_ref_dropped\":0,\"output_buffers\":[{\"arg_index\":1,\"address\":8192,\"size\":1,\"before\":\"6e\",\"after\":\"6e\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn winsock_send_without_payload_evidence_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"ws2_32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"send\",\"semantic_class\":\"network\",\"operation\":\"send\",\"external\":true,\"stack_args\":[3,8192,1,0],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=1,protocol=6\",\"handle\":3,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"socket\",\"handle\":3,\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=1,protocol=6\"}],\"resource_ref_dropped\":0,\"network_effect\":{\"captured\":true,\"operation\":\"send\",\"succeeded\":true,\"target\":{\"handle\":3,\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=1,protocol=6\"},\"result\":{\"handle\":null,\"known\":false,\"kind\":\"\",\"label\":\"\"},\"domain\":null,\"type\":null,\"protocol\":null,\"backlog\":null,\"shutdown_how\":null,\"option_level\":null,\"option_name\":null,\"option_value_address\":null,\"option_value_size\":null,\"address_address\":null,\"address_size\":null,\"address_length_address\":null,\"address_length\":null,\"payload_address\":8192,\"requested_size\":1,\"transferred\":1,\"flags\":0,\"mutation_captured\":true,\"mutates_socket_state\":false,\"mutates_network\":true,\"mutates_caller_buffer\":false},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn unresolved_external_api_call_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":2}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":false,\"callee_symbol\":\"\",\"semantic_class\":\"window_messages\",\"operation\":\"module_call\",\"external\":true,\"return_captured\":true,\"return_value\":2,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":2}],\"external_events\":[],\"limitations\":[\"api_symbol_not_resolved\",\"api_semantics_decoder_missing\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_memory_aggregate_side_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            format!(
                concat!(
                    "{{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{{\"registers\":{{\"eax\":1}}}}}}\n",
                    "{{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{{\"registers\":{{\"eax\":2}}}},\"side_effects\":{{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"memory_aggregates\":{{\"reads\":{{\"count\":4,\"sha256\":\"{digest}\",\"sha256_ok\":true}},\"writes\":{{\"count\":4,\"sha256\":\"{digest}\",\"sha256_ok\":true}}}},\"api_calls\":[],\"api_returns\":[],\"external_events\":[],\"limitations\":[]}}}}\n"
                ),
                digest = digest
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("memory_reads")));
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("memory_writes")));
    }

    #[test]
    fn decoded_external_api_call_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1234}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"libc.so.6\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"getpid\",\"semantic_class\":\"process\",\"operation\":\"getpid\",\"external\":true,\"return_captured\":true,\"return_value\":1234,\"thread_error_state\":{\"kind\":\"errno\",\"captured\":true,\"before\":0,\"after\":0},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1234}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn unresolved_win32_api_resource_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"WriteFile\",\"semantic_class\":\"files\",\"operation\":\"WriteFile\",\"external\":true,\"stack_args\":[57005,8192,1,12288,0],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":57005,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"output_buffers\":[{\"arg_index\":1,\"address\":8192,\"size\":1,\"before\":\"78\",\"after\":\"78\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false},{\"arg_index\":3,\"address\":12288,\"size\":4,\"before\":\"00000000\",\"after\":\"01000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[\"api_resource_not_resolved\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn resolved_win32_api_resource_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"WriteFile\",\"semantic_class\":\"files\",\"operation\":\"WriteFile\",\"external\":true,\"stack_args\":[4,8192,1,12288,0],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"stdio\",\"label\":\"stdout\",\"handle\":4,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"file_effect\":{\"captured\":true,\"operation\":\"write_file\",\"succeeded\":true,\"target\":{\"handle\":4,\"known\":true,\"kind\":\"stdio\",\"label\":\"stdout\"},\"result\":{\"handle\":null,\"known\":false,\"kind\":\"\",\"label\":\"\"},\"desired_access\":null,\"share_mode\":null,\"creation_disposition\":null,\"flags_attributes\":null,\"data_address\":8192,\"requested_size\":1,\"transferred_address\":12288,\"transferred\":1,\"distance\":null,\"move_method\":null,\"new_position_address\":null,\"new_position\":null,\"size\":null,\"file_type\":null,\"mutation_captured\":true,\"mutates_data\":true,\"mutates_position\":true,\"mutates_size\":false,\"mutates_caller_buffer\":false},\"output_buffers\":[{\"arg_index\":1,\"address\":8192,\"size\":1,\"before\":\"78\",\"after\":\"78\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false},{\"arg_index\":3,\"address\":12288,\"size\":4,\"before\":\"00000000\",\"after\":\"01000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn resolved_win32_file_api_without_file_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"WriteFile\",\"semantic_class\":\"files\",\"operation\":\"WriteFile\",\"external\":true,\"stack_args\":[4,8192,1,12288,0],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"stdio\",\"label\":\"stdout\",\"handle\":4,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"output_buffers\":[{\"arg_index\":1,\"address\":8192,\"size\":1,\"before\":\"78\",\"after\":\"78\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false},{\"arg_index\":3,\"address\":12288,\"size\":4,\"before\":\"00000000\",\"after\":\"01000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn unresolved_win32_api_resource_ref_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"ReleaseDC\",\"semantic_class\":\"gdi_calls\",\"operation\":\"ReleaseDC\",\"external\":true,\"stack_args\":[100,200],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":200,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"hwnd\",\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"},{\"arg_index\":1,\"role\":\"hdc\",\"handle\":200,\"known\":false,\"kind\":\"\",\"label\":\"\"}],\"resource_ref_dropped\":0,\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[\"api_resource_not_resolved\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn resolved_win32_api_resource_refs_pass_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"ReleaseDC\",\"semantic_class\":\"gdi_calls\",\"operation\":\"ReleaseDC\",\"external\":true,\"stack_args\":[100,200],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main\",\"handle\":200,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"hwnd\",\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"},{\"arg_index\":1,\"role\":\"hdc\",\"handle\":200,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main\"}],\"resource_ref_dropped\":0,\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn complete_win32_api_resource_ref_aggregate_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            format!(
                concat!(
                    "{{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{{\"registers\":{{\"eax\":1}}}}}}\n",
                    "{{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{{\"registers\":{{\"eax\":1}}}},\"side_effects\":{{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"SyntheticManyResources\",\"semantic_class\":\"gdi_calls\",\"operation\":\"SyntheticManyResources\",\"external\":true,\"stack_args\":[10,11,12,13,14],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0}},\"resource\":{{\"known\":true,\"kind\":\"window\",\"label\":\"window:main\",\"handle\":10,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false}},\"resource_refs\":[{{\"arg_index\":0,\"role\":\"hwnd\",\"handle\":10,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"}},{{\"arg_index\":1,\"role\":\"hwnd\",\"handle\":11,\"known\":true,\"kind\":\"window\",\"label\":\"window:aux1\"}},{{\"arg_index\":2,\"role\":\"hwnd\",\"handle\":12,\"known\":true,\"kind\":\"window\",\"label\":\"window:aux2\"}},{{\"arg_index\":3,\"role\":\"hwnd\",\"handle\":13,\"known\":true,\"kind\":\"window\",\"label\":\"window:aux3\"}}],\"resource_ref_dropped\":0,\"resource_ref_aggregate\":{{\"count\":1,\"sha256\":\"{digest}\",\"sha256_ok\":true,\"entries\":[{{\"arg_index\":4,\"role\":\"hdc\",\"handle\":14,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:overflow\"}}]}},\"output_buffers\":[],\"output_buffer_dropped\":0}}],\"api_returns\":[{{\"caller_rva\":4096,\"return_value\":1}}],\"external_events\":[],\"limitations\":[]}}}}\n"
                ),
                digest = digest
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("api_resources")));
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("api_resource:dc")));
    }

    #[test]
    fn incomplete_win32_drawing_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"gdi32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"LineTo\",\"semantic_class\":\"gdi_calls\",\"operation\":\"LineTo\",\"external\":true,\"stack_args\":[200,10,20],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main\",\"handle\":200,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"hdc\",\"handle\":200,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main\"}],\"resource_ref_dropped\":0,\"draw_effect\":{\"captured\":false,\"operation\":\"line_to\",\"target\":{\"handle\":200,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main\"},\"arguments\":[200,10,20]},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[\"api_drawing_effect_not_captured\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_drawing_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"gdi32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"LineTo\",\"semantic_class\":\"gdi_calls\",\"operation\":\"LineTo\",\"external\":true,\"stack_args\":[200,10,20],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main\",\"handle\":200,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"hdc\",\"handle\":200,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main\"}],\"resource_ref_dropped\":0,\"draw_effect\":{\"captured\":true,\"operation\":\"line_to\",\"target\":{\"handle\":200,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main\"},\"arguments\":[200,10,20]},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn incomplete_win32_framebuffer_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"gdi32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"BitBlt\",\"semantic_class\":\"gdi_calls\",\"operation\":\"BitBlt\",\"external\":true,\"stack_args\":[200,0,0,640,480,201,0,0,13369376],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"dc\",\"label\":\"dc:front\",\"handle\":200,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"dest_hdc\",\"handle\":200,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:front\"},{\"arg_index\":5,\"role\":\"src_hdc\",\"handle\":201,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:back\"}],\"resource_ref_dropped\":0,\"draw_effect\":{\"captured\":true,\"operation\":\"bit_blt\",\"target\":{\"handle\":200,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:front\"},\"arguments\":[200,0,0,640,480,201,0,0,13369376]},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_framebuffer_blit_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"gdi32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"BitBlt\",\"semantic_class\":\"gdi_calls\",\"operation\":\"BitBlt\",\"external\":true,\"stack_args\":[200,0,0,640,480,201,0,0,13369376],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"dc\",\"label\":\"dc:front\",\"handle\":200,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"dest_hdc\",\"handle\":200,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:front\"},{\"arg_index\":5,\"role\":\"src_hdc\",\"handle\":201,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:back\"}],\"resource_ref_dropped\":0,\"draw_effect\":{\"captured\":true,\"operation\":\"bit_blt\",\"target\":{\"handle\":200,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:front\"},\"arguments\":[200,0,0,640,480,201,0,0,13369376],\"framebuffer_effect\":{\"captured\":true,\"operation\":\"bit_blt\",\"presentation_kind\":\"dc_blit\",\"destination\":{\"target\":{\"arg_index\":0,\"role\":\"dest_hdc\",\"handle\":200,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:front\"},\"rect\":{\"x\":0,\"y\":0,\"width\":640,\"height\":480}},\"source\":{\"target\":{\"arg_index\":5,\"role\":\"src_hdc\",\"handle\":201,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:back\"},\"rect\":{\"x\":0,\"y\":0,\"width\":640,\"height\":480}},\"raster_op\":13369376,\"payload\":{\"kind\":\"source_dc\",\"source_target_arg\":5,\"bits_arg\":null,\"bits_digest_captured\":false,\"bitmap_info_arg\":null,\"bitmap_info_digest_captured\":false}}},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("framebuffer_effects")));
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("framebuffer:dc_blit")));
    }

    #[test]
    fn gdi_pixel_effect_without_typed_draw_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"gdi32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"SetPixel\",\"semantic_class\":\"gdi_calls\",\"operation\":\"SetPixel\",\"external\":true,\"stack_args\":[200,10,20,16711680],\"return_captured\":true,\"return_value\":16711680,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main\",\"handle\":200,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"hdc\",\"handle\":200,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main\"}],\"resource_ref_dropped\":0,\"draw_effect\":{\"captured\":false,\"operation\":\"set_pixel\",\"target\":{\"handle\":200,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main\"},\"arguments\":[200,10,20,16711680]},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":16711680}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_gdi_pixel_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"gdi32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"SetPixel\",\"semantic_class\":\"gdi_calls\",\"operation\":\"SetPixel\",\"external\":true,\"stack_args\":[200,10,20,16711680],\"return_captured\":true,\"return_value\":16711680,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main\",\"handle\":200,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"hdc\",\"handle\":200,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main\"}],\"resource_ref_dropped\":0,\"draw_effect\":{\"captured\":true,\"operation\":\"set_pixel\",\"target\":{\"handle\":200,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main\"},\"arguments\":[200,10,20,16711680]},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":16711680}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn gdi_dib_transfer_without_bitmap_buffers_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        let entry = r#"{"kind":"block_entry","test_id":"t1","rva":"0x1000","state":{"registers":{"eax":1}}}"#;
        let exit = r#"{"kind":"block_exit","test_id":"t1","rva":"0x1000","successor_rva":"0x1001","state":{"registers":{"eax":1}},"side_effects":{"capture_status":"complete","memory_reads":[],"memory_writes":[],"api_calls":[{"caller_rva":4096,"callee_module":"gdi32.dll","callee_rva":1234,"symbol_resolved":true,"callee_symbol":"StretchDIBits","semantic_class":"gdi_calls","operation":"StretchDIBits","external":true,"stack_args":[200,0,0,2,2,0,0,2,2,8192,12288,0],"return_captured":true,"return_value":2,"thread_error_state":{"kind":"win32_last_error","captured":true,"before":0,"after":0},"resource":{"known":true,"kind":"dc","label":"dc:window:main","handle":200,"handle_result":null,"path_argument_captured":false,"path_argument":"","path_argument_truncated":false},"resource_refs":[{"arg_index":0,"role":"hdc","handle":200,"known":true,"kind":"dc","label":"dc:window:main"}],"resource_ref_dropped":0,"draw_effect":{"captured":true,"operation":"stretch_dibits","target":{"handle":200,"known":true,"kind":"dc","label":"dc:window:main"},"arguments":[200,0,0,2,2,0,0,2,2,8192,12288,0]},"output_buffers":[],"output_buffer_dropped":0}],"api_returns":[{"caller_rva":4096,"return_value":2}],"external_events":[],"limitations":[]}}"#;
        fs::write(&trace, format!("{entry}\n{exit}\n")).unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn gdi_dib_transfer_with_bitmap_buffer_digests_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let entry = r#"{"kind":"block_entry","test_id":"t1","rva":"0x1000","state":{"registers":{"eax":1}}}"#;
        let exit = r#"{"kind":"block_exit","test_id":"t1","rva":"0x1000","successor_rva":"0x1001","state":{"registers":{"eax":1}},"side_effects":{"capture_status":"complete","memory_reads":[],"memory_writes":[],"api_calls":[{"caller_rva":4096,"callee_module":"gdi32.dll","callee_rva":1234,"symbol_resolved":true,"callee_symbol":"StretchDIBits","semantic_class":"gdi_calls","operation":"StretchDIBits","external":true,"stack_args":[200,0,0,2,2,0,0,2,2,8192,12288,0,13369376],"return_captured":true,"return_value":2,"thread_error_state":{"kind":"win32_last_error","captured":true,"before":0,"after":0},"resource":{"known":true,"kind":"dc","label":"dc:window:main","handle":200,"handle_result":null,"path_argument_captured":false,"path_argument":"","path_argument_truncated":false},"resource_refs":[{"arg_index":0,"role":"hdc","handle":200,"known":true,"kind":"dc","label":"dc:window:main"}],"resource_ref_dropped":0,"draw_effect":{"captured":true,"operation":"stretch_dibits","target":{"handle":200,"known":true,"kind":"dc","label":"dc:window:main"},"arguments":[200,0,0,2,2,0,0,2,2,8192,12288,0,13369376],"framebuffer_effect":{"captured":true,"operation":"stretch_dibits","presentation_kind":"dib_to_dc","destination":{"target":{"arg_index":0,"role":"hdc","handle":200,"known":true,"kind":"dc","label":"dc:window:main"},"rect":{"x":0,"y":0,"width":2,"height":2}},"source":{"target":null,"rect":{"x":0,"y":0,"width":2,"height":2}},"raster_op":13369376,"payload":{"kind":"dib_argument","source_target_arg":null,"bits_arg":9,"bits_digest_captured":true,"bitmap_info_arg":10,"bitmap_info_digest_captured":true}}},"output_buffers":[{"arg_index":9,"address":8192,"size":4096,"before":"0011223344556677","before_sha256":"{digest}","before_sha256_ok":true,"after":"0011223344556677","after_sha256":"{digest}","after_sha256_ok":true,"before_ok":true,"after_ok":true,"truncated":true},{"arg_index":10,"address":12288,"size":40,"before":"28000000020000000200000001002000000000001000000000000000000000000000000000000000","before_sha256":"{digest}","before_sha256_ok":true,"after":"28000000020000000200000001002000000000001000000000000000000000000000000000000000","after_sha256":"{digest}","after_sha256_ok":true,"before_ok":true,"after_ok":true,"truncated":false}],"output_buffer_dropped":0}],"api_returns":[{"caller_rva":4096,"return_value":2}],"external_events":[],"limitations":[]}}"#.replace("{digest}", digest);
        fs::write(&trace, format!("{entry}\n{exit}\n")).unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn create_dib_section_without_bitmap_outputs_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        let entry = r#"{"kind":"block_entry","test_id":"t1","rva":"0x1000","state":{"registers":{"eax":1}}}"#;
        let exit = r#"{"kind":"block_exit","test_id":"t1","rva":"0x1000","successor_rva":"0x1001","state":{"registers":{"eax":1}},"side_effects":{"capture_status":"complete","memory_reads":[],"memory_writes":[],"api_calls":[{"caller_rva":4096,"callee_module":"gdi32.dll","callee_rva":1234,"symbol_resolved":true,"callee_symbol":"CreateDIBSection","semantic_class":"gdi_calls","operation":"CreateDIBSection","external":true,"stack_args":[200,12288,0,16384,0,0],"return_captured":true,"return_value":300,"thread_error_state":{"kind":"win32_last_error","captured":true,"before":0,"after":0},"resource":{"known":true,"kind":"gdi_object","label":"bitmap:dib:width=2,height=2,bpp=32,compression=0,bytes=16","handle":null,"handle_result":300,"path_argument_captured":false,"path_argument":"","path_argument_truncated":false},"resource_refs":[],"resource_ref_dropped":0,"output_buffers":[],"output_buffer_dropped":0}],"api_returns":[{"caller_rva":4096,"return_value":300}],"external_events":[],"limitations":[]}}"#;
        fs::write(&trace, format!("{entry}\n{exit}\n")).unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn create_dib_section_with_bitmap_outputs_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let entry = r#"{"kind":"block_entry","test_id":"t1","rva":"0x1000","state":{"registers":{"eax":1}}}"#;
        let exit = r#"{"kind":"block_exit","test_id":"t1","rva":"0x1000","successor_rva":"0x1001","state":{"registers":{"eax":1}},"side_effects":{"capture_status":"complete","memory_reads":[],"memory_writes":[],"api_calls":[{"caller_rva":4096,"callee_module":"gdi32.dll","callee_rva":1234,"symbol_resolved":true,"callee_symbol":"CreateDIBSection","semantic_class":"gdi_calls","operation":"CreateDIBSection","external":true,"stack_args":[200,12288,0,16384,0,0],"return_captured":true,"return_value":300,"thread_error_state":{"kind":"win32_last_error","captured":true,"before":0,"after":0},"resource":{"known":true,"kind":"gdi_object","label":"bitmap:dib:width=2,height=2,bpp=32,compression=0,bytes=16","handle":null,"handle_result":300,"path_argument_captured":false,"path_argument":"","path_argument_truncated":false},"resource_refs":[],"resource_ref_dropped":0,"output_buffers":[{"arg_index":1,"address":12288,"size":40,"before":"28000000020000000200000001002000000000001000000000000000000000000000000000000000","before_sha256":"{digest}","before_sha256_ok":true,"after":"28000000020000000200000001002000000000001000000000000000000000000000000000000000","after_sha256":"{digest}","after_sha256_ok":true,"before_ok":true,"after_ok":true,"truncated":false},{"arg_index":3,"address":16384,"size":4,"before":"00000000","before_sha256":"{digest}","before_sha256_ok":true,"after":"00200000","after_sha256":"{digest}","after_sha256_ok":true,"before_ok":true,"after_ok":true,"truncated":false}],"output_buffer_dropped":0}],"api_returns":[{"caller_rva":4096,"return_value":300}],"external_events":[],"limitations":[]}}"#.replace("{digest}", digest);
        fs::write(&trace, format!("{entry}\n{exit}\n")).unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn incomplete_win32_message_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"SendMessageA\",\"semantic_class\":\"window_messages\",\"operation\":\"SendMessageA\",\"external\":true,\"stack_args\":[100,256,1,2],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"window\",\"label\":\"window:main\",\"handle\":100,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"hwnd\",\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"}],\"resource_ref_dropped\":0,\"draw_effect\":null,\"message_effect\":{\"captured\":false,\"operation\":\"send_message\",\"source\":\"direct_args\",\"has_message\":false,\"target\":null,\"message\":null,\"wparam\":null,\"lparam\":null,\"time\":null,\"point\":null},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":0}],\"external_events\":[],\"limitations\":[\"api_message_effect_not_captured\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_message_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"SendMessageA\",\"semantic_class\":\"window_messages\",\"operation\":\"SendMessageA\",\"external\":true,\"stack_args\":[100,256,1,2],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"window\",\"label\":\"window:main\",\"handle\":100,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"hwnd\",\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"}],\"resource_ref_dropped\":0,\"draw_effect\":null,\"message_effect\":{\"captured\":true,\"operation\":\"send_message\",\"source\":\"direct_args\",\"has_message\":true,\"target\":{\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"},\"message\":256,\"wparam\":1,\"lparam\":2,\"time\":null,\"point\":null},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":0}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn complete_win32_wndproc_callback_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[],\"api_returns\":[],\"callbacks\":[{\"captured\":true,\"operation\":\"wndproc_entry\",\"callback_rva\":4096,\"class_name\":\"GameWindow\",\"class_name_captured\":true,\"instance\":4096,\"atom\":49152,\"target\":{\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"},\"message\":15,\"wparam\":0,\"lparam\":0}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed.iter().any(|value| value == "callbacks"));
        assert!(observed.iter().any(|value| value == "callback_effects"));
        assert!(observed.iter().any(|value| value == "window_callbacks"));
        assert!(observed
            .iter()
            .any(|value| value == "callback:wndproc_entry"));
    }

    #[test]
    fn incomplete_win32_window_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"ShowWindow\",\"semantic_class\":\"window_messages\",\"operation\":\"ShowWindow\",\"external\":true,\"stack_args\":[100,5],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"window\",\"label\":\"window:main\",\"handle\":100,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"hwnd\",\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"}],\"resource_ref_dropped\":0,\"window_effect\":{\"captured\":false,\"operation\":\"show_window\",\"target\":null,\"result\":null,\"show_cmd\":null},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[\"api_window_effect_not_captured\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_window_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"ShowWindow\",\"semantic_class\":\"window_messages\",\"operation\":\"ShowWindow\",\"external\":true,\"stack_args\":[100,5],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"window\",\"label\":\"window:main\",\"handle\":100,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"hwnd\",\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"}],\"resource_ref_dropped\":0,\"window_effect\":{\"captured\":true,\"operation\":\"show_window\",\"target\":{\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"},\"result\":null,\"show_cmd\":5},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn incomplete_win32_window_long_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"SetWindowLongPtrA\",\"semantic_class\":\"window_messages\",\"operation\":\"SetWindowLongPtrA\",\"external\":true,\"stack_args\":[100,4294967292,4198400],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"window\",\"label\":\"window:main\",\"handle\":100,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"hwnd\",\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"}],\"resource_ref_dropped\":0,\"window_long_effect\":{\"captured\":false,\"succeeded\":true,\"operation\":\"set_wndproc\",\"target\":{\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"},\"index\":-4,\"slot\":\"wndproc\",\"value\":4198400,\"previous_value\":null},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":0}],\"external_events\":[],\"limitations\":[\"api_window_long_effect_not_captured\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_wndproc_subclass_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"SetWindowLongPtrA\",\"semantic_class\":\"window_messages\",\"operation\":\"SetWindowLongPtrA\",\"external\":true,\"stack_args\":[100,4294967292,4198400],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"window\",\"label\":\"window:main\",\"handle\":100,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"hwnd\",\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"}],\"resource_ref_dropped\":0,\"window_long_effect\":{\"captured\":true,\"succeeded\":true,\"operation\":\"set_wndproc\",\"target\":{\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"},\"index\":-4,\"slot\":\"wndproc\",\"value\":4198400,\"previous_value\":0},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":0}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed.iter().any(|value| value == "window_long_effects"));
        assert!(observed.iter().any(|value| value == "subclass_effects"));
        assert!(observed.iter().any(|value| value == "window_callbacks"));
        assert!(observed
            .iter()
            .any(|value| value == "window_long:set_wndproc"));
    }

    #[test]
    fn incomplete_win32_paint_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"BeginPaint\",\"semantic_class\":\"gdi_calls\",\"operation\":\"BeginPaint\",\"external\":true,\"stack_args\":[100,8192],\"return_captured\":true,\"return_value\":200,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main:paint\",\"handle\":null,\"handle_result\":200,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"hwnd\",\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"}],\"resource_ref_dropped\":0,\"paint_effect\":{\"captured\":false,\"operation\":\"begin_paint\",\"target\":{\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"},\"paintstruct_address\":null,\"hdc\":null,\"erase\":null,\"rect\":null,\"restore\":null,\"inc_update\":null},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":200}],\"external_events\":[],\"limitations\":[\"api_paint_effect_not_captured\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_paint_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"BeginPaint\",\"semantic_class\":\"gdi_calls\",\"operation\":\"BeginPaint\",\"external\":true,\"stack_args\":[100,8192],\"return_captured\":true,\"return_value\":200,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main:paint\",\"handle\":null,\"handle_result\":200,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"hwnd\",\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"}],\"resource_ref_dropped\":0,\"paint_effect\":{\"captured\":true,\"operation\":\"begin_paint\",\"target\":{\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"},\"paintstruct_address\":8192,\"hdc\":{\"handle\":200,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main:paint\"},\"erase\":1,\"rect\":{\"left\":0,\"top\":0,\"right\":640,\"bottom\":480},\"restore\":0,\"inc_update\":0},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":200}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn incomplete_win32_input_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"GetCursorPos\",\"semantic_class\":\"input_events\",\"operation\":\"GetCursorPos\",\"external\":true,\"stack_args\":[8192],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"input_effect\":{\"captured\":false,\"operation\":\"get_cursor_pos\",\"vkey\":null,\"key_state\":null,\"point_address\":8192,\"point\":null,\"requested_point\":null},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[\"api_input_effect_not_captured\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_input_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"GetCursorPos\",\"semantic_class\":\"input_events\",\"operation\":\"GetCursorPos\",\"external\":true,\"stack_args\":[8192],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"input_effect\":{\"captured\":true,\"operation\":\"get_cursor_pos\",\"vkey\":null,\"key_state\":null,\"point_address\":8192,\"point\":{\"x\":320,\"y\":200},\"requested_point\":null},\"output_buffers\":[{\"arg_index\":0,\"address\":8192,\"size\":8,\"before\":\"0000000000000000\",\"before_sha256\":\"\",\"before_sha256_ok\":true,\"after\":\"40010000c8000000\",\"after_sha256\":\"\",\"after_sha256_ok\":true,\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn incomplete_win32_raw_input_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"GetRawInputData\",\"semantic_class\":\"input_events\",\"operation\":\"GetRawInputData\",\"external\":true,\"stack_args\":[57005,268435459,8192,12288,24],\"return_captured\":true,\"return_value\":32,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"input_effect\":{\"captured\":false,\"operation\":\"get_raw_input_data\",\"vkey\":null,\"key_state\":null,\"point_address\":null,\"point\":null,\"requested_point\":null,\"raw_input\":{\"handle\":57005,\"command\":268435459,\"data_address\":8192,\"size_address\":12288,\"size_before\":32,\"size_after\":null,\"header_size\":24},\"raw_input_devices\":{\"address\":null,\"count\":null,\"entry_size\":null,\"bytes\":null,\"sha256\":\"\",\"sha256_ok\":false}},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":32}],\"external_events\":[],\"limitations\":[\"api_input_effect_not_captured\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_raw_input_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"RegisterRawInputDevices\",\"semantic_class\":\"input_events\",\"operation\":\"RegisterRawInputDevices\",\"external\":true,\"stack_args\":[8192,1,12],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"input_effect\":{\"captured\":true,\"operation\":\"register_raw_input_devices\",\"vkey\":null,\"key_state\":null,\"point_address\":null,\"point\":null,\"requested_point\":null,\"raw_input\":{\"handle\":null,\"command\":null,\"data_address\":null,\"size_address\":null,\"size_before\":null,\"size_after\":null,\"header_size\":null},\"raw_input_devices\":{\"address\":8192,\"count\":1,\"entry_size\":12,\"bytes\":12,\"sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"sha256_ok\":true}},\"output_buffers\":[{\"arg_index\":0,\"address\":8192,\"size\":12,\"before\":\"010006000030000001000000\",\"after\":\"010006000030000001000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"output_buffer_dropped\":0},{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1240,\"symbol_resolved\":true,\"callee_symbol\":\"GetRawInputData\",\"semantic_class\":\"input_events\",\"operation\":\"GetRawInputData\",\"external\":true,\"stack_args\":[57005,268435459,12288,16384,24],\"return_captured\":true,\"return_value\":32,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"input_effect\":{\"captured\":true,\"operation\":\"get_raw_input_data\",\"vkey\":null,\"key_state\":null,\"point_address\":null,\"point\":null,\"requested_point\":null,\"raw_input\":{\"handle\":57005,\"command\":268435459,\"data_address\":12288,\"size_address\":16384,\"size_before\":32,\"size_after\":32,\"header_size\":24},\"raw_input_devices\":{\"address\":null,\"count\":null,\"entry_size\":null,\"bytes\":null,\"sha256\":\"\",\"sha256_ok\":false}},\"output_buffers\":[{\"arg_index\":2,\"address\":12288,\"size\":32,\"before\":\"0000000000000000\",\"after\":\"0100000000000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false},{\"arg_index\":3,\"address\":16384,\"size\":4,\"before\":\"20000000\",\"after\":\"20000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1},{\"caller_rva\":4096,\"return_value\":32}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed.iter().any(|value| value == "input_effects"));
        assert!(observed.iter().any(|value| value == "raw_input_effects"));
        assert!(observed
            .iter()
            .any(|value| value == "input:register_raw_input_devices"));
        assert!(observed
            .iter()
            .any(|value| value == "input:get_raw_input_data"));
    }

    #[test]
    fn incomplete_win32_audio_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"winmm.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"MessageBeep\",\"semantic_class\":\"audio_output\",\"operation\":\"MessageBeep\",\"external\":true,\"stack_args\":[16],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"audio_effect\":{\"captured\":false,\"succeeded\":true,\"operation\":\"message_beep\",\"sound_arg\":null,\"sound_text\":\"\",\"sound_text_captured\":false,\"sound_text_truncated\":false,\"module\":null,\"flags\":null,\"beep_type\":16,\"device_id\":null,\"wave_handle\":null,\"wave_handle_result\":null,\"format_address\":null,\"callback\":null,\"instance\":null,\"wave_header\":{\"address\":null,\"size\":null,\"data_address\":null,\"data_size\":null,\"data_sha256\":\"\",\"data_sha256_ok\":false}},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[\"api_audio_effect_not_captured\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_audio_effects_pass_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"winmm.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"PlaySoundA\",\"semantic_class\":\"audio_output\",\"operation\":\"PlaySoundA\",\"external\":true,\"stack_args\":[8192,0,1],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"audio_effect\":{\"captured\":true,\"succeeded\":true,\"operation\":\"play_sound\",\"sound_arg\":8192,\"sound_text\":\"ding.wav\",\"sound_text_captured\":true,\"sound_text_truncated\":false,\"module\":0,\"flags\":1,\"beep_type\":null,\"device_id\":null,\"wave_handle\":null,\"wave_handle_result\":null,\"format_address\":null,\"callback\":null,\"instance\":null,\"wave_header\":{\"address\":null,\"size\":null,\"data_address\":null,\"data_size\":null,\"data_sha256\":\"\",\"data_sha256_ok\":false}},\"output_buffers\":[{\"arg_index\":0,\"address\":8192,\"size\":9,\"before\":\"64696e672e77617600\",\"after\":\"64696e672e77617600\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"output_buffer_dropped\":0},{\"caller_rva\":4096,\"callee_module\":\"winmm.dll\",\"callee_rva\":1240,\"symbol_resolved\":true,\"callee_symbol\":\"waveOutWrite\",\"semantic_class\":\"audio_output\",\"operation\":\"waveOutWrite\",\"external\":true,\"stack_args\":[57005,12288,32],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"audio_device\",\"handle\":57005,\"known\":true,\"kind\":\"audio_device\",\"label\":\"waveout:device=0\"}],\"resource_ref_dropped\":0,\"audio_effect\":{\"captured\":true,\"succeeded\":true,\"operation\":\"wave_out_write\",\"sound_arg\":null,\"sound_text\":\"\",\"sound_text_captured\":false,\"sound_text_truncated\":false,\"module\":null,\"flags\":null,\"beep_type\":null,\"device_id\":null,\"wave_handle\":{\"handle\":57005,\"known\":true,\"kind\":\"audio_device\",\"label\":\"waveout:device=0\"},\"wave_handle_result\":null,\"format_address\":null,\"callback\":null,\"instance\":null,\"wave_header\":{\"address\":12288,\"size\":32,\"data_address\":16384,\"data_size\":4,\"data_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"data_sha256_ok\":true}},\"output_buffers\":[{\"arg_index\":1,\"address\":12288,\"size\":32,\"before\":\"0040000004000000000000000000000000000000000000000000000000000000\",\"after\":\"0040000004000000000000000000000000000000000000000000000000000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1},{\"caller_rva\":4096,\"return_value\":0}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed.iter().any(|value| value == "audio_effects"));
        assert!(observed.iter().any(|value| value == "audio_output"));
        assert!(observed.iter().any(|value| value == "audio:play_sound"));
        assert!(observed.iter().any(|value| value == "audio:wave_out_write"));
        assert!(observed
            .iter()
            .any(|value| value == "api_resource:audio_device"));
    }

    #[test]
    fn incomplete_win32_timer_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"SetTimer\",\"semantic_class\":\"timer_events\",\"operation\":\"SetTimer\",\"external\":true,\"stack_args\":[100,7,16,0],\"return_captured\":true,\"return_value\":7,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"window\",\"label\":\"window:main\",\"handle\":100,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"timer_hwnd\",\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"}],\"resource_ref_dropped\":0,\"timer_effect\":{\"captured\":false,\"operation\":\"set_timer\",\"target\":{\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"},\"requested_id\":7,\"interval_ms\":16,\"callback\":0,\"result_id\":null},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":7}],\"external_events\":[],\"limitations\":[\"api_timer_effect_not_captured\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_timer_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"SetTimer\",\"semantic_class\":\"timer_events\",\"operation\":\"SetTimer\",\"external\":true,\"stack_args\":[100,7,16,0],\"return_captured\":true,\"return_value\":7,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"window\",\"label\":\"window:main\",\"handle\":100,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"timer_hwnd\",\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"}],\"resource_ref_dropped\":0,\"timer_effect\":{\"captured\":true,\"operation\":\"set_timer\",\"target\":{\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"},\"requested_id\":7,\"interval_ms\":16,\"callback\":0,\"result_id\":7},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":7}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn complete_win32_thread_timer_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"SetTimer\",\"semantic_class\":\"timer_events\",\"operation\":\"SetTimer\",\"external\":true,\"stack_args\":[0,0,16,4198400],\"return_captured\":true,\"return_value\":42,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"timer_queue\",\"label\":\"thread\",\"handle\":0,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"timer_hwnd\",\"handle\":0,\"known\":true,\"kind\":\"timer_queue\",\"label\":\"thread\"}],\"resource_ref_dropped\":0,\"timer_effect\":{\"captured\":true,\"operation\":\"set_timer\",\"target\":{\"handle\":0,\"known\":true,\"kind\":\"timer_queue\",\"label\":\"thread\"},\"requested_id\":0,\"interval_ms\":16,\"callback\":4198400,\"result_id\":42},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":42}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed.iter().any(|value| value == "timer_effects"));
        assert!(observed.iter().any(|value| value == "timer:set_timer"));
        assert!(observed
            .iter()
            .any(|value| value == "api_resource:timer_queue"));
    }

    #[test]
    fn complete_win32_timerproc_callback_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[],\"api_returns\":[],\"callbacks\":[{\"captured\":true,\"operation\":\"timerproc_entry\",\"callback_rva\":4096,\"class_name\":\"\",\"class_name_captured\":false,\"instance\":null,\"atom\":null,\"target\":{\"handle\":100,\"known\":true,\"kind\":\"window\",\"label\":\"window:main\"},\"message\":275,\"wparam\":null,\"lparam\":null,\"timer_id\":7,\"elapsed_ms\":12345}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed.iter().any(|value| value == "callbacks"));
        assert!(observed.iter().any(|value| value == "callback_effects"));
        assert!(observed.iter().any(|value| value == "timer_callbacks"));
        assert!(observed
            .iter()
            .any(|value| value == "callback:timerproc_entry"));
    }

    #[test]
    fn incomplete_win32_time_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"QueryPerformanceCounter\",\"semantic_class\":\"time\",\"operation\":\"QueryPerformanceCounter\",\"external\":true,\"stack_args\":[8192],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"time_effect\":{\"captured\":false,\"operation\":\"query_performance_counter\",\"return_value\":null,\"output_address\":8192,\"output_value\":null,\"clock_id\":null,\"sleep_duration_ms\":null},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[\"api_time_effect_not_captured\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_time_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"QueryPerformanceCounter\",\"semantic_class\":\"time\",\"operation\":\"QueryPerformanceCounter\",\"external\":true,\"stack_args\":[8192],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"time_effect\":{\"captured\":true,\"operation\":\"query_performance_counter\",\"return_value\":null,\"output_address\":8192,\"output_value\":123456789,\"clock_id\":null,\"sleep_duration_ms\":null},\"output_buffers\":[{\"arg_index\":0,\"address\":8192,\"size\":8,\"before\":\"0000000000000000\",\"before_sha256\":\"\",\"before_sha256_ok\":true,\"after\":\"15cd5b0700000000\",\"after_sha256\":\"\",\"after_sha256_ok\":true,\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn complete_win32_process_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"GetCommandLineA\",\"semantic_class\":\"process\",\"operation\":\"GetCommandLineA\",\"external\":true,\"stack_args\":[],\"return_captured\":true,\"return_value\":8192,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"process_effect\":{\"captured\":true,\"operation\":\"get_command_line\",\"result_pointer\":8192,\"command_line\":\"wincr-3d-game.exe --json\",\"command_line_captured\":true,\"command_line_truncated\":false},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":8192}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed.iter().any(|value| value == "process_effects"));
        assert!(observed
            .iter()
            .any(|value| value == "process:get_command_line"));
    }

    #[test]
    fn complete_win32_process_creation_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            format!(
                concat!(
                    "{{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{{\"registers\":{{\"eax\":1}}}}}}\n",
                    "{{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{{\"registers\":{{\"eax\":1}}}},\"side_effects\":{{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"CreateProcessA\",\"semantic_class\":\"process\",\"operation\":\"CreateProcessA\",\"external\":true,\"stack_args\":[8192,12288,0,0,0,16,0,0,16384,20480],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0}},\"resource\":{{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false}},\"resource_refs\":[],\"resource_ref_dropped\":0,\"process_effect\":{{\"captured\":true,\"operation\":\"create_process\",\"name\":\"game.exe\",\"name_captured\":true,\"name_truncated\":false,\"name_address\":8192,\"command_line\":\"game.exe -windowed\",\"command_line_captured\":true,\"command_line_truncated\":false,\"command_line_address\":12288,\"directory\":\"\",\"directory_captured\":false,\"directory_truncated\":false,\"directory_address\":0,\"inherit_handles\":false,\"creation_flags\":16,\"environment_address\":0,\"environment_inherited\":true,\"environment_block_size\":null,\"environment_block_sha256\":\"\",\"environment_block_sha256_ok\":false,\"startup_info_address\":16384,\"startup_info_size\":68,\"startup_info_sha256\":\"{digest}\",\"startup_info_sha256_ok\":true,\"process_info_address\":20480,\"process_handle\":1000,\"thread_handle\":1001,\"process_id\":200,\"thread_id\":201,\"succeeded\":true,\"spawned\":true,\"mutated\":true}},\"output_buffers\":[],\"output_buffer_dropped\":0}}],\"api_returns\":[{{\"caller_rva\":4096,\"return_value\":1}}],\"external_events\":[],\"limitations\":[]}}}}\n"
                ),
                digest = digest
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed
            .iter()
            .any(|value| value == "process:create_process"));
    }

    #[test]
    fn incomplete_win32_process_creation_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            format!(
                concat!(
                    "{{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{{\"registers\":{{\"eax\":1}}}}}}\n",
                    "{{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{{\"registers\":{{\"eax\":1}}}},\"side_effects\":{{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"CreateProcessA\",\"semantic_class\":\"process\",\"operation\":\"CreateProcessA\",\"external\":true,\"stack_args\":[8192,12288,0,0,0,16,0,0,16384,20480],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0}},\"resource\":{{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false}},\"resource_refs\":[],\"resource_ref_dropped\":0,\"process_effect\":{{\"captured\":true,\"operation\":\"create_process\",\"name\":\"game.exe\",\"name_captured\":true,\"name_truncated\":false,\"name_address\":8192,\"command_line\":\"game.exe -windowed\",\"command_line_captured\":true,\"command_line_truncated\":false,\"command_line_address\":12288,\"directory\":\"\",\"directory_captured\":false,\"directory_truncated\":false,\"directory_address\":0,\"inherit_handles\":false,\"creation_flags\":16,\"environment_address\":0,\"environment_inherited\":true,\"startup_info_address\":16384,\"startup_info_size\":68,\"startup_info_sha256\":\"{digest}\",\"startup_info_sha256_ok\":true,\"process_info_address\":20480,\"process_handle\":null,\"thread_handle\":null,\"process_id\":null,\"thread_id\":null,\"succeeded\":true,\"spawned\":true,\"mutated\":true}},\"output_buffers\":[],\"output_buffer_dropped\":0}}],\"api_returns\":[{{\"caller_rva\":4096,\"return_value\":1}}],\"external_events\":[],\"limitations\":[]}}}}\n"
                ),
                digest = digest
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn incomplete_win32_environment_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"GetEnvironmentVariableA\",\"semantic_class\":\"process\",\"operation\":\"GetEnvironmentVariableA\",\"external\":true,\"stack_args\":[8192,12288,16],\"return_captured\":true,\"return_value\":4,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"process_effect\":{\"captured\":false,\"operation\":\"get_environment_variable\",\"name\":\"\",\"name_captured\":false,\"name_truncated\":false,\"value\":\"\",\"value_captured\":false,\"value_truncated\":false,\"output_address\":null,\"output_capacity\":null,\"result_length\":null,\"succeeded\":null},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":4}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_environment_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"GetEnvironmentVariableA\",\"semantic_class\":\"process\",\"operation\":\"GetEnvironmentVariableA\",\"external\":true,\"stack_args\":[8192,12288,16],\"return_captured\":true,\"return_value\":4,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"process_effect\":{\"captured\":true,\"operation\":\"get_environment_variable\",\"name\":\"WINDIR\",\"name_captured\":true,\"name_truncated\":false,\"value\":\"C:\\\\W\",\"value_captured\":true,\"value_truncated\":false,\"output_address\":12288,\"output_capacity\":16,\"result_length\":4,\"succeeded\":true},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":4}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn complete_win32_current_directory_mutation_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"SetCurrentDirectoryA\",\"semantic_class\":\"process\",\"operation\":\"SetCurrentDirectoryA\",\"external\":true,\"stack_args\":[8192],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"process_effect\":{\"captured\":true,\"operation\":\"set_current_directory\",\"directory\":\"C:\\\\Games\\\\Halo\",\"directory_captured\":true,\"directory_truncated\":false,\"succeeded\":true,\"mutated\":true},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn incomplete_win32_memory_api_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"HeapAlloc\",\"semantic_class\":\"memory\",\"operation\":\"HeapAlloc\",\"external\":true,\"stack_args\":[57005,0,64],\"return_captured\":true,\"return_value\":16384,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":16384}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_memory_api_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"VirtualProtect\",\"semantic_class\":\"memory\",\"operation\":\"VirtualProtect\",\"external\":true,\"stack_args\":[16384,4096,64,12288],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"memory_api_effect\":{\"captured\":true,\"operation\":\"virtual_protect\",\"succeeded\":true,\"heap\":null,\"address\":16384,\"result_address\":null,\"size\":4096,\"flags\":null,\"allocation_type\":null,\"protect\":64,\"old_protect_address\":12288,\"old_protect\":4,\"mutated\":true},\"output_buffers\":[{\"arg_index\":3,\"address\":12288,\"size\":4,\"before\":\"00000000\",\"after\":\"04000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed.iter().any(|value| value == "memory_api_effects"));
        assert!(observed.iter().any(|value| value == "memory"));
        assert!(observed
            .iter()
            .any(|value| value == "memory_api:virtual_protect"));
    }

    #[test]
    fn complete_crt_and_local_memory_api_effects_pass_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"msvcrt.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"calloc\",\"semantic_class\":\"memory\",\"operation\":\"calloc\",\"external\":true,\"stack_args\":[4,16],\"return_captured\":true,\"return_value\":16384,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"memory_api_effect\":{\"captured\":true,\"operation\":\"crt_calloc\",\"succeeded\":true,\"heap\":null,\"address\":null,\"result_address\":16384,\"size\":64,\"count\":4,\"element_size\":16,\"flags\":null,\"allocation_type\":null,\"protect\":null,\"old_protect_address\":null,\"old_protect\":null,\"zeroed\":true,\"mutated\":true},\"output_buffers\":[],\"output_buffer_dropped\":0},{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1240,\"symbol_resolved\":true,\"callee_symbol\":\"LocalAlloc\",\"semantic_class\":\"memory\",\"operation\":\"LocalAlloc\",\"external\":true,\"stack_args\":[64,128],\"return_captured\":true,\"return_value\":20480,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"memory_api_effect\":{\"captured\":true,\"operation\":\"local_alloc\",\"succeeded\":true,\"heap\":null,\"address\":null,\"result_address\":20480,\"size\":128,\"count\":null,\"element_size\":null,\"flags\":64,\"allocation_type\":null,\"protect\":null,\"old_protect_address\":null,\"old_protect\":null,\"zeroed\":true,\"mutated\":true},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":16384},{\"caller_rva\":4096,\"return_value\":20480}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed
            .iter()
            .any(|value| value == "memory_api:crt_calloc"));
        assert!(observed
            .iter()
            .any(|value| value == "memory_api:local_alloc"));
    }

    #[test]
    fn complete_win32_exit_process_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":0}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":null,\"state\":{\"registers\":{\"eax\":0}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"ExitProcess\",\"semantic_class\":\"process\",\"operation\":\"ExitProcess\",\"external\":true,\"stack_args\":[7],\"return_captured\":false,\"return_value\":null,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"process_effect\":{\"captured\":true,\"operation\":\"exit_process\",\"result_pointer\":null,\"command_line\":\"\",\"command_line_captured\":false,\"command_line_truncated\":false,\"exit_code\":7,\"does_not_return\":true},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed.iter().any(|value| value == "process:exit_process"));
        assert!(observed.iter().any(|value| value == "process_exit"));
    }

    #[test]
    fn incomplete_win32_dynamic_loader_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"GetProcAddress\",\"semantic_class\":\"dynamic_loading\",\"operation\":\"GetProcAddress\",\"external\":true,\"stack_args\":[57005,8192],\"return_captured\":true,\"return_value\":4198400,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"module\",\"label\":\"module:dsound.dll\",\"handle\":57005,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"module\",\"handle\":57005,\"known\":true,\"kind\":\"module\",\"label\":\"module:dsound.dll\"}],\"resource_ref_dropped\":0,\"dynamic_loader_effect\":{\"captured\":false,\"succeeded\":true,\"operation\":\"get_proc_address\",\"target\":{\"handle\":57005,\"known\":true,\"kind\":\"module\",\"label\":\"module:dsound.dll\"},\"proc_name_arg\":8192,\"proc_name\":\"DirectSoundCreate\",\"proc_name_captured\":true,\"proc_name_truncated\":false,\"ordinal\":null,\"result_pointer\":4198400},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":4198400}],\"external_events\":[],\"limitations\":[\"api_dynamic_loader_effect_not_captured\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_dynamic_loader_effects_pass_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"LoadLibraryA\",\"semantic_class\":\"dynamic_loading\",\"operation\":\"LoadLibraryA\",\"external\":true,\"stack_args\":[8192],\"return_captured\":true,\"return_value\":57005,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"module\",\"label\":\"module:dsound.dll\",\"handle\":null,\"handle_result\":57005,\"path_argument_captured\":true,\"path_argument\":\"module:dsound.dll\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"dynamic_loader_effect\":{\"captured\":true,\"succeeded\":true,\"operation\":\"load_library\",\"module_arg\":8192,\"module_name\":\"dsound.dll\",\"module_name_captured\":true,\"module_name_truncated\":false,\"flags\":null,\"target\":null,\"proc_name_arg\":null,\"proc_name\":\"\",\"proc_name_captured\":false,\"proc_name_truncated\":false,\"ordinal\":null,\"result_handle\":{\"handle\":57005,\"known\":true,\"kind\":\"module\",\"label\":\"module:dsound.dll\"},\"result_pointer\":null},\"output_buffers\":[],\"output_buffer_dropped\":0},{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1240,\"symbol_resolved\":true,\"callee_symbol\":\"GetProcAddress\",\"semantic_class\":\"dynamic_loading\",\"operation\":\"GetProcAddress\",\"external\":true,\"stack_args\":[57005,12288],\"return_captured\":true,\"return_value\":4198400,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"module\",\"label\":\"module:dsound.dll\",\"handle\":57005,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"module\",\"handle\":57005,\"known\":true,\"kind\":\"module\",\"label\":\"module:dsound.dll\"}],\"resource_ref_dropped\":0,\"dynamic_loader_effect\":{\"captured\":true,\"succeeded\":true,\"operation\":\"get_proc_address\",\"module_arg\":null,\"module_name\":\"\",\"module_name_captured\":false,\"module_name_truncated\":false,\"flags\":null,\"target\":{\"handle\":57005,\"known\":true,\"kind\":\"module\",\"label\":\"module:dsound.dll\"},\"proc_name_arg\":12288,\"proc_name\":\"DirectSoundCreate\",\"proc_name_captured\":true,\"proc_name_truncated\":false,\"ordinal\":null,\"result_handle\":null,\"result_pointer\":4198400},\"output_buffers\":[],\"output_buffer_dropped\":0},{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1248,\"symbol_resolved\":true,\"callee_symbol\":\"FreeLibrary\",\"semantic_class\":\"dynamic_loading\",\"operation\":\"FreeLibrary\",\"external\":true,\"stack_args\":[57005],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"module\",\"label\":\"module:dsound.dll\",\"handle\":57005,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"module\",\"handle\":57005,\"known\":true,\"kind\":\"module\",\"label\":\"module:dsound.dll\"}],\"resource_ref_dropped\":0,\"dynamic_loader_effect\":{\"captured\":true,\"succeeded\":true,\"operation\":\"free_library\",\"module_arg\":null,\"module_name\":\"\",\"module_name_captured\":false,\"module_name_truncated\":false,\"flags\":null,\"target\":{\"handle\":57005,\"known\":true,\"kind\":\"module\",\"label\":\"module:dsound.dll\"},\"proc_name_arg\":null,\"proc_name\":\"\",\"proc_name_captured\":false,\"proc_name_truncated\":false,\"ordinal\":null,\"result_handle\":null,\"result_pointer\":null},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":57005},{\"caller_rva\":4096,\"return_value\":4198400},{\"caller_rva\":4096,\"return_value\":1}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed
            .iter()
            .any(|value| value == "dynamic_loading_effects"));
        assert!(observed.iter().any(|value| value == "dynamic_loading"));
        assert!(observed
            .iter()
            .any(|value| value == "dynamic_loading:load_library"));
        assert!(observed
            .iter()
            .any(|value| value == "dynamic_loading:get_proc_address"));
        assert!(observed
            .iter()
            .any(|value| value == "dynamic_loading:free_library"));
        assert!(observed.iter().any(|value| value == "api_resource:module"));
    }

    #[test]
    fn incomplete_win32_com_vtable_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"dsound.dll\",\"callee_rva\":8192,\"symbol_resolved\":false,\"callee_symbol\":\"\",\"semantic_class\":\"audio_input\",\"operation\":\"module_call\",\"external\":true,\"stack_args\":[12288,1,2],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"com_vtable_effect\":{\"captured\":false,\"operation\":\"com_vtable_call\",\"subsystem\":\"audio\",\"receiver\":12288,\"vtable\":16384,\"slot\":3,\"slot_address\":16408,\"entry\":4198400,\"vtable_prefix_bytes\":32,\"vtable_prefix_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"vtable_prefix_sha256_ok\":true,\"return_captured\":true,\"return_value\":0},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":0}],\"external_events\":[],\"limitations\":[\"api_com_vtable_effect_not_captured\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_com_vtable_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"dsound.dll\",\"callee_rva\":8192,\"symbol_resolved\":false,\"callee_symbol\":\"\",\"semantic_class\":\"audio_input\",\"operation\":\"module_call\",\"external\":true,\"stack_args\":[12288,1,2],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"com_vtable_effect\":{\"captured\":true,\"operation\":\"com_vtable_call\",\"subsystem\":\"audio\",\"semantic_kind\":\"audio_buffer_submit\",\"method_candidates\":[\"IDirectSoundBuffer::Unlock\"],\"method_ambiguous\":false,\"interface_captured\":true,\"interface_known\":true,\"interface_name\":\"IDirectSoundBuffer\",\"interface_label\":\"com:IDirectSoundBuffer:object=0x3000:source=IDirectSound::CreateSoundBuffer\",\"method_name\":\"IDirectSoundBuffer::Unlock\",\"method_exact\":true,\"receiver\":12288,\"vtable\":16384,\"slot\":19,\"slot_address\":16460,\"entry\":4198400,\"vtable_prefix_bytes\":80,\"vtable_prefix_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"vtable_prefix_sha256_ok\":true,\"return_captured\":true,\"return_value\":0,\"method_buffers\":[{\"role\":\"audio_unlock_region_1\",\"arg_index\":1,\"address\":20480,\"requested_size\":4,\"size\":4,\"before\":\"01020304\",\"before_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"before_sha256_ok\":true,\"after\":\"01020304\",\"after_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"after_sha256_ok\":true,\"before_ok\":true,\"after_ok\":true,\"before_captured\":true,\"after_captured\":true,\"truncated\":false}],\"method_buffer_dropped\":0},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":0}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed.iter().any(|value| value == "com_vtable_effects"));
        assert!(observed.iter().any(|value| value == "com_vtable"));
        assert!(observed
            .iter()
            .any(|value| value == "com_vtable:com_vtable_call"));
        assert!(observed.iter().any(|value| value == "com_subsystem:audio"));
        assert!(observed.iter().any(|value| value == "audio_effects"));
        assert!(observed
            .iter()
            .any(|value| value == "com_method_semantic:audio_buffer_submit"));
        assert!(observed
            .iter()
            .any(|value| value == "com_method:IDirectSoundBuffer::Unlock"));
        assert!(observed.iter().any(|value| value == "com_interface_known"));
        assert!(observed
            .iter()
            .any(|value| value == "com_interface:IDirectSoundBuffer"));
        assert!(observed.iter().any(|value| value == "com_method_exact"));
        assert!(observed
            .iter()
            .any(|value| value == "com_method_exact:IDirectSoundBuffer::Unlock"));
        assert!(observed
            .iter()
            .any(|value| value == "com_method_buffer_effects"));
    }

    #[test]
    fn complete_win32_graphics_com_vtable_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            r#"{"kind":"block_entry","test_id":"t1","rva":"0x1000","state":{"registers":{"eax":1}}}
{"kind":"block_exit","test_id":"t1","rva":"0x1000","successor_rva":"0x1001","state":{"registers":{"eax":1}},"side_effects":{"capture_status":"complete","memory_reads":[],"memory_writes":[],"api_calls":[{"caller_rva":4096,"callee_module":"d3d8.dll","callee_rva":8192,"symbol_resolved":false,"callee_symbol":"","semantic_class":"gdi_calls","operation":"module_call","external":true,"stack_args":[12288,20480,0,0,24576],"return_captured":true,"return_value":0,"thread_error_state":{"kind":"win32_last_error","captured":true,"before":0,"after":0},"resource":{"known":false,"kind":"","label":"","handle":null,"handle_result":null,"path_argument_captured":false,"path_argument":"","path_argument_truncated":false},"resource_refs":[],"resource_ref_dropped":0,"com_vtable_effect":{"captured":true,"operation":"com_vtable_call","subsystem":"graphics","semantic_kind":"graphics_present","method_candidates":["IDirect3DDevice8::Present"],"method_ambiguous":false,"interface_captured":true,"interface_known":true,"interface_name":"IDirect3DDevice8","interface_label":"com:IDirect3DDevice8:object=0x3000:source=IDirect3D8::CreateDevice","method_name":"IDirect3DDevice8::Present","method_exact":true,"receiver":12288,"vtable":16384,"slot":15,"slot_address":16444,"entry":4198400,"vtable_prefix_bytes":80,"vtable_prefix_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","vtable_prefix_sha256_ok":true,"return_captured":true,"return_value":0,"method_buffers":[{"role":"graphics_present_src_rect","arg_index":1,"address":20480,"requested_size":16,"size":16,"before":"000000000000000040010000f0000000","before_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","before_sha256_ok":true,"after":"000000000000000040010000f0000000","after_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","after_sha256_ok":true,"before_ok":true,"after_ok":true,"before_captured":true,"after_captured":true,"truncated":false}],"method_buffer_dropped":0},"output_buffers":[],"output_buffer_dropped":0}],"api_returns":[{"caller_rva":4096,"return_value":0}],"external_events":[],"limitations":[]}}
"#,
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed.iter().any(|value| value == "gdi_calls"));
        assert!(observed
            .iter()
            .any(|value| value == "com_subsystem:graphics"));
        assert!(observed
            .iter()
            .any(|value| value == "com_method_semantic:graphics_present"));
        assert!(observed
            .iter()
            .any(|value| value == "com_interface:IDirect3DDevice8"));
        assert!(observed
            .iter()
            .any(|value| value == "com_method_exact:IDirect3DDevice8::Present"));
        assert!(observed
            .iter()
            .any(|value| value == "com_method_buffer_effects"));
    }

    #[test]
    fn dropped_com_method_buffer_fails_strict_coverage_even_with_complete_status() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            r#"{"kind":"block_entry","test_id":"t1","rva":"0x1000","state":{"registers":{"eax":1}}}
{"kind":"block_exit","test_id":"t1","rva":"0x1000","successor_rva":"0x1001","state":{"registers":{"eax":1}},"side_effects":{"capture_status":"complete","memory_reads":[],"memory_writes":[],"api_calls":[{"caller_rva":4096,"callee_module":"d3d8.dll","callee_rva":8192,"symbol_resolved":false,"callee_symbol":"","semantic_class":"gdi_calls","operation":"module_call","external":true,"stack_args":[12288],"return_captured":true,"return_value":0,"thread_error_state":{"kind":"win32_last_error","captured":true,"before":0,"after":0},"resource":{"known":false,"kind":"","label":"","handle":null,"handle_result":null,"path_argument_captured":false,"path_argument":"","path_argument_truncated":false},"resource_refs":[],"resource_ref_dropped":0,"com_vtable_effect":{"captured":true,"operation":"com_vtable_call","subsystem":"graphics","semantic_kind":"graphics_vertex_buffer_unlock","method_candidates":["IDirect3DVertexBuffer8::Unlock"],"method_ambiguous":false,"interface_captured":true,"interface_known":true,"interface_name":"IDirect3DVertexBuffer8","interface_label":"com:IDirect3DVertexBuffer8:object=0x3000:source=IDirect3DDevice8::CreateVertexBuffer","method_name":"IDirect3DVertexBuffer8::Unlock","method_exact":true,"receiver":12288,"vtable":16384,"slot":12,"slot_address":16432,"entry":4198400,"vtable_prefix_bytes":52,"vtable_prefix_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","vtable_prefix_sha256_ok":true,"return_captured":true,"return_value":0,"method_buffers":[],"method_buffer_dropped":1},"output_buffers":[],"output_buffer_dropped":0}],"api_returns":[{"caller_rva":4096,"return_value":0}],"external_events":[],"limitations":[]}}
"#,
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn graphics_unlock_without_payload_buffer_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            r#"{"kind":"block_entry","test_id":"t1","rva":"0x1000","state":{"registers":{"eax":1}}}
{"kind":"block_exit","test_id":"t1","rva":"0x1000","successor_rva":"0x1001","state":{"registers":{"eax":1}},"side_effects":{"capture_status":"complete","memory_reads":[],"memory_writes":[],"api_calls":[{"caller_rva":4096,"callee_module":"d3d8.dll","callee_rva":8192,"symbol_resolved":false,"callee_symbol":"","semantic_class":"gdi_calls","operation":"module_call","external":true,"stack_args":[12288],"return_captured":true,"return_value":0,"thread_error_state":{"kind":"win32_last_error","captured":true,"before":0,"after":0},"resource":{"known":false,"kind":"","label":"","handle":null,"handle_result":null,"path_argument_captured":false,"path_argument":"","path_argument_truncated":false},"resource_refs":[],"resource_ref_dropped":0,"com_vtable_effect":{"captured":true,"operation":"com_vtable_call","subsystem":"graphics","semantic_kind":"graphics_vertex_buffer_unlock","method_candidates":["IDirect3DVertexBuffer8::Unlock"],"method_ambiguous":false,"interface_captured":true,"interface_known":true,"interface_name":"IDirect3DVertexBuffer8","interface_label":"com:IDirect3DVertexBuffer8:object=0x3000:source=IDirect3DDevice8::CreateVertexBuffer","method_name":"IDirect3DVertexBuffer8::Unlock","method_exact":true,"receiver":12288,"vtable":16384,"slot":12,"slot_address":16432,"entry":4198400,"vtable_prefix_bytes":52,"vtable_prefix_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","vtable_prefix_sha256_ok":true,"return_captured":true,"return_value":0,"method_buffers":[],"method_buffer_dropped":0},"output_buffers":[],"output_buffer_dropped":0}],"api_returns":[{"caller_rva":4096,"return_value":0}],"external_events":[],"limitations":[]}}
"#,
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn incomplete_win32_thread_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"CreateThread\",\"semantic_class\":\"threading\",\"operation\":\"CreateThread\",\"external\":true,\"stack_args\":[0,0,8192,12288,0,16384],\"return_captured\":true,\"return_value\":57005,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"thread\",\"label\":\"thread:start=0x2000,param=0x3000\",\"handle\":null,\"handle_result\":57005,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"thread_effect\":{\"captured\":false,\"succeeded\":true,\"operation\":\"create_thread\",\"security_attributes\":0,\"stack_size\":0,\"start_address\":8192,\"parameter\":12288,\"creation_flags\":0,\"thread_id_address\":16384,\"thread_id\":null,\"result_handle\":null,\"wait_handle\":null,\"timeout_ms\":null,\"alertable\":null},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":57005}],\"callbacks\":[],\"external_events\":[],\"limitations\":[\"api_thread_effect_not_captured\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_thread_effects_pass_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"CreateThread\",\"semantic_class\":\"threading\",\"operation\":\"CreateThread\",\"external\":true,\"stack_args\":[0,0,8192,12288,0,16384],\"return_captured\":true,\"return_value\":57005,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"thread\",\"label\":\"thread:id=44,start=0x2000,param=0x3000\",\"handle\":null,\"handle_result\":57005,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"thread_effect\":{\"captured\":true,\"succeeded\":true,\"operation\":\"create_thread\",\"security_attributes\":0,\"stack_size\":0,\"start_address\":8192,\"parameter\":12288,\"creation_flags\":0,\"thread_id_address\":16384,\"thread_id\":44,\"result_handle\":{\"handle\":57005,\"known\":true,\"kind\":\"thread\",\"label\":\"thread:id=44,start=0x2000,param=0x3000\"},\"wait_handle\":null,\"timeout_ms\":null,\"alertable\":null},\"output_buffers\":[{\"arg_index\":5,\"address\":16384,\"size\":4,\"before\":\"00000000\",\"after\":\"2c000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"output_buffer_dropped\":0},{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1240,\"symbol_resolved\":true,\"callee_symbol\":\"WaitForSingleObject\",\"semantic_class\":\"threading\",\"operation\":\"WaitForSingleObject\",\"external\":true,\"stack_args\":[57005,5000],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"thread\",\"label\":\"thread:id=44,start=0x2000,param=0x3000\",\"handle\":57005,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"wait_handle\",\"handle\":57005,\"known\":true,\"kind\":\"thread\",\"label\":\"thread:id=44,start=0x2000,param=0x3000\"}],\"resource_ref_dropped\":0,\"thread_effect\":{\"captured\":true,\"succeeded\":true,\"operation\":\"wait_single_object\",\"security_attributes\":null,\"stack_size\":null,\"start_address\":null,\"parameter\":null,\"creation_flags\":null,\"thread_id_address\":null,\"thread_id\":null,\"result_handle\":null,\"wait_handle\":{\"handle\":57005,\"known\":true,\"kind\":\"thread\",\"label\":\"thread:id=44,start=0x2000,param=0x3000\"},\"timeout_ms\":5000,\"alertable\":null},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":57005},{\"caller_rva\":4096,\"return_value\":0}],\"callbacks\":[{\"captured\":true,\"operation\":\"thread_entry\",\"callback_rva\":8192,\"class_name\":\"\",\"class_name_captured\":false,\"instance\":null,\"atom\":null,\"target\":null,\"message\":null,\"wparam\":null,\"lparam\":null,\"timer_id\":null,\"elapsed_ms\":null,\"thread_id\":44,\"thread_parameter\":12288,\"thread_handle\":{\"handle\":57005,\"known\":true,\"kind\":\"thread\",\"label\":\"thread:id=44,start=0x2000,param=0x3000\"}}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed.iter().any(|value| value == "thread_effects"));
        assert!(observed.iter().any(|value| value == "threading"));
        assert!(observed.iter().any(|value| value == "thread_callbacks"));
        assert!(observed.iter().any(|value| value == "thread:create_thread"));
        assert!(observed
            .iter()
            .any(|value| value == "thread:wait_single_object"));
        assert!(observed
            .iter()
            .any(|value| value == "callback:thread_entry"));
        assert!(observed.iter().any(|value| value == "api_resource:thread"));
    }

    #[test]
    fn incomplete_win32_sync_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"SetEvent\",\"semantic_class\":\"synchronization\",\"operation\":\"SetEvent\",\"external\":true,\"stack_args\":[57005],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"event\",\"label\":\"event:name=ready\",\"handle\":57005,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"event\",\"handle\":57005,\"known\":true,\"kind\":\"event\",\"label\":\"event:name=ready\"}],\"resource_ref_dropped\":0,\"sync_effect\":{\"captured\":false,\"succeeded\":true,\"operation\":\"set_event\",\"object_type\":\"event\",\"target\":{\"handle\":57005,\"known\":true,\"kind\":\"event\",\"label\":\"event:name=ready\"}},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":1}],\"callbacks\":[],\"external_events\":[],\"limitations\":[\"api_sync_effect_not_captured\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_sync_effects_pass_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"CreateEventA\",\"semantic_class\":\"synchronization\",\"operation\":\"CreateEventA\",\"external\":true,\"stack_args\":[0,1,0,8192],\"return_captured\":true,\"return_value\":57005,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"event\",\"label\":\"event:name=ready\",\"handle\":null,\"handle_result\":57005,\"path_argument_captured\":true,\"path_argument\":\"event:name=ready\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"sync_effect\":{\"captured\":true,\"succeeded\":true,\"operation\":\"create_event\",\"object_type\":\"event\",\"security_attributes\":0,\"desired_access\":null,\"inherit_handle\":null,\"manual_reset\":true,\"initial_state\":false,\"initial_owner\":null,\"initial_count\":null,\"maximum_count\":null,\"release_count\":null,\"previous_count_address\":null,\"previous_count\":null,\"name_arg\":8192,\"name_text\":\"ready\",\"name_text_captured\":true,\"name_text_truncated\":false,\"target\":null,\"result\":{\"handle\":57005,\"known\":true,\"kind\":\"event\",\"label\":\"event:name=ready\"},\"wait_count\":null,\"wait_all\":null,\"timeout_ms\":null,\"alertable\":null,\"handle_array\":{\"address\":null,\"bytes\":null,\"sha256\":\"\",\"sha256_ok\":false}},\"output_buffers\":[{\"arg_index\":3,\"address\":8192,\"size\":6,\"before\":\"726561647900\",\"after\":\"726561647900\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"output_buffer_dropped\":0},{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1240,\"symbol_resolved\":true,\"callee_symbol\":\"SetEvent\",\"semantic_class\":\"synchronization\",\"operation\":\"SetEvent\",\"external\":true,\"stack_args\":[57005],\"return_captured\":true,\"return_value\":1,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"event\",\"label\":\"event:name=ready\",\"handle\":57005,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"event\",\"handle\":57005,\"known\":true,\"kind\":\"event\",\"label\":\"event:name=ready\"}],\"resource_ref_dropped\":0,\"sync_effect\":{\"captured\":true,\"succeeded\":true,\"operation\":\"set_event\",\"object_type\":\"event\",\"target\":{\"handle\":57005,\"known\":true,\"kind\":\"event\",\"label\":\"event:name=ready\"},\"result\":null,\"handle_array\":{\"address\":null,\"bytes\":null,\"sha256\":\"\",\"sha256_ok\":false}},\"output_buffers\":[],\"output_buffer_dropped\":0},{\"caller_rva\":4096,\"callee_module\":\"kernel32.dll\",\"callee_rva\":1248,\"symbol_resolved\":true,\"callee_symbol\":\"WaitForMultipleObjects\",\"semantic_class\":\"threading\",\"operation\":\"WaitForMultipleObjects\",\"external\":true,\"stack_args\":[1,12288,0,1000],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"sync_effect\":{\"captured\":true,\"succeeded\":true,\"operation\":\"wait_multiple_objects\",\"object_type\":\"sync_object\",\"wait_count\":1,\"wait_all\":false,\"timeout_ms\":1000,\"alertable\":null,\"handle_array\":{\"address\":12288,\"bytes\":8,\"sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"sha256_ok\":true}},\"output_buffers\":[{\"arg_index\":1,\"address\":12288,\"size\":8,\"before\":\"adde000000000000\",\"after\":\"adde000000000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":57005},{\"caller_rva\":4096,\"return_value\":1},{\"caller_rva\":4096,\"return_value\":0}],\"callbacks\":[],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed.iter().any(|value| value == "sync_effects"));
        assert!(observed.iter().any(|value| value == "synchronization"));
        assert!(observed.iter().any(|value| value == "sync:create_event"));
        assert!(observed.iter().any(|value| value == "sync:set_event"));
        assert!(observed
            .iter()
            .any(|value| value == "sync:wait_multiple_objects"));
        assert!(observed.iter().any(|value| value == "sync_object:event"));
        assert!(observed.iter().any(|value| value == "api_resource:event"));
    }

    #[test]
    fn incomplete_win32_class_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"RegisterClassA\",\"semantic_class\":\"window_class\",\"operation\":\"RegisterClassA\",\"external\":true,\"stack_args\":[8192],\"return_captured\":true,\"return_value\":49152,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"class_effect\":{\"captured\":false,\"operation\":\"register_class\",\"class_name\":\"\",\"class_name_captured\":false,\"class_name_truncated\":false,\"menu_name_present\":false,\"menu_name\":\"\",\"menu_name_captured\":false,\"menu_name_truncated\":false,\"cb_size\":null,\"style\":null,\"cb_cls_extra\":null,\"cb_wnd_extra\":null,\"wndproc\":null,\"instance\":null,\"icon\":null,\"cursor\":null,\"background_brush\":null,\"small_icon\":null,\"atom\":null},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":49152}],\"external_events\":[],\"limitations\":[\"api_class_effect_not_captured\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_class_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"RegisterClassA\",\"semantic_class\":\"window_class\",\"operation\":\"RegisterClassA\",\"external\":true,\"stack_args\":[8192],\"return_captured\":true,\"return_value\":49152,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"handle\":null,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"class_effect\":{\"captured\":true,\"operation\":\"register_class\",\"class_name\":\"GameWindow\",\"class_name_captured\":true,\"class_name_truncated\":false,\"menu_name_present\":false,\"menu_name\":\"\",\"menu_name_captured\":false,\"menu_name_truncated\":false,\"cb_size\":null,\"style\":3,\"cb_cls_extra\":0,\"cb_wnd_extra\":0,\"wndproc\":4198400,\"instance\":4096,\"icon\":0,\"cursor\":0,\"background_brush\":6,\"small_icon\":null,\"atom\":49152},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":49152}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed.iter().any(|value| value == "class_effects"));
        assert!(observed.iter().any(|value| value == "window_class"));
        assert!(observed.iter().any(|value| value == "class:register_class"));
    }

    #[test]
    fn incomplete_win32_gdi_state_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"gdi32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"SelectObject\",\"semantic_class\":\"gdi_calls\",\"operation\":\"SelectObject\",\"external\":true,\"stack_args\":[200,300],\"return_captured\":true,\"return_value\":301,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main\",\"handle\":200,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"hdc\",\"handle\":200,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main\"},{\"arg_index\":1,\"role\":\"gdi_object\",\"handle\":300,\"known\":true,\"kind\":\"gdi_object\",\"label\":\"pen:style=0,width=1,color=0x00000000\"}],\"resource_ref_dropped\":0,\"gdi_state_effect\":{\"captured\":false,\"operation\":\"select_object\",\"target\":null,\"object\":null,\"color\":null,\"mode\":null,\"previous_value\":null},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":301}],\"external_events\":[],\"limitations\":[\"api_gdi_state_effect_not_captured\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_gdi_state_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"gdi32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"SelectObject\",\"semantic_class\":\"gdi_calls\",\"operation\":\"SelectObject\",\"external\":true,\"stack_args\":[200,300],\"return_captured\":true,\"return_value\":301,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main\",\"handle\":200,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"hdc\",\"handle\":200,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main\"},{\"arg_index\":1,\"role\":\"gdi_object\",\"handle\":300,\"known\":true,\"kind\":\"gdi_object\",\"label\":\"pen:style=0,width=1,color=0x00000000\"}],\"resource_ref_dropped\":0,\"gdi_state_effect\":{\"captured\":true,\"operation\":\"select_object\",\"target\":{\"handle\":200,\"known\":true,\"kind\":\"dc\",\"label\":\"dc:window:main\"},\"object\":{\"handle\":300,\"known\":true,\"kind\":\"gdi_object\",\"label\":\"pen:style=0,width=1,color=0x00000000\"},\"color\":null,\"mode\":null,\"previous_value\":301},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":301}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed.iter().any(|value| value == "gdi_state_effects"));
        assert!(observed
            .iter()
            .any(|value| value == "gdi_state:select_object"));
    }

    #[test]
    fn incomplete_win32_cursor_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"LoadCursorA\",\"semantic_class\":\"window_resources\",\"operation\":\"LoadCursorA\",\"external\":true,\"stack_args\":[0,32512],\"return_captured\":true,\"return_value\":400,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"cursor\",\"label\":\"cursor:system:atom:32512\",\"handle\":null,\"handle_result\":400,\"path_argument_captured\":true,\"path_argument\":\"cursor:system:atom:32512\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"cursor_effect\":{\"captured\":false,\"operation\":\"load_cursor\",\"instance\":0,\"cursor_name\":\"atom:32512\",\"cursor_name_captured\":true,\"cursor_name_truncated\":false,\"result\":{\"handle\":null,\"known\":false,\"label\":\"\"}},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":400}],\"external_events\":[],\"limitations\":[\"api_cursor_effect_not_captured\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_cursor_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"user32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"LoadCursorA\",\"semantic_class\":\"window_resources\",\"operation\":\"LoadCursorA\",\"external\":true,\"stack_args\":[0,32512],\"return_captured\":true,\"return_value\":400,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"cursor\",\"label\":\"cursor:system:atom:32512\",\"handle\":null,\"handle_result\":400,\"path_argument_captured\":true,\"path_argument\":\"cursor:system:atom:32512\",\"path_argument_truncated\":false},\"resource_refs\":[],\"resource_ref_dropped\":0,\"cursor_effect\":{\"captured\":true,\"operation\":\"load_cursor\",\"instance\":0,\"cursor_name\":\"atom:32512\",\"cursor_name_captured\":true,\"cursor_name_truncated\":false,\"result\":{\"handle\":400,\"known\":true,\"label\":\"cursor:system:atom:32512\"}},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":400}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed.iter().any(|value| value == "cursor_effects"));
        assert!(observed.iter().any(|value| value == "window_resources"));
    }

    #[test]
    fn incomplete_win32_registry_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":0}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"advapi32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"RegSetValueExA\",\"semantic_class\":\"registry\",\"operation\":\"RegSetValueExA\",\"external\":true,\"stack_args\":[2147483649,8192,0,4,12288,4],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"registry_key\",\"label\":\"HKEY_CURRENT_USER\",\"handle\":2147483649,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"registry_key\",\"handle\":2147483649,\"known\":true,\"kind\":\"registry_key\",\"label\":\"HKEY_CURRENT_USER\"}],\"resource_ref_dropped\":0,\"draw_effect\":null,\"message_effect\":null,\"registry_effect\":{\"captured\":false,\"operation\":\"set_value\",\"key\":{\"handle\":2147483649,\"known\":true,\"label\":\"HKEY_CURRENT_USER\"},\"subkey\":\"\",\"subkey_captured\":false,\"subkey_truncated\":false,\"value_name\":\"\",\"value_name_captured\":false,\"value_name_truncated\":false,\"value_type\":null,\"data_size\":null,\"data_arg_index\":null,\"result_key\":{\"handle\":null,\"known\":false,\"label\":\"\"}},\"output_buffers\":[],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":0}],\"external_events\":[],\"limitations\":[\"api_registry_effect_not_captured\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_win32_registry_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":0}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[{\"caller_rva\":4096,\"callee_module\":\"advapi32.dll\",\"callee_rva\":1234,\"symbol_resolved\":true,\"callee_symbol\":\"RegSetValueExA\",\"semantic_class\":\"registry\",\"operation\":\"RegSetValueExA\",\"external\":true,\"stack_args\":[2147483649,8192,0,4,12288,4],\"return_captured\":true,\"return_value\":0,\"thread_error_state\":{\"kind\":\"win32_last_error\",\"captured\":true,\"before\":0,\"after\":0},\"resource\":{\"known\":true,\"kind\":\"registry_key\",\"label\":\"HKEY_CURRENT_USER\",\"handle\":2147483649,\"handle_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"resource_refs\":[{\"arg_index\":0,\"role\":\"registry_key\",\"handle\":2147483649,\"known\":true,\"kind\":\"registry_key\",\"label\":\"HKEY_CURRENT_USER\"}],\"resource_ref_dropped\":0,\"draw_effect\":null,\"message_effect\":null,\"registry_effect\":{\"captured\":true,\"operation\":\"set_value\",\"key\":{\"handle\":2147483649,\"known\":true,\"label\":\"HKEY_CURRENT_USER\"},\"subkey\":\"\",\"subkey_captured\":false,\"subkey_truncated\":false,\"value_name\":\"MouseSpeed\",\"value_name_captured\":true,\"value_name_truncated\":false,\"value_type\":4,\"data_size\":4,\"data_arg_index\":4,\"result_key\":{\"handle\":null,\"known\":false,\"label\":\"\"}},\"output_buffers\":[{\"arg_index\":1,\"address\":8192,\"size\":11,\"before\":\"4d6f757365537065656400\",\"after\":\"4d6f757365537065656400\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false},{\"arg_index\":4,\"address\":12288,\"size\":4,\"before\":\"02000000\",\"after\":\"02000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"output_buffer_dropped\":0}],\"api_returns\":[{\"caller_rva\":4096,\"return_value\":0}],\"external_events\":[],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn unknown_syscall_external_event_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":2}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[],\"api_returns\":[],\"external_events\":[{\"kind\":\"syscall\",\"block_rva\":4096,\"sysnum\":999999,\"semantic_class\":\"unknown\",\"operation\":\"syscall\",\"args\":[1,8192,2],\"result_expected\":true,\"result_captured\":true,\"succeeded\":true,\"result\":2,\"errno\":0,\"buffers\":[],\"buffer_dropped\":0}],\"limitations\":[\"external_event_semantics_unknown_syscall\",\"external_event_semantics_decoder_missing\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn classified_syscall_external_event_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":2}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[],\"api_returns\":[],\"external_events\":[{\"kind\":\"syscall\",\"block_rva\":4096,\"sysnum\":1,\"semantic_class\":\"file_io\",\"operation\":\"write\",\"args\":[1,8192,1],\"result_expected\":true,\"result_captured\":true,\"succeeded\":true,\"result\":1,\"errno\":0,\"buffers\":[{\"arg_index\":1,\"address\":8192,\"size\":1,\"before\":\"78\",\"after\":\"78\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"buffer_dropped\":0}],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn incomplete_vector_syscall_effect_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":2}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[],\"api_returns\":[],\"external_events\":[{\"kind\":\"syscall\",\"block_rva\":4096,\"sysnum\":20,\"semantic_class\":\"file_io\",\"operation\":\"writev\",\"args\":[1,8192,9],\"result_expected\":true,\"result_captured\":true,\"succeeded\":true,\"result\":2,\"errno\":0,\"resource\":{\"known\":true,\"kind\":\"stdio\",\"label\":\"stdout\",\"fd\":1,\"fd_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"buffers\":[{\"source\":\"iovec_data\",\"arg_index\":1,\"iov_index\":0,\"address\":12288,\"size\":1,\"before\":\"78\",\"after\":\"78\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"buffer_dropped\":1}],\"limitations\":[\"syscall_buffer_record_limit_reached\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_vector_syscall_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":2}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[],\"api_returns\":[],\"external_events\":[{\"kind\":\"syscall\",\"block_rva\":4096,\"sysnum\":20,\"semantic_class\":\"file_io\",\"operation\":\"writev\",\"args\":[1,8192,2],\"result_expected\":true,\"result_captured\":true,\"succeeded\":true,\"result\":2,\"errno\":0,\"resource\":{\"known\":true,\"kind\":\"stdio\",\"label\":\"stdout\",\"fd\":1,\"fd_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"buffers\":[{\"source\":\"iovec_data\",\"arg_index\":1,\"iov_index\":0,\"address\":12288,\"size\":1,\"before\":\"78\",\"after\":\"78\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false},{\"source\":\"iovec_data\",\"arg_index\":1,\"iov_index\":1,\"address\":12304,\"size\":1,\"before\":\"79\",\"after\":\"79\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"buffer_dropped\":0}],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(side_effects["observed_effect_classes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|class| class.as_str() == Some("vector_io")));
    }

    #[test]
    fn complete_oversized_vector_syscall_with_aggregate_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            format!(
                concat!(
                    "{{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{{\"registers\":{{\"eax\":1}}}}}}\n",
                    "{{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{{\"registers\":{{\"eax\":2}}}},\"side_effects\":{{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[],\"api_returns\":[],\"external_events\":[{{\"kind\":\"syscall\",\"block_rva\":4096,\"sysnum\":20,\"semantic_class\":\"file_io\",\"operation\":\"writev\",\"args\":[1,8192,10],\"result_expected\":true,\"result_captured\":true,\"succeeded\":true,\"result\":10,\"errno\":0,\"resource\":{{\"known\":true,\"kind\":\"stdio\",\"label\":\"stdout\",\"fd\":1,\"fd_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false}},\"buffers\":[],\"buffer_dropped\":0,\"aggregates\":[{{\"source\":\"iovec_array\",\"arg_index\":1,\"message_index\":null,\"element_count\":10,\"descriptor_address\":8192,\"descriptor_size\":160,\"descriptor_sha256\":\"{digest}\",\"descriptor_sha256_ok\":true,\"before_sha256\":\"{digest}\",\"before_sha256_ok\":true,\"after_sha256\":\"{digest}\",\"after_sha256_ok\":true}}],\"aggregate_dropped\":0}}],\"limitations\":[]}}}}\n"
                ),
                digest = digest
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(side_effects["observed_effect_classes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|class| class.as_str() == Some("vector_io")));
    }

    #[test]
    fn complete_syscall_buffer_aggregate_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            format!(
                concat!(
                    "{{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{{\"registers\":{{\"eax\":1}}}}}}\n",
                    "{{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{{\"registers\":{{\"eax\":2}}}},\"side_effects\":{{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[],\"api_returns\":[],\"external_events\":[{{\"kind\":\"syscall\",\"block_rva\":4096,\"sysnum\":20,\"semantic_class\":\"file_io\",\"operation\":\"writev\",\"args\":[1,8192,12],\"result_expected\":true,\"result_captured\":true,\"succeeded\":true,\"result\":12,\"errno\":0,\"resource\":{{\"known\":true,\"kind\":\"stdio\",\"label\":\"stdout\",\"fd\":1,\"fd_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false}},\"buffers\":[],\"buffer_dropped\":0,\"buffer_aggregate\":{{\"count\":1,\"sha256\":\"{digest}\",\"sha256_ok\":true,\"entries\":[{{\"source\":\"iovec_data\",\"arg_index\":1,\"iov_index\":9,\"message_index\":null,\"address\":12288,\"size\":1,\"before_sha256\":\"{digest}\",\"before_sha256_ok\":true,\"after_sha256\":\"{digest}\",\"after_sha256_ok\":true,\"truncated\":false}}]}},\"aggregates\":[],\"aggregate_dropped\":0}}],\"limitations\":[]}}}}\n"
                ),
                digest = digest
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("vector_io")));
    }

    #[test]
    fn over_cap_complete_api_and_syscall_events_pass_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();

        let api_calls: Vec<Value> = (0..12)
            .map(|index| {
                json!({
                    "caller_rva": 4096 + index,
                    "external": false,
                    "return_captured": true,
                    "return_value": index,
                    "output_buffers": [],
                    "output_buffer_dropped": 0
                })
            })
            .collect();
        let external_events: Vec<Value> = (0..20)
            .map(|index| {
                json!({
                    "kind": "syscall",
                    "block_rva": 4096,
                    "sysnum": 39,
                    "semantic_class": "process",
                    "operation": "getpid",
                    "args": [],
                    "result_expected": true,
                    "result_captured": true,
                    "succeeded": true,
                    "result": 1000 + index,
                    "errno": 0,
                    "buffers": [],
                    "buffer_dropped": 0,
                    "aggregates": [],
                    "aggregate_dropped": 0
                })
            })
            .collect();
        let entry = json!({
            "kind": "block_entry",
            "test_id": "t1",
            "rva": "0x1000",
            "state": {"registers": {"eax": 1}}
        });
        let exit = json!({
            "kind": "block_exit",
            "test_id": "t1",
            "rva": "0x1000",
            "successor_rva": "0x1001",
            "state": {"registers": {"eax": 2}},
            "side_effects": {
                "capture_status": "complete",
                "memory_reads": [],
                "memory_writes": [],
                "api_calls": api_calls,
                "api_returns": [],
                "external_events": external_events,
                "limitations": []
            }
        });
        fs::write(&trace, format!("{entry}\n{exit}\n")).unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("api_calls")));
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("syscalls")));
    }

    #[test]
    fn incomplete_network_syscall_resource_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[],\"api_returns\":[],\"external_events\":[{\"kind\":\"syscall\",\"block_rva\":4096,\"sysnum\":44,\"semantic_class\":\"network\",\"operation\":\"sendto\",\"args\":[99,8192,1,0,12288,16],\"result_expected\":true,\"result_captured\":true,\"succeeded\":true,\"result\":1,\"errno\":0,\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"fd\":99,\"fd_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"buffers\":[{\"source\":\"argument\",\"arg_index\":1,\"iov_index\":null,\"address\":8192,\"size\":1,\"before\":\"6e\",\"after\":\"6e\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false},{\"source\":\"argument\",\"arg_index\":4,\"iov_index\":null,\"address\":12288,\"size\":16,\"before\":\"020000097f0000010000000000000000\",\"after\":\"020000097f0000010000000000000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"buffer_dropped\":0}],\"limitations\":[\"syscall_resource_not_resolved\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_network_syscall_effect_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[],\"api_returns\":[],\"external_events\":[{\"kind\":\"syscall\",\"block_rva\":4096,\"sysnum\":44,\"semantic_class\":\"network\",\"operation\":\"sendto\",\"args\":[3,8192,1,0,12288,16],\"result_expected\":true,\"result_captured\":true,\"succeeded\":true,\"result\":1,\"errno\":0,\"resource\":{\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=2,protocol=0\",\"fd\":3,\"fd_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"buffers\":[{\"source\":\"argument\",\"arg_index\":1,\"iov_index\":null,\"address\":8192,\"size\":1,\"before\":\"6e\",\"after\":\"6e\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false},{\"source\":\"argument\",\"arg_index\":4,\"iov_index\":null,\"address\":12288,\"size\":16,\"before\":\"020000097f0000010000000000000000\",\"after\":\"020000097f0000010000000000000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"buffer_dropped\":0}],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(side_effects["observed_effect_classes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|class| class.as_str() == Some("network")));
    }

    #[test]
    fn incomplete_message_header_network_syscall_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[],\"api_returns\":[],\"external_events\":[{\"kind\":\"syscall\",\"block_rva\":4096,\"sysnum\":46,\"semantic_class\":\"network\",\"operation\":\"sendmsg\",\"args\":[3,8192,0,0,0,0],\"result_expected\":true,\"result_captured\":true,\"succeeded\":true,\"result\":1,\"errno\":0,\"resource\":{\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=2,protocol=0\",\"fd\":3,\"fd_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"buffers\":[{\"source\":\"msghdr\",\"arg_index\":1,\"iov_index\":null,\"address\":8192,\"size\":56,\"before\":\"00300000000000001000000000000000004000000000000001000000000000000000000000000000000000000000000000000000000000000\",\"after\":\"00300000000000001000000000000000004000000000000001000000000000000000000000000000000000000000000000000000000000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"buffer_dropped\":1}],\"limitations\":[\"syscall_buffer_record_limit_reached\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_message_header_network_syscall_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[],\"api_returns\":[],\"external_events\":[{\"kind\":\"syscall\",\"block_rva\":4096,\"sysnum\":46,\"semantic_class\":\"network\",\"operation\":\"sendmsg\",\"args\":[3,8192,0,0,0,0],\"result_expected\":true,\"result_captured\":true,\"succeeded\":true,\"result\":1,\"errno\":0,\"resource\":{\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=2,protocol=0\",\"fd\":3,\"fd_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"buffers\":[{\"source\":\"msghdr\",\"arg_index\":1,\"iov_index\":null,\"address\":8192,\"size\":56,\"before\":\"00300000000000001000000000000000004000000000000001000000000000000000000000000000000000000000000000000000000000000\",\"after\":\"00300000000000001000000000000000004000000000000001000000000000000000000000000000000000000000000000000000000000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false},{\"source\":\"msghdr_name\",\"arg_index\":1,\"iov_index\":null,\"address\":12288,\"size\":16,\"before\":\"020000097f0000010000000000000000\",\"after\":\"020000097f0000010000000000000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false},{\"source\":\"msghdr_iovec_data\",\"arg_index\":1,\"iov_index\":0,\"address\":16384,\"size\":1,\"before\":\"6d\",\"after\":\"6d\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"buffer_dropped\":0}],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("network")));
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("vector_io")));
    }

    #[test]
    fn incomplete_batched_message_network_syscall_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[],\"api_returns\":[],\"external_events\":[{\"kind\":\"syscall\",\"block_rva\":4096,\"sysnum\":307,\"semantic_class\":\"network\",\"operation\":\"sendmmsg\",\"args\":[3,8192,5,0,0,0],\"result_expected\":true,\"result_captured\":true,\"succeeded\":true,\"result\":4,\"errno\":0,\"resource\":{\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=2,protocol=0\",\"fd\":3,\"fd_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"buffers\":[{\"source\":\"mmsghdr\",\"arg_index\":1,\"iov_index\":null,\"message_index\":0,\"address\":8192,\"size\":64,\"before\":\"00300000000000001000000000000000004000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"after\":\"00300000000000001000000000000000004000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"buffer_dropped\":1}],\"limitations\":[\"syscall_buffer_record_limit_reached\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_batched_message_network_syscall_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":1}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[],\"api_returns\":[],\"external_events\":[{\"kind\":\"syscall\",\"block_rva\":4096,\"sysnum\":307,\"semantic_class\":\"network\",\"operation\":\"sendmmsg\",\"args\":[3,8192,2,0,0,0],\"result_expected\":true,\"result_captured\":true,\"succeeded\":true,\"result\":2,\"errno\":0,\"resource\":{\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=2,protocol=0\",\"fd\":3,\"fd_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"buffers\":[{\"source\":\"mmsghdr\",\"arg_index\":1,\"iov_index\":null,\"message_index\":0,\"address\":8192,\"size\":64,\"before\":\"00300000000000001000000000000000004000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"after\":\"00300000000000001000000000000000004000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false},{\"source\":\"msghdr_name\",\"arg_index\":1,\"iov_index\":null,\"message_index\":0,\"address\":12288,\"size\":16,\"before\":\"020000097f0000010000000000000000\",\"after\":\"020000097f0000010000000000000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false},{\"source\":\"msghdr_iovec_data\",\"arg_index\":1,\"iov_index\":0,\"message_index\":0,\"address\":16384,\"size\":1,\"before\":\"61\",\"after\":\"61\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false},{\"source\":\"mmsghdr\",\"arg_index\":1,\"iov_index\":null,\"message_index\":1,\"address\":8256,\"size\":64,\"before\":\"10300000000000001000000000000000104000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"after\":\"10300000000000001000000000000000104000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false},{\"source\":\"msghdr_name\",\"arg_index\":1,\"iov_index\":null,\"message_index\":1,\"address\":12304,\"size\":16,\"before\":\"020000097f0000010000000000000000\",\"after\":\"020000097f0000010000000000000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false},{\"source\":\"msghdr_iovec_data\",\"arg_index\":1,\"iov_index\":0,\"message_index\":1,\"address\":16400,\"size\":1,\"before\":\"62\",\"after\":\"62\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"buffer_dropped\":0}],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("network")));
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("vector_io")));
    }

    #[test]
    fn complete_oversized_batched_message_with_aggregate_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            format!(
                concat!(
                    "{{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{{\"registers\":{{\"eax\":1}}}}}}\n",
                    "{{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{{\"registers\":{{\"eax\":1}}}},\"side_effects\":{{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[],\"api_returns\":[],\"external_events\":[{{\"kind\":\"syscall\",\"block_rva\":4096,\"sysnum\":307,\"semantic_class\":\"network\",\"operation\":\"sendmmsg\",\"args\":[3,8192,5,0,0,0],\"result_expected\":true,\"result_captured\":true,\"succeeded\":true,\"result\":5,\"errno\":0,\"resource\":{{\"known\":true,\"kind\":\"socket\",\"label\":\"socket:domain=2,type=2,protocol=0\",\"fd\":3,\"fd_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false}},\"buffers\":[],\"buffer_dropped\":0,\"aggregates\":[{{\"source\":\"mmsghdr_array\",\"arg_index\":1,\"message_index\":null,\"element_count\":5,\"descriptor_address\":8192,\"descriptor_size\":320,\"descriptor_sha256\":\"{digest}\",\"descriptor_sha256_ok\":true,\"descriptor_after_sha256\":\"{digest}\",\"descriptor_after_sha256_ok\":true,\"before_sha256\":\"{digest}\",\"before_sha256_ok\":true,\"after_sha256\":\"{digest}\",\"after_sha256_ok\":true}}],\"aggregate_dropped\":0}}],\"limitations\":[]}}}}\n"
                ),
                digest = digest
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let observed = side_effects["observed_effect_classes"].as_array().unwrap();
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("network")));
        assert!(observed
            .iter()
            .any(|class| class.as_str() == Some("vector_io")));
    }

    #[test]
    fn unknown_ioctl_request_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":0}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[],\"api_returns\":[],\"external_events\":[{\"kind\":\"syscall\",\"block_rva\":4096,\"sysnum\":16,\"semantic_class\":\"device_io\",\"operation\":\"ioctl\",\"args\":[1,3735928559,8192,0,0,0],\"result_expected\":true,\"result_captured\":true,\"succeeded\":false,\"result\":18446744073709551615,\"errno\":25,\"resource\":{\"known\":true,\"kind\":\"stdio\",\"label\":\"stdout\",\"fd\":1,\"fd_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"buffers\":[],\"buffer_dropped\":0}],\"limitations\":[\"external_event_semantics_decoder_missing\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn complete_ioctl_request_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":0}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[],\"api_returns\":[],\"external_events\":[{\"kind\":\"syscall\",\"block_rva\":4096,\"sysnum\":16,\"semantic_class\":\"device_io\",\"operation\":\"ioctl\",\"args\":[1,21531,8192,0,0,0],\"result_expected\":true,\"result_captured\":true,\"succeeded\":true,\"result\":0,\"errno\":0,\"resource\":{\"known\":true,\"kind\":\"stdio\",\"label\":\"stdout\",\"fd\":1,\"fd_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"buffers\":[{\"source\":\"ioctl_data\",\"arg_index\":2,\"iov_index\":null,\"address\":8192,\"size\":4,\"before\":\"00000000\",\"after\":\"05000000\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"buffer_dropped\":0}],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);

        let labels = suite_block_labels(&suite).unwrap();
        let side_effects: Value = serde_json::from_str(
            &fs::read_to_string(
                suite
                    .join("blocks")
                    .join(&labels[0])
                    .join("side-effects.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(side_effects["observed_effect_classes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|class| class.as_str() == Some("device_io")));
    }

    #[test]
    fn unresolved_syscall_resource_fails_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":2}},\"side_effects\":{\"capture_status\":\"partial\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[],\"api_returns\":[],\"external_events\":[{\"kind\":\"syscall\",\"block_rva\":4096,\"sysnum\":1,\"semantic_class\":\"file_io\",\"operation\":\"write\",\"args\":[99,8192,1],\"result_expected\":true,\"result_captured\":true,\"succeeded\":true,\"result\":1,\"errno\":0,\"resource\":{\"known\":false,\"kind\":\"\",\"label\":\"\",\"fd\":99,\"fd_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"buffers\":[{\"arg_index\":1,\"address\":8192,\"size\":1,\"before\":\"78\",\"after\":\"78\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"buffer_dropped\":0}],\"limitations\":[\"syscall_resource_not_resolved\"]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "fail");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 1);
    }

    #[test]
    fn resolved_syscall_resource_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":1}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{\"registers\":{\"eax\":2}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[],\"api_returns\":[],\"external_events\":[{\"kind\":\"syscall\",\"block_rva\":4096,\"sysnum\":1,\"semantic_class\":\"file_io\",\"operation\":\"write\",\"args\":[1,8192,1],\"result_expected\":true,\"result_captured\":true,\"succeeded\":true,\"result\":1,\"errno\":0,\"resource\":{\"known\":true,\"kind\":\"stdio\",\"label\":\"stdout\",\"fd\":1,\"fd_result\":null,\"path_argument_captured\":false,\"path_argument\":\"\",\"path_argument_truncated\":false},\"buffers\":[{\"arg_index\":1,\"address\":8192,\"size\":1,\"before\":\"78\",\"after\":\"78\",\"before_ok\":true,\"after_ok\":true,\"truncated\":false}],\"buffer_dropped\":0}],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn nonreturning_syscall_external_event_passes_strict_coverage() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        fs::write(
            &trace,
            concat!(
                "{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{\"registers\":{\"eax\":60}}}\n",
                "{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":null,\"state\":{\"registers\":{\"eax\":60}},\"side_effects\":{\"capture_status\":\"complete\",\"memory_reads\":[],\"memory_writes\":[],\"api_calls\":[],\"api_returns\":[],\"external_events\":[{\"kind\":\"syscall\",\"block_rva\":4096,\"sysnum\":60,\"semantic_class\":\"process\",\"operation\":\"exit\",\"args\":[0],\"result_expected\":false,\"result_captured\":false,\"succeeded\":true,\"result\":null,\"errno\":0,\"buffers\":[],\"buffer_dropped\":0}],\"limitations\":[]}}\n",
            ),
        )
        .unwrap();

        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let coverage = coverage_report_for_suite(&suite, &CoverageOptions::default()).unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.side_effect_incomplete_blocks.len(), 0);
    }

    #[test]
    fn candidate_validation_requires_complete_case_per_block() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let suite = temp.path().join("suite");
        let mapping = temp.path().join("mapping.json");
        fs::write(&binary, minimal_pe(&[0xc3])).unwrap();
        emit_suite(&binary, &suite, &SuiteOptions::default()).unwrap();
        let labels = suite_block_labels(&suite).unwrap();
        fs::write(
            &mapping,
            json!({
                "blocks": {
                    labels[0].clone(): {
                        "semantic_point": "hook",
                        "source": "candidate.cpp",
                        "state_adapter": "state",
                        "side_effect_adapter": "effects"
                    }
                }
            })
            .to_string(),
        )
        .unwrap();

        let report =
            validate_candidate_mapping(&suite, &mapping, &CandidateValidationOptions::default())
                .unwrap();
        assert_eq!(report.status, "fail");
        assert_eq!(report.uncharacterized_blocks, labels);
    }

    #[test]
    fn reviewed_waiver_satisfies_uncovered_block_gate() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let suite = temp.path().join("suite");
        let mapping = temp.path().join("mapping.json");
        let waivers = temp.path().join("waivers.json");
        fs::write(&binary, minimal_pe(&[0xc3])).unwrap();
        emit_suite(&binary, &suite, &SuiteOptions::default()).unwrap();
        let labels = suite_block_labels(&suite).unwrap();
        fs::write(&mapping, json!({"blocks": {}}).to_string()).unwrap();
        fs::write(
            &waivers,
            json!({
                "format": "wincr-block-coverage-waivers-v1",
                "waivers": {
                    labels[0].clone(): {
                        "reason": "synthetic test unreachable",
                        "evidence": "unit test fixture has no dynamic trace"
                    }
                }
            })
            .to_string(),
        )
        .unwrap();

        let coverage = coverage_report_for_suite(
            &suite,
            &CoverageOptions {
                waivers: Some(waivers.clone()),
                allow_incomplete_side_effects: false,
            },
        )
        .unwrap();
        assert_eq!(coverage.status, "pass");
        assert_eq!(coverage.waived_blocks, 1);

        let report = validate_candidate_mapping(
            &suite,
            &mapping,
            &CandidateValidationOptions {
                waivers: Some(waivers),
                ..CandidateValidationOptions::default()
            },
        )
        .unwrap();
        assert_eq!(report.status, "pass");
        assert_eq!(report.waived_blocks, 1);
    }

    #[test]
    fn candidate_trace_must_match_original_case() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("minimal.exe");
        let trace = temp.path().join("trace.jsonl");
        let suite = temp.path().join("suite");
        let mapping = temp.path().join("mapping.json");
        let candidate_trace = temp.path().join("candidate.jsonl");
        fs::write(&binary, minimal_pe(&[0x40, 0xc3])).unwrap();
        let effects = json!({
            "capture_status": "complete",
            "memory_writes": [],
            "api_calls": [],
            "external_events": [],
            "limitations": []
        });
        fs::write(
            &trace,
            format!(
                "{{\"kind\":\"block_entry\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"state\":{{\"registers\":{{\"eax\":1}}}}}}\n\
                 {{\"kind\":\"block_exit\",\"test_id\":\"t1\",\"rva\":\"0x1000\",\"successor_rva\":\"0x1001\",\"state\":{{\"registers\":{{\"eax\":2}}}},\"side_effects\":{}}}\n",
                effects
            ),
        )
        .unwrap();
        emit_suite(
            &binary,
            &suite,
            &SuiteOptions {
                traces: vec![trace],
                ..SuiteOptions::default()
            },
        )
        .unwrap();
        let labels = suite_block_labels(&suite).unwrap();
        let cases =
            read_jsonl_values(&suite.join("blocks").join(&labels[0]).join("cases.jsonl")).unwrap();
        let case_id = cases[0]["case_id"].as_str().unwrap();
        fs::write(
            &mapping,
            json!({
                "blocks": {
                    labels[0].clone(): {
                        "semantic_point": "hook",
                        "source": "candidate.cpp",
                        "state_adapter": "state",
                        "side_effect_adapter": "effects"
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        fs::write(
            &candidate_trace,
            json!({
                "kind": "candidate_block_result",
                "case_id": case_id,
                "block_label": labels[0],
                "post_state": {"registers": {"eax": 2}},
                "side_effects": effects,
                "successor_rva": "0x1001"
            })
            .to_string()
                + "\n",
        )
        .unwrap();

        let report = validate_candidate_mapping(
            &suite,
            &mapping,
            &CandidateValidationOptions {
                candidate_trace: Some(candidate_trace),
                ..CandidateValidationOptions::default()
            },
        )
        .unwrap();
        assert_eq!(report.status, "pass");
        assert_eq!(report.candidate_results.as_ref().unwrap().passed_cases, 1);
    }

    fn synthetic_image(code: &[u8]) -> PeImage {
        PeImage {
            path: PathBuf::from("synthetic.exe"),
            object_format: "Pe".to_string(),
            architecture: "I386".to_string(),
            machine: 0x14c,
            bitness: 32,
            is_pe64: false,
            image_base: 0x400000,
            entry_rva: 0x1000,
            sections: vec![PeSection {
                name: ".text".to_string(),
                virtual_address: 0x1000,
                virtual_size: code.len() as u32,
                raw_pointer: 0,
                raw_size: code.len() as u32,
                characteristics: 0x6000_0020,
                executable: true,
            }],
            data: code.to_vec(),
        }
    }

    fn minimal_pe(code: &[u8]) -> Vec<u8> {
        let mut data = vec![0u8; 0x400];
        data[0] = b'M';
        data[1] = b'Z';
        put_u32(&mut data, 0x3c, 0x80);
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        put_u16(&mut data, coff, 0x14c);
        put_u16(&mut data, coff + 2, 1);
        put_u16(&mut data, coff + 16, 0xe0);
        put_u16(&mut data, coff + 18, 0x010f);
        let optional = coff + 20;
        put_u16(&mut data, optional, 0x10b);
        put_u32(&mut data, optional + 16, 0x1000);
        put_u32(&mut data, optional + 28, 0x400000);
        put_u32(&mut data, optional + 32, 0x1000);
        put_u32(&mut data, optional + 36, 0x200);
        let section = optional + 0xe0;
        data[section..section + 5].copy_from_slice(b".text");
        put_u32(&mut data, section + 8, code.len() as u32);
        put_u32(&mut data, section + 12, 0x1000);
        put_u32(&mut data, section + 16, 0x200);
        put_u32(&mut data, section + 20, 0x200);
        put_u32(&mut data, section + 36, 0x6000_0020);
        data[0x200..0x200 + code.len()].copy_from_slice(code);
        data
    }

    fn put_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}
