use std::collections::{BTreeMap, BTreeSet};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};

const DEFAULT_MAX_SUBJECTS: usize = 250_000;
const DEFAULT_MAX_FACTS: usize = 1_000_000;
const DEFAULT_MAX_EQUALITIES: usize = 1_000_000;
const DEFAULT_MAX_NODES: usize = 1_000_000;
const DEFAULT_MAX_VALUES_PER_FACT: usize = 256;
const DEFAULT_MAX_TOTAL_VALUES: usize = 4_000_000;
const DEFAULT_MAX_LINKS_PER_RECORD: usize = 1_024;
const DEFAULT_MAX_TOTAL_LINKS: usize = 8_000_000;
const DEFAULT_MAX_STRING_BYTES: usize = 512;
const DEFAULT_MAX_VALUE_BYTES: usize = 1_048_576;
const DEFAULT_MAX_TOTAL_VALUE_BYTES: usize = 268_435_456;
const DEFAULT_MAX_OUTPUT_FACTS: usize = 1_000_000;
const DEFAULT_MAX_ALTERNATIVES: usize = 16;

const HARD_MAX_SUBJECTS: usize = 1_000_000;
const HARD_MAX_FACTS: usize = 4_000_000;
const HARD_MAX_EQUALITIES: usize = 4_000_000;
const HARD_MAX_NODES: usize = 4_000_000;
const HARD_MAX_VALUES_PER_FACT: usize = 4_096;
const HARD_MAX_TOTAL_VALUES: usize = 16_000_000;
const HARD_MAX_LINKS_PER_RECORD: usize = 16_384;
const HARD_MAX_TOTAL_LINKS: usize = 32_000_000;
const HARD_MAX_STRING_BYTES: usize = 4_096;
const HARD_MAX_VALUE_BYTES: usize = 16_777_216;
const HARD_MAX_TOTAL_VALUE_BYTES: usize = 1_073_741_824;
const HARD_MAX_OUTPUT_FACTS: usize = 4_000_000;
const HARD_MAX_ALTERNATIVES: usize = 4_096;
const MAX_VALUE_DEPTH: usize = 128;

const SUBJECT_KINDS: &[&str] = &[
    "function",
    "import",
    "callback",
    "table_slot",
    "callsite",
    "library_member",
];
const FACT_FIELDS: &[&str] = &[
    "subject_id",
    "field",
    "status",
    "values",
    "evidence_ids",
    "dependency_ids",
];
const EQUALITY_FIELDS: &[&str] = &["left", "right", "evidence_ids"];
const ENDPOINT_FIELDS: &[&str] = &["subject_id", "field"];
const LIMIT_FIELDS: &[(&str, usize, usize)] = &[
    ("max_subjects", DEFAULT_MAX_SUBJECTS, HARD_MAX_SUBJECTS),
    ("max_facts", DEFAULT_MAX_FACTS, HARD_MAX_FACTS),
    (
        "max_equalities",
        DEFAULT_MAX_EQUALITIES,
        HARD_MAX_EQUALITIES,
    ),
    ("max_nodes", DEFAULT_MAX_NODES, HARD_MAX_NODES),
    (
        "max_values_per_fact",
        DEFAULT_MAX_VALUES_PER_FACT,
        HARD_MAX_VALUES_PER_FACT,
    ),
    (
        "max_total_values",
        DEFAULT_MAX_TOTAL_VALUES,
        HARD_MAX_TOTAL_VALUES,
    ),
    (
        "max_links_per_record",
        DEFAULT_MAX_LINKS_PER_RECORD,
        HARD_MAX_LINKS_PER_RECORD,
    ),
    (
        "max_total_links",
        DEFAULT_MAX_TOTAL_LINKS,
        HARD_MAX_TOTAL_LINKS,
    ),
    (
        "max_string_bytes",
        DEFAULT_MAX_STRING_BYTES,
        HARD_MAX_STRING_BYTES,
    ),
    (
        "max_value_bytes",
        DEFAULT_MAX_VALUE_BYTES,
        HARD_MAX_VALUE_BYTES,
    ),
    (
        "max_total_value_bytes",
        DEFAULT_MAX_TOTAL_VALUE_BYTES,
        HARD_MAX_TOTAL_VALUE_BYTES,
    ),
    (
        "max_output_facts",
        DEFAULT_MAX_OUTPUT_FACTS,
        HARD_MAX_OUTPUT_FACTS,
    ),
    (
        "max_alternatives",
        DEFAULT_MAX_ALTERNATIVES,
        HARD_MAX_ALTERNATIVES,
    ),
];

type Node = (String, String);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FactStatus {
    Unknown,
    Exact,
    Alternatives,
    Contradiction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Fact {
    node: Node,
    status: FactStatus,
    values: Vec<Vec<u8>>,
    evidence_ids: Vec<String>,
    dependency_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Equality {
    left: Node,
    right: Node,
    evidence_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SolverLimits {
    max_subjects: usize,
    max_facts: usize,
    max_equalities: usize,
    max_nodes: usize,
    max_values_per_fact: usize,
    max_total_values: usize,
    max_links_per_record: usize,
    max_total_links: usize,
    max_string_bytes: usize,
    max_value_bytes: usize,
    max_total_value_bytes: usize,
    max_output_facts: usize,
    max_alternatives: usize,
}

impl Default for SolverLimits {
    fn default() -> Self {
        Self {
            max_subjects: DEFAULT_MAX_SUBJECTS,
            max_facts: DEFAULT_MAX_FACTS,
            max_equalities: DEFAULT_MAX_EQUALITIES,
            max_nodes: DEFAULT_MAX_NODES,
            max_values_per_fact: DEFAULT_MAX_VALUES_PER_FACT,
            max_total_values: DEFAULT_MAX_TOTAL_VALUES,
            max_links_per_record: DEFAULT_MAX_LINKS_PER_RECORD,
            max_total_links: DEFAULT_MAX_TOTAL_LINKS,
            max_string_bytes: DEFAULT_MAX_STRING_BYTES,
            max_value_bytes: DEFAULT_MAX_VALUE_BYTES,
            max_total_value_bytes: DEFAULT_MAX_TOTAL_VALUE_BYTES,
            max_output_facts: DEFAULT_MAX_OUTPUT_FACTS,
            max_alternatives: DEFAULT_MAX_ALTERNATIVES,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedInput {
    facts: Vec<Fact>,
    equalities: Vec<Equality>,
    nodes: BTreeSet<Node>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedFact {
    node: Node,
    status: FactStatus,
    values: Vec<Vec<u8>>,
    evidence_ids: Vec<String>,
    dependency_ids: Vec<String>,
}

#[derive(Clone, Debug)]
struct Counters {
    total_values: usize,
    total_links: usize,
    total_value_bytes: usize,
}

impl Counters {
    fn new() -> Self {
        Self {
            total_values: 0,
            total_links: 0,
            total_value_bytes: 0,
        }
    }

    fn add(
        &mut self,
        current: &mut usize,
        amount: usize,
        maximum: usize,
        label: &str,
    ) -> PyResult<()> {
        *current = current
            .checked_add(amount)
            .ok_or_else(|| invalid(format!("oversized_input: {label} count overflow")))?;
        if *current > maximum {
            return Err(invalid(format!("oversized_input: input exceeds {label}")));
        }
        Ok(())
    }

    fn add_values(&mut self, amount: usize, limits: SolverLimits) -> PyResult<()> {
        let mut current = self.total_values;
        self.add(
            &mut current,
            amount,
            limits.max_total_values,
            "max_total_values",
        )?;
        self.total_values = current;
        Ok(())
    }

    fn add_links(&mut self, amount: usize, limits: SolverLimits) -> PyResult<()> {
        let mut current = self.total_links;
        self.add(
            &mut current,
            amount,
            limits.max_total_links,
            "max_total_links",
        )?;
        self.total_links = current;
        Ok(())
    }

    fn add_value_bytes(&mut self, amount: usize, limits: SolverLimits) -> PyResult<()> {
        let mut current = self.total_value_bytes;
        self.add(
            &mut current,
            amount,
            limits.max_total_value_bytes,
            "max_total_value_bytes",
        )?;
        self.total_value_bytes = current;
        Ok(())
    }
}

struct UnionFind {
    parent: Vec<usize>,
}

impl UnionFind {
    fn new(size: usize) -> Self {
        Self {
            parent: (0..size).collect(),
        }
    }

    fn find(&mut self, value: usize) -> usize {
        let parent = self.parent[value];
        if parent != value {
            self.parent[value] = self.find(parent);
        }
        self.parent[value]
    }

    fn union(&mut self, left: usize, right: usize) {
        let left_root = self.find(left);
        let right_root = self.find(right);
        if left_root == right_root {
            return;
        }
        let (root, child) = if left_root < right_root {
            (left_root, right_root)
        } else {
            (right_root, left_root)
        };
        self.parent[child] = root;
    }
}

fn invalid(message: impl Into<String>) -> PyErr {
    PyValueError::new_err(message.into())
}

fn required_field<'py>(
    record: &Bound<'py, PyDict>,
    field: &str,
    label: &str,
) -> PyResult<Bound<'py, PyAny>> {
    record
        .get_item(field)?
        .ok_or_else(|| invalid(format!("malformed_input: {label} lacks {field}")))
}

fn validate_keys(record: &Bound<'_, PyDict>, fields: &[&str], label: &str) -> PyResult<()> {
    for (key, _) in record.iter() {
        let key = key
            .cast::<PyString>()
            .map_err(|_| invalid(format!("malformed_input: {label} has a non-string key")))?
            .to_str()?;
        if !fields.contains(&key) {
            return Err(invalid(format!(
                "malformed_input: {label} has unknown field {key}"
            )));
        }
    }
    for field in fields {
        if !record.contains(*field)? {
            return Err(invalid(format!("malformed_input: {label} lacks {field}")));
        }
    }
    Ok(())
}

fn list_items<'py>(value: &Bound<'py, PyAny>, label: &str) -> PyResult<Vec<Bound<'py, PyAny>>> {
    let values = value
        .cast::<PyList>()
        .map_err(|_| invalid(format!("malformed_input: {label} must be an array")))?;
    Ok(values.iter().collect())
}

fn bounded_string(value: &Bound<'_, PyAny>, label: &str, maximum_bytes: usize) -> PyResult<String> {
    let value = value
        .cast::<PyString>()
        .map_err(|_| invalid(format!("malformed_input: {label} must be a string")))?
        .to_str()?
        .to_owned();
    if value.is_empty() {
        return Err(invalid(format!(
            "malformed_input: {label} must not be empty"
        )));
    }
    if value.len() > maximum_bytes {
        return Err(invalid(format!(
            "oversized_input: {label} exceeds {maximum_bytes} bytes"
        )));
    }
    Ok(value)
}

fn canonical_identifier(
    value: &Bound<'_, PyAny>,
    label: &str,
    maximum_bytes: usize,
) -> PyResult<String> {
    let value = bounded_string(value, label, maximum_bytes)?;
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(invalid(format!(
            "malformed_input: {label} is not a canonical identifier"
        )));
    };
    let valid = |byte: u8| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'+' | b'-')
    };
    if !first.is_ascii_alphanumeric() || !bytes.all(valid) {
        return Err(invalid(format!(
            "malformed_input: {label} is not a canonical identifier"
        )));
    }
    Ok(value)
}

fn canonical_identifiers(
    value: &Bound<'_, PyAny>,
    label: &str,
    limits: SolverLimits,
    counters: &mut Counters,
) -> PyResult<Vec<String>> {
    let values = list_items(value, label)?;
    if values.len() > limits.max_links_per_record {
        return Err(invalid(format!(
            "oversized_input: {label} exceeds max_links_per_record"
        )));
    }
    counters.add_links(values.len(), limits)?;
    let mut result = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        result.push(canonical_identifier(
            value,
            &format!("{label}[{index}]"),
            limits.max_string_bytes,
        )?);
    }
    if result.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid(format!(
            "malformed_input: {label} must be sorted and unique"
        )));
    }
    Ok(result)
}

fn limit_value(limits: &Bound<'_, PyDict>, field: &str, default: usize) -> PyResult<usize> {
    let Some(value) = limits.get_item(field)? else {
        return Ok(default);
    };
    if value.is_instance_of::<PyBool>() || !value.is_instance_of::<PyInt>() {
        return Err(invalid(format!(
            "malformed_input: limits.{field} must be an integer"
        )));
    }
    value.extract::<usize>().map_err(|_| {
        invalid(format!(
            "malformed_input: limits.{field} must be a positive bounded integer"
        ))
    })
}

fn parse_limits(value: Option<&Bound<'_, PyAny>>) -> PyResult<SolverLimits> {
    let Some(value) = value else {
        return Ok(SolverLimits::default());
    };
    let value = value
        .cast::<PyDict>()
        .map_err(|_| invalid("malformed_input: limits must be an object"))?;
    for (key, _) in value.iter() {
        let key = key
            .cast::<PyString>()
            .map_err(|_| invalid("malformed_input: limits has a non-string key"))?
            .to_str()?;
        if !LIMIT_FIELDS.iter().any(|(field, _, _)| *field == key) {
            return Err(invalid(format!(
                "malformed_input: limits has unknown field {key}"
            )));
        }
    }
    let mut parsed = BTreeMap::new();
    for (field, default, hard_maximum) in LIMIT_FIELDS {
        let configured = limit_value(value, field, *default)?;
        let minimum = if *field == "max_alternatives" { 2 } else { 1 };
        if configured < minimum || configured > *hard_maximum {
            return Err(invalid(format!(
                "oversized_input: limits.{field} must be between {minimum} and {hard_maximum}"
            )));
        }
        parsed.insert(*field, configured);
    }
    Ok(SolverLimits {
        max_subjects: parsed["max_subjects"],
        max_facts: parsed["max_facts"],
        max_equalities: parsed["max_equalities"],
        max_nodes: parsed["max_nodes"],
        max_values_per_fact: parsed["max_values_per_fact"],
        max_total_values: parsed["max_total_values"],
        max_links_per_record: parsed["max_links_per_record"],
        max_total_links: parsed["max_total_links"],
        max_string_bytes: parsed["max_string_bytes"],
        max_value_bytes: parsed["max_value_bytes"],
        max_total_value_bytes: parsed["max_total_value_bytes"],
        max_output_facts: parsed["max_output_facts"],
        max_alternatives: parsed["max_alternatives"],
    })
}

fn parse_subjects(value: &Bound<'_, PyAny>, limits: SolverLimits) -> PyResult<BTreeSet<String>> {
    let subjects = value
        .cast::<PyDict>()
        .map_err(|_| invalid("malformed_input: subjects must be an object"))?;
    if subjects.len() > limits.max_subjects {
        return Err(invalid("oversized_input: subjects exceeds max_subjects"));
    }
    let mut result = BTreeSet::new();
    for (subject_id, subject_kind) in subjects.iter() {
        let subject_id =
            canonical_identifier(&subject_id, "subjects key", limits.max_string_bytes)?;
        let subject_kind = bounded_string(
            &subject_kind,
            &format!("subjects[{subject_id}]"),
            limits.max_string_bytes,
        )?;
        if !SUBJECT_KINDS.contains(&subject_kind.as_str()) {
            return Err(invalid(format!(
                "malformed_input: subjects[{subject_id}] has unsupported subject kind {subject_kind}"
            )));
        }
        result.insert(subject_id);
    }
    Ok(result)
}

fn parse_status(
    value: &Bound<'_, PyAny>,
    label: &str,
    limits: SolverLimits,
) -> PyResult<FactStatus> {
    match bounded_string(value, label, limits.max_string_bytes)?.as_str() {
        "unknown" => Ok(FactStatus::Unknown),
        "exact" => Ok(FactStatus::Exact),
        "alternatives" => Ok(FactStatus::Alternatives),
        "contradiction" => Ok(FactStatus::Contradiction),
        status => Err(invalid(format!(
            "malformed_input: {label} has unsupported fact status {status}"
        ))),
    }
}

fn parse_values(
    value: &Bound<'_, PyAny>,
    label: &str,
    limits: SolverLimits,
    counters: &mut Counters,
) -> PyResult<Vec<Vec<u8>>> {
    let values = list_items(value, label)?;
    if values.len() > limits.max_values_per_fact {
        return Err(invalid(format!(
            "oversized_input: {label} exceeds max_values_per_fact"
        )));
    }
    counters.add_values(values.len(), limits)?;
    let mut result = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let contains_float =
            validate_canonical_value(value, &format!("{label}[{index}]"), limits.max_value_bytes)?;
        let encoded = if contains_float {
            python_canonical_bytes(value)
        } else {
            super::canonical_bytes(value)
        }
        .map_err(|error| {
            invalid(format!(
                "malformed_input: {label}[{index}] is not canonical JSON: {error}"
            ))
        })?;
        if encoded.len() > limits.max_value_bytes {
            return Err(invalid(format!(
                "oversized_input: {label}[{index}] exceeds max_value_bytes"
            )));
        }
        counters.add_value_bytes(encoded.len(), limits)?;
        result.push(encoded);
    }
    if result.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid(format!(
            "malformed_input: {label} must be canonical and unique"
        )));
    }
    Ok(result)
}

fn validate_canonical_value(
    value: &Bound<'_, PyAny>,
    label: &str,
    maximum_bytes: usize,
) -> PyResult<bool> {
    let mut stack = vec![(value.clone(), 0_usize)];
    let mut nodes = 0_usize;
    let mut contains_float = false;
    while let Some((value, depth)) = stack.pop() {
        if depth > MAX_VALUE_DEPTH {
            return Err(invalid(format!(
                "oversized_input: {label} exceeds canonical JSON depth {MAX_VALUE_DEPTH}"
            )));
        }
        nodes = nodes
            .checked_add(1)
            .ok_or_else(|| invalid(format!("oversized_input: {label} node count overflow")))?;
        if nodes > maximum_bytes {
            return Err(invalid(format!(
                "oversized_input: {label} exceeds max_value_bytes"
            )));
        }
        if value.is_none() || value.is_instance_of::<PyBool>() {
            continue;
        }
        if value.is_instance_of::<PyFloat>() {
            contains_float = true;
            continue;
        }
        if let Ok(value) = value.cast::<PyString>() {
            if value.to_str()?.len() > maximum_bytes {
                return Err(invalid(format!(
                    "oversized_input: {label} contains a string exceeding max_value_bytes"
                )));
            }
            continue;
        }
        if value.is_instance_of::<PyInt>() {
            if value.str()?.to_str()?.len() > maximum_bytes {
                return Err(invalid(format!(
                    "oversized_input: {label} contains an integer exceeding max_value_bytes"
                )));
            }
            continue;
        }
        if let Ok(value) = value.cast::<PyDict>() {
            for (key, item) in value.iter() {
                let key = key.cast::<PyString>().map_err(|_| {
                    invalid(format!(
                        "malformed_input: {label} has a non-string object key"
                    ))
                })?;
                if key.to_str()?.len() > maximum_bytes {
                    return Err(invalid(format!(
                        "oversized_input: {label} contains an object key exceeding max_value_bytes"
                    )));
                }
                stack.push((item, depth + 1));
            }
            continue;
        }
        if let Ok(value) = value.cast::<PyList>() {
            stack.extend(value.iter().map(|item| (item, depth + 1)));
            continue;
        }
        if let Ok(value) = value.cast::<PyTuple>() {
            stack.extend(value.iter().map(|item| (item, depth + 1)));
            continue;
        }
        return Err(invalid(format!(
            "malformed_input: {label} contains unsupported canonical JSON type {}",
            value.get_type().name()?
        )));
    }
    Ok(contains_float)
}

fn python_canonical_bytes(value: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let py = value.py();
    let json = PyModule::import(py, "json")?;
    let keyword_arguments = PyDict::new(py);
    keyword_arguments.set_item("sort_keys", true)?;
    keyword_arguments.set_item("separators", (",", ":"))?;
    keyword_arguments.set_item("ensure_ascii", true)?;
    keyword_arguments.set_item("allow_nan", false)?;
    let encoded = json
        .call_method("dumps", (value,), Some(&keyword_arguments))?
        .cast_into::<PyString>()?;
    Ok(encoded.to_str()?.as_bytes().to_vec())
}

fn validate_value_count(status: FactStatus, count: usize, label: &str) -> PyResult<()> {
    let valid = match status {
        FactStatus::Unknown | FactStatus::Contradiction => count == 0,
        FactStatus::Exact => count == 1,
        FactStatus::Alternatives => count >= 2,
    };
    if !valid {
        return Err(invalid(format!(
            "malformed_input: {label} has an invalid value count for its status"
        )));
    }
    Ok(())
}

fn parse_fact(
    value: &Bound<'_, PyAny>,
    label: &str,
    subjects: &BTreeSet<String>,
    limits: SolverLimits,
    counters: &mut Counters,
) -> PyResult<Fact> {
    let record = value
        .cast::<PyDict>()
        .map_err(|_| invalid(format!("malformed_input: {label} must be an object")))?;
    validate_keys(record, FACT_FIELDS, label)?;
    let subject_id = canonical_identifier(
        &required_field(record, "subject_id", label)?,
        &format!("{label}.subject_id"),
        limits.max_string_bytes,
    )?;
    if !subjects.contains(&subject_id) {
        return Err(invalid(format!(
            "malformed_input: {label} references unknown subject {subject_id}"
        )));
    }
    let field = canonical_identifier(
        &required_field(record, "field", label)?,
        &format!("{label}.field"),
        limits.max_string_bytes,
    )?;
    let status = parse_status(
        &required_field(record, "status", label)?,
        &format!("{label}.status"),
        limits,
    )?;
    let values = parse_values(
        &required_field(record, "values", label)?,
        &format!("{label}.values"),
        limits,
        counters,
    )?;
    validate_value_count(status, values.len(), label)?;
    let evidence_ids = canonical_identifiers(
        &required_field(record, "evidence_ids", label)?,
        &format!("{label}.evidence_ids"),
        limits,
        counters,
    )?;
    let dependency_ids = canonical_identifiers(
        &required_field(record, "dependency_ids", label)?,
        &format!("{label}.dependency_ids"),
        limits,
        counters,
    )?;
    Ok(Fact {
        node: (subject_id, field),
        status,
        values,
        evidence_ids,
        dependency_ids,
    })
}

fn parse_endpoint(
    value: &Bound<'_, PyAny>,
    label: &str,
    subjects: &BTreeSet<String>,
    limits: SolverLimits,
) -> PyResult<Node> {
    let record = value
        .cast::<PyDict>()
        .map_err(|_| invalid(format!("malformed_input: {label} must be an object")))?;
    validate_keys(record, ENDPOINT_FIELDS, label)?;
    let subject_id = canonical_identifier(
        &required_field(record, "subject_id", label)?,
        &format!("{label}.subject_id"),
        limits.max_string_bytes,
    )?;
    if !subjects.contains(&subject_id) {
        return Err(invalid(format!(
            "malformed_input: {label} references unknown subject {subject_id}"
        )));
    }
    let field = canonical_identifier(
        &required_field(record, "field", label)?,
        &format!("{label}.field"),
        limits.max_string_bytes,
    )?;
    Ok((subject_id, field))
}

fn parse_equality(
    value: &Bound<'_, PyAny>,
    label: &str,
    subjects: &BTreeSet<String>,
    limits: SolverLimits,
    counters: &mut Counters,
) -> PyResult<Equality> {
    let record = value
        .cast::<PyDict>()
        .map_err(|_| invalid(format!("malformed_input: {label} must be an object")))?;
    validate_keys(record, EQUALITY_FIELDS, label)?;
    Ok(Equality {
        left: parse_endpoint(
            &required_field(record, "left", label)?,
            &format!("{label}.left"),
            subjects,
            limits,
        )?,
        right: parse_endpoint(
            &required_field(record, "right", label)?,
            &format!("{label}.right"),
            subjects,
            limits,
        )?,
        evidence_ids: canonical_identifiers(
            &required_field(record, "evidence_ids", label)?,
            &format!("{label}.evidence_ids"),
            limits,
            counters,
        )?,
    })
}

fn parse_input(
    subjects: &Bound<'_, PyAny>,
    facts: &Bound<'_, PyAny>,
    equalities: &Bound<'_, PyAny>,
    limits: SolverLimits,
) -> PyResult<ParsedInput> {
    let subjects = parse_subjects(subjects, limits)?;
    let fact_values = list_items(facts, "facts")?;
    if fact_values.len() > limits.max_facts {
        return Err(invalid("oversized_input: facts exceeds max_facts"));
    }
    let equality_values = list_items(equalities, "equalities")?;
    if equality_values.len() > limits.max_equalities {
        return Err(invalid(
            "oversized_input: equalities exceeds max_equalities",
        ));
    }

    let mut counters = Counters::new();
    let mut nodes = BTreeSet::new();
    let mut parsed_facts = Vec::with_capacity(fact_values.len());
    for (index, value) in fact_values.iter().enumerate() {
        let fact = parse_fact(
            value,
            &format!("facts[{index}]"),
            &subjects,
            limits,
            &mut counters,
        )?;
        nodes.insert(fact.node.clone());
        parsed_facts.push(fact);
    }
    let mut parsed_equalities = Vec::with_capacity(equality_values.len());
    for (index, value) in equality_values.iter().enumerate() {
        let equality = parse_equality(
            value,
            &format!("equalities[{index}]"),
            &subjects,
            limits,
            &mut counters,
        )?;
        nodes.insert(equality.left.clone());
        nodes.insert(equality.right.clone());
        parsed_equalities.push(equality);
    }
    if nodes.len() > limits.max_nodes {
        return Err(invalid("oversized_input: graph exceeds max_nodes"));
    }
    if nodes.len() > limits.max_output_facts {
        return Err(invalid("oversized_result: graph exceeds max_output_facts"));
    }
    parsed_equalities.sort_unstable();
    Ok(ParsedInput {
        facts: parsed_facts,
        equalities: parsed_equalities,
        nodes,
    })
}

fn status_name(status: FactStatus) -> &'static str {
    match status {
        FactStatus::Unknown => "unknown",
        FactStatus::Exact => "exact",
        FactStatus::Alternatives => "alternatives",
        FactStatus::Contradiction => "contradiction",
    }
}

fn resolve(input: ParsedInput, limits: SolverLimits) -> Vec<ResolvedFact> {
    let nodes = input.nodes.into_iter().collect::<Vec<_>>();
    let node_indices = nodes
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, node)| (node, index))
        .collect::<BTreeMap<_, _>>();
    let mut union = UnionFind::new(nodes.len());
    for equality in &input.equalities {
        union.union(node_indices[&equality.left], node_indices[&equality.right]);
    }

    let mut facts_by_root: BTreeMap<usize, Vec<Fact>> = BTreeMap::new();
    for fact in input.facts {
        let root = union.find(node_indices[&fact.node]);
        facts_by_root.entry(root).or_default().push(fact);
    }
    let mut evidence_by_root: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
    for equality in input.equalities {
        let root = union.find(node_indices[&equality.left]);
        evidence_by_root
            .entry(root)
            .or_default()
            .extend(equality.evidence_ids);
    }

    let mut component_result: BTreeMap<usize, ResolvedFact> = BTreeMap::new();
    for (index, node) in nodes.iter().enumerate() {
        let root = union.find(index);
        if component_result.contains_key(&root) {
            continue;
        }
        let mut possible: Option<BTreeSet<Vec<u8>>> = None;
        let mut contradiction = false;
        let mut evidence_ids = evidence_by_root.remove(&root).unwrap_or_default();
        let mut dependency_ids = BTreeSet::new();
        for fact in facts_by_root.remove(&root).unwrap_or_default() {
            evidence_ids.extend(fact.evidence_ids);
            dependency_ids.extend(fact.dependency_ids);
            match fact.status {
                FactStatus::Unknown => {}
                FactStatus::Contradiction => contradiction = true,
                FactStatus::Exact | FactStatus::Alternatives => {
                    let values = fact.values.into_iter().collect::<BTreeSet<_>>();
                    possible = Some(match possible.take() {
                        None => values,
                        Some(current) => current.intersection(&values).cloned().collect(),
                    });
                    if possible.as_ref().is_some_and(BTreeSet::is_empty) {
                        contradiction = true;
                    }
                }
            }
        }
        let (status, values) = if contradiction {
            (FactStatus::Contradiction, Vec::new())
        } else if let Some(values) = possible {
            if values.len() > limits.max_alternatives {
                (FactStatus::Unknown, Vec::new())
            } else if values.len() == 1 {
                (FactStatus::Exact, values.into_iter().collect())
            } else {
                (FactStatus::Alternatives, values.into_iter().collect())
            }
        } else {
            (FactStatus::Unknown, Vec::new())
        };
        component_result.insert(
            root,
            ResolvedFact {
                node: node.clone(),
                status,
                values,
                evidence_ids: evidence_ids.into_iter().collect(),
                dependency_ids: dependency_ids.into_iter().collect(),
            },
        );
    }

    nodes
        .into_iter()
        .enumerate()
        .map(|(index, node)| {
            let root = union.find(index);
            let component = &component_result[&root];
            ResolvedFact {
                node,
                status: component.status,
                values: component.values.clone(),
                evidence_ids: component.evidence_ids.clone(),
                dependency_ids: component.dependency_ids.clone(),
            }
        })
        .collect()
}

fn results_to_python<'py>(
    py: Python<'py>,
    resolved: &[ResolvedFact],
) -> PyResult<Bound<'py, PyList>> {
    let json = PyModule::import(py, "json")?;
    let result = PyList::empty(py);
    for fact in resolved {
        let row = PyDict::new(py);
        row.set_item("subject_id", &fact.node.0)?;
        row.set_item("field", &fact.node.1)?;
        row.set_item("status", status_name(fact.status))?;
        let values = PyList::empty(py);
        for value in &fact.values {
            values.append(json.call_method1("loads", (PyBytes::new(py, value),))?)?;
        }
        row.set_item("values", values)?;
        row.set_item("evidence_ids", &fact.evidence_ids)?;
        row.set_item("dependency_ids", &fact.dependency_ids)?;
        result.append(row)?;
    }
    Ok(result)
}

#[pyfunction(signature = (subjects, facts, equalities, limits=None))]
pub(crate) fn resolve_abi_equalities<'py>(
    py: Python<'py>,
    subjects: &Bound<'py, PyAny>,
    facts: &Bound<'py, PyAny>,
    equalities: &Bound<'py, PyAny>,
    limits: Option<&Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyList>> {
    let limits = parse_limits(limits)?;
    let input = parse_input(subjects, facts, equalities, limits)?;
    let resolved = py.detach(move || resolve(input, limits));
    results_to_python(py, &resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(subject: &str, field: &str) -> Node {
        (subject.to_owned(), field.to_owned())
    }

    fn exact(subject: &str, field: &str, value: &[u8]) -> Fact {
        Fact {
            node: node(subject, field),
            status: FactStatus::Exact,
            values: vec![value.to_vec()],
            evidence_ids: vec![format!("evidence:{subject}")],
            dependency_ids: vec![format!("dependency:{subject}")],
        }
    }

    #[test]
    fn equality_components_intersect_and_merge_provenance() {
        let nodes = [node("a", "cc"), node("b", "cc")].into_iter().collect();
        let input = ParsedInput {
            facts: vec![exact("a", "cc", b"\"cdecl\"")],
            equalities: vec![Equality {
                left: node("a", "cc"),
                right: node("b", "cc"),
                evidence_ids: vec!["equality:ab".to_owned()],
            }],
            nodes,
        };
        let result = resolve(input, SolverLimits::default());
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|fact| fact.status == FactStatus::Exact));
        assert_eq!(result[1].values, vec![b"\"cdecl\"".to_vec()]);
        assert_eq!(
            result[1].evidence_ids,
            vec!["equality:ab".to_owned(), "evidence:a".to_owned()]
        );
        assert_eq!(result[1].dependency_ids, vec!["dependency:a".to_owned()]);
    }

    #[test]
    fn empty_intersection_is_a_contradiction() {
        let nodes = [node("a", "cc"), node("b", "cc")].into_iter().collect();
        let input = ParsedInput {
            facts: vec![
                exact("a", "cc", b"\"cdecl\""),
                exact("b", "cc", b"\"stdcall\""),
            ],
            equalities: vec![Equality {
                left: node("a", "cc"),
                right: node("b", "cc"),
                evidence_ids: Vec::new(),
            }],
            nodes,
        };
        let result = resolve(input, SolverLimits::default());
        assert!(
            result
                .iter()
                .all(|fact| fact.status == FactStatus::Contradiction)
        );
        assert!(result.iter().all(|fact| fact.values.is_empty()));
    }

    #[test]
    fn alternative_budget_fails_closed_to_unknown() {
        let only_node = node("a", "cc");
        let input = ParsedInput {
            facts: vec![Fact {
                node: only_node.clone(),
                status: FactStatus::Alternatives,
                values: vec![b"1".to_vec(), b"2".to_vec(), b"3".to_vec()],
                evidence_ids: Vec::new(),
                dependency_ids: Vec::new(),
            }],
            equalities: Vec::new(),
            nodes: [only_node].into_iter().collect(),
        };
        let limits = SolverLimits {
            max_alternatives: 2,
            ..SolverLimits::default()
        };
        let result = resolve(input, limits);
        assert_eq!(result[0].status, FactStatus::Unknown);
        assert!(result[0].values.is_empty());
    }
}
