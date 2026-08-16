use std::collections::{BTreeSet, HashMap};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool, PyDict, PyInt, PyList, PyString, PyTuple};

const DEFAULT_MAX_CATALOG_RECORDS: usize = 1_000_000;
const DEFAULT_MAX_TARGET_RECORDS: usize = 250_000;
const DEFAULT_MAX_FEATURES_PER_RECORD: usize = 256;
const DEFAULT_MAX_TOTAL_FEATURES: usize = 8_000_000;
const DEFAULT_MAX_SPARSE_HITS: usize = 2_000_000;
const DEFAULT_MAX_OUTPUT_RECORDS: usize = 250_000;
const DEFAULT_MAX_STRING_BYTES: usize = 512;

const HARD_MAX_CATALOG_RECORDS: usize = 2_000_000;
const HARD_MAX_TARGET_RECORDS: usize = 1_000_000;
const HARD_MAX_FEATURES_PER_RECORD: usize = 1_024;
const HARD_MAX_TOTAL_FEATURES: usize = 16_000_000;
const HARD_MAX_SPARSE_HITS: usize = 8_000_000;
const HARD_MAX_OUTPUT_RECORDS: usize = 2_000_000;
const HARD_MAX_STRING_BYTES: usize = 4_096;

const RECORD_FIELDS: &[&str] = &[
    "record_id",
    "abi_key",
    "fixed_anchor_hashes",
    "normalized_hashes",
    "structural_feature_hashes",
];

const LIMIT_FIELDS: &[(&str, usize, usize)] = &[
    (
        "max_catalog_records",
        DEFAULT_MAX_CATALOG_RECORDS,
        HARD_MAX_CATALOG_RECORDS,
    ),
    (
        "max_target_records",
        DEFAULT_MAX_TARGET_RECORDS,
        HARD_MAX_TARGET_RECORDS,
    ),
    (
        "max_features_per_record",
        DEFAULT_MAX_FEATURES_PER_RECORD,
        HARD_MAX_FEATURES_PER_RECORD,
    ),
    (
        "max_total_features",
        DEFAULT_MAX_TOTAL_FEATURES,
        HARD_MAX_TOTAL_FEATURES,
    ),
    (
        "max_sparse_hits",
        DEFAULT_MAX_SPARSE_HITS,
        HARD_MAX_SPARSE_HITS,
    ),
    (
        "max_output_records",
        DEFAULT_MAX_OUTPUT_RECORDS,
        HARD_MAX_OUTPUT_RECORDS,
    ),
    (
        "max_string_bytes",
        DEFAULT_MAX_STRING_BYTES,
        HARD_MAX_STRING_BYTES,
    ),
];

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum FeatureKind {
    FixedAnchor,
    Normalized,
    Structural,
}

impl FeatureKind {
    fn output_name(self) -> &'static str {
        match self {
            Self::FixedAnchor => "fixed_anchor_hash",
            Self::Normalized => "normalized_hash",
            Self::Structural => "structural_feature_hash",
        }
    }

    fn witness_prefix(self) -> &'static str {
        match self {
            Self::FixedAnchor => "fixed-anchor",
            Self::Normalized => "normalized",
            Self::Structural => "structural",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SignatureRecord {
    record_id: String,
    abi_key: String,
    fixed_anchor_hashes: Vec<String>,
    normalized_hashes: Vec<String>,
    structural_feature_hashes: Vec<String>,
}

impl SignatureRecord {
    fn feature_count(&self) -> usize {
        self.fixed_anchor_hashes.len()
            + self.normalized_hashes.len()
            + self.structural_feature_hashes.len()
    }

    fn features(&self) -> impl Iterator<Item = (FeatureKind, &str)> {
        self.fixed_anchor_hashes
            .iter()
            .map(|value| (FeatureKind::FixedAnchor, value.as_str()))
            .chain(
                self.normalized_hashes
                    .iter()
                    .map(|value| (FeatureKind::Normalized, value.as_str())),
            )
            .chain(
                self.structural_feature_hashes
                    .iter()
                    .map(|value| (FeatureKind::Structural, value.as_str())),
            )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetrievalLimits {
    max_catalog_records: usize,
    max_target_records: usize,
    max_features_per_record: usize,
    max_total_features: usize,
    max_sparse_hits: usize,
    max_output_records: usize,
    max_string_bytes: usize,
}

impl Default for RetrievalLimits {
    fn default() -> Self {
        Self {
            max_catalog_records: DEFAULT_MAX_CATALOG_RECORDS,
            max_target_records: DEFAULT_MAX_TARGET_RECORDS,
            max_features_per_record: DEFAULT_MAX_FEATURES_PER_RECORD,
            max_total_features: DEFAULT_MAX_TOTAL_FEATURES,
            max_sparse_hits: DEFAULT_MAX_SPARSE_HITS,
            max_output_records: DEFAULT_MAX_OUTPUT_RECORDS,
            max_string_bytes: DEFAULT_MAX_STRING_BYTES,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FeatureWitness {
    kind: FeatureKind,
    feature_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CandidateWitness {
    target_record_id: String,
    catalog_record_id: String,
    abi_key: String,
    witnesses: Vec<FeatureWitness>,
}

fn invalid(message: impl Into<String>) -> PyErr {
    PyValueError::new_err(message.into())
}

fn sequence_items<'py>(value: &Bound<'py, PyAny>, label: &str) -> PyResult<Vec<Bound<'py, PyAny>>> {
    if let Ok(values) = value.cast::<PyList>() {
        return Ok(values.iter().collect());
    }
    if let Ok(values) = value.cast::<PyTuple>() {
        return Ok(values.iter().collect());
    }
    Err(invalid(format!(
        "malformed_input: {label} must be an array"
    )))
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
    if value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "malformed_input: {label} contains a control character"
        )));
    }
    Ok(value)
}

fn hash_string(value: &Bound<'_, PyAny>, label: &str) -> PyResult<String> {
    let value = value
        .cast::<PyString>()
        .map_err(|_| invalid(format!("malformed_input: {label} must be a string")))?
        .to_str()?
        .to_owned();
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!(
            "malformed_input: {label} must be a lowercase SHA-256"
        )));
    }
    Ok(value)
}

fn parse_feature_hashes(
    value: &Bound<'_, PyAny>,
    label: &str,
    limits: RetrievalLimits,
) -> PyResult<Vec<String>> {
    let values = sequence_items(value, label)?;
    if values.len() > limits.max_features_per_record {
        return Err(invalid(format!(
            "oversized_input: {label} exceeds max_features_per_record"
        )));
    }
    let mut result = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        result.push(hash_string(value, &format!("{label}[{index}]"))?);
    }
    result.sort_unstable();
    result.dedup();
    Ok(result)
}

fn validate_record_keys(record: &Bound<'_, PyDict>, label: &str) -> PyResult<()> {
    for (key, _) in record.iter() {
        let key = key
            .cast::<PyString>()
            .map_err(|_| invalid(format!("malformed_input: {label} has a non-string key")))?
            .to_str()?;
        if !RECORD_FIELDS.contains(&key) {
            return Err(invalid(format!(
                "malformed_input: {label} has unknown field {key}"
            )));
        }
    }
    Ok(())
}

fn parse_record(
    value: &Bound<'_, PyAny>,
    label: &str,
    limits: RetrievalLimits,
) -> PyResult<SignatureRecord> {
    let record = value
        .cast::<PyDict>()
        .map_err(|_| invalid(format!("malformed_input: {label} must be an object")))?;
    validate_record_keys(record, label)?;
    let result = SignatureRecord {
        record_id: bounded_string(
            &required_field(record, "record_id", label)?,
            &format!("{label}.record_id"),
            limits.max_string_bytes,
        )?,
        abi_key: bounded_string(
            &required_field(record, "abi_key", label)?,
            &format!("{label}.abi_key"),
            limits.max_string_bytes,
        )?,
        fixed_anchor_hashes: parse_feature_hashes(
            &required_field(record, "fixed_anchor_hashes", label)?,
            &format!("{label}.fixed_anchor_hashes"),
            limits,
        )?,
        normalized_hashes: parse_feature_hashes(
            &required_field(record, "normalized_hashes", label)?,
            &format!("{label}.normalized_hashes"),
            limits,
        )?,
        structural_feature_hashes: parse_feature_hashes(
            &required_field(record, "structural_feature_hashes", label)?,
            &format!("{label}.structural_feature_hashes"),
            limits,
        )?,
    };
    if result.feature_count() == 0 {
        return Err(invalid(format!(
            "malformed_input: {label} must contain at least one retrieval feature"
        )));
    }
    if result.feature_count() > limits.max_features_per_record {
        return Err(invalid(format!(
            "oversized_input: {label} exceeds max_features_per_record in total"
        )));
    }
    Ok(result)
}

fn parse_records(
    value: &Bound<'_, PyAny>,
    label: &str,
    maximum_records: usize,
    limits: RetrievalLimits,
    total_features: &mut usize,
) -> PyResult<Vec<SignatureRecord>> {
    let values = sequence_items(value, label)?;
    if values.len() > maximum_records {
        return Err(invalid(format!(
            "oversized_input: {label} exceeds its record bound"
        )));
    }
    let mut result = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let record = parse_record(value, &format!("{label}[{index}]"), limits)?;
        *total_features = total_features
            .checked_add(record.feature_count())
            .ok_or_else(|| invalid("oversized_input: total feature count overflow"))?;
        if *total_features > limits.max_total_features {
            return Err(invalid(
                "oversized_input: catalog and target features exceed max_total_features",
            ));
        }
        result.push(record);
    }
    let mut ids = result
        .iter()
        .map(|record| record.record_id.as_str())
        .collect::<Vec<_>>();
    ids.sort_unstable();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid(format!(
            "malformed_input: {label} contains duplicate record_id values"
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

fn parse_limits(value: Option<&Bound<'_, PyAny>>) -> PyResult<RetrievalLimits> {
    let Some(value) = value else {
        return Ok(RetrievalLimits::default());
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
    let mut parsed = HashMap::with_capacity(LIMIT_FIELDS.len());
    for (field, default, hard_maximum) in LIMIT_FIELDS {
        let configured = limit_value(value, field, *default)?;
        if configured == 0 || configured > *hard_maximum {
            return Err(invalid(format!(
                "oversized_input: limits.{field} must be between 1 and {hard_maximum}"
            )));
        }
        parsed.insert(*field, configured);
    }
    Ok(RetrievalLimits {
        max_catalog_records: parsed["max_catalog_records"],
        max_target_records: parsed["max_target_records"],
        max_features_per_record: parsed["max_features_per_record"],
        max_total_features: parsed["max_total_features"],
        max_sparse_hits: parsed["max_sparse_hits"],
        max_output_records: parsed["max_output_records"],
        max_string_bytes: parsed["max_string_bytes"],
    })
}

fn retrieve_candidates(
    catalog: &[SignatureRecord],
    targets: &[SignatureRecord],
    limits: RetrievalLimits,
) -> Result<Vec<CandidateWitness>, String> {
    let mut inverted: HashMap<(&str, FeatureKind, &str), Vec<usize>> = HashMap::new();
    for (catalog_index, record) in catalog.iter().enumerate() {
        for (kind, feature_hash) in record.features() {
            inverted
                .entry((record.abi_key.as_str(), kind, feature_hash))
                .or_default()
                .push(catalog_index);
        }
    }

    let mut result = Vec::new();
    let mut sparse_hits = 0_usize;
    for target in targets {
        let mut candidates: HashMap<usize, BTreeSet<FeatureWitness>> = HashMap::new();
        for (kind, feature_hash) in target.features() {
            let Some(postings) = inverted.get(&(target.abi_key.as_str(), kind, feature_hash))
            else {
                continue;
            };
            sparse_hits = sparse_hits
                .checked_add(postings.len())
                .ok_or_else(|| "oversized_result: sparse hit count overflow".to_owned())?;
            if sparse_hits > limits.max_sparse_hits {
                return Err("oversized_result: retrieval exceeds max_sparse_hits".to_owned());
            }
            for catalog_index in postings {
                candidates
                    .entry(*catalog_index)
                    .or_default()
                    .insert(FeatureWitness {
                        kind,
                        feature_hash: feature_hash.to_owned(),
                    });
            }
        }
        if result.len().saturating_add(candidates.len()) > limits.max_output_records {
            return Err("oversized_result: retrieval exceeds max_output_records".to_owned());
        }
        for (catalog_index, witnesses) in candidates {
            let candidate = &catalog[catalog_index];
            result.push(CandidateWitness {
                target_record_id: target.record_id.clone(),
                catalog_record_id: candidate.record_id.clone(),
                abi_key: target.abi_key.clone(),
                witnesses: witnesses.into_iter().collect(),
            });
        }
    }
    result.sort_unstable_by(|left, right| {
        (
            left.target_record_id.as_str(),
            left.catalog_record_id.as_str(),
            left.abi_key.as_str(),
        )
            .cmp(&(
                right.target_record_id.as_str(),
                right.catalog_record_id.as_str(),
                right.abi_key.as_str(),
            ))
    });
    Ok(result)
}

fn witnesses_to_python<'py>(
    py: Python<'py>,
    witnesses: &[CandidateWitness],
) -> PyResult<Bound<'py, PyList>> {
    let result = PyList::empty(py);
    for candidate in witnesses {
        let row = PyDict::new(py);
        row.set_item("format", "spaghetti-extractor-library-candidate-witness-v1")?;
        row.set_item("authority", "proposal_only")?;
        row.set_item("target_record_id", &candidate.target_record_id)?;
        row.set_item("catalog_record_id", &candidate.catalog_record_id)?;
        row.set_item("abi_key", &candidate.abi_key)?;
        let evidence = PyList::empty(py);
        for witness in &candidate.witnesses {
            let item = PyDict::new(py);
            item.set_item("kind", witness.kind.output_name())?;
            item.set_item("feature_hash", &witness.feature_hash)?;
            item.set_item(
                "witness_id",
                format!("{}:{}", witness.kind.witness_prefix(), witness.feature_hash),
            )?;
            evidence.append(item)?;
        }
        row.set_item("witnesses", evidence)?;
        row.set_item("witness_count", candidate.witnesses.len())?;
        result.append(row)?;
    }
    Ok(result)
}

#[pyfunction(signature = (catalog_records, target_records, limits=None))]
pub(crate) fn retrieve_library_candidates<'py>(
    py: Python<'py>,
    catalog_records: &Bound<'py, PyAny>,
    target_records: &Bound<'py, PyAny>,
    limits: Option<&Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyList>> {
    let limits = parse_limits(limits)?;
    let mut total_features = 0_usize;
    let catalog = parse_records(
        catalog_records,
        "catalog_records",
        limits.max_catalog_records,
        limits,
        &mut total_features,
    )?;
    let targets = parse_records(
        target_records,
        "target_records",
        limits.max_target_records,
        limits,
        &mut total_features,
    )?;
    let witnesses = py
        .detach(move || retrieve_candidates(&catalog, &targets, limits))
        .map_err(invalid)?;
    witnesses_to_python(py, &witnesses)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn record(id: &str, abi: &str, hashes: &[String]) -> SignatureRecord {
        SignatureRecord {
            record_id: id.to_owned(),
            abi_key: abi.to_owned(),
            fixed_anchor_hashes: hashes.to_vec(),
            normalized_hashes: Vec::new(),
            structural_feature_hashes: Vec::new(),
        }
    }

    #[test]
    fn retrieval_partitions_by_abi_and_preserves_aliases() {
        let shared = hash('a');
        let catalog = vec![
            record("alias:a", "cdecl", std::slice::from_ref(&shared)),
            record("alias:b", "cdecl", std::slice::from_ref(&shared)),
            record("stdcall", "stdcall", std::slice::from_ref(&shared)),
        ];
        let targets = vec![record("target", "cdecl", std::slice::from_ref(&shared))];
        let result = retrieve_candidates(&catalog, &targets, RetrievalLimits::default()).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].catalog_record_id, "alias:a");
        assert_eq!(result[1].catalog_record_id, "alias:b");
    }

    #[test]
    fn sparse_hit_bound_fails_closed() {
        let shared = hash('b');
        let catalog = (0..3)
            .map(|index| {
                record(
                    &format!("catalog:{index}"),
                    "cdecl",
                    std::slice::from_ref(&shared),
                )
            })
            .collect::<Vec<_>>();
        let targets = vec![record("target", "cdecl", std::slice::from_ref(&shared))];
        let limits = RetrievalLimits {
            max_sparse_hits: 2,
            ..RetrievalLimits::default()
        };
        assert_eq!(
            retrieve_candidates(&catalog, &targets, limits).unwrap_err(),
            "oversized_result: retrieval exceeds max_sparse_hits"
        );
    }
}
