use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::hash::BuildHasherDefault;
use std::hash::{Hash, Hasher};
use std::iter::FromIterator;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyBytesMethods};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

use crate::reference_plan;

const REGISTER_COUNT: usize = 8;
const FLAG_COUNT: usize = 7;
const STACK_ALTERNATIVE_LIMIT: usize = 256;
const SCALAR_CONSTRAINT_LIMIT: usize = 256;
const MAX_BATCH_CASES: usize = 100_000;
const MAX_MEMORY_ROWS: usize = 1_000_000;
const MAX_STRING_BYTES: usize = 4_096;
const X87_MEMORY_WRITE_MNEMONICS: &[&str] = &[
    "fbstp", "fist", "fistp", "fnsave", "fnstcw", "fnstenv", "fnstsw", "fsave", "fst", "fstcw",
    "fstenv", "fstp", "fstsw",
];
const X87_FLAG_WRITE_MNEMONICS: &[&str] =
    &["fcomi", "fcomip", "fcompi", "fucomi", "fucomip", "fucompi"];

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct ReferenceAtom {
    kind: String,
    identity: SharedText,
    offset: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(transparent)]
struct SharedAlternatives<T>(Arc<Vec<T>>);

#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
struct SharedText(Arc<str>);

thread_local! {
    static SHARED_TEXT_INTERNER: RefCell<HashSet<Arc<str>>> =
        RefCell::new(HashSet::new());
}

struct SharedTextInterningScope;

impl SharedTextInterningScope {
    fn new() -> Self {
        SHARED_TEXT_INTERNER.with(|interner| interner.borrow_mut().clear());
        Self
    }
}

impl Drop for SharedTextInterningScope {
    fn drop(&mut self) {
        SHARED_TEXT_INTERNER.with(|interner| interner.borrow_mut().clear());
    }
}

fn intern_shared_text(value: &str) -> Arc<str> {
    SHARED_TEXT_INTERNER.with(|interner| {
        let mut interner = interner.borrow_mut();
        if let Some(existing) = interner.get(value) {
            return existing.clone();
        }
        let shared: Arc<str> = Arc::from(value);
        interner.insert(shared.clone());
        shared
    })
}

impl<'de> Deserialize<'de> for SharedText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Ok(Self(intern_shared_text(&value)))
    }
}

impl PartialEq for SharedText {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0) || self.0 == other.0
    }
}

impl Eq for SharedText {}

impl Ord for SharedText {
    fn cmp(&self, other: &Self) -> Ordering {
        if Arc::ptr_eq(&self.0, &other.0) {
            Ordering::Equal
        } else {
            self.0.cmp(&other.0)
        }
    }
}

impl PartialOrd for SharedText {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Deref for SharedText {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for SharedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl From<String> for SharedText {
    fn from(value: String) -> Self {
        Self(intern_shared_text(&value))
    }
}

impl From<&str> for SharedText {
    fn from(value: &str) -> Self {
        Self(intern_shared_text(value))
    }
}

impl PartialEq<str> for SharedText {
    fn eq(&self, other: &str) -> bool {
        &*self.0 == other
    }
}

impl PartialEq<&str> for SharedText {
    fn eq(&self, other: &&str) -> bool {
        &*self.0 == *other
    }
}

impl PartialEq<String> for SharedText {
    fn eq(&self, other: &String) -> bool {
        &*self.0 == other
    }
}

impl PartialEq<SharedText> for String {
    fn eq(&self, other: &SharedText) -> bool {
        self == &*other.0
    }
}

impl<T> Default for SharedAlternatives<T> {
    fn default() -> Self {
        Self(Arc::new(Vec::new()))
    }
}

impl<T: PartialEq> PartialEq for SharedAlternatives<T> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0) || self.0 == other.0
    }
}

impl<T: Eq> Eq for SharedAlternatives<T> {}

impl<T> Deref for SharedAlternatives<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Clone> DerefMut for SharedAlternatives<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.0)
    }
}

impl<T> From<Vec<T>> for SharedAlternatives<T> {
    fn from(value: Vec<T>) -> Self {
        Self(Arc::new(value))
    }
}

impl<T> FromIterator<T> for SharedAlternatives<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self(Arc::new(iter.into_iter().collect()))
    }
}

impl<T: Clone> IntoIterator for SharedAlternatives<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        Arc::unwrap_or_clone(self.0).into_iter()
    }
}

impl<'a, T> IntoIterator for &'a SharedAlternatives<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T: PartialEq, const N: usize> PartialEq<[T; N]> for SharedAlternatives<T> {
    fn eq(&self, other: &[T; N]) -> bool {
        self.as_slice() == other
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReferenceValueData {
    kind: String,
    scalars: SharedAlternatives<u32>,
    references: SharedAlternatives<ReferenceAtom>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(transparent)]
struct ReferenceValue(Arc<ReferenceValueData>);

impl PartialEq for ReferenceValue {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0) || self.0 == other.0
    }
}

impl Eq for ReferenceValue {}

impl Deref for ReferenceValue {
    type Target = ReferenceValueData;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ReferenceValue {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.0)
    }
}

impl ReferenceValue {
    fn new(
        kind: impl Into<String>,
        scalars: impl Into<SharedAlternatives<u32>>,
        references: impl Into<SharedAlternatives<ReferenceAtom>>,
    ) -> Self {
        Self(Arc::new(ReferenceValueData {
            kind: kind.into(),
            scalars: scalars.into(),
            references: references.into(),
        }))
    }
}

fn stable_text_fingerprint(value: &str) -> u64 {
    value
        .as_bytes()
        .iter()
        .fold(0xcbf29ce484222325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MemoryKeyData {
    kind: SharedText,
    identity: SharedText,
    offset: i64,
    width: u32,
    #[serde(skip)]
    kind_fingerprint: u64,
    #[serde(skip)]
    identity_fingerprint: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryKeyWire {
    kind: SharedText,
    identity: SharedText,
    offset: i64,
    width: u32,
}

#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
struct MemoryKey(Arc<MemoryKeyData>);

impl<'de> Deserialize<'de> for MemoryKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = MemoryKeyWire::deserialize(deserializer)?;
        Ok(Self::new(wire.kind, wire.identity, wire.offset, wire.width))
    }
}

impl PartialEq for MemoryKey {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0) || self.0 == other.0
    }
}

impl Eq for MemoryKey {}

impl Hash for MemoryKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut value = self.kind_fingerprint
            ^ self.identity_fingerprint.rotate_left(17)
            ^ (self.offset as u64).rotate_left(31)
            ^ u64::from(self.width).rotate_left(47);
        value ^= value >> 30;
        value = value.wrapping_mul(0xbf58476d1ce4e5b9);
        value ^= value >> 27;
        value = value.wrapping_mul(0x94d049bb133111eb);
        state.write_u64(value ^ (value >> 31));
    }
}

impl Ord for MemoryKey {
    fn cmp(&self, other: &Self) -> Ordering {
        if Arc::ptr_eq(&self.0, &other.0) {
            Ordering::Equal
        } else {
            self.kind_fingerprint
                .cmp(&other.kind_fingerprint)
                .then_with(|| self.identity_fingerprint.cmp(&other.identity_fingerprint))
                .then_with(|| self.kind.cmp(&other.kind))
                .then_with(|| self.identity.cmp(&other.identity))
                .then_with(|| self.offset.cmp(&other.offset))
                .then_with(|| self.width.cmp(&other.width))
        }
    }
}

impl PartialOrd for MemoryKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Deref for MemoryKey {
    type Target = MemoryKeyData;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl MemoryKey {
    fn new(
        kind: impl Into<SharedText>,
        identity: impl Into<SharedText>,
        offset: i64,
        width: u32,
    ) -> Self {
        let kind = kind.into();
        let identity = identity.into();
        Self(Arc::new(MemoryKeyData {
            kind_fingerprint: stable_text_fingerprint(&kind),
            identity_fingerprint: stable_text_fingerprint(&identity),
            kind,
            identity,
            offset,
            width,
        }))
    }

    fn with_offset(&self, offset: i64) -> Self {
        Self::new(self.kind.clone(), self.identity.clone(), offset, self.width)
    }
}

fn lexical_memory_key_cmp(left: &MemoryKey, right: &MemoryKey) -> Ordering {
    left.kind
        .cmp(&right.kind)
        .then_with(|| left.identity.cmp(&right.identity))
        .then_with(|| left.offset.cmp(&right.offset))
        .then_with(|| left.width.cmp(&right.width))
}

#[derive(Default)]
struct MemoryHasher(u64);

impl Hasher for MemoryHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0 = bytes.iter().fold(0xcbf29ce484222325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        });
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }
}

type MemoryMap = HashMap<MemoryKey, ReferenceValue, BuildHasherDefault<MemoryHasher>>;
type MemoryKeySet = HashSet<MemoryKey, BuildHasherDefault<MemoryHasher>>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MemoryRow {
    #[serde(flatten)]
    key: MemoryKey,
    value: ReferenceValue,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MemoryRange {
    kind: SharedText,
    identity: SharedText,
    // Endpoints need a few bits beyond signed 64: the closed Python model
    // represents an unknown object by [-2^63, 2^63), and stack projection can
    // translate that exclusive upper endpoint slightly further.  Storing two
    // i128 values made every range 16-byte aligned and pushed real Hello over
    // the semantic-link memory budget.  Keep a signed base-2^64 segment plus
    // a low word for each coordinate; Rust packs the two segment bytes beside
    // the two words, while the wire form remains the exact JSON integer.
    start_segment: i8,
    start_low: u64,
    end_segment: i8,
    end_low: u64,
}

impl MemoryRange {
    const SEGMENT_WIDTH: i128 = 1i128 << 64;

    fn split_coordinate(value: i128) -> Option<(i8, u64)> {
        let segment = value.div_euclid(Self::SEGMENT_WIDTH);
        let low = value.rem_euclid(Self::SEGMENT_WIDTH) as u64;
        Some((i8::try_from(segment).ok()?, low))
    }

    fn from_coordinates(
        kind: SharedText,
        identity: SharedText,
        start: i128,
        end: i128,
    ) -> Self {
        let (start_segment, start_low) = Self::split_coordinate(start)
            .expect("internal memory-range start exceeds the compact coordinate domain");
        let (end_segment, end_low) = Self::split_coordinate(end)
            .expect("internal memory-range end exceeds the compact coordinate domain");
        Self {
            kind,
            identity,
            start_segment,
            start_low,
            end_segment,
            end_low,
        }
    }

    fn start(&self) -> i128 {
        i128::from(self.start_segment) * Self::SEGMENT_WIDTH
            + i128::from(self.start_low)
    }

    fn end(&self) -> i128 {
        i128::from(self.end_segment) * Self::SEGMENT_WIDTH
            + i128::from(self.end_low)
    }
}

const _: () = assert!(std::mem::size_of::<MemoryRange>() <= 56);

impl Serialize for MemoryRange {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut row = serializer.serialize_struct("MemoryRange", 4)?;
        row.serialize_field("kind", &self.kind)?;
        row.serialize_field("identity", &self.identity)?;
        row.serialize_field("start", &self.start())?;
        row.serialize_field("end", &self.end())?;
        row.end()
    }
}

impl<'de> Deserialize<'de> for MemoryRange {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            kind: SharedText,
            identity: SharedText,
            start: i128,
            end: i128,
        }

        let row = Wire::deserialize(deserializer)?;
        if Self::split_coordinate(row.start).is_none()
            || Self::split_coordinate(row.end).is_none()
        {
            return Err(serde::de::Error::custom(
                "memory range exceeds the compact coordinate domain",
            ));
        }
        Ok(Self::from_coordinates(
            row.kind, row.identity, row.start, row.end,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NamedValue {
    identity: String,
    value: ReferenceValue,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FlagRelation {
    register_index: u8,
    mask: u32,
    relation: String,
    constant: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ScalarConstraint {
    register_index: u8,
    mask: u32,
    values: Vec<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReferenceStatePayload {
    registers: Vec<ReferenceValue>,
    flags: Vec<ReferenceValue>,
    memory: Vec<MemoryRow>,
    call_registers: Vec<ReferenceValue>,
    call_flags: Vec<ReferenceValue>,
    invalidated_memory_ranges: Vec<MemoryRange>,
    all_memory_invalidated: bool,
    callback_registry: Vec<NamedValue>,
    flag_relations: Vec<Option<FlagRelation>>,
    scalar_constraints: Vec<ScalarConstraint>,
    preserves_inherited_memory: bool,
    relational_object_bindings: Vec<NamedValue>,
    written_memory_keys: Vec<MemoryKey>,
    effect_invalidated_memory_ranges: Vec<MemoryRange>,
    effect_all_memory_invalidated: bool,
    possible_allocation_identities: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinCase {
    left: ReferenceStatePayload,
    right: ReferenceStatePayload,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchInput {
    alternative_limit: usize,
    baseline_memory: Vec<MemoryRow>,
    cases: Vec<JoinCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosureContextInput {
    version: u32,
    roots: Vec<u32>,
    catalog: CatalogPayload,
    authority_bindings: BTreeMap<String, String>,
    initial_states: Vec<InitialStatePayload>,
    runtime_provider_requirements: Vec<String>,
    external_declarations: Vec<ExternalDeclarationPayload>,
    preexisting_blockers: Vec<JsonValue>,
    maximum_worklist_steps: usize,
    call_string_limit: usize,
    boundary_exit_rvas: Vec<u32>,
    checked_exception_transitions: Vec<CheckedExceptionTransitionInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalDeclarationPayload {
    dll: String,
    identity: String,
    contract_sha256: String,
    loader_service_contract_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckedExceptionTransitionInput {
    unit_id: String,
    source_rva: u32,
    effect_index: usize,
    fault_index: u32,
    fault_sha256: String,
    transition_id: Option<String>,
    transition_sha256: Option<String>,
    authorizing: bool,
    disposition: Option<String>,
    handler_unit_id: Option<String>,
    handler_rva: Option<u32>,
    resumption_unit_id: Option<String>,
    resumption_rva: Option<u32>,
    unwind_unit_ids: Vec<String>,
    state_projection: Option<ExceptionStateProjectionInput>,
    native_exception_code: Option<u32>,
    native_exception_flags: Option<u32>,
    native_exception_parameter_count: Option<u32>,
    native_exception_continuable: Option<bool>,
    native_exception_access_violation: Option<[usize; 2]>,
    guard: JsonValue,
    blocker_code: Option<String>,
    occurrence_kind: String,
    operation: Option<String>,
    call_index: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExceptionStateProjectionInput {
    registers: Vec<String>,
    flags: Vec<String>,
    x87: Vec<String>,
    stack: Vec<String>,
    exception_record: Vec<String>,
    context: Vec<String>,
}

impl ExceptionStateProjectionInput {
    fn canonical(&self) -> bool {
        [
            &self.registers,
            &self.flags,
            &self.x87,
            &self.stack,
            &self.exception_record,
            &self.context,
        ]
        .into_iter()
        .all(|values| sorted_unique(values) && values.iter().all(|value| !value.is_empty()))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogPayload {
    guest_code_rvas: Vec<u32>,
    guest_image_base: u32,
    external_functions: Vec<AddressIdentityPayload>,
    external_function_contracts: Vec<FunctionContractPayload>,
    objects: Vec<ObjectPayload>,
    external_calls: Vec<ExternalCallPayload>,
    initial_memory: Vec<MemoryRow>,
    object_bytes: Vec<ObjectBytesPayload>,
    alternative_limit: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AddressIdentityPayload {
    address: u32,
    identity: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FunctionContractPayload {
    function_identity: String,
    dll: String,
    identity: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectPayload {
    identity: String,
    address: u32,
    extent: u32,
    writable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
struct ExternalCallPayload {
    dll: String,
    identity: String,
    contract_sha256: Option<String>,
    loader_service_contract_sha256: Option<String>,
    preserved_registers: Vec<u8>,
    argument_words: usize,
    stack_cleanup_bytes: u32,
    disposition: String,
    allocation_result_register: Option<u8>,
    allocation_nullable: bool,
    write_footprints: Vec<ExternalWritePayload>,
    memory_copies: Vec<ExternalMemoryCopyPayload>,
    out_pointers: Vec<ExternalOutPointerPayload>,
    unknown_guest_memory_write: bool,
    callback: Option<ExternalCallbackPayload>,
    module_handle_name_argument: Option<usize>,
    module_handle_nullable_name: bool,
    module_handle_wide_name: bool,
    dynamic_export_handle_argument: Option<usize>,
    dynamic_export_name_argument: Option<usize>,
    dynamic_export_results: Vec<DynamicExportPayload>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
struct ExternalWritePayload {
    base_argument: usize,
    offset: i64,
    fixed_bytes: Option<u32>,
    size_argument: Option<usize>,
    scale: u32,
    authority_selector: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
struct ExternalMemoryCopyPayload {
    destination_argument: usize,
    source_argument: usize,
    size_argument: usize,
    scale: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
struct ExternalOutPointerPayload {
    argument: usize,
    offset: u32,
    nullable: bool,
    max_elements: u32,
    element_unit_bytes: u32,
    element_max_units: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
struct ExternalCallbackPayload {
    protocol_id: String,
    source_argument: usize,
    source_kind: String,
    source_offset: u32,
    sentinels: Vec<u32>,
    action: String,
    lifetime: String,
    delivery_thread: String,
    delivery_timing: String,
    instance_kind: String,
    instance_argument: Option<usize>,
    previous_result_register: Option<u8>,
    previous_sentinels: Vec<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
struct DynamicExportPayload {
    dll: String,
    identity: String,
    target: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectBytesPayload {
    identity: String,
    hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialStatePayload {
    rva: u32,
    state: ReferenceStatePayload,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ClosureInputReceipt {
    transfers: usize,
    roots: usize,
    guest_code_rvas: usize,
    objects: usize,
    external_calls: usize,
    external_declarations: usize,
    initial_memory_cells: usize,
    object_byte_owners: usize,
    initial_states: usize,
    preexisting_blockers: usize,
    checked_exception_transitions: usize,
}

#[derive(Debug, Serialize)]
struct RootExpressionReceipt {
    roots: Vec<RootExpressionRow>,
}

#[derive(Debug, Serialize)]
struct RootExpressionRow {
    rva: u32,
    values: Vec<ReferenceValue>,
}

#[derive(Debug, Serialize)]
struct RootEffectReceipt {
    roots: Vec<RootEffectRow>,
}

#[derive(Debug, Serialize)]
struct RootEffectRow {
    rva: u32,
    state: ReferenceStatePayload,
    values: Vec<ReferenceValue>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NativeFunctionContext {
    root_rva: u32,
    function_entry_rva: u32,
    call_string: Vec<u32>,
    identity: SharedText,
    frame_identity: SharedText,
}

impl NativeFunctionContext {
    fn new(
        root_rva: u32,
        function_entry_rva: u32,
        call_string: Vec<u32>,
    ) -> Self {
        let call_string_text = call_string
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let canonical = format!(
            "{{\"call_string\":[{call_string_text}],\"function_entry_rva\":{function_entry_rva},\"root_rva\":{root_rva}}}",
        );
        let digest = Sha256::digest(canonical.as_bytes());
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write;
            write!(&mut encoded, "{byte:02x}").expect("string formatting cannot fail");
        }
        let identity = format!("execution-context:{encoded}");
        let frame_identity = format!("captured_stack_frame:{identity}");
        Self {
            root_rva,
            function_entry_rva,
            call_string,
            identity: identity.into(),
            frame_identity: frame_identity.into(),
        }
    }

    fn child(
        &self,
        target_rva: u32,
        instruction_rva: u32,
        limit: usize,
    ) -> Self {
        let mut call_string = self.call_string.clone();
        call_string.push(instruction_rva);
        if call_string.len() > limit {
            call_string.drain(..call_string.len() - limit);
        }
        Self::new(self.root_rva, target_rva, call_string)
    }

    fn identity(&self) -> &str {
        &self.identity
    }

    fn frame_identity(&self) -> &str {
        &self.frame_identity
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NativeWorkKey {
    rva: u32,
    context: NativeFunctionContext,
}

#[derive(Clone)]
struct NativeActiveCallFrame {
    caller_key: NativeWorkKey,
    callee_context: NativeFunctionContext,
    return_rva: u32,
    caller_state: ReferenceState,
    caller_esp: ReferenceValue,
    parameter_bindings: BTreeMap<String, ReferenceValue>,
}

struct NativePending {
    roots: Vec<u32>,
    static_adjacency: BTreeMap<u32, BTreeSet<u32>>,
    discovered_edges: BTreeSet<(u32, u32)>,
    priorities: BTreeMap<u32, usize>,
    queued: BTreeSet<NativeWorkKey>,
    rows: BTreeSet<(usize, NativeWorkKey)>,
}

fn native_rpo_priorities(
    roots: &[u32],
    static_adjacency: &BTreeMap<u32, BTreeSet<u32>>,
    discovered_edges: &BTreeSet<(u32, u32)>,
) -> BTreeMap<u32, usize> {
    let rvas = static_adjacency.keys().copied().collect::<BTreeSet<_>>();
    let mut adjacency = static_adjacency.clone();
    for (source, target) in discovered_edges {
        if rvas.contains(source) && rvas.contains(target) {
            adjacency.entry(*source).or_default().insert(*target);
        }
    }
    let mut visited = BTreeSet::new();
    let mut postorder = Vec::new();
    for seed in roots.iter().copied().chain(rvas.iter().copied()) {
        if !rvas.contains(&seed) || !visited.insert(seed) {
            continue;
        }
        let mut stack = vec![(seed, false)];
        while let Some((rva, exiting)) = stack.pop() {
            if exiting {
                postorder.push(rva);
                continue;
            }
            stack.push((rva, true));
            for target in adjacency[&rva].iter().rev() {
                if visited.insert(*target) {
                    stack.push((*target, false));
                }
            }
        }
    }
    postorder
        .into_iter()
        .rev()
        .enumerate()
        .map(|(priority, rva)| (rva, priority))
        .collect()
}

impl NativePending {
    fn new(transfers: &BTreeMap<u32, &reference_plan::Transfer>, roots: &[u32]) -> Self {
        let rvas = transfers.keys().copied().collect::<BTreeSet<_>>();
        let static_adjacency = transfers
            .iter()
            .map(|(rva, transfer)| {
                let mut targets = BTreeSet::new();
                match transfer.terminator.op.as_str() {
                    "outcome_fallthrough" | "outcome_jump" => {
                        targets.insert(transfer.terminator.operands[0] as u32);
                    }
                    "outcome_branch" => {
                        targets.insert(transfer.terminator.operands[1] as u32);
                        targets.insert(transfer.terminator.operands[2] as u32);
                    }
                    _ => {}
                }
                targets.extend(
                    transfer
                        .calls
                        .iter()
                        .map(|call| call.target_rva)
                        .filter(|target| *target != 0),
                );
                targets.retain(|target| rvas.contains(target));
                (*rva, targets)
            })
            .collect::<BTreeMap<_, _>>();
        let discovered_edges = BTreeSet::new();
        let priorities = native_rpo_priorities(roots, &static_adjacency, &discovered_edges);
        Self {
            roots: roots.to_vec(),
            static_adjacency,
            discovered_edges,
            priorities,
            queued: BTreeSet::new(),
            rows: BTreeSet::new(),
        }
    }

    fn queue(&mut self, key: NativeWorkKey) {
        if self.queued.insert(key.clone()) {
            self.rows.insert((self.priorities[&key.rva], key));
        }
    }

    fn pop(&mut self) -> Option<NativeWorkKey> {
        let (_priority, key) = self.rows.pop_first()?;
        self.queued.remove(&key);
        Some(key)
    }

    fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    fn discover<I: IntoIterator<Item = u32>>(&mut self, source: u32, targets: I) {
        let mut changed = false;
        for target in targets {
            if self.static_adjacency.contains_key(&target) {
                changed |= self.discovered_edges.insert((source, target));
            }
        }
        if !changed {
            return;
        }
        self.priorities =
            native_rpo_priorities(&self.roots, &self.static_adjacency, &self.discovered_edges);
        self.rows = self
            .queued
            .iter()
            .cloned()
            .map(|key| (self.priorities[&key.rva], key))
            .collect();
    }
}

#[derive(Debug, Serialize)]
struct NativeClosureFrontierReceipt {
    worklist_steps: usize,
    states: Vec<NativeClosureStateRow>,
    reachable_edges: Vec<NativeClosureEdgeRow>,
    blockers: Vec<JsonValue>,
}

struct NativeClosureEvaluationOutput {
    frontier: NativeClosureFrontierReceipt,
    edge_root_provenance: Vec<NativeClosureEdgeProvenanceRow>,
    state_contexts: usize,
    reachable_rvas: Vec<u32>,
    indirect_targets: Vec<JsonValue>,
    external_contracts: Vec<JsonValue>,
    callback_escapes: Vec<JsonValue>,
    exception_continuations: Vec<JsonValue>,
    nonlocal_transitions: Vec<JsonValue>,
    lifecycle_effects: Vec<JsonValue>,
    witnesses: Vec<JsonValue>,
    reference_facts: NativeSemanticReferenceFacts,
    semantic_metrics: NativeClosureSemanticMetrics,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticLinkKernelInput {
    version: u32,
    symbols: Vec<SemanticLinkSymbolInput>,
    relocations: Vec<SemanticLinkRelocationInput>,
    objects: Vec<SemanticLinkObjectInput>,
    runtime_primitive_dependencies: Vec<SemanticLinkRuntimeDependencyInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticLinkSymbolInput {
    symbol_id: String,
    kind: String,
    linkage: String,
    original_rva: Option<u32>,
    unit_id: Option<String>,
    definition_kind: Option<String>,
    runtime_provider_id: Option<String>,
    external_dll: Option<String>,
    external_identity: Option<String>,
    checked_contract_sha256: Option<String>,
    loader_service_contract_sha256: Option<String>,
    provider_qualified: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticLinkRelocationInput {
    relocation_id: String,
    kind: String,
    source_symbol: String,
    source_rva: Option<u32>,
    target_symbol: Option<String>,
    target_rva: Option<u32>,
    input_status: String,
    instruction_rva: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticLinkObjectInput {
    object_id: String,
    semantic_symbol_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticLinkRuntimeDependencyInput {
    provider_id: String,
    target_symbol: String,
    source_symbols: Vec<String>,
}

#[derive(Debug, Serialize)]
struct NativeSemanticLinkFacts {
    symbols: Vec<NativeSemanticLinkSymbolFact>,
    relocations: Vec<NativeSemanticLinkRelocationFact>,
    objects: Vec<NativeSemanticLinkObjectFact>,
    effects: NativeSemanticLinkEffects,
    references: NativeSemanticReferenceFacts,
    blockers: Vec<JsonValue>,
}

#[derive(Debug, Serialize)]
struct NativeSemanticLinkEffects {
    runtime_providers: Vec<NativeSemanticLinkEffectFact>,
    external_contracts: Vec<NativeSemanticLinkEffectFact>,
    indirect_targets: Vec<NativeSemanticLinkEffectFact>,
    callbacks: Vec<NativeSemanticLinkEffectFact>,
    exceptions: Vec<NativeSemanticLinkEffectFact>,
    nonlocal_transitions: Vec<NativeSemanticLinkEffectFact>,
    lifecycle: Vec<NativeSemanticLinkEffectFact>,
}

#[derive(Debug, Serialize)]
struct NativeSemanticLinkEffectFact {
    effect: JsonValue,
    root_rvas: Vec<u32>,
}

#[derive(Debug, Serialize)]
struct NativeSemanticLinkSymbolFact {
    symbol_id: String,
    resolution: JsonValue,
    reachable: bool,
    root_rvas: Vec<u32>,
}

#[derive(Debug, Serialize)]
struct NativeSemanticLinkRelocationFact {
    relocation_id: String,
    status: String,
    target_symbols: Vec<String>,
    reachable: bool,
}

#[derive(Debug, Serialize)]
struct NativeSemanticLinkObjectFact {
    object_id: String,
    semantic_symbol_id: Option<String>,
    reachable: bool,
    root_rvas: Vec<u32>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct NativeSemanticReferenceFacts {
    catalog: NativeSemanticReferenceCatalog,
    facts: Vec<NativeSemanticReferenceFact>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct NativeSemanticReferenceCatalog {
    reference_atoms: Vec<ReferenceAtom>,
    bindings: Vec<NativeSemanticReferenceBinding>,
    memory_keys: Vec<MemoryKey>,
    memory_ranges: Vec<MemoryRange>,
    allocation_identities: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct NativeSemanticReferenceFact {
    unit_id: String,
    rva: u32,
    root_rva: u32,
    state_contexts: usize,
    reference_atom_indices: String,
    callback_binding_indices: String,
    relational_object_binding_indices: String,
    written_memory_key_indices: String,
    invalidated_memory_range_indices: String,
    all_memory_invalidated: bool,
    effect_invalidated_memory_range_indices: String,
    effect_all_memory_invalidated: bool,
    possible_allocation_identity_indices: String,
    all_preserve_inherited_memory: bool,
    any_preserve_inherited_memory: bool,
}

#[derive(Clone, Debug, Serialize)]
struct NativeSemanticReferenceBinding {
    identity: String,
    values: Vec<JsonValue>,
}

struct NativeSemanticReferenceAccumulator {
    unit_id: String,
    state_contexts: usize,
    reference_atom_indices: Vec<usize>,
    callback_binding_indices: Vec<usize>,
    relational_object_binding_indices: Vec<usize>,
    written_memory_key_indices: Vec<usize>,
    invalidated_memory_range_indices: Vec<usize>,
    all_memory_invalidated: bool,
    effect_invalidated_memory_range_indices: Vec<usize>,
    effect_all_memory_invalidated: bool,
    possible_allocation_identity_indices: Vec<usize>,
    all_preserve_inherited_memory: bool,
    any_preserve_inherited_memory: bool,
}

struct NativeClosureSemanticMetrics {
    reachable_expression_nodes: usize,
    indirect_sites: usize,
    function_contexts: usize,
    return_summaries: usize,
    relational_object_bindings: usize,
}

#[derive(Debug, Serialize)]
struct NativeClosureSummaryReceipt {
    worklist_steps: usize,
    state_contexts: usize,
    reachable_rvas: Vec<u32>,
    reachable_edges: Vec<NativeClosureEdgeRow>,
    blockers: Vec<JsonValue>,
}

#[derive(Debug, Serialize)]
struct NativeClosureStateRow {
    rva: u32,
    root_rva: u32,
    function_entry_rva: u32,
    call_string: Vec<u32>,
    state: ReferenceStatePayload,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct NativeClosureEdgeRow {
    source_rva: u32,
    target_rva: u32,
    kind: String,
}

#[derive(Clone, Debug, Serialize)]
struct NativeClosureEdgeProvenanceRow {
    source_rva: u32,
    target_rva: u32,
    kind: String,
    root_rvas: Vec<u32>,
}

type NativeTargetResolution = Option<(BTreeSet<u32>, BTreeSet<(String, String)>)>;

#[derive(Clone)]
struct NativeExternalWriteFailure {
    instruction_rva: u32,
    arguments: Vec<ReferenceValue>,
    external_targets: BTreeSet<(String, String)>,
}

#[derive(Clone)]
struct NativeReturnInstantiationFailure {
    instruction_rva: u32,
    reason: String,
    register_inputs: Vec<ReferenceValue>,
    parameter_bindings: BTreeMap<String, ReferenceValue>,
}

fn canonical_json_digest(value: &JsonValue) -> PyResult<String> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| invalid(format!("cannot canonicalize blocker: {error}")))?;
    let digest = Sha256::digest(encoded);
    let mut result = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        write!(&mut result, "{byte:02x}").expect("string formatting cannot fail");
    }
    Ok(result)
}

fn insert_native_blocker(
    blockers: &mut BTreeMap<String, JsonValue>,
    blocker: JsonValue,
) -> PyResult<()> {
    blockers.insert(canonical_json_digest(&blocker)?, blocker);
    Ok(())
}

fn intern_reference_catalog_row<T: Clone + Ord>(
    index: &mut BTreeMap<T, usize>,
    rows: &mut Vec<T>,
    value: &T,
) -> usize {
    if let Some(existing) = index.get(value) {
        return *existing;
    }
    let row_index = rows.len();
    rows.push(value.clone());
    index.insert(value.clone(), row_index);
    row_index
}

type NativeSemanticReferenceValueBinding = (String, String, JsonValue);

fn intern_reference_binding_value(
    index: &mut BTreeMap<(String, String), usize>,
    rows: &mut Vec<NativeSemanticReferenceValueBinding>,
    identity: &str,
    value: &ReferenceValue,
) -> PyResult<usize> {
    let payload = serde_json::to_value(value)
        .map_err(|error| invalid(format!("cannot encode semantic reference value: {error}")))?;
    let digest = canonical_json_digest(&payload)?;
    let key = (identity.to_owned(), digest.clone());
    if let Some(existing) = index.get(&key) {
        return Ok(*existing);
    }
    let row_index = rows.len();
    rows.push((identity.to_owned(), digest, payload));
    index.insert(key, row_index);
    Ok(row_index)
}

fn intern_reference_bindings(
    destination: &mut Vec<usize>,
    source: &BTreeMap<String, ReferenceValue>,
    index: &mut BTreeMap<(String, String), usize>,
    rows: &mut Vec<NativeSemanticReferenceValueBinding>,
) -> PyResult<()> {
    for (identity, value) in source {
        destination.push(intern_reference_binding_value(
            index, rows, identity, value,
        )?);
    }
    Ok(())
}

fn canonical_reference_catalog<T: Clone>(
    rows: Vec<T>,
    mut compare: impl FnMut(&T, &T) -> Ordering,
) -> (Vec<T>, Vec<usize>) {
    let mut indexed = rows.into_iter().enumerate().collect::<Vec<_>>();
    indexed.sort_unstable_by(|left, right| compare(&left.1, &right.1));
    let mut remap = vec![0; indexed.len()];
    let mut canonical = Vec::with_capacity(indexed.len());
    for (new_index, (old_index, row)) in indexed.into_iter().enumerate() {
        remap[old_index] = new_index;
        canonical.push(row);
    }
    (canonical, remap)
}

fn encoded_reference_indices(mut rows: Vec<usize>, remap: &[usize]) -> String {
    for index in &mut rows {
        *index = remap[*index];
    }
    rows.sort_unstable();
    rows.dedup();
    let mut encoded = Vec::new();
    let mut previous = 0usize;
    for (position, index) in rows.into_iter().enumerate() {
        let mut delta = if position == 0 {
            index
        } else {
            index - previous
        };
        loop {
            let mut byte = (delta & 0x7f) as u8;
            delta >>= 7;
            if delta != 0 {
                byte |= 0x80;
            }
            encoded.push(byte);
            if delta == 0 {
                break;
            }
        }
        previous = index;
    }
    let mut result = String::with_capacity(encoded.len() * 2);
    for byte in encoded {
        use std::fmt::Write;
        write!(&mut result, "{byte:02x}").expect("string formatting cannot fail");
    }
    result
}

fn aggregate_reference_binding_indices(
    mut exact_indices: Vec<usize>,
    exact_rows: &[NativeSemanticReferenceValueBinding],
    binding_index: &mut BTreeMap<String, usize>,
    binding_rows: &mut Vec<NativeSemanticReferenceBinding>,
) -> PyResult<Vec<usize>> {
    exact_indices.sort_unstable();
    exact_indices.dedup();
    let mut grouped = BTreeMap::<String, BTreeMap<String, &JsonValue>>::new();
    for exact_index in exact_indices {
        let (identity, digest, payload) = exact_rows
            .get(exact_index)
            .ok_or_else(|| invalid("semantic reference binding index is out of range"))?;
        grouped
            .entry(identity.clone())
            .or_default()
            .insert(digest.clone(), payload);
    }
    let mut result = Vec::with_capacity(grouped.len());
    for (identity, values) in grouped {
        let row = NativeSemanticReferenceBinding {
            identity,
            values: values.into_values().cloned().collect(),
        };
        let payload = serde_json::to_value(&row).map_err(|error| {
            invalid(format!("cannot encode semantic reference binding: {error}"))
        })?;
        let digest = canonical_json_digest(&payload)?;
        let row_index = if let Some(existing) = binding_index.get(&digest) {
            if binding_rows[*existing].identity != row.identity
                || binding_rows[*existing].values != row.values
            {
                return Err(invalid("semantic reference binding digest collision"));
            }
            *existing
        } else {
            let index = binding_rows.len();
            binding_rows.push(row);
            binding_index.insert(digest, index);
            index
        };
        result.push(row_index);
    }
    result.sort_unstable();
    result.dedup();
    Ok(result)
}

fn compact_native_reference_facts(
    states: &BTreeMap<NativeWorkKey, ReferenceState>,
    transfers: &BTreeMap<u32, &reference_plan::Transfer>,
) -> PyResult<NativeSemanticReferenceFacts> {
    let mut grouped = BTreeMap::<(u32, u32), NativeSemanticReferenceAccumulator>::new();
    let mut reference_atom_index = BTreeMap::<ReferenceAtom, usize>::new();
    let mut reference_atoms = Vec::<ReferenceAtom>::new();
    let mut exact_binding_index = BTreeMap::<(String, String), usize>::new();
    let mut exact_bindings = Vec::<NativeSemanticReferenceValueBinding>::new();
    let mut memory_key_index = BTreeMap::<MemoryKey, usize>::new();
    let mut memory_keys = Vec::<MemoryKey>::new();
    let mut memory_range_index = BTreeMap::<MemoryRange, usize>::new();
    let mut memory_ranges = Vec::<MemoryRange>::new();
    let mut allocation_index = BTreeMap::<String, usize>::new();
    let mut allocation_identities = Vec::<String>::new();
    for (key, state) in states {
        let transfer = transfers
            .get(&key.rva)
            .ok_or_else(|| invalid("semantic reference state lies outside the exact universe"))?;
        let fact = grouped
            .entry((key.rva, key.context.root_rva))
            .or_insert_with(|| NativeSemanticReferenceAccumulator {
                unit_id: transfer.identity().to_owned(),
                state_contexts: 0,
                reference_atom_indices: Vec::new(),
                callback_binding_indices: Vec::new(),
                relational_object_binding_indices: Vec::new(),
                written_memory_key_indices: Vec::new(),
                invalidated_memory_range_indices: Vec::new(),
                all_memory_invalidated: false,
                effect_invalidated_memory_range_indices: Vec::new(),
                effect_all_memory_invalidated: false,
                possible_allocation_identity_indices: Vec::new(),
                all_preserve_inherited_memory: true,
                any_preserve_inherited_memory: false,
            });
        fact.state_contexts += 1;
        for value in state
            .registers
            .iter()
            .chain(&state.flags)
            .chain(state.memory.values())
            .chain(&state.call_registers)
            .chain(&state.call_flags)
            .chain(state.callback_registry.values())
            .chain(state.relational_object_bindings.values())
        {
            for atom in &value.references {
                fact.reference_atom_indices
                    .push(intern_reference_catalog_row(
                        &mut reference_atom_index,
                        &mut reference_atoms,
                        atom,
                    ));
            }
        }
        intern_reference_bindings(
            &mut fact.callback_binding_indices,
            &state.callback_registry,
            &mut exact_binding_index,
            &mut exact_bindings,
        )?;
        intern_reference_bindings(
            &mut fact.relational_object_binding_indices,
            &state.relational_object_bindings,
            &mut exact_binding_index,
            &mut exact_bindings,
        )?;
        fact.written_memory_key_indices.extend(
            state.written_memory_keys.iter().map(|row| {
                intern_reference_catalog_row(&mut memory_key_index, &mut memory_keys, row)
            }),
        );
        fact.invalidated_memory_range_indices
            .extend(state.invalidated_memory_ranges.iter().map(|row| {
                intern_reference_catalog_row(&mut memory_range_index, &mut memory_ranges, row)
            }));
        fact.all_memory_invalidated |= state.all_memory_invalidated;
        fact.effect_invalidated_memory_range_indices.extend(
            state.effect_invalidated_memory_ranges.iter().map(|row| {
                intern_reference_catalog_row(&mut memory_range_index, &mut memory_ranges, row)
            }),
        );
        fact.effect_all_memory_invalidated |= state.effect_all_memory_invalidated;
        fact.possible_allocation_identity_indices.extend(
            state.possible_allocation_identities.iter().map(|row| {
                intern_reference_catalog_row(&mut allocation_index, &mut allocation_identities, row)
            }),
        );
        fact.all_preserve_inherited_memory &= state.preserves_inherited_memory;
        fact.any_preserve_inherited_memory |= state.preserves_inherited_memory;
    }

    let mut binding_index = BTreeMap::<String, usize>::new();
    let mut binding_rows = Vec::<NativeSemanticReferenceBinding>::new();
    for fact in grouped.values_mut() {
        fact.callback_binding_indices = aggregate_reference_binding_indices(
            std::mem::take(&mut fact.callback_binding_indices),
            &exact_bindings,
            &mut binding_index,
            &mut binding_rows,
        )?;
        fact.relational_object_binding_indices = aggregate_reference_binding_indices(
            std::mem::take(&mut fact.relational_object_binding_indices),
            &exact_bindings,
            &mut binding_index,
            &mut binding_rows,
        )?;
    }

    let (reference_atoms, reference_atom_remap) =
        canonical_reference_catalog(reference_atoms, Ord::cmp);
    let (memory_keys, memory_key_remap) =
        canonical_reference_catalog(memory_keys, lexical_memory_key_cmp);
    let (memory_ranges, memory_range_remap) = canonical_reference_catalog(memory_ranges, Ord::cmp);
    let (allocation_identities, allocation_remap) =
        canonical_reference_catalog(allocation_identities, Ord::cmp);
    let mut binding_remap = vec![0; binding_rows.len()];
    let mut bindings = Vec::with_capacity(binding_rows.len());
    for (_digest, old_index) in binding_index {
        binding_remap[old_index] = bindings.len();
        bindings.push(binding_rows[old_index].clone());
    }
    let facts = grouped
        .into_iter()
        .map(|((rva, root_rva), fact)| {
            Ok(NativeSemanticReferenceFact {
                unit_id: fact.unit_id,
                rva,
                root_rva,
                state_contexts: fact.state_contexts,
                reference_atom_indices: encoded_reference_indices(
                    fact.reference_atom_indices,
                    &reference_atom_remap,
                ),
                callback_binding_indices: encoded_reference_indices(
                    fact.callback_binding_indices,
                    &binding_remap,
                ),
                relational_object_binding_indices: encoded_reference_indices(
                    fact.relational_object_binding_indices,
                    &binding_remap,
                ),
                written_memory_key_indices: encoded_reference_indices(
                    fact.written_memory_key_indices,
                    &memory_key_remap,
                ),
                invalidated_memory_range_indices: encoded_reference_indices(
                    fact.invalidated_memory_range_indices,
                    &memory_range_remap,
                ),
                all_memory_invalidated: fact.all_memory_invalidated,
                effect_invalidated_memory_range_indices: encoded_reference_indices(
                    fact.effect_invalidated_memory_range_indices,
                    &memory_range_remap,
                ),
                effect_all_memory_invalidated: fact.effect_all_memory_invalidated,
                possible_allocation_identity_indices: encoded_reference_indices(
                    fact.possible_allocation_identity_indices,
                    &allocation_remap,
                ),
                all_preserve_inherited_memory: fact.all_preserve_inherited_memory,
                any_preserve_inherited_memory: fact.any_preserve_inherited_memory,
            })
        })
        .collect::<PyResult<Vec<_>>>()?;
    Ok(NativeSemanticReferenceFacts {
        catalog: NativeSemanticReferenceCatalog {
            reference_atoms,
            bindings,
            memory_keys,
            memory_ranges,
            allocation_identities,
        },
        facts,
    })
}

fn sha256_hex(payload: &[u8]) -> String {
    let digest = Sha256::digest(payload);
    let mut result = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        write!(&mut result, "{byte:02x}").expect("string formatting cannot fail");
    }
    result
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[allow(dead_code)]
struct RuntimeCatalog {
    guest_code_rvas: BTreeSet<u32>,
    guest_image_base: u32,
    external_functions: BTreeMap<u32, String>,
    external_function_contracts: BTreeMap<String, (String, String)>,
    objects: Vec<ObjectPayload>,
    external_calls: BTreeMap<(String, String), ExternalCallPayload>,
    initial_memory: MemoryMap,
    baseline_memory_index: BaselineMemoryIndex,
    object_bytes: BTreeMap<String, Vec<u8>>,
    alternative_limit: usize,
}

#[allow(dead_code)]
struct RuntimeClosureContext {
    roots: Vec<u32>,
    catalog: RuntimeCatalog,
    initial_states: BTreeMap<u32, ReferenceState>,
    authority_bindings: BTreeMap<String, String>,
    runtime_provider_requirements: Vec<String>,
    external_declarations: BTreeMap<
        (String, String),
        (String, Option<String>),
    >,
    preexisting_blockers: Vec<JsonValue>,
    maximum_worklist_steps: usize,
    call_string_limit: usize,
    boundary_exit_rvas: BTreeSet<u32>,
    checked_exception_transitions:
        BTreeMap<(String, usize, Option<String>), CheckedExceptionTransitionInput>,
}

fn finite_value(
    scalars: impl IntoIterator<Item = u32>,
    references: impl IntoIterator<Item = ReferenceAtom>,
    alternative_limit: usize,
) -> PyResult<ReferenceValue> {
    canonical_value(
        ReferenceValue::new(
            "finite",
            scalars.into_iter().collect::<SharedAlternatives<_>>(),
            references.into_iter().collect::<SharedAlternatives<_>>(),
        ),
        alternative_limit,
    )
}

impl RuntimeCatalog {
    fn classify_scalar(&self, value: u32) -> PyResult<ReferenceValue> {
        let mut references = Vec::new();
        for object in &self.objects {
            let start = object.address as u64;
            let end = start + object.extent as u64;
            if (value as u64) >= start && (value as u64) < end {
                references.push(ReferenceAtom {
                    kind: "object".to_owned(),
                    identity: object.identity.clone().into(),
                    offset: value as i64 - object.address as i64,
                });
            }
        }
        let guest_rva = if self.guest_image_base != 0 && value >= self.guest_image_base {
            value - self.guest_image_base
        } else {
            value
        };
        if self.guest_code_rvas.contains(&guest_rva) {
            references.push(ReferenceAtom {
                kind: "guest_code".to_owned(),
                identity: format!("rva:{guest_rva:08x}").into(),
                offset: 0,
            });
        }
        if let Some(identity) = self.external_functions.get(&value) {
            references.push(ReferenceAtom {
                kind: "external_function".to_owned(),
                identity: identity.clone().into(),
                offset: 0,
            });
        }
        if references.len() > 1 {
            Ok(conflict_value())
        } else if references.is_empty() {
            finite_value([value], [], self.alternative_limit)
        } else {
            finite_value([], references, self.alternative_limit)
        }
    }
}

fn reference_memory_keys(value: &ReferenceValue, width: u32) -> Option<Vec<MemoryKey>> {
    if value.kind != "finite" {
        return None;
    }
    let mut keys = Vec::with_capacity(value.scalars.len() + value.references.len());
    for atom in &value.references {
        if atom.kind != "object" {
            return None;
        }
        keys.push(MemoryKey::new(
            "object",
            atom.identity.clone(),
            atom.offset,
            width,
        ));
    }
    keys.extend(
        value
            .scalars
            .iter()
            .map(|scalar| MemoryKey::new("absolute", "", *scalar as i64, width)),
    );
    Some(keys)
}

fn aligned_object_identity(identity: &str) -> Option<(&str, &str, i64)> {
    let encoded = identity.strip_prefix("aligned:")?;
    let (mask, derived) = encoded.split_once(':')?;
    let (base, offset) = derived.rsplit_once(':')?;
    Some((mask, base, offset.parse().ok()?))
}

fn captured_stack_owner(identity: &str) -> Option<String> {
    if identity.starts_with("captured_stack_frame:") {
        return Some(identity.to_owned());
    }
    if let Some((_mask, base, _offset)) = aligned_object_identity(identity) {
        return captured_stack_owner(base);
    }
    if let Some(encoded) = identity.strip_prefix("dynamic_stack_region:") {
        let (owner, _allocation) = encoded.split_once('|')?;
        return captured_stack_owner(owner);
    }
    None
}

fn call_parameter_owner(identity: &str) -> Option<String> {
    if identity.starts_with("call_parameter_object:") {
        return Some(identity.to_owned());
    }
    aligned_object_identity(identity).and_then(|(_mask, base, _offset)| call_parameter_owner(base))
}

fn transient_owner(identity: &str) -> Option<String> {
    captured_stack_owner(identity).or_else(|| call_parameter_owner(identity))
}

fn instantiate_call_parameter_identity(
    identity: &str,
    actual: &ReferenceAtom,
) -> Option<ReferenceAtom> {
    let owner = call_parameter_owner(identity)?;
    if actual.kind != "object" {
        return None;
    }
    fn instantiate(identity: &str, owner: &str, actual: &ReferenceAtom) -> Option<(String, i64)> {
        if identity == owner {
            return Some((actual.identity.to_string(), actual.offset));
        }
        let (mask, base, offset) = aligned_object_identity(identity)?;
        let (base_identity, base_offset) = instantiate(base, owner, actual)?;
        Some((
            format!("aligned:{mask}:{base_identity}:{}", base_offset + offset),
            0,
        ))
    }
    let (identity, offset) = instantiate(identity, &owner, actual)?;
    Some(ReferenceAtom {
        kind: "object".to_owned(),
        identity: identity.into(),
        offset,
    })
}

fn reference_memory_value_resolving(
    state: &ReferenceState,
    key: &MemoryKey,
    catalog: &RuntimeCatalog,
    resolving: &BTreeSet<MemoryKey>,
) -> PyResult<ReferenceValue> {
    if let Some(value) = state.memory.get(key) {
        return Ok(value.clone());
    }
    let start = i128::from(key.offset);
    let end = start + i128::from(key.width);
    let immutable_object = key.kind == "object"
        && catalog.objects.iter().any(|object| {
            object.identity == key.identity && !object.writable
        });
    if !immutable_object && (state.all_memory_invalidated
        || state.invalidated_memory_ranges.iter().any(|row| {
            row.kind == key.kind
                && row.identity == key.identity
                && start < row.end()
                && row.start() < end
        }))
    {
        return Ok(unknown_value());
    }
    let parameter_owner = if key.kind == "object" {
        call_parameter_owner(&key.identity)
    } else {
        None
    };
    let frame_backed = key.kind == "object"
        && key.offset >= 4
        && captured_stack_owner(&key.identity).as_deref() == Some(&*key.identity)
        && state
            .relational_object_bindings
            .contains_key(&*key.identity);
    if parameter_owner.is_some() || frame_backed {
        if resolving.contains(key) {
            return Ok(conflict_value());
        }
        let binding_identity = parameter_owner.as_deref().unwrap_or(&*key.identity);
        let Some(binding) = state.relational_object_bindings.get(binding_identity) else {
            return Ok(conflict_value());
        };
        if binding.kind != "finite"
            || !binding.scalars.is_empty()
            || binding.references.is_empty()
            || binding.references.iter().any(|atom| atom.kind != "object")
        {
            return Ok(conflict_value());
        }
        let mut nested = resolving.clone();
        nested.insert(key.clone());
        let mut result = bottom_value();
        for atom in &binding.references {
            let actual = if parameter_owner.is_some() {
                let Some(actual) = instantiate_call_parameter_identity(&key.identity, atom) else {
                    return Ok(conflict_value());
                };
                actual
            } else {
                atom.clone()
            };
            let actual_key = MemoryKey::new(
                "object",
                actual.identity.clone(),
                actual
                    .offset
                    .checked_add(key.offset)
                    .ok_or_else(|| invalid("relational memory offset overflow"))?,
                key.width,
            );
            let mut value = reference_memory_value_resolving(state, &actual_key, catalog, &nested)?;
            if value.kind == "finite" {
                let references = value.references.iter().map(|reference| {
                    if reference.kind == "object" && reference.identity == actual.identity {
                        ReferenceAtom {
                            kind: "object".to_owned(),
                            identity: key.identity.to_string().into(),
                            offset: reference.offset - actual.offset,
                        }
                    } else {
                        reference.clone()
                    }
                });
                value = finite_value(
                    value.scalars.iter().copied(),
                    references,
                    catalog.alternative_limit.max(STACK_ALTERNATIVE_LIMIT),
                )?;
            }
            result = join_value(&result, &value, catalog.alternative_limit)?;
        }
        return Ok(result);
    }
    Ok(catalog
        .initial_memory
        .get(key)
        .cloned()
        .unwrap_or_else(unknown_value))
}

fn reference_memory_value(
    state: &ReferenceState,
    key: &MemoryKey,
    catalog: &RuntimeCatalog,
) -> PyResult<ReferenceValue> {
    reference_memory_value_resolving(state, key, catalog, &BTreeSet::new())
}

fn adjusted_reference(
    left: &ReferenceValue,
    right: &ReferenceValue,
    subtract: bool,
    alternative_limit: usize,
) -> PyResult<ReferenceValue> {
    if left.kind != "finite" || right.kind != "finite" {
        return Ok(if left.kind == "conflict" || right.kind == "conflict" {
            conflict_value()
        } else {
            unknown_value()
        });
    }
    let mut scalars = BTreeSet::new();
    for lhs in &left.scalars {
        for rhs in &right.scalars {
            scalars.insert(if subtract {
                lhs.wrapping_sub(*rhs)
            } else {
                lhs.wrapping_add(*rhs)
            });
        }
    }
    let mut references = BTreeSet::new();
    let mut is_invalid = subtract && !left.scalars.is_empty() && !right.references.is_empty();
    for atom in &left.references {
        for delta in &right.scalars {
            let signed_delta = *delta as i32 as i64;
            if atom.kind == "object_view" {
                references.insert(atom.clone());
            } else if atom.kind != "object" && signed_delta != 0 {
                is_invalid = true;
            } else {
                let offset = if subtract {
                    atom.offset.checked_sub(signed_delta)
                } else {
                    atom.offset.checked_add(signed_delta)
                }
                .ok_or_else(|| invalid("reference offset overflow"))?;
                references.insert(ReferenceAtom {
                    offset,
                    ..atom.clone()
                });
            }
        }
        for other in &right.references {
            if subtract
                && matches!(atom.kind.as_str(), "object" | "object_view")
                && matches!(other.kind.as_str(), "object" | "object_view")
                && atom.identity == other.identity
                && (atom.kind == "object_view" || other.kind == "object_view")
            {
                return Ok(unknown_value());
            }
            if subtract && atom.kind == other.kind && atom.identity == other.identity {
                scalars.insert((atom.offset.wrapping_sub(other.offset)) as u32);
            } else {
                is_invalid = true;
            }
        }
    }
    if !subtract {
        for atom in &right.references {
            for delta in &left.scalars {
                let signed_delta = *delta as i32 as i64;
                if atom.kind == "object_view" {
                    references.insert(atom.clone());
                } else if atom.kind != "object" && signed_delta != 0 {
                    is_invalid = true;
                } else {
                    references.insert(ReferenceAtom {
                        offset: atom
                            .offset
                            .checked_add(signed_delta)
                            .ok_or_else(|| invalid("reference offset overflow"))?,
                        ..atom.clone()
                    });
                }
            }
        }
    }
    if is_invalid {
        Ok(conflict_value())
    } else {
        finite_value(scalars, references, alternative_limit)
    }
}

fn scalar_product(
    arguments: &[ReferenceValue],
    operation: &str,
    alternative_limit: usize,
) -> PyResult<ReferenceValue> {
    if arguments
        .iter()
        .any(|value| value.kind == "conflict" || !value.references.is_empty())
    {
        return Ok(conflict_value());
    }
    if arguments.iter().any(|value| value.kind != "finite") {
        return Ok(unknown_value());
    }
    let mut rows: Vec<Vec<u32>> = vec![Vec::new()];
    for value in arguments {
        let mut next = Vec::new();
        for prefix in &rows {
            for item in &value.scalars {
                let mut row = prefix.clone();
                row.push(*item);
                next.push(row);
                if next.len() > alternative_limit {
                    return Ok(conflict_value());
                }
            }
        }
        rows = next;
    }
    let mut products = BTreeSet::new();
    for row in rows {
        let result = match operation {
            "mul32" => row
                .iter()
                .fold(1_u32, |result, item| result.wrapping_mul(*item)),
            "xor32" => row.iter().fold(0_u32, |result, item| result ^ item),
            "and32" => row.iter().fold(u32::MAX, |result, item| result & item),
            "or32" => row.iter().fold(0_u32, |result, item| result | item),
            "not32" => !row[0],
            "neg32" => 0_u32.wrapping_sub(row[0]),
            "shl32" => row[0].wrapping_shl(row[1] & 31),
            "lshr32" => row[0].wrapping_shr(row[1] & 31),
            "bool_to_bit" => u32::from(row[0] != 0),
            "imul_low32" | "mul_low32" => row[0].wrapping_mul(row[1]),
            _ => return Ok(unknown_value()),
        };
        products.insert(result);
        if products.len() > alternative_limit {
            return Ok(conflict_value());
        }
    }
    finite_value(products, [], alternative_limit)
}

fn aligned_object_reference(
    arguments: &[ReferenceValue],
    alternative_limit: usize,
) -> PyResult<Option<ReferenceValue>> {
    if arguments.len() != 2 {
        return Ok(None);
    }
    for (reference, mask_value) in [
        (&arguments[0], &arguments[1]),
        (&arguments[1], &arguments[0]),
    ] {
        if reference.kind != "finite"
            || !reference.scalars.is_empty()
            || reference.references.is_empty()
            || reference
                .references
                .iter()
                .any(|atom| !matches!(atom.kind.as_str(), "object" | "object_view"))
            || mask_value.kind != "finite"
            || !mask_value.references.is_empty()
            || mask_value.scalars.len() != 1
        {
            continue;
        }
        let mask = mask_value.scalars[0];
        let cleared = !mask;
        if cleared == 0 || cleared & cleared.wrapping_add(1) != 0 {
            continue;
        }
        let prefix = format!("aligned:{mask:08x}:");
        let alignment = cleared as i64 + 1;
        let mut rows = Vec::new();
        for atom in &reference.references {
            rows.push(if atom.kind == "object_view" {
                atom.clone()
            } else if atom.identity.starts_with(&prefix) {
                ReferenceAtom {
                    kind: "object".to_owned(),
                    identity: atom.identity.clone(),
                    offset: atom.offset - atom.offset.rem_euclid(alignment),
                }
            } else {
                // The aligned identity records the exact pre-alignment base
                // coordinate; its exposed offset therefore starts at zero.
                // Keeping the old offset in both places double-counts it and
                // shifts every nested stack alias by one alignment quantum.
                ReferenceAtom {
                    kind: atom.kind.clone(),
                    identity: format!("{prefix}{}:{}", atom.identity, atom.offset).into(),
                    offset: 0,
                }
            });
        }
        return finite_value([], rows, alternative_limit).map(Some);
    }
    Ok(None)
}

fn predicate_value(
    operation: &str,
    arguments: &[ReferenceValue],
    alternative_limit: usize,
) -> PyResult<ReferenceValue> {
    if matches!(operation, "eq" | "eq_bool") && arguments.len() == 2 {
        let left = &arguments[0];
        let right = &arguments[1];
        if left.kind == "finite" && right.kind == "finite" {
            let mut possibilities = BTreeSet::new();
            for lhs in &left.scalars {
                for rhs in &right.scalars {
                    possibilities.insert(u32::from(lhs == rhs));
                }
                if !right.references.is_empty() {
                    possibilities.insert(0);
                }
            }
            if !left.references.is_empty() && !right.scalars.is_empty() {
                possibilities.insert(0);
            }
            for lhs in &left.references {
                for rhs in &right.references {
                    if (lhs.identity == rhs.identity
                        && (lhs.kind == "object_view" || rhs.kind == "object_view"))
                        || (lhs.identity != rhs.identity
                            && lhs.identity.starts_with("call_parameter_object:")
                            && rhs.identity.starts_with("call_parameter_object:"))
                    {
                        possibilities.extend([0, 1]);
                    } else {
                        possibilities.insert(u32::from(lhs == rhs));
                    }
                }
            }
            return finite_value(possibilities, [], alternative_limit);
        }
    }
    if operation == "ult32" && arguments.len() == 2 {
        if arguments
            .iter()
            .all(|value| value.kind == "finite" && value.references.is_empty())
        {
            let values = arguments[0]
                .scalars
                .iter()
                .flat_map(|left| {
                    arguments[1]
                        .scalars
                        .iter()
                        .map(move |right| u32::from(left < right))
                })
                .collect::<BTreeSet<_>>();
            return finite_value(values, [], alternative_limit);
        }
        if arguments.iter().all(|value| {
            value.kind == "finite" && value.scalars.is_empty() && !value.references.is_empty()
        }) {
            let pairs = arguments[0]
                .references
                .iter()
                .flat_map(|left| {
                    arguments[1]
                        .references
                        .iter()
                        .map(move |right| (left, right))
                })
                .collect::<Vec<_>>();
            if pairs.iter().all(|(left, right)| {
                matches!(left.kind.as_str(), "object" | "object_view")
                    && matches!(right.kind.as_str(), "object" | "object_view")
                    && left.identity == right.identity
            }) {
                let values = if pairs
                    .iter()
                    .any(|(left, right)| left.kind == "object_view" || right.kind == "object_view")
                {
                    BTreeSet::from([0, 1])
                } else {
                    pairs
                        .into_iter()
                        .map(|(left, right)| u32::from(left.offset < right.offset))
                        .collect()
                };
                return finite_value(values, [], alternative_limit);
            }
        }
    }
    if operation == "not" && arguments.len() == 1 {
        let value = &arguments[0];
        if value.kind == "finite" && value.references.is_empty() {
            return finite_value(
                value.scalars.iter().map(|item| u32::from(*item == 0)),
                [],
                alternative_limit,
            );
        }
    }
    finite_value([0, 1], [], alternative_limit)
}

fn is_predicate_operation(operation: &str) -> bool {
    matches!(
        operation,
        "true"
            | "false"
            | "flag"
            | "undefined_flag"
            | "call_flag"
            | "ult32"
            | "eq"
            | "eq_bool"
            | "xor_bool"
            | "not"
            | "and_bool"
            | "or_bool"
            | "parity"
            | "add_overflow"
            | "sub_overflow"
            | "imul_overflow"
            | "mul_carry"
            | "udiv_valid32"
            | "sbb_borrow"
            | "sbb_overflow"
            | "adc_carry"
            | "adc_overflow"
            | "shift_cf"
            | "shift_of"
            | "fpu_pending_exception"
    )
}

fn is_exact_scalar_operation(operation: &str) -> bool {
    matches!(
        operation,
        "mul32"
            | "xor32"
            | "and32"
            | "or32"
            | "not32"
            | "neg32"
            | "shl32"
            | "lshr32"
            | "sar"
            | "sign_extend"
            | "bool_to_bit"
            | "imul_low32"
            | "mul_low32"
            | "imul_high32"
            | "mul_high32"
            | "udiv_quot32"
            | "udiv_rem32"
            | "bsr_index"
            | "tzcnt"
            | "fpu_control_load"
            | "fpu_control_word"
            | "fpu_status_word"
    )
}

fn default_reference_state() -> ReferenceState {
    ReferenceState {
        registers: vec![unknown_value(); REGISTER_COUNT],
        flags: vec![unknown_value(); FLAG_COUNT],
        memory: Arc::new(MemoryMap::default()),
        call_registers: vec![unknown_value(); REGISTER_COUNT],
        call_flags: vec![unknown_value(); FLAG_COUNT],
        invalidated_memory_ranges: Arc::new(BTreeSet::new()),
        all_memory_invalidated: false,
        callback_registry: Arc::new(BTreeMap::new()),
        flag_relations: vec![None; FLAG_COUNT],
        scalar_constraints: BTreeMap::new(),
        preserves_inherited_memory: true,
        relational_object_bindings: Arc::new(BTreeMap::new()),
        written_memory_keys: Arc::new(MemoryKeySet::default()),
        effect_invalidated_memory_ranges: Arc::new(BTreeSet::new()),
        effect_all_memory_invalidated: false,
        possible_allocation_identities: Arc::new(BTreeSet::new()),
    }
}

fn interpret_expression(
    node: &reference_plan::Expression,
    arguments: &[ReferenceValue],
    initial: &ReferenceState,
    current: &ReferenceState,
    catalog: &RuntimeCatalog,
    alternative_limit: usize,
) -> PyResult<ReferenceValue> {
    let operation = node.op.as_str();
    Ok(match operation {
        "const" => catalog.classify_scalar(node.parameters.immediate)?,
        "reg" => {
            let index = node.parameters.aux as usize;
            if index >= REGISTER_COUNT {
                return Err(invalid("register expression index is invalid"));
            }
            if node.parameters.immediate != 0 {
                current.registers[index].clone()
            } else {
                initial.registers[index].clone()
            }
        }
        "flag" => {
            let index = node.parameters.aux as usize;
            if index >= FLAG_COUNT {
                return Err(invalid("flag expression index is invalid"));
            }
            if node.parameters.immediate != 0 {
                current.flags[index].clone()
            } else {
                initial.flags[index].clone()
            }
        }
        "fs_base" | "undefined_bv" => unknown_value(),
        "call_response" => {
            let index = node.parameters.aux as usize;
            if index >= REGISTER_COUNT {
                return Err(invalid("call-response register index is invalid"));
            }
            current.call_registers[index].clone()
        }
        "undefined_flag" => finite_value([0, 1], [], alternative_limit)?,
        "call_flag" => {
            let index = node.parameters.aux as usize;
            if index >= FLAG_COUNT {
                return Err(invalid("call-response flag index is invalid"));
            }
            current.call_flags[index].clone()
        }
        "true" => finite_value([1], [], alternative_limit)?,
        "false" => finite_value([0], [], alternative_limit)?,
        "load" => {
            let Some(keys) = reference_memory_keys(&arguments[0], node.parameters.aux) else {
                return Ok(unknown_value());
            };
            let mut value = bottom_value();
            for key in keys {
                value = join_value(
                    &value,
                    &reference_memory_value(current, &key, catalog)?,
                    alternative_limit,
                )?;
            }
            value
        }
        "add32" | "sub32" => adjusted_reference(
            &arguments[0],
            &arguments[1],
            operation == "sub32",
            alternative_limit,
        )?,
        "ite" => join_value(&arguments[1], &arguments[2], alternative_limit)?,
        operation if is_predicate_operation(operation) => {
            predicate_value(operation, arguments, alternative_limit)?
        }
        operation if is_exact_scalar_operation(operation) => {
            if operation == "and32" {
                if let Some(value) = aligned_object_reference(arguments, alternative_limit)? {
                    value
                } else {
                    scalar_product(arguments, operation, alternative_limit)?
                }
            } else {
                scalar_product(arguments, operation, alternative_limit)?
            }
        }
        _ => unknown_value(),
    })
}

fn evaluate_transfer_expressions(
    transfer: &reference_plan::Transfer,
    initial: &ReferenceState,
    current: &ReferenceState,
    catalog: &RuntimeCatalog,
) -> PyResult<Vec<ReferenceValue>> {
    let alternative_limits = expression_alternative_limits(transfer, catalog);
    let mut values = vec![None; transfer.expressions.len()];
    for index in 0..transfer.expressions.len() {
        evaluate_word(
            index,
            transfer,
            initial,
            current,
            catalog,
            &alternative_limits,
            &mut values,
        )?;
    }
    Ok(values.into_iter().map(Option::unwrap).collect())
}

fn masked_register_subject(
    transfer: &reference_plan::Transfer,
    node_index: usize,
) -> Option<(u8, u32)> {
    let node = &transfer.expressions[node_index];
    if node.op == "reg" && node.parameters.immediate != 0 {
        return u8::try_from(node.parameters.aux)
            .ok()
            .filter(|index| (*index as usize) < REGISTER_COUNT)
            .map(|index| (index, u32::MAX));
    }
    if node.op != "and32" || node.operands.len() != 2 {
        return None;
    }
    if node.operands[0] == node.operands[1] {
        let register = &transfer.expressions[node.operands[0]];
        if register.op == "reg" && register.parameters.immediate != 0 {
            return u8::try_from(register.parameters.aux)
                .ok()
                .filter(|index| (*index as usize) < REGISTER_COUNT)
                .map(|index| (index, u32::MAX));
        }
    }
    for (register_index, mask_index) in [
        (node.operands[0], node.operands[1]),
        (node.operands[1], node.operands[0]),
    ] {
        let register = &transfer.expressions[register_index];
        let mask = &transfer.expressions[mask_index];
        if register.op == "reg" && register.parameters.immediate != 0 && mask.op == "const" {
            if let Ok(index) = u8::try_from(register.parameters.aux) {
                if (index as usize) < REGISTER_COUNT {
                    return Some((index, mask.parameters.immediate));
                }
            }
        }
    }
    None
}

fn scalar_flag_relation(
    transfer: &reference_plan::Transfer,
    node_index: usize,
) -> Option<FlagRelation> {
    let node = &transfer.expressions[node_index];
    if node.op == "ult32" && node.operands.len() == 2 {
        let subject = masked_register_subject(transfer, node.operands[0]);
        let constant = &transfer.expressions[node.operands[1]];
        if let Some((register_index, mask)) = subject {
            if constant.op == "const" {
                return Some(FlagRelation {
                    register_index,
                    mask,
                    relation: "ult".to_owned(),
                    constant: constant.parameters.immediate,
                });
            }
        }
    }
    if node.op != "eq" || node.operands.len() != 2 {
        return None;
    }
    for (masked_index, zero_index) in [
        (node.operands[0], node.operands[1]),
        (node.operands[1], node.operands[0]),
    ] {
        let zero = &transfer.expressions[zero_index];
        if let Some((register_index, mask)) = masked_register_subject(transfer, masked_index) {
            if zero.op == "const" && zero.parameters.immediate == 0 {
                return Some(FlagRelation {
                    register_index,
                    mask,
                    relation: "eq".to_owned(),
                    constant: 0,
                });
            }
        }
    }
    for (difference_index, zero_index) in [
        (node.operands[0], node.operands[1]),
        (node.operands[1], node.operands[0]),
    ] {
        let mut difference = &transfer.expressions[difference_index];
        let zero = &transfer.expressions[zero_index];
        if difference.op == "and32" && difference.operands.len() == 2 {
            if let Some(candidate) = difference
                .operands
                .iter()
                .map(|index| &transfer.expressions[*index])
                .find(|candidate| candidate.op == "sub32")
            {
                difference = candidate;
            }
        }
        if difference.op != "sub32"
            || difference.operands.len() != 2
            || zero.op != "const"
            || zero.parameters.immediate != 0
        {
            continue;
        }
        if let Some((register_index, mask)) =
            masked_register_subject(transfer, difference.operands[0])
        {
            let constant = &transfer.expressions[difference.operands[1]];
            if constant.op == "const" {
                return Some(FlagRelation {
                    register_index,
                    mask,
                    relation: "eq".to_owned(),
                    constant: constant.parameters.immediate,
                });
            }
        }
    }
    None
}

fn branch_flag_relation(
    transfer: &reference_plan::Transfer,
    state: &ReferenceState,
    node_index: usize,
    desired: bool,
) -> Option<(FlagRelation, bool)> {
    let candidate = &transfer.expressions[node_index];
    if candidate.op == "not" && candidate.operands.len() == 1 {
        return branch_flag_relation(transfer, state, candidate.operands[0], !desired);
    }
    if candidate.op != "flag" || candidate.parameters.immediate == 0 {
        return None;
    }
    state.flag_relations[candidate.parameters.aux as usize]
        .clone()
        .map(|relation| (relation, desired))
}

fn branch_scalar_constraint(
    transfer: &reference_plan::Transfer,
    state: &ReferenceState,
    node_index: usize,
    desired: bool,
) -> Option<((u8, u32), BTreeSet<u32>)> {
    let node = &transfer.expressions[node_index];
    if let Some((relation, expected)) = branch_flag_relation(transfer, state, node_index, desired) {
        let allowed = if relation.relation == "eq"
            && expected
            && relation.constant < SCALAR_CONSTRAINT_LIMIT as u32
        {
            [relation.constant & relation.mask].into_iter().collect()
        } else if relation.relation == "ult"
            && expected
            && relation.constant <= SCALAR_CONSTRAINT_LIMIT as u32
        {
            (0..relation.constant).collect()
        } else {
            return None;
        };
        return Some(((relation.register_index, relation.mask), allowed));
    }
    if node.op != "and_bool" || node.operands.len() != 2 || desired {
        return None;
    }
    let decoded = node
        .operands
        .iter()
        .map(|index| branch_flag_relation(transfer, state, *index, true))
        .collect::<Option<Vec<_>>>()?;
    if decoded.iter().any(|(_relation, expected)| *expected) {
        return None;
    }
    let less = decoded
        .iter()
        .map(|(relation, _expected)| relation)
        .find(|relation| relation.relation == "ult")?;
    let equal = decoded
        .iter()
        .map(|(relation, _expected)| relation)
        .find(|relation| relation.relation == "eq")?;
    if less.register_index != equal.register_index
        || less.mask != equal.mask
        || less.constant != equal.constant
        || less.constant >= SCALAR_CONSTRAINT_LIMIT as u32
    {
        return None;
    }
    Some((
        (less.register_index, less.mask),
        (0..=less.constant).collect(),
    ))
}

fn branch_predicate_node(
    transfer: &reference_plan::Transfer,
    mut node_index: usize,
    mut desired: bool,
) -> (usize, bool) {
    let mut seen = BTreeSet::new();
    while seen.insert(node_index) {
        let node = &transfer.expressions[node_index];
        if node.op == "not" && node.operands.len() == 1 {
            node_index = node.operands[0];
            desired = !desired;
            continue;
        }
        if node.op == "flag" && node.parameters.immediate != 0 {
            if let Some(setter) = transfer.effects.iter().rev().find(|action| {
                action.op == "set_flag" && action.parameters.aux == node.parameters.aux
            }) {
                node_index = setter.operands[0];
                continue;
            }
        }
        break;
    }
    (node_index, desired)
}

fn branch_equality_subject(
    transfer: &reference_plan::Transfer,
    values: &[ReferenceValue],
    node_index: usize,
) -> Option<(usize, ReferenceValue)> {
    let node = &transfer.expressions[node_index];
    if !matches!(node.op.as_str(), "eq" | "eq_bool") || node.operands.len() != 2 {
        return None;
    }
    let [left_index, right_index] = [node.operands[0], node.operands[1]];
    let register = |index: usize| {
        let candidate = &transfer.expressions[index];
        (candidate.op == "reg" && candidate.parameters.immediate != 0)
            .then_some(candidate.parameters.aux as usize)
    };
    let constant =
        |index: usize| (transfer.expressions[index].op == "const").then(|| values[index].clone());
    for (register_index, constant_index) in [(left_index, right_index), (right_index, left_index)] {
        if let (Some(register), Some(expected)) =
            (register(register_index), constant(constant_index))
        {
            return Some((register, expected));
        }
    }
    for (difference_index, zero_index) in [(left_index, right_index), (right_index, left_index)] {
        let zero = constant(zero_index);
        let difference = &transfer.expressions[difference_index];
        if zero.as_ref().is_none_or(|value| {
            value.kind != "finite" || !value.references.is_empty() || value.scalars != [0]
        }) || difference.op != "sub32"
            || difference.operands.len() != 2
        {
            continue;
        }
        for (register_index, constant_index) in [
            (difference.operands[0], difference.operands[1]),
            (difference.operands[1], difference.operands[0]),
        ] {
            if let (Some(register), Some(expected)) =
                (register(register_index), constant(constant_index))
            {
                return Some((register, expected));
            }
        }
    }
    for (mask_index, zero_index) in [(left_index, right_index), (right_index, left_index)] {
        let zero = constant(zero_index);
        let mask = &transfer.expressions[mask_index];
        if zero.as_ref().is_none_or(|value| {
            value.kind != "finite" || !value.references.is_empty() || value.scalars != [0]
        }) || mask.op != "and32"
            || mask.operands.len() != 2
            || mask.operands[0] != mask.operands[1]
        {
            continue;
        }
        if let Some(register) = register(mask.operands[0]) {
            return Some((register, zero.expect("checked constant")));
        }
    }
    None
}

fn filter_reference_equality(
    value: &ReferenceValue,
    expected: &ReferenceValue,
    equal: bool,
    alternative_limit: usize,
) -> PyResult<Option<ReferenceValue>> {
    if value.kind != "finite" || expected.kind != "finite" {
        return Ok(Some(value.clone()));
    }
    // Relational words preserve correlation but carry no scalar or pointer
    // fact until the caller binding is substituted into the shared summary.
    let expected_scalars = expected.scalars.iter().copied().collect::<BTreeSet<_>>();
    let expected_references = expected.references.iter().cloned().collect::<BTreeSet<_>>();
    let scalars = value
        .scalars
        .iter()
        .copied()
        .filter(|item| expected_scalars.contains(item) == equal)
        .collect::<BTreeSet<_>>();
    let mut references = BTreeSet::new();
    for item in &value.references {
        let matching = expected_references
            .iter()
            .filter(|candidate| {
                item.kind == "object_view"
                    && matches!(candidate.kind.as_str(), "object" | "object_view")
                    && item.identity == candidate.identity
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        if !matching.is_empty() {
            if equal {
                references.extend(matching);
            } else {
                references.insert(item.clone());
            }
        } else if expected_references.contains(item) == equal {
            references.insert(item.clone());
        }
    }
    if scalars.is_empty() && references.is_empty() {
        return Ok(None);
    }
    finite_value(scalars, references, alternative_limit).map(Some)
}

fn removed_allocation_alternatives(
    before: &ReferenceValue,
    after: &ReferenceValue,
) -> BTreeSet<String> {
    before
        .references
        .iter()
        .filter(|atom| {
            matches!(atom.kind.as_str(), "object" | "object_view")
                && atom.identity.starts_with("allocation:")
                && !after.references.contains(atom)
        })
        .map(|atom| atom.identity.to_string())
        .collect()
}

fn drop_narrowed_allocation_alternatives(state: &mut ReferenceState, removed: BTreeSet<String>) {
    if removed.is_empty() {
        return;
    }
    let disproved = removed
        .into_iter()
        .filter(|identity| {
            let referenced = state
                .registers
                .iter()
                .chain(&state.call_registers)
                .chain(state.memory.values())
                .chain(state.callback_registry.values())
                .chain(state.relational_object_bindings.values())
                .any(|value| {
                    value.references.iter().any(|atom| {
                        matches!(atom.kind.as_str(), "object" | "object_view")
                            && atom.identity.deref() == identity.as_str()
                    })
                });
            if referenced {
                return false;
            }
            !state
                .memory
                .keys()
                .chain(state.written_memory_keys.iter())
                .any(|key| {
                    key.kind.deref() == "object" && key.identity.deref() == identity.as_str()
                })
                && !state
                    .invalidated_memory_ranges
                    .iter()
                    .chain(state.effect_invalidated_memory_ranges.iter())
                    .any(|range| {
                        range.kind.deref() == "object" && range.identity.deref() == identity
                    })
        })
        .collect::<Vec<_>>();
    let possible = Arc::make_mut(&mut state.possible_allocation_identities);
    for identity in disproved {
        possible.remove(&identity);
    }
}

fn refine_state_for_branch(
    transfer: &reference_plan::Transfer,
    state: &ReferenceState,
    values: &[ReferenceValue],
    taken: bool,
    alternative_limit: usize,
) -> PyResult<Option<ReferenceState>> {
    if transfer.terminator.op != "outcome_branch" {
        return Ok(Some(state.clone()));
    }
    let condition = transfer.terminator.operands[0];
    let mut result = state.clone();
    if let Some((key, allowed)) = branch_scalar_constraint(transfer, state, condition, taken) {
        let narrowed = if let Some(previous) = state.scalar_constraints.get(&key) {
            previous.intersection(&allowed).copied().collect()
        } else {
            allowed
        };
        if narrowed.is_empty() {
            return Ok(None);
        }
        result.scalar_constraints.insert(key, narrowed);
    }
    if let Some((relation, equal)) = branch_flag_relation(transfer, state, condition, taken) {
        if relation.relation == "eq" && relation.mask == u32::MAX && relation.constant == 0 {
            let expected = finite_value([0], [], alternative_limit)?;
            let Some(narrowed) = filter_reference_equality(
                &result.registers[relation.register_index as usize],
                &expected,
                equal,
                alternative_limit,
            )?
            else {
                return Ok(None);
            };
            let register = relation.register_index as usize;
            let removed = removed_allocation_alternatives(&result.registers[register], &narrowed);
            result.registers[register] = narrowed;
            drop_narrowed_allocation_alternatives(&mut result, removed);
        }
    }
    let (predicate, desired) = branch_predicate_node(transfer, condition, taken);
    let Some((register, expected)) = branch_equality_subject(transfer, values, predicate) else {
        return Ok(Some(result));
    };
    let Some(narrowed) = filter_reference_equality(
        &result.registers[register],
        &expected,
        desired,
        alternative_limit,
    )?
    else {
        return Ok(None);
    };
    let removed = removed_allocation_alternatives(&result.registers[register], &narrowed);
    result.registers[register] = narrowed;
    drop_narrowed_allocation_alternatives(&mut result, removed);
    Ok(Some(result))
}

fn writes_outside_current_frame(state: &ReferenceState, keys: Option<&[MemoryKey]>) -> bool {
    let Some(keys) = keys else {
        return true;
    };
    let current_frames = state.registers[7]
        .references
        .iter()
        .filter_map(|atom| captured_stack_owner(&atom.identity))
        .collect::<BTreeSet<_>>();
    keys.iter().any(|key| {
        key.kind != "object"
            || captured_stack_owner(&key.identity)
                .is_none_or(|owner| !current_frames.contains(&owner))
    })
}

fn ranges_outside_current_frame(state: &ReferenceState, ranges: &[MemoryRange]) -> bool {
    let current_frames = state.registers[7]
        .references
        .iter()
        .filter_map(|atom| captured_stack_owner(&atom.identity))
        .collect::<BTreeSet<_>>();
    ranges.iter().any(|row| {
        row.kind != "object"
            || captured_stack_owner(&row.identity)
                .is_none_or(|owner| !current_frames.contains(&owner))
    })
}

fn repeated_write_ranges(
    destination: &ReferenceValue,
    count: &ReferenceValue,
    direction: &ReferenceValue,
    width: u32,
) -> PyResult<Option<Vec<MemoryRange>>> {
    let Some(keys) = reference_memory_keys(destination, width) else {
        return Ok(None);
    };
    if count.kind != "finite"
        || !count.references.is_empty()
        || direction.kind != "finite"
        || !direction.references.is_empty()
    {
        return Ok(None);
    }
    let mut ranges = BTreeSet::new();
    for key in keys {
        for repetitions in &count.scalars {
            if *repetitions == 0 {
                continue;
            }
            for backwards in &direction.scalars {
                let (start, end) = if backwards & 1 != 0 {
                    (
                        key.offset
                            .checked_sub((*repetitions as i64 - 1) * width as i64)
                            .ok_or_else(|| invalid("repeat range underflow"))?,
                        key.offset
                            .checked_add(width as i64)
                            .ok_or_else(|| invalid("repeat range overflow"))?,
                    )
                } else {
                    (
                        key.offset,
                        key.offset
                            .checked_add(*repetitions as i64 * width as i64)
                            .ok_or_else(|| invalid("repeat range overflow"))?,
                    )
                };
                ranges.insert(MemoryRange::from_coordinates(
                    key.kind.clone(),
                    key.identity.clone(),
                    i128::from(start),
                    i128::from(end),
                ));
            }
        }
    }
    Ok(Some(ranges.into_iter().collect()))
}

fn object_scoped_repeat_write_ranges(
    destination: &ReferenceValue,
    direction: &ReferenceValue,
    width: u32,
) -> Option<Vec<MemoryRange>> {
    if destination.kind != "finite"
        || !destination.scalars.is_empty()
        || destination.references.is_empty()
        || destination
            .references
            .iter()
            .any(|atom| !matches!(atom.kind.as_str(), "object" | "object_view"))
    {
        return None;
    }
    let directions = if direction.kind == "finite"
        && direction.references.is_empty()
        && !direction.scalars.is_empty()
    {
        Some(
            direction
                .scalars
                .iter()
                .map(|value| value & 1 != 0)
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };
    let mut ranges = BTreeSet::new();
    for atom in &destination.references {
        if atom.kind == "object_view" || directions.is_none() {
            ranges.insert(MemoryRange::from_coordinates(
                "object".into(),
                atom.identity.clone(),
                -(1i128 << 63),
                1i128 << 63,
            ));
            continue;
        }
        for backwards in directions.as_ref().expect("checked directions") {
            ranges.insert(MemoryRange::from_coordinates(
                "object".into(),
                atom.identity.clone(),
                if *backwards {
                    -(1i128 << 63)
                } else {
                    i128::from(atom.offset)
                },
                if *backwards {
                    i128::from(atom.offset) + i128::from(width)
                } else {
                    1i128 << 63
                },
            ));
        }
    }
    Some(ranges.into_iter().collect())
}

fn exact_repeat_shape(
    address: &ReferenceValue,
    count: &ReferenceValue,
    direction: &ReferenceValue,
    width: u32,
) -> Option<(MemoryKey, u32, bool)> {
    let keys = reference_memory_keys(address, width)?;
    if keys.len() != 1
        || count.kind != "finite"
        || !count.references.is_empty()
        || count.scalars.len() != 1
        || direction.kind != "finite"
        || !direction.references.is_empty()
        || direction.scalars.len() != 1
    {
        return None;
    }
    let repetitions = count.scalars[0];
    if repetitions > 256 {
        return None;
    }
    Some((keys[0].clone(), repetitions, direction.scalars[0] & 1 != 0))
}

fn invalidate_ranges(state: &mut ReferenceState, ranges: &[MemoryRange]) {
    Arc::make_mut(&mut state.invalidated_memory_ranges).extend(ranges.iter().cloned());
    Arc::make_mut(&mut state.effect_invalidated_memory_ranges).extend(ranges.iter().cloned());
    let removed = state
        .memory
        .keys()
        .filter(|key| {
            ranges.iter().any(|row| {
                row.kind == key.kind
                    && row.identity == key.identity
                    && i128::from(key.offset) < row.end()
                    && row.start() < i128::from(key.offset) + i128::from(key.width)
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    for key in removed {
        Arc::make_mut(&mut state.memory).remove(&key);
    }
}

fn invalidate_all_memory(state: &mut ReferenceState) {
    state.all_memory_invalidated = true;
    Arc::make_mut(&mut state.invalidated_memory_ranges).clear();
    state.effect_all_memory_invalidated = true;
    Arc::make_mut(&mut state.effect_invalidated_memory_ranges).clear();
    Arc::make_mut(&mut state.written_memory_keys).clear();
    Arc::make_mut(&mut state.memory).clear();
}

fn adjust_reference_by_constant(
    value: &ReferenceValue,
    delta: i64,
    alternative_limit: usize,
) -> PyResult<ReferenceValue> {
    let magnitude = u32::try_from(delta.unsigned_abs())
        .map_err(|_| invalid("reference delta exceeds a word"))?;
    adjusted_reference(
        value,
        &finite_value([magnitude], [], alternative_limit)?,
        delta < 0,
        alternative_limit,
    )
}

fn dynamic_stack_region(
    transfer: &reference_plan::Transfer,
    node_index: usize,
    base: &ReferenceValue,
    catalog: &RuntimeCatalog,
) -> PyResult<Option<ReferenceValue>> {
    // Use a stable allocation-site abstraction.  Including the previous stack
    // object's identity here recursively minted one semantic object per loop
    // visit and made the result depend on worklist order.  Merging executions
    // of one site within one captured-frame owner is conservative and reaches
    // the same fixed point under every deterministic schedule.
    if base.kind != "finite"
        || !base.scalars.is_empty()
        || base.references.is_empty()
        || base
            .references
            .iter()
            .any(|atom| atom.kind != "object" || captured_stack_owner(&atom.identity).is_none())
    {
        return Ok(None);
    }
    let references = base.references.iter().map(|atom| ReferenceAtom {
        kind: "object".to_owned(),
        identity: format!(
            "dynamic_stack_region:{}|{}:{node_index}",
            captured_stack_owner(&atom.identity).expect("checked captured stack owner"),
            transfer.identity(),
        )
        .into(),
        offset: 0,
    });
    finite_value(
        [],
        references,
        catalog.alternative_limit.max(STACK_ALTERNATIVE_LIMIT),
    )
    .map(Some)
}

fn call_argument_values(
    call: &reference_plan::Call,
    argument_words: usize,
    base_offset: u32,
    transfer: &reference_plan::Transfer,
    initial: &ReferenceState,
    current: &ReferenceState,
    catalog: &RuntimeCatalog,
    alternative_limits: &[usize],
    values: &mut [Option<ReferenceValue>],
) -> PyResult<Vec<ReferenceValue>> {
    if !call.argument_nodes.is_empty() {
        return call
            .argument_nodes
            .iter()
            .map(|index| {
                evaluate_word(
                    *index,
                    transfer,
                    initial,
                    current,
                    catalog,
                    alternative_limits,
                    values,
                )
            })
            .collect();
    }
    let maximum = call
        .stack_inputs
        .iter()
        .filter(|(offset, _width, _node)| {
            *offset >= base_offset && (*offset - base_offset) % 4 == 0
        })
        .map(|(offset, _width, _node)| ((*offset - base_offset) / 4) as usize)
        .max();
    let count = argument_words.max(maximum.map_or(0, |index| index + 1));
    if count == 0 {
        return Ok(Vec::new());
    }
    let mut arguments = vec![None; count];
    for (offset, width, node) in &call.stack_inputs {
        if *width != 4 || *offset < base_offset || (*offset - base_offset) % 4 != 0 {
            continue;
        }
        let index = ((*offset - base_offset) / 4) as usize;
        if index < count {
            arguments[index] = Some(evaluate_word(
                *node,
                transfer,
                initial,
                current,
                catalog,
                alternative_limits,
                values,
            )?);
        }
    }
    let stack = evaluate_word(
        call.register_nodes[7],
        transfer,
        initial,
        current,
        catalog,
        alternative_limits,
        values,
    )?;
    for (index, argument) in arguments.iter_mut().enumerate() {
        if argument.is_some() {
            continue;
        }
        let address = adjust_reference_by_constant(
            &stack,
            base_offset as i64 + index as i64 * 4,
            catalog.alternative_limit,
        )?;
        let Some(keys) = reference_memory_keys(&address, 4) else {
            *argument = Some(unknown_value());
            continue;
        };
        let mut value = bottom_value();
        for key in keys {
            value = join_value(
                &value,
                &reference_memory_value(current, &key, catalog)?,
                catalog.alternative_limit,
            )?;
        }
        *argument = Some(value);
    }
    Ok(arguments.into_iter().map(Option::unwrap).collect())
}

fn external_write_ranges(
    footprint: &ExternalWritePayload,
    arguments: &[ReferenceValue],
) -> PyResult<Option<Vec<MemoryRange>>> {
    if footprint.base_argument >= arguments.len() {
        return Ok(None);
    }
    let base = &arguments[footprint.base_argument];
    if base.kind != "finite" {
        return Ok(None);
    }
    let extent = if let Some(bytes) = footprint.fixed_bytes {
        Some(bytes as i64)
    } else if let Some(index) = footprint.size_argument {
        let Some(size) = arguments.get(index) else {
            return Ok(None);
        };
        if size.kind != "finite" || !size.references.is_empty() || size.scalars.is_empty() {
            None
        } else {
            Some(
                *size.scalars.iter().max().expect("checked nonempty size") as i64
                    * footprint.scale as i64,
            )
        }
    } else {
        None
    };
    if extent.is_some_and(|value| !(0..=u32::MAX as i64).contains(&value)) {
        return Ok(None);
    }
    let mut ranges = BTreeSet::new();
    for atom in &base.references {
        if !matches!(atom.kind.as_str(), "object" | "object_view") {
            return Ok(None);
        }
        if footprint
            .authority_selector
            .as_ref()
            .is_some_and(|selector| selector != &atom.identity)
        {
            return Ok(None);
        }
        if atom.kind == "object_view" {
            ranges.insert(MemoryRange::from_coordinates(
                "object".into(),
                atom.identity.clone(),
                -(1i128 << 63),
                1i128 << 63,
            ));
            continue;
        }
        let start = atom
            .offset
            .checked_add(footprint.offset)
            .ok_or_else(|| invalid("external write offset overflow"))?;
        ranges.insert(MemoryRange::from_coordinates(
            "object".into(),
            atom.identity.clone(),
            i128::from(start),
            if let Some(extent) = extent {
                i128::from(start)
                    .checked_add(i128::from(extent))
                    .ok_or_else(|| invalid("external write extent overflow"))?
            } else {
                1i128 << 63
            },
        ));
    }
    for scalar in &base.scalars {
        if *scalar == 0 {
            continue;
        }
        let Some(extent) = extent else {
            return Ok(None);
        };
        let start = *scalar as i64 + footprint.offset;
        ranges.insert(MemoryRange::from_coordinates(
            "absolute".into(),
            "".into(),
            i128::from(start),
            i128::from(start) + i128::from(extent),
        ));
    }
    Ok(Some(ranges.into_iter().collect()))
}

fn external_memory_copy_words(
    relation: &ExternalMemoryCopyPayload,
    arguments: &[ReferenceValue],
    state: &ReferenceState,
    catalog: &RuntimeCatalog,
) -> Option<Vec<(MemoryKey, ReferenceValue)>> {
    let destination = arguments.get(relation.destination_argument)?;
    let source = arguments.get(relation.source_argument)?;
    let size = arguments.get(relation.size_argument)?;
    if destination.kind != "finite"
        || !destination.scalars.is_empty()
        || destination.references.len() != 1
        || destination.references[0].kind != "object"
        || source.kind != "finite"
        || !source.scalars.is_empty()
        || source.references.len() != 1
        || source.references[0].kind != "object"
        || size.kind != "finite"
        || !size.references.is_empty()
        || size.scalars.len() != 1
    {
        return None;
    }
    let extent = u64::from(size.scalars[0]).checked_mul(u64::from(relation.scale))?;
    let destination = &destination.references[0];
    let source = &source.references[0];
    let mut available = state.memory.keys().cloned().collect::<BTreeSet<_>>();
    available.extend(catalog.initial_memory.keys().cloned());
    let invalidated = invalidation_index(&state.invalidated_memory_ranges);
    let mut copied = Vec::new();
    for key in available {
        if key.kind != "object" || key.identity != source.identity {
            continue;
        }
        let relative = i128::from(key.offset) - i128::from(source.offset);
        if relative < 0 || relative + i128::from(key.width) > i128::from(extent) {
            continue;
        }
        let value = memory_value(state, &key, &catalog.initial_memory, &invalidated);
        if value.kind != "finite" {
            continue;
        }
        let offset = i128::from(destination.offset).checked_add(relative)?;
        let offset = i64::try_from(offset).ok()?;
        copied.push((
            MemoryKey::new("object", destination.identity.clone(), offset, key.width),
            value,
        ));
    }
    Some(copied)
}

fn apply_external_call(
    rule: &ExternalCallPayload,
    call: &reference_plan::Call,
    transfer: &reference_plan::Transfer,
    initial: &ReferenceState,
    current: &mut ReferenceState,
    catalog: &RuntimeCatalog,
    alternative_limits: &[usize],
    values: &mut [Option<ReferenceValue>],
) -> PyResult<Option<Vec<ReferenceValue>>> {
    current.call_registers.fill(unknown_value());
    current.call_flags.fill(unknown_value());
    for register in &rule.preserved_registers {
        current.call_registers[*register as usize] = evaluate_word(
            call.register_nodes[*register as usize],
            transfer,
            initial,
            current,
            catalog,
            alternative_limits,
            values,
        )?;
    }
    if rule.preserved_registers.contains(&7) && rule.stack_cleanup_bytes != 0 {
        current.call_registers[7] = adjust_reference_by_constant(
            &current.call_registers[7],
            rule.stack_cleanup_bytes as i64,
            catalog.alternative_limit,
        )?;
    }
    let arguments = call_argument_values(
        call,
        rule.argument_words,
        if transfer.terminator.op == "outcome_external" {
            4
        } else {
            0
        },
        transfer,
        initial,
        current,
        catalog,
        alternative_limits,
        values,
    )?;
    if rule.module_handle_name_argument.is_some() {
        current.call_registers[0] = module_handle_result(rule, &arguments, catalog)?;
    }
    if rule.dynamic_export_handle_argument.is_some() {
        current.call_registers[0] = dynamic_export_result(rule, &arguments, catalog)?;
    }
    let mut write_ranges = BTreeSet::new();
    let mut precise_writes = !rule.unknown_guest_memory_write;
    for footprint in &rule.write_footprints {
        let Some(ranges) = external_write_ranges(footprint, &arguments)? else {
            precise_writes = false;
            break;
        };
        write_ranges.extend(ranges);
    }
    let copy_writes = rule
        .memory_copies
        .iter()
        .filter_map(|relation| {
            external_memory_copy_words(relation, &arguments, current, catalog)
        })
        .flatten()
        .collect::<Vec<_>>();
    let mut out_pointer_writes = Vec::new();
    if precise_writes {
        for (index, relation) in rule.out_pointers.iter().enumerate() {
            let Some(argument) = arguments.get(relation.argument) else {
                precise_writes = false;
                break;
            };
            let destination = adjust_reference_by_constant(
                argument,
                relation.offset as i64,
                catalog.alternative_limit,
            )?;
            let Some(keys) = reference_memory_keys(&destination, 4) else {
                precise_writes = false;
                break;
            };
            write_ranges.extend(keys.iter().map(|key| {
                MemoryRange::from_coordinates(
                    key.kind.clone(),
                    key.identity.clone(),
                    i128::from(key.offset),
                    i128::from(key.offset) + i128::from(key.width),
                )
            }));
            let allocation_identity = format!(
                "external-out-pointer:{}:{:08x}:{}:{index}",
                transfer.identity(),
                call.instruction_rva,
                call.event_index,
            );
            let pointer = finite_value(
                if relation.nullable {
                    vec![0]
                } else {
                    Vec::new()
                },
                [ReferenceAtom {
                    kind: "object".into(),
                    identity: allocation_identity.clone().into(),
                    offset: 0,
                }],
                catalog.alternative_limit,
            )?;
            out_pointer_writes.push((keys, pointer));
        }
    }
    if !precise_writes {
        current.preserves_inherited_memory = false;
        invalidate_all_memory(current);
    } else if !write_ranges.is_empty() {
        let ranges = write_ranges.into_iter().collect::<Vec<_>>();
        if ranges_outside_current_frame(current, &ranges) {
            current.preserves_inherited_memory = false;
        }
        invalidate_ranges(current, &ranges);
        for (key, copied) in copy_writes {
            Arc::make_mut(&mut current.memory).insert(key.clone(), copied);
            Arc::make_mut(&mut current.written_memory_keys).insert(key);
        }
        for (keys, pointer) in out_pointer_writes {
            for key in keys {
                Arc::make_mut(&mut current.memory).insert(key.clone(), pointer.clone());
                Arc::make_mut(&mut current.written_memory_keys).insert(key);
            }
        }
    }
    if let Some(callback) = &rule.callback {
        let source = callback_source_value(callback, &arguments, current, catalog)?;
        let instance_keys: Option<Vec<String>> = if matches!(
            callback.instance_kind.as_str(), "singleton" | "registration_sequence"
        ) {
            Some(vec![callback.protocol_id.clone()])
        } else if let Some(index) = callback.instance_argument {
            arguments.get(index).and_then(|instance| {
                if instance.kind != "finite" {
                    return None;
                }
                if callback.instance_kind == "provider_resource" {
                    let mut keys = instance
                        .scalars
                        .iter()
                        .map(|value| format!(
                            "{}:provider-resource:scalar:{value:08x}",
                            callback.protocol_id,
                        ))
                        .collect::<Vec<_>>();
                    keys.extend(instance.references.iter().map(|atom| format!(
                        "{}:provider-resource:{}:{}:{}",
                        callback.protocol_id, atom.kind, atom.identity, atom.offset,
                    )));
                    (!keys.is_empty()).then_some(keys)
                } else if instance.references.is_empty() {
                    Some(
                        instance
                            .scalars
                            .iter()
                            .map(|value| format!("{}:argument:{value:08x}", callback.protocol_id))
                            .collect(),
                    )
                } else {
                    None
                }
            })
        } else {
            None
        };
        if callback.action == "replace" {
            if let Some(register) = callback.previous_result_register {
                let defaults = finite_value(
                    callback.previous_sentinels.iter().copied(),
                    [],
                    catalog.alternative_limit,
                )?;
                let mut previous = bottom_value();
                if let Some(keys) = &instance_keys {
                    for key in keys {
                        previous = join_value(
                            &previous,
                            current.callback_registry.get(key).unwrap_or(&defaults),
                            catalog.alternative_limit,
                        )?;
                    }
                } else {
                    previous = unknown_value();
                }
                current.call_registers[register as usize] = previous;
            }
        }
        if let Some(keys) = instance_keys {
            for key in keys {
                Arc::make_mut(&mut current.callback_registry).insert(key, source.clone());
            }
        } else {
            Arc::make_mut(&mut current.callback_registry).insert(
                format!("{}:unknown-instance", callback.protocol_id),
                unknown_value(),
            );
        }
        let _checked_protocol = (
            &callback.action,
            &callback.lifetime,
            &callback.delivery_thread,
            &callback.delivery_timing,
            &callback.sentinels,
        );
    }
    if let Some(register) = rule.allocation_result_register {
        let allocation_identity = format!(
            "allocation:{}:{:08x}:{}",
            transfer.identity(),
            call.instruction_rva,
            call.event_index,
        );
        current.call_registers[register as usize] = finite_value(
            if rule.allocation_nullable {
                vec![0]
            } else {
                Vec::new()
            },
            [ReferenceAtom {
                kind: "object".to_owned(),
                identity: allocation_identity.clone().into(),
                offset: 0,
            }],
            catalog.alternative_limit,
        )?;
        Arc::make_mut(&mut current.possible_allocation_identities).insert(allocation_identity);
    }
    let _checked_disposition = &rule.disposition;
    Ok((!precise_writes).then_some(arguments))
}

fn static_loader_name(
    value: &ReferenceValue,
    catalog: &RuntimeCatalog,
    wide: bool,
) -> Option<String> {
    if value.kind != "finite" || !value.scalars.is_empty() || value.references.is_empty() {
        return None;
    }
    let mut names = BTreeSet::new();
    for atom in &value.references {
        if atom.kind != "object" || atom.offset < 0 {
            return None;
        }
        let data = catalog.object_bytes.get(&*atom.identity)?;
        let start = usize::try_from(atom.offset).ok()?;
        if start >= data.len() {
            return None;
        }
        let suffix = &data[start..data.len().min(start.saturating_add(MAX_STRING_BYTES))];
        let name = if wide {
            let end = (0..suffix.len().saturating_sub(1))
                .step_by(2)
                .find(|index| suffix[*index] == 0 && suffix[*index + 1] == 0)?;
            let units = suffix[..end]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            String::from_utf16(&units).ok()?
        } else {
            let end = suffix.iter().position(|byte| *byte == 0)?;
            let bytes = &suffix[..end];
            if !bytes.is_ascii() {
                return None;
            }
            String::from_utf8(bytes.to_vec()).ok()?
        };
        names.insert(name);
    }
    if names.len() == 1 {
        names.into_iter().next()
    } else {
        None
    }
}

fn module_handle_result(
    rule: &ExternalCallPayload,
    arguments: &[ReferenceValue],
    catalog: &RuntimeCatalog,
) -> PyResult<ReferenceValue> {
    let Some(index) = rule.module_handle_name_argument else {
        return Ok(unknown_value());
    };
    let Some(argument) = arguments.get(index) else {
        return Ok(unknown_value());
    };
    let module_name = if rule.module_handle_nullable_name
        && argument.kind == "finite"
        && argument.scalars == [0]
        && argument.references.is_empty()
    {
        "<process-image>".to_owned()
    } else {
        let Some(name) = static_loader_name(argument, catalog, rule.module_handle_wide_name) else {
            return Ok(unknown_value());
        };
        name.to_lowercase()
    };
    finite_value(
        [0],
        [ReferenceAtom {
            kind: "loader_module".to_owned(),
            identity: module_name.into(),
            offset: 0,
        }],
        catalog.alternative_limit,
    )
}

fn dynamic_export_result(
    rule: &ExternalCallPayload,
    arguments: &[ReferenceValue],
    catalog: &RuntimeCatalog,
) -> PyResult<ReferenceValue> {
    let (Some(handle_index), Some(name_index)) = (
        rule.dynamic_export_handle_argument,
        rule.dynamic_export_name_argument,
    ) else {
        return Ok(unknown_value());
    };
    let (Some(handles), Some(name_value)) =
        (arguments.get(handle_index), arguments.get(name_index))
    else {
        return Ok(unknown_value());
    };
    if handles.kind != "finite"
        || !handles.scalars.is_empty()
        || handles.references.is_empty()
        || handles
            .references
            .iter()
            .any(|atom| atom.kind != "loader_module" || atom.offset != 0)
    {
        return Ok(unknown_value());
    }
    let export_identity = if name_value.kind == "finite"
        && name_value.references.is_empty()
        && name_value.scalars.len() == 1
        && (1..=0xffff).contains(&name_value.scalars[0])
    {
        format!("ordinal:{}", name_value.scalars[0])
    } else {
        let Some(name) = static_loader_name(name_value, catalog, false) else {
            return Ok(unknown_value());
        };
        name
    };
    let mut targets = BTreeSet::new();
    for handle in &handles.references {
        let Some(target) = rule
            .dynamic_export_results
            .iter()
            .find(|row| row.dll == handle.identity && row.identity == export_identity)
            .map(|row| row.target.clone())
        else {
            return Ok(unknown_value());
        };
        targets.insert(ReferenceAtom {
            kind: "external_function".to_owned(),
            identity: target.into(),
            offset: 0,
        });
    }
    finite_value([0], targets, catalog.alternative_limit)
}

fn shared_external_field<T: Clone + Eq>(
    rows: &[&ExternalCallPayload],
    field: impl Fn(&ExternalCallPayload) -> T,
) -> Option<T> {
    let candidate = field(rows.first()?);
    rows.iter()
        .skip(1)
        .all(|row| field(row) == candidate)
        .then_some(candidate)
}

fn merged_external_call_rule(rows: &[&ExternalCallPayload]) -> Option<ExternalCallPayload> {
    let first = (*rows.first()?).clone();
    let cleanup_shared = rows
        .iter()
        .all(|row| row.stack_cleanup_bytes == first.stack_cleanup_bytes);
    let mut preserved = first
        .preserved_registers
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    for row in &rows[1..] {
        preserved.retain(|register| row.preserved_registers.contains(register));
    }
    if !cleanup_shared {
        preserved.remove(&7);
    }
    let mut write_footprints = BTreeSet::new();
    let memory_copies = rows
        .iter()
        .all(|row| row.memory_copies == first.memory_copies)
        .then_some(first.memory_copies.clone())
        .unwrap_or_default();
    let mut out_pointers = BTreeSet::new();
    for row in rows {
        write_footprints.extend(row.write_footprints.iter().cloned());
        out_pointers.extend(row.out_pointers.iter().cloned());
    }
    Some(ExternalCallPayload {
        dll: first.dll,
        identity: first.identity,
        contract_sha256: shared_external_field(rows, |row| {
            row.contract_sha256.clone()
        })
        .flatten(),
        loader_service_contract_sha256: shared_external_field(rows, |row| {
            row.loader_service_contract_sha256.clone()
        })
        .flatten(),
        preserved_registers: preserved.into_iter().collect(),
        argument_words: if rows
            .iter()
            .all(|row| row.argument_words == first.argument_words)
        {
            first.argument_words
        } else {
            0
        },
        stack_cleanup_bytes: if cleanup_shared {
            first.stack_cleanup_bytes
        } else {
            0
        },
        disposition: if rows.iter().all(|row| row.disposition == first.disposition) {
            first.disposition
        } else {
            "returns".to_owned()
        },
        allocation_result_register: if rows
            .iter()
            .all(|row| row.allocation_result_register == first.allocation_result_register)
        {
            first.allocation_result_register
        } else {
            None
        },
        allocation_nullable: if rows
            .iter()
            .all(|row| row.allocation_nullable == first.allocation_nullable)
        {
            first.allocation_nullable
        } else {
            true
        },
        write_footprints: write_footprints.into_iter().collect(),
        memory_copies,
        out_pointers: out_pointers.into_iter().collect(),
        unknown_guest_memory_write: rows.iter().any(|row| row.unknown_guest_memory_write),
        callback: rows
            .iter()
            .all(|row| row.callback == first.callback)
            .then_some(first.callback)
            .flatten(),
        module_handle_name_argument: shared_external_field(rows, |row| {
            row.module_handle_name_argument
        })
        .flatten(),
        module_handle_nullable_name: shared_external_field(rows, |row| {
            row.module_handle_nullable_name
        })
        .unwrap_or(false),
        module_handle_wide_name: shared_external_field(rows, |row| row.module_handle_wide_name)
            .unwrap_or(false),
        dynamic_export_handle_argument: shared_external_field(rows, |row| {
            row.dynamic_export_handle_argument
        })
        .flatten(),
        dynamic_export_name_argument: shared_external_field(rows, |row| {
            row.dynamic_export_name_argument
        })
        .flatten(),
        dynamic_export_results: if rows
            .iter()
            .all(|row| row.dynamic_export_results == first.dynamic_export_results)
        {
            first.dynamic_export_results
        } else {
            Vec::new()
        },
    })
}

fn external_call_rule(
    call: &reference_plan::Call,
    transfer: &reference_plan::Transfer,
    initial: &ReferenceState,
    current: &ReferenceState,
    catalog: &RuntimeCatalog,
    alternative_limits: &[usize],
    values: &mut [Option<ReferenceValue>],
) -> PyResult<Option<ExternalCallPayload>> {
    if call.kind == "external_call" {
        let identity = if let Some(symbol) = &call.symbol {
            symbol.clone()
        } else if let Some(ordinal) = call.ordinal {
            format!("ordinal:{ordinal}")
        } else {
            return Err(invalid("external call has no identity"));
        };
        return Ok(catalog
            .external_calls
            .get(&(
                call.dll.clone().unwrap_or_default().to_lowercase(),
                identity,
            ))
            .cloned());
    }
    let Some(target_node) = call.target_node else {
        return Ok(None);
    };
    let target = evaluate_word(
        target_node,
        transfer,
        initial,
        current,
        catalog,
        alternative_limits,
        values,
    )?;
    if target.kind != "finite" || !target.scalars.is_empty() || target.references.is_empty() {
        return Ok(None);
    }
    let mut rules = Vec::new();
    for atom in &target.references {
        if atom.kind != "external_function" || atom.offset != 0 {
            return Ok(None);
        }
        let Some(key) = catalog.external_function_contracts.get(&*atom.identity) else {
            return Ok(None);
        };
        let Some(rule) = catalog.external_calls.get(key) else {
            return Ok(None);
        };
        rules.push(rule);
    }
    Ok(merged_external_call_rule(&rules))
}

fn register_index(name: &str) -> Option<usize> {
    match name {
        "eax" => Some(0),
        "ebx" => Some(1),
        "ecx" => Some(2),
        "edx" => Some(3),
        "esi" => Some(4),
        "edi" => Some(5),
        "ebp" => Some(6),
        "esp" => Some(7),
        _ => None,
    }
}

fn typed_x87_memory_address(
    row: &reference_plan::X87Intrinsic,
    current: &ReferenceState,
    catalog: &RuntimeCatalog,
) -> PyResult<ReferenceValue> {
    let operand = &row.operation.operand;
    let Some(address) = &operand.address else {
        return Err(invalid("typed x87 memory operand has no address"));
    };
    if let Some(image_rva) = address.image_rva {
        let absolute = row
            .image_base
            .checked_add(image_rva)
            .ok_or_else(|| invalid("typed x87 image address overflows"))?;
        return catalog.classify_scalar(absolute);
    }
    let mut result = if let Some(base) = &address.base {
        current.registers[register_index(base)
            .ok_or_else(|| invalid("typed x87 memory operand has an invalid base register"))?]
        .clone()
    } else {
        finite_value([0], [], catalog.alternative_limit)?
    };
    if let Some(index) = &address.index {
        let index_value = current.registers[register_index(index)
            .ok_or_else(|| invalid("typed x87 memory operand has an invalid index register"))?]
        .clone();
        let scale = finite_value([address.scale], [], catalog.alternative_limit)?;
        let product = scalar_product(&[index_value, scale], "mul32", catalog.alternative_limit)?;
        result = adjusted_reference(&result, &product, false, catalog.alternative_limit)?;
    }
    adjust_reference_by_constant(&result, address.displacement, catalog.alternative_limit)
}

fn apply_typed_x87_effect(
    row: &reference_plan::X87Intrinsic,
    current: &mut ReferenceState,
    catalog: &RuntimeCatalog,
) -> PyResult<()> {
    let operation = &row.operation;
    if operation.operand.kind == "ax" {
        current.registers[0] = unknown_value();
    }
    if X87_FLAG_WRITE_MNEMONICS.contains(&operation.mnemonic.as_str()) {
        for index in [0, 1, 4] {
            current.flags[index] = unknown_value();
            current.flag_relations[index] = None;
        }
    }
    if operation.operand.kind != "memory"
        || !X87_MEMORY_WRITE_MNEMONICS.contains(&operation.mnemonic.as_str())
    {
        return Ok(());
    }
    let address = typed_x87_memory_address(row, current, catalog)?;
    let keys = reference_memory_keys(&address, operation.operand.width);
    if keys.is_none() {
        current.preserves_inherited_memory = false;
        invalidate_all_memory(current);
        return Ok(());
    }
    let keys = keys.expect("checked keys");
    if writes_outside_current_frame(current, Some(&keys)) {
        current.preserves_inherited_memory = false;
    }
    let ranges = keys
        .into_iter()
        .map(|key| {
            MemoryRange::from_coordinates(
                key.kind.clone(),
                key.identity.clone(),
                i128::from(key.offset),
                i128::from(key.offset) + i128::from(key.width),
            )
        })
        .collect::<Vec<_>>();
    invalidate_ranges(current, &ranges);
    Ok(())
}

fn evaluate_word(
    index: usize,
    transfer: &reference_plan::Transfer,
    initial: &ReferenceState,
    current: &ReferenceState,
    catalog: &RuntimeCatalog,
    alternative_limits: &[usize],
    values: &mut [Option<ReferenceValue>],
) -> PyResult<ReferenceValue> {
    if let Some(value) = &values[index] {
        return Ok(value.clone());
    }
    let node = &transfer.expressions[index];
    let mut arguments = Vec::with_capacity(node.operands.len());
    for argument in &node.operands {
        arguments.push(evaluate_word(
            *argument,
            transfer,
            initial,
            current,
            catalog,
            alternative_limits,
            values,
        )?);
    }
    let subject = matches!(node.op.as_str(), "and32" | "reg")
        .then(|| masked_register_subject(transfer, index))
        .flatten();
    let value = if let Some(allowed) = subject.and_then(|key| current.scalar_constraints.get(&key))
    {
        finite_value(allowed.iter().copied(), [], STACK_ALTERNATIVE_LIMIT)?
    } else {
        interpret_expression(
            node,
            &arguments,
            initial,
            current,
            catalog,
            alternative_limits[index],
        )?
    };
    values[index] = Some(value.clone());
    Ok(value)
}

fn expression_alternative_limits(
    transfer: &reference_plan::Transfer,
    catalog: &RuntimeCatalog,
) -> Vec<usize> {
    let mut widened = BTreeSet::new();
    let mut pending = transfer
        .effects
        .iter()
        .filter(|effect| effect.op == "set_reg" && effect.parameters.aux == 7)
        .filter_map(|effect| effect.operands.first().copied())
        .collect::<Vec<_>>();
    if transfer.terminator.op == "outcome_indirect" || transfer.terminator.op == "outcome_nonlocal"
    {
        pending.extend(transfer.terminator.operands.first().copied());
    }
    pending.extend(transfer.calls.iter().filter_map(|call| call.target_node));
    while let Some(index) = pending.pop() {
        if !widened.insert(index) {
            continue;
        }
        pending.extend(transfer.expressions[index].operands.iter().copied());
    }
    (0..transfer.expressions.len())
        .map(|index| {
            if widened.contains(&index) {
                catalog.alternative_limit.max(STACK_ALTERNATIVE_LIMIT)
            } else {
                catalog.alternative_limit
            }
        })
        .collect()
}

#[allow(dead_code)] // Consumed by the resident fixed-point increment next.
struct EffectApplication {
    state: ReferenceState,
    values: Vec<ReferenceValue>,
    call_input_states: BTreeMap<usize, ReferenceState>,
    unresolved_external_writes: BTreeMap<usize, Vec<ReferenceValue>>,
    effect_input_states: BTreeMap<usize, ReferenceState>,
}

fn apply_reference_effects(
    transfer: &reference_plan::Transfer,
    initial: &ReferenceState,
    catalog: &RuntimeCatalog,
    overrides: Option<&BTreeMap<usize, ReferenceState>>,
) -> PyResult<EffectApplication> {
    let mut current = initial.clone();
    let mut values = vec![None; transfer.expressions.len()];
    let alternative_limits = expression_alternative_limits(transfer, catalog);
    let mut call_input_states = BTreeMap::new();
    let mut unresolved_external_writes = BTreeMap::new();
    let mut effect_input_states = BTreeMap::new();
    for (effect_index, action) in transfer.effects.iter().enumerate() {
        effect_input_states.insert(effect_index, current.clone());
        match action.op.as_str() {
            "eval_word" => {
                evaluate_word(
                    action.operands[0],
                    transfer,
                    initial,
                    &current,
                    catalog,
                    &alternative_limits,
                    &mut values,
                )?;
            }
            "set_reg" => {
                let register = action.parameters.aux as usize;
                if register >= REGISTER_COUNT {
                    return Err(invalid("set-reg index is invalid"));
                }
                let mut assigned = evaluate_word(
                    action.operands[0],
                    transfer,
                    initial,
                    &current,
                    catalog,
                    &alternative_limits,
                    &mut values,
                )?;
                let assigned_node = &transfer.expressions[action.operands[0]];
                if register == 7
                    && matches!(assigned.kind.as_str(), "unknown_scalar" | "conflict")
                    && assigned_node.op == "sub32"
                {
                    let base = evaluate_word(
                        assigned_node.operands[0],
                        transfer,
                        initial,
                        &current,
                        catalog,
                        &alternative_limits,
                        &mut values,
                    )?;
                    if let Some(region) =
                        dynamic_stack_region(transfer, action.operands[0], &base, catalog)?
                    {
                        assigned = region;
                    }
                }
                current
                    .scalar_constraints
                    .retain(|(index, _mask), _values| *index as usize != register);
                for relation in &mut current.flag_relations {
                    if relation
                        .as_ref()
                        .is_some_and(|relation| relation.register_index as usize == register)
                    {
                        *relation = None;
                    }
                }
                current.registers[register] = assigned;
            }
            "set_flag" => {
                let flag = action.parameters.aux as usize;
                if flag >= FLAG_COUNT {
                    return Err(invalid("set-flag index is invalid"));
                }
                current.flags[flag] = evaluate_word(
                    action.operands[0],
                    transfer,
                    initial,
                    &current,
                    catalog,
                    &alternative_limits,
                    &mut values,
                )?;
                current.flag_relations[flag] = scalar_flag_relation(transfer, action.operands[0]);
            }
            "memory_write" | "atomic_exchange" => {
                let keys = reference_memory_keys(
                    &evaluate_word(
                        action.operands[0],
                        transfer,
                        initial,
                        &current,
                        catalog,
                        &alternative_limits,
                        &mut values,
                    )?,
                    action.parameters.aux,
                );
                if writes_outside_current_frame(&current, keys.as_deref()) {
                    current.preserves_inherited_memory = false;
                }
                if let Some(keys) = keys {
                    let value = evaluate_word(
                        action.operands[1],
                        transfer,
                        initial,
                        &current,
                        catalog,
                        &alternative_limits,
                        &mut values,
                    )?;
                    for key in keys {
                        Arc::make_mut(&mut current.memory).insert(key.clone(), value.clone());
                        Arc::make_mut(&mut current.written_memory_keys).insert(key);
                    }
                }
            }
            "atomic_compare_exchange" => {
                let keys = reference_memory_keys(
                    &evaluate_word(
                        action.operands[0],
                        transfer,
                        initial,
                        &current,
                        catalog,
                        &alternative_limits,
                        &mut values,
                    )?,
                    action.parameters.aux,
                );
                if writes_outside_current_frame(&current, keys.as_deref()) {
                    current.preserves_inherited_memory = false;
                }
                if let Some(keys) = keys {
                    let replacement = evaluate_word(
                        action.operands[2],
                        transfer,
                        initial,
                        &current,
                        catalog,
                        &alternative_limits,
                        &mut values,
                    )?;
                    for key in keys {
                        let value = join_value(
                            &reference_memory_value(&current, &key, catalog)?,
                            &replacement,
                            catalog.alternative_limit,
                        )?;
                        Arc::make_mut(&mut current.memory).insert(key.clone(), value);
                        Arc::make_mut(&mut current.written_memory_keys).insert(key);
                    }
                }
            }
            "rep_movsd" | "rep_movs" | "rep_stosd" | "rep_stos" => {
                let width = if matches!(action.op.as_str(), "rep_movsd" | "rep_stosd") {
                    4
                } else {
                    action.parameters.aux
                };
                let destination_index = if matches!(action.op.as_str(), "rep_movsd" | "rep_movs") {
                    1
                } else {
                    0
                };
                let mut arguments = Vec::with_capacity(4);
                for operand in &action.operands {
                    arguments.push(evaluate_word(
                        *operand,
                        transfer,
                        initial,
                        &current,
                        catalog,
                        &alternative_limits,
                        &mut values,
                    )?);
                }
                let destination_shape = exact_repeat_shape(
                    &arguments[destination_index],
                    &arguments[2],
                    &arguments[3],
                    width,
                );
                let ranges = repeated_write_ranges(
                    &arguments[destination_index],
                    &arguments[2],
                    &arguments[3],
                    width,
                )?;
                let source_shape = if matches!(action.op.as_str(), "rep_movsd" | "rep_movs") {
                    exact_repeat_shape(&arguments[0], &arguments[2], &arguments[3], width)
                } else {
                    None
                };
                let exact = destination_shape.is_some()
                    && (!matches!(action.op.as_str(), "rep_movsd" | "rep_movs")
                        || source_shape.is_some());
                if exact {
                    let (destination, repetitions, backwards) =
                        destination_shape.expect("checked exact destination");
                    if ranges
                        .as_deref()
                        .is_some_and(|rows| ranges_outside_current_frame(&current, rows))
                    {
                        current.preserves_inherited_memory = false;
                    }
                    if let Some(rows) = &ranges {
                        Arc::make_mut(&mut current.invalidated_memory_ranges)
                            .extend(rows.iter().cloned());
                        Arc::make_mut(&mut current.effect_invalidated_memory_ranges)
                            .extend(rows.iter().cloned());
                    }
                    for index in 0..repetitions {
                        let delta = if backwards {
                            -(index as i64) * width as i64
                        } else {
                            index as i64 * width as i64
                        };
                        let write_key = destination.with_offset(destination.offset + delta);
                        let copied = if let Some((source, _count, _backwards)) = &source_shape {
                            let read_key = source.with_offset(source.offset + delta);
                            reference_memory_value(&current, &read_key, catalog)?
                        } else {
                            arguments[1].clone()
                        };
                        Arc::make_mut(&mut current.memory).insert(write_key.clone(), copied);
                        Arc::make_mut(&mut current.written_memory_keys).insert(write_key);
                    }
                } else if let Some(rows) = ranges {
                    if !rows.is_empty() {
                        if ranges_outside_current_frame(&current, &rows) {
                            current.preserves_inherited_memory = false;
                        }
                        invalidate_ranges(&mut current, &rows);
                    }
                } else if let Some(rows) = object_scoped_repeat_write_ranges(
                    &arguments[destination_index],
                    &arguments[3],
                    width,
                ) {
                    if ranges_outside_current_frame(&current, &rows) {
                        current.preserves_inherited_memory = false;
                    }
                    invalidate_ranges(&mut current, &rows);
                } else {
                    current.preserves_inherited_memory = false;
                    invalidate_all_memory(&mut current);
                }
            }
            "rep_scas" => {}
            "call" => {
                let call = &transfer.calls[action.operands[0]];
                call_input_states.insert(call.event_index, current.clone());
                if let Some(override_state) = overrides.and_then(|rows| rows.get(&call.event_index))
                {
                    current.call_registers = override_state.registers.clone();
                    current.call_flags = override_state.flags.clone();
                    current.memory = override_state.memory.clone();
                    current.invalidated_memory_ranges =
                        override_state.invalidated_memory_ranges.clone();
                    current.all_memory_invalidated = override_state.all_memory_invalidated;
                    current.callback_registry = override_state.callback_registry.clone();
                    current.preserves_inherited_memory = override_state.preserves_inherited_memory;
                    current.written_memory_keys = override_state.written_memory_keys.clone();
                    current.effect_invalidated_memory_ranges =
                        override_state.effect_invalidated_memory_ranges.clone();
                    current.effect_all_memory_invalidated =
                        override_state.effect_all_memory_invalidated;
                    current.possible_allocation_identities =
                        override_state.possible_allocation_identities.clone();
                    continue;
                }
                let rule = external_call_rule(
                    call,
                    transfer,
                    initial,
                    &current,
                    catalog,
                    &alternative_limits,
                    &mut values,
                )?;
                if let Some(rule) = rule {
                    if let Some(arguments) = apply_external_call(
                        &rule,
                        call,
                        transfer,
                        initial,
                        &mut current,
                        catalog,
                        &alternative_limits,
                        &mut values,
                    )? {
                        unresolved_external_writes.insert(call.event_index, arguments);
                    }
                } else {
                    current.call_registers.fill(unknown_value());
                    current.call_flags.fill(unknown_value());
                }
            }
            "typed_x87" => {
                apply_typed_x87_effect(
                    &transfer.x87_intrinsics[action.operands[0]],
                    &mut current,
                    catalog,
                )?;
            }
            "sync_eflags" | "divide_if" | "access_violation_if" => {}
            operation => {
                return Err(invalid(format!(
                    "basic native effect slice does not yet cover {operation:?}"
                )));
            }
        }
    }
    match transfer.terminator.op.as_str() {
        "outcome_branch" | "outcome_return" | "outcome_indirect" => {
            evaluate_word(
                transfer.terminator.operands[0],
                transfer,
                initial,
                &current,
                catalog,
                &alternative_limits,
                &mut values,
            )?;
        }
        "outcome_nonlocal" => {
            for operand in &transfer.terminator.operands {
                evaluate_word(
                    *operand,
                    transfer,
                    initial,
                    &current,
                    catalog,
                    &alternative_limits,
                    &mut values,
                )?;
            }
        }
        _ => {}
    }
    for index in 0..values.len() {
        evaluate_word(
            index,
            transfer,
            initial,
            &current,
            catalog,
            &alternative_limits,
            &mut values,
        )?;
    }
    current.invalidated_memory_ranges =
        normalize_shared_ranges(std::mem::take(&mut current.invalidated_memory_ranges))?;
    current.effect_invalidated_memory_ranges = normalize_shared_ranges(std::mem::take(
        &mut current.effect_invalidated_memory_ranges,
    ))?;
    Ok(EffectApplication {
        state: current,
        values: values.into_iter().map(Option::unwrap).collect(),
        call_input_states,
        unresolved_external_writes,
        effect_input_states,
    })
}

fn apply_basic_reference_effects(
    transfer: &reference_plan::Transfer,
    initial: &ReferenceState,
    catalog: &RuntimeCatalog,
) -> PyResult<(ReferenceState, Vec<ReferenceValue>)> {
    let result = apply_reference_effects(transfer, initial, catalog, None)?;
    Ok((result.state, result.values))
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct BatchOutput {
    results: Vec<ReferenceStatePayload>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReferenceState {
    registers: Vec<ReferenceValue>,
    flags: Vec<ReferenceValue>,
    memory: Arc<MemoryMap>,
    call_registers: Vec<ReferenceValue>,
    call_flags: Vec<ReferenceValue>,
    invalidated_memory_ranges: Arc<BTreeSet<MemoryRange>>,
    all_memory_invalidated: bool,
    callback_registry: Arc<BTreeMap<String, ReferenceValue>>,
    flag_relations: Vec<Option<FlagRelation>>,
    scalar_constraints: BTreeMap<(u8, u32), BTreeSet<u32>>,
    preserves_inherited_memory: bool,
    relational_object_bindings: Arc<BTreeMap<String, ReferenceValue>>,
    written_memory_keys: Arc<MemoryKeySet>,
    effect_invalidated_memory_ranges: Arc<BTreeSet<MemoryRange>>,
    effect_all_memory_invalidated: bool,
    possible_allocation_identities: Arc<BTreeSet<String>>,
}

fn reference_states_equal(left: &ReferenceState, right: &ReferenceState) -> bool {
    left.registers == right.registers
        && left.flags == right.flags
        && (Arc::ptr_eq(&left.memory, &right.memory) || left.memory == right.memory)
        && left.call_registers == right.call_registers
        && left.call_flags == right.call_flags
        && (Arc::ptr_eq(
            &left.invalidated_memory_ranges,
            &right.invalidated_memory_ranges,
        ) || left.invalidated_memory_ranges == right.invalidated_memory_ranges)
        && left.all_memory_invalidated == right.all_memory_invalidated
        && (Arc::ptr_eq(&left.callback_registry, &right.callback_registry)
            || left.callback_registry == right.callback_registry)
        && left.flag_relations == right.flag_relations
        && left.scalar_constraints == right.scalar_constraints
        && left.preserves_inherited_memory == right.preserves_inherited_memory
        && (Arc::ptr_eq(
            &left.relational_object_bindings,
            &right.relational_object_bindings,
        ) || left.relational_object_bindings == right.relational_object_bindings)
        && (Arc::ptr_eq(&left.written_memory_keys, &right.written_memory_keys)
            || left.written_memory_keys == right.written_memory_keys)
        && (Arc::ptr_eq(
            &left.effect_invalidated_memory_ranges,
            &right.effect_invalidated_memory_ranges,
        ) || left.effect_invalidated_memory_ranges == right.effect_invalidated_memory_ranges)
        && left.effect_all_memory_invalidated == right.effect_all_memory_invalidated
        && (Arc::ptr_eq(
            &left.possible_allocation_identities,
            &right.possible_allocation_identities,
        ) || left.possible_allocation_identities == right.possible_allocation_identities)
}

fn invalid(message: impl Into<String>) -> PyErr {
    PyValueError::new_err(format!(
        "reference kernel input is malformed: {}",
        message.into()
    ))
}

fn validate_text(value: &str, context: &str) -> PyResult<()> {
    if value.is_empty() || value.len() > MAX_STRING_BYTES {
        return Err(invalid(format!("{context} has an invalid string")));
    }
    Ok(())
}

fn canonical_value(mut value: ReferenceValue, limit: usize) -> PyResult<ReferenceValue> {
    if !matches!(
        value.kind.as_str(),
        "bottom" | "finite" | "unknown_scalar" | "conflict"
    ) {
        return Err(invalid("reference value kind is unsupported"));
    }
    if value.kind != "finite" && (!value.scalars.is_empty() || !value.references.is_empty()) {
        return Err(invalid("non-finite reference value carries alternatives"));
    }
    if value.kind != "finite" {
        return Ok(match value.kind.as_str() {
            "bottom" => bottom_value(),
            "unknown_scalar" => unknown_value(),
            "conflict" => conflict_value(),
            _ => unreachable!("validated reference value kind"),
        });
    }
    for atom in &value.references {
        if !matches!(
            atom.kind.as_str(),
            "object"
                | "object_view"
                | "guest_code"
                | "external_function"
                | "loader_module"
        ) {
            return Err(invalid("reference atom kind is unsupported"));
        }
        validate_text(&atom.identity, "reference atom")?;
        if atom.kind == "object_view" && atom.offset != 0 {
            return Err(invalid("object view has a nonzero offset"));
        }
    }
    value.scalars.sort_unstable();
    value.scalars.dedup();
    value.references.sort_unstable();
    value.references.dedup();
    if value.kind != "finite" {
        return Ok(value);
    }
    if value.scalars.is_empty() && value.references.is_empty() {
        return Ok(bottom_value());
    }
    if !value.references.is_empty()
        && value
        .references
        .iter()
        .any(|atom| atom.kind == "object_view")
    {
        let mut collapsed = BTreeSet::new();
        for atom in std::mem::take(&mut value.references) {
            if matches!(atom.kind.as_str(), "object" | "object_view") {
                collapsed.insert(ReferenceAtom {
                    kind: "object_view".to_owned(),
                    identity: atom.identity,
                    offset: 0,
                });
            } else {
                collapsed.insert(atom);
            }
        }
        value.references = collapsed.into_iter().collect();
    }
    if value.scalars.len() + value.references.len() > limit {
        let mut collapsed = BTreeSet::new();
        for atom in std::mem::take(&mut value.references) {
            if matches!(atom.kind.as_str(), "object" | "object_view") {
                collapsed.insert(ReferenceAtom {
                    kind: "object_view".to_owned(),
                    identity: atom.identity,
                    offset: 0,
                });
            } else {
                collapsed.insert(atom);
            }
        }
        value.references = collapsed.into_iter().collect();
        if value.scalars.len() + value.references.len() > limit {
            return Ok(conflict_value());
        }
    }
    Ok(value)
}

fn bottom_value() -> ReferenceValue {
    static VALUE: OnceLock<ReferenceValue> = OnceLock::new();
    VALUE
        .get_or_init(|| {
            ReferenceValue::new(
                "bottom",
                SharedAlternatives::default(),
                SharedAlternatives::default(),
            )
        })
        .clone()
}

fn unknown_value() -> ReferenceValue {
    static VALUE: OnceLock<ReferenceValue> = OnceLock::new();
    VALUE
        .get_or_init(|| {
            ReferenceValue::new(
                "unknown_scalar",
                SharedAlternatives::default(),
                SharedAlternatives::default(),
            )
        })
        .clone()
}

fn conflict_value() -> ReferenceValue {
    static VALUE: OnceLock<ReferenceValue> = OnceLock::new();
    VALUE
        .get_or_init(|| {
            ReferenceValue::new(
                "conflict",
                SharedAlternatives::default(),
                SharedAlternatives::default(),
            )
        })
        .clone()
}

fn join_value(
    left: &ReferenceValue,
    right: &ReferenceValue,
    alternative_limit: usize,
) -> PyResult<ReferenceValue> {
    if left.kind == "bottom" {
        return Ok(right.clone());
    }
    if right.kind == "bottom" {
        return Ok(left.clone());
    }
    if left.kind == "conflict" || right.kind == "conflict" {
        return Ok(conflict_value());
    }
    if left.kind == "unknown_scalar" || right.kind == "unknown_scalar" {
        let other = if left.kind == "unknown_scalar" {
            right
        } else {
            left
        };
        return Ok(
            if other.kind == "unknown_scalar"
                || (other.kind == "finite" && other.references.is_empty())
            {
                unknown_value()
            } else {
                conflict_value()
            },
        );
    }
    canonical_value(
        ReferenceValue::new(
            "finite",
            left.scalars
                .iter()
                .chain(&right.scalars)
                .copied()
                .collect::<SharedAlternatives<_>>(),
            left.references
                .iter()
                .chain(&right.references)
                .cloned()
                .collect::<SharedAlternatives<_>>(),
        ),
        alternative_limit,
    )
}

fn normalize_ranges(rows: BTreeSet<MemoryRange>) -> PyResult<BTreeSet<MemoryRange>> {
    let mut grouped: BTreeMap<MemoryOwner, Vec<(i128, i128)>> = BTreeMap::new();
    for row in rows {
        validate_memory_owner(&row.kind, &row.identity, "memory range")?;
        let start = row.start();
        let end = row.end();
        if end < start {
            return Err(invalid(format!(
                "memory range has a negative extent: {}:{} [{}, {})",
                row.kind, row.identity, start, end,
            )));
        }
        grouped
            .entry((row.kind, row.identity))
            .or_default()
            .push((start, end));
    }
    let mut result = BTreeSet::new();
    for ((kind, identity), mut intervals) in grouped {
        intervals.sort_unstable();
        let mut current: Option<(i128, i128)> = None;
        for (start, end) in intervals {
            current = match current {
                None => Some((start, end)),
                Some((current_start, current_end)) if start <= current_end => {
                    Some((current_start, current_end.max(end)))
                }
                Some((current_start, current_end)) => {
                    result.insert(MemoryRange::from_coordinates(
                        kind.clone(),
                        identity.clone(),
                        current_start,
                        current_end,
                    ));
                    Some((start, end))
                }
            };
        }
        if let Some((start, end)) = current {
            result.insert(MemoryRange::from_coordinates(
                kind, identity, start, end,
            ));
        }
    }
    Ok(result)
}

fn normalize_shared_ranges(
    rows: Arc<BTreeSet<MemoryRange>>,
) -> PyResult<Arc<BTreeSet<MemoryRange>>> {
    normalize_ranges(Arc::unwrap_or_clone(rows)).map(Arc::new)
}

fn validate_memory_owner(kind: &str, identity: &str, context: &str) -> PyResult<()> {
    match kind {
        "object" => validate_text(identity, &format!("{context} identity")),
        "absolute" if identity.is_empty() => Ok(()),
        _ => Err(invalid(format!("{context} owner is malformed"))),
    }
}

fn validate_memory_key(key: &MemoryKey, context: &str) -> PyResult<()> {
    validate_memory_owner(&key.kind, &key.identity, context)?;
    if key.width == 0 {
        return Err(invalid(format!("{context} width is zero")));
    }
    Ok(())
}

fn rows_to_memory(rows: Vec<MemoryRow>, context: &str) -> PyResult<MemoryMap> {
    if rows.len() > MAX_MEMORY_ROWS {
        return Err(invalid(format!("{context} exceeds the memory-row limit")));
    }
    let mut result = MemoryMap::default();
    for row in rows {
        validate_memory_key(&row.key, "memory key")?;
        let value = canonical_value(row.value, STACK_ALTERNATIVE_LIMIT)?;
        if result.insert(row.key, value).is_some() {
            return Err(invalid(format!(
                "{context} contains a duplicate memory key"
            )));
        }
    }
    Ok(result)
}

fn named_values_to_map(
    rows: Vec<NamedValue>,
    context: &str,
) -> PyResult<BTreeMap<String, ReferenceValue>> {
    let mut result = BTreeMap::new();
    for row in rows {
        validate_text(&row.identity, context)?;
        let value = canonical_value(row.value, STACK_ALTERNATIVE_LIMIT)?;
        if result.insert(row.identity, value).is_some() {
            return Err(invalid(format!("{context} contains a duplicate identity")));
        }
    }
    Ok(result)
}

fn keys_to_set(rows: Vec<MemoryKey>, context: &str) -> PyResult<MemoryKeySet> {
    let count = rows.len();
    let mut result = MemoryKeySet::default();
    for key in rows {
        validate_memory_key(&key, context)?;
        result.insert(key);
    }
    if result.len() != count {
        return Err(invalid(format!("{context} contains a duplicate key")));
    }
    Ok(result)
}

fn allocation_identities_to_set(rows: Vec<String>) -> PyResult<BTreeSet<String>> {
    let count = rows.len();
    let result = rows
        .into_iter()
        .map(|identity| {
            if !identity.starts_with("allocation:") {
                Err(invalid("allocation identity is malformed"))
            } else {
                validate_text(&identity, "allocation identity")?;
                Ok(identity)
            }
        })
        .collect::<PyResult<BTreeSet<_>>>()?;
    if result.len() != count {
        return Err(invalid(
            "allocation identities contain a duplicate identity",
        ));
    }
    Ok(result)
}

impl ReferenceState {
    fn parse(payload: ReferenceStatePayload, alternative_limit: usize) -> PyResult<Self> {
        if payload.registers.len() != REGISTER_COUNT
            || payload.call_registers.len() != REGISTER_COUNT
            || payload.flags.len() != FLAG_COUNT
            || payload.call_flags.len() != FLAG_COUNT
            || payload.flag_relations.len() != FLAG_COUNT
        {
            return Err(invalid(
                "reference state has invalid register or flag cardinality",
            ));
        }
        let canonical_values = |rows: Vec<ReferenceValue>, limit: usize| {
            rows.into_iter()
                .map(|value| canonical_value(value, limit))
                .collect::<PyResult<Vec<_>>>()
        };
        let mut scalar_constraints = BTreeMap::new();
        for mut row in payload.scalar_constraints {
            if row.register_index as usize >= REGISTER_COUNT || row.values.is_empty() {
                return Err(invalid("scalar constraint is malformed"));
            }
            row.values.sort_unstable();
            row.values.dedup();
            if row.values.len() > SCALAR_CONSTRAINT_LIMIT
                || row.values.iter().any(|value| *value > row.mask)
                || scalar_constraints
                    .insert(
                        (row.register_index, row.mask),
                        row.values.into_iter().collect(),
                    )
                    .is_some()
            {
                return Err(invalid("scalar constraint is malformed"));
            }
        }
        for relation in payload.flag_relations.iter().flatten() {
            if relation.register_index as usize >= REGISTER_COUNT
                || !matches!(relation.relation.as_str(), "eq" | "ult")
            {
                return Err(invalid("flag relation is malformed"));
            }
        }
        let possible_allocation_identities =
            allocation_identities_to_set(payload.possible_allocation_identities)?;
        let written_memory_keys = keys_to_set(payload.written_memory_keys, "written memory keys")?;
        Ok(Self {
            registers: canonical_values(payload.registers, alternative_limit)?,
            flags: canonical_values(payload.flags, alternative_limit)?,
            memory: Arc::new(rows_to_memory(payload.memory, "state")?),
            call_registers: canonical_values(payload.call_registers, alternative_limit)?,
            call_flags: canonical_values(payload.call_flags, alternative_limit)?,
            invalidated_memory_ranges: Arc::new(normalize_ranges(
                payload.invalidated_memory_ranges.into_iter().collect(),
            )?),
            all_memory_invalidated: payload.all_memory_invalidated,
            callback_registry: Arc::new(named_values_to_map(
                payload.callback_registry,
                "callback registry",
            )?),
            flag_relations: payload.flag_relations,
            scalar_constraints,
            preserves_inherited_memory: payload.preserves_inherited_memory,
            relational_object_bindings: Arc::new(named_values_to_map(
                payload.relational_object_bindings,
                "relational binding",
            )?),
            written_memory_keys: Arc::new(written_memory_keys),
            effect_invalidated_memory_ranges: Arc::new(normalize_ranges(
                payload
                    .effect_invalidated_memory_ranges
                    .into_iter()
                    .collect(),
            )?),
            effect_all_memory_invalidated: payload.effect_all_memory_invalidated,
            possible_allocation_identities: Arc::new(possible_allocation_identities),
        })
    }

    fn payload(self) -> ReferenceStatePayload {
        let mut memory = self
            .memory
            .iter()
            .map(|(key, value)| MemoryRow {
                key: key.clone(),
                value: value.clone(),
            })
            .collect::<Vec<_>>();
        memory.sort_unstable_by(|left, right| lexical_memory_key_cmp(&left.key, &right.key));
        let mut written_memory_keys = self.written_memory_keys.iter().cloned().collect::<Vec<_>>();
        written_memory_keys.sort_unstable_by(lexical_memory_key_cmp);
        ReferenceStatePayload {
            registers: self.registers,
            flags: self.flags,
            memory,
            call_registers: self.call_registers,
            call_flags: self.call_flags,
            invalidated_memory_ranges: self.invalidated_memory_ranges.iter().cloned().collect(),
            all_memory_invalidated: self.all_memory_invalidated,
            callback_registry: self
                .callback_registry
                .iter()
                .map(|(identity, value)| NamedValue {
                    identity: identity.clone(),
                    value: value.clone(),
                })
                .collect(),
            flag_relations: self.flag_relations,
            scalar_constraints: self
                .scalar_constraints
                .into_iter()
                .map(|((register_index, mask), values)| ScalarConstraint {
                    register_index,
                    mask,
                    values: values.into_iter().collect(),
                })
                .collect(),
            preserves_inherited_memory: self.preserves_inherited_memory,
            relational_object_bindings: self
                .relational_object_bindings
                .iter()
                .map(|(identity, value)| NamedValue {
                    identity: identity.clone(),
                    value: value.clone(),
                })
                .collect(),
            written_memory_keys,
            effect_invalidated_memory_ranges: self
                .effect_invalidated_memory_ranges
                .iter()
                .cloned()
                .collect(),
            effect_all_memory_invalidated: self.effect_all_memory_invalidated,
            possible_allocation_identities: self
                .possible_allocation_identities
                .iter()
                .cloned()
                .collect(),
        }
    }
}

type MemoryOwner = (SharedText, SharedText);
type InvalidationIndex = Vec<(MemoryOwner, Vec<(i128, i128)>)>;
type BaselineMemoryIndex = Vec<(MemoryOwner, Vec<MemoryKey>)>;

fn owner_index_get<'a, T>(
    index: &'a [(MemoryOwner, T)],
    kind: &str,
    identity: &str,
) -> Option<&'a T> {
    index
        .binary_search_by(|((candidate_kind, candidate_identity), _value)| {
            candidate_kind
                .deref()
                .cmp(kind)
                .then_with(|| candidate_identity.deref().cmp(identity))
        })
        .ok()
        .map(|position| &index[position].1)
}

fn baseline_memory_index(
    baseline: &MemoryMap,
    objects: &[ObjectPayload],
    alternative_limit: usize,
) -> PyResult<BaselineMemoryIndex> {
    let mut result: BaselineMemoryIndex = Vec::new();
    let mut keys = Vec::new();
    for (key, value) in baseline {
        if key.kind == "object"
            && objects.iter().any(|object| {
                object.identity == key.identity && !object.writable
            })
        {
            continue;
        }
        if join_value(value, &unknown_value(), alternative_limit)? != unknown_value() {
            keys.push(key.clone());
        }
    }
    keys.sort_unstable_by(lexical_memory_key_cmp);
    for key in keys {
        if let Some(((kind, identity), grouped_keys)) = result.last_mut()
            && kind == &key.kind
            && identity == &key.identity
        {
            grouped_keys.push(key);
        } else {
            result.push(((key.kind.clone(), key.identity.clone()), vec![key]));
        }
    }
    Ok(result)
}

fn invalidation_index(rows: &BTreeSet<MemoryRange>) -> InvalidationIndex {
    let mut result: InvalidationIndex = Vec::new();
    for row in rows {
        if let Some(((kind, identity), ranges)) = result.last_mut()
            && kind == &row.kind
            && identity == &row.identity
        {
            ranges.push((row.start(), row.end()));
        } else {
            result.push((
                (row.kind.clone(), row.identity.clone()),
                vec![(row.start(), row.end())],
            ));
        }
    }
    result
}

fn implicit_value(
    state: &ReferenceState,
    key: &MemoryKey,
    baseline: &MemoryMap,
    invalidated: &InvalidationIndex,
) -> ReferenceValue {
    if state.all_memory_invalidated {
        return unknown_value();
    }
    if owner_index_get(invalidated, key.kind.deref(), key.identity.deref())
        .into_iter()
        .flatten()
        .any(|(start, end)| {
            i128::from(key.offset) < *end
                && *start < i128::from(key.offset) + i128::from(key.width)
        })
    {
        return unknown_value();
    }
    if key.kind == "object"
        && key.identity.starts_with("allocation:")
        && !state
            .possible_allocation_identities
            .contains(&*key.identity)
    {
        return bottom_value();
    }
    if let Some(value) = baseline.get(key) {
        return value.clone();
    }
    if key.kind == "object" && key.identity.starts_with("call_parameter_object:") {
        return conflict_value();
    }
    unknown_value()
}

fn memory_value(
    state: &ReferenceState,
    key: &MemoryKey,
    baseline: &MemoryMap,
    invalidated: &InvalidationIndex,
) -> ReferenceValue {
    state
        .memory
        .get(key)
        .cloned()
        .unwrap_or_else(|| implicit_value(state, key, baseline, invalidated))
}

fn normalize_memory(state: &mut ReferenceState, baseline: &MemoryMap) {
    if state.memory.is_empty() {
        return;
    }
    let invalidated = invalidation_index(&state.invalidated_memory_ranges);
    let redundant: Vec<MemoryKey> = state
        .memory
        .iter()
        .filter(|(key, value)| {
            !state.written_memory_keys.contains(*key)
                && **value == implicit_value(state, key, baseline, &invalidated)
        })
        .map(|(key, _value)| key.clone())
        .collect();
    for key in redundant {
        Arc::make_mut(&mut state.memory).remove(&key);
    }
}

fn join_value_vectors(
    left: &[ReferenceValue],
    right: &[ReferenceValue],
    alternative_limit: usize,
    stack_pointer: bool,
) -> PyResult<Vec<ReferenceValue>> {
    left.iter()
        .zip(right)
        .enumerate()
        .map(|(index, (one, two))| {
            if one == two {
                Ok(one.clone())
            } else {
                join_value(
                    one,
                    two,
                    if stack_pointer && index == 7 {
                        alternative_limit.max(STACK_ALTERNATIVE_LIMIT)
                    } else {
                        alternative_limit
                    },
                )
            }
        })
        .collect()
}

fn join_state(
    left: ReferenceState,
    right: ReferenceState,
    baseline: &MemoryMap,
    baseline_index: &BaselineMemoryIndex,
    alternative_limit: usize,
) -> PyResult<ReferenceState> {
    if reference_states_equal(&left, &right) {
        return Ok(left);
    }
    let left_invalidated = invalidation_index(&left.invalidated_memory_ranges);
    let right_invalidated = invalidation_index(&right.invalidated_memory_ranges);
    let memory_maps_unchanged =
        Arc::ptr_eq(&left.memory, &right.memory) || left.memory == right.memory;
    let invalidations_unchanged = left.invalidated_memory_ranges == right.invalidated_memory_ranges
        && left.all_memory_invalidated == right.all_memory_invalidated;
    let mut baseline_keys = BTreeSet::new();
    if !invalidations_unchanged {
        let affected: BTreeSet<MemoryOwner> =
            if left.all_memory_invalidated != right.all_memory_invalidated {
                baseline_index
                    .iter()
                    .map(|(owner, _keys)| owner.clone())
                    .collect()
            } else {
                left.invalidated_memory_ranges
                    .iter()
                    .chain(right.invalidated_memory_ranges.iter())
                    .map(|row| (row.kind.clone(), row.identity.clone()))
                    .collect()
            };
        for owner in affected {
            for key in owner_index_get(baseline_index, owner.0.deref(), owner.1.deref())
                .into_iter()
                .flatten()
            {
                if !left.memory.contains_key(key)
                    && memory_value(&left, key, baseline, &left_invalidated)
                        != memory_value(&right, key, baseline, &right_invalidated)
                {
                    baseline_keys.insert(key.clone());
                }
            }
        }
    }
    let memory_keys: BTreeSet<MemoryKey> = if memory_maps_unchanged {
        baseline_keys
    } else {
        left.memory
            .keys()
            .chain(right.memory.keys())
            .cloned()
            .chain(baseline_keys)
            .collect()
    };
    let mut memory = if memory_maps_unchanged {
        left.memory.clone()
    } else {
        Arc::new(MemoryMap::default())
    };
    for key in &memory_keys {
        let left_value = memory_value(&left, key, baseline, &left_invalidated);
        let right_value = memory_value(&right, key, baseline, &right_invalidated);
        Arc::make_mut(&mut memory).insert(
            key.clone(),
            if left_value == right_value {
                left_value
            } else {
                join_value(&left_value, &right_value, alternative_limit)?
            },
        );
    }
    let callback_registry = if left.callback_registry == right.callback_registry {
        left.callback_registry.clone()
    } else {
        let mut joined = BTreeMap::new();
        for identity in left
            .callback_registry
            .keys()
            .chain(right.callback_registry.keys())
            .collect::<BTreeSet<_>>()
        {
            let one = left
                .callback_registry
                .get(identity)
                .cloned()
                .unwrap_or_else(unknown_value);
            let two = right
                .callback_registry
                .get(identity)
                .cloned()
                .unwrap_or_else(unknown_value);
            joined.insert(
                identity.clone(),
                if one == two {
                    one
                } else {
                    join_value(&one, &two, alternative_limit)?
                },
            );
        }
        Arc::new(joined)
    };
    let mut scalar_constraints = BTreeMap::new();
    for key in left.scalar_constraints.keys() {
        if let Some(right_values) = right.scalar_constraints.get(key) {
            let values: BTreeSet<u32> = left.scalar_constraints[key]
                .union(right_values)
                .copied()
                .collect();
            if values.len() <= SCALAR_CONSTRAINT_LIMIT {
                scalar_constraints.insert(*key, values);
            }
        }
    }
    let relational_object_bindings =
        if left.relational_object_bindings == right.relational_object_bindings {
            left.relational_object_bindings.clone()
        } else {
            let mut joined = BTreeMap::new();
            for identity in left
                .relational_object_bindings
                .keys()
                .chain(right.relational_object_bindings.keys())
                .collect::<BTreeSet<_>>()
            {
                let value = match (
                    left.relational_object_bindings.get(identity),
                    right.relational_object_bindings.get(identity),
                ) {
                    (Some(one), Some(two)) if one != two => {
                        join_value(one, two, alternative_limit.max(STACK_ALTERNATIVE_LIMIT))?
                    }
                    (Some(one), _) => one.clone(),
                    (_, Some(two)) => two.clone(),
                    (None, None) => unreachable!(),
                };
                joined.insert(identity.clone(), value);
            }
            Arc::new(joined)
        };
    let invalidated_memory_ranges =
        if left.invalidated_memory_ranges == right.invalidated_memory_ranges {
            left.invalidated_memory_ranges.clone()
        } else {
            Arc::new(normalize_ranges(
                left.invalidated_memory_ranges
                    .union(&right.invalidated_memory_ranges)
                    .cloned()
                    .collect(),
            )?)
        };
    let written_memory_keys = if left.written_memory_keys == right.written_memory_keys {
        left.written_memory_keys.clone()
    } else {
        Arc::new(
            left.written_memory_keys
                .union(&right.written_memory_keys)
                .cloned()
                .collect(),
        )
    };
    let effect_invalidated_memory_ranges =
        if left.effect_invalidated_memory_ranges == right.effect_invalidated_memory_ranges {
            left.effect_invalidated_memory_ranges.clone()
        } else {
            Arc::new(normalize_ranges(
                left.effect_invalidated_memory_ranges
                    .union(&right.effect_invalidated_memory_ranges)
                    .cloned()
                    .collect(),
            )?)
        };
    let possible_allocation_identities =
        if left.possible_allocation_identities == right.possible_allocation_identities {
            left.possible_allocation_identities.clone()
        } else {
            Arc::new(
                left.possible_allocation_identities
                    .union(&right.possible_allocation_identities)
                    .cloned()
                    .collect(),
            )
        };
    let mut result = ReferenceState {
        registers: join_value_vectors(&left.registers, &right.registers, alternative_limit, true)?,
        flags: join_value_vectors(&left.flags, &right.flags, alternative_limit, false)?,
        memory,
        call_registers: join_value_vectors(
            &left.call_registers,
            &right.call_registers,
            alternative_limit,
            true,
        )?,
        call_flags: join_value_vectors(
            &left.call_flags,
            &right.call_flags,
            alternative_limit,
            false,
        )?,
        invalidated_memory_ranges,
        all_memory_invalidated: left.all_memory_invalidated || right.all_memory_invalidated,
        callback_registry,
        flag_relations: left
            .flag_relations
            .iter()
            .zip(&right.flag_relations)
            .map(|(one, two)| if one == two { one.clone() } else { None })
            .collect(),
        scalar_constraints,
        preserves_inherited_memory: left.preserves_inherited_memory
            && right.preserves_inherited_memory,
        relational_object_bindings,
        written_memory_keys,
        effect_invalidated_memory_ranges,
        effect_all_memory_invalidated: left.effect_all_memory_invalidated
            || right.effect_all_memory_invalidated,
        possible_allocation_identities,
    };
    if !(memory_maps_unchanged && memory_keys.is_empty()) {
        normalize_memory(&mut result, baseline);
    }
    Ok(result)
}

fn sorted_unique<T: Ord>(rows: &[T]) -> bool {
    rows.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_external_call(row: &ExternalCallPayload) -> PyResult<()> {
    validate_text(&row.dll, "external DLL")?;
    validate_text(&row.identity, "external identity")?;
    if row.dll != row.dll.to_lowercase()
        || row
            .contract_sha256
            .as_ref()
            .is_some_and(|digest| !valid_sha256(digest))
        || row
            .loader_service_contract_sha256
            .as_ref()
            .is_some_and(|digest| !valid_sha256(digest))
        || !sorted_unique(&row.preserved_registers)
        || row.preserved_registers.iter().any(|index| *index >= 8)
        || row.stack_cleanup_bytes % 4 != 0
        || !matches!(row.disposition.as_str(), "returns" | "terminates")
        || row
            .allocation_result_register
            .is_some_and(|index| index >= 8)
        || row
            .module_handle_name_argument
            .is_some_and(|index| index >= row.argument_words)
        || row
            .dynamic_export_handle_argument
            .is_some_and(|index| index >= row.argument_words)
        || row
            .dynamic_export_name_argument
            .is_some_and(|index| index >= row.argument_words)
        || row.dynamic_export_handle_argument.is_some()
            != row.dynamic_export_name_argument.is_some()
    {
        return Err(invalid("external call contract is malformed"));
    }
    if row.module_handle_name_argument.is_none()
        && (row.module_handle_nullable_name || row.module_handle_wide_name)
    {
        return Err(invalid("module-handle options have no loader service"));
    }
    if row.dynamic_export_handle_argument.is_none() && !row.dynamic_export_results.is_empty() {
        return Err(invalid("dynamic-export catalog has no loader service"));
    }
    for footprint in &row.write_footprints {
        if footprint.base_argument >= row.argument_words
            || (footprint.fixed_bytes.is_none() == footprint.size_argument.is_none())
            || footprint
                .size_argument
                .is_some_and(|index| index >= row.argument_words)
            || footprint.scale == 0
            || footprint
                .authority_selector
                .as_ref()
                .is_some_and(|selector| selector.is_empty())
        {
            return Err(invalid("external write footprint is malformed"));
        }
        let _checked_offset = footprint.offset;
    }
    for relation in &row.memory_copies {
        if relation.destination_argument >= row.argument_words
            || relation.source_argument >= row.argument_words
            || relation.size_argument >= row.argument_words
            || relation.destination_argument == relation.source_argument
            || relation.scale == 0
        {
            return Err(invalid("external memory-copy relation is malformed"));
        }
    }
    for pointer in &row.out_pointers {
        if pointer.argument >= row.argument_words
            || !pointer.nullable
            || pointer.max_elements == 0
            || !matches!(pointer.element_unit_bytes, 1 | 2 | 4)
            || pointer.element_max_units == 0
        {
            return Err(invalid("external out-pointer relation is malformed"));
        }
        let _checked_offset = pointer.offset;
    }
    if let Some(callback) = &row.callback {
        validate_text(&callback.protocol_id, "callback protocol")?;
        validate_text(&callback.lifetime, "callback lifetime")?;
        validate_text(&callback.delivery_thread, "callback thread")?;
        validate_text(&callback.delivery_timing, "callback timing")?;
        if callback.source_argument >= row.argument_words
            || !matches!(
                callback.source_kind.as_str(),
                "argument_word" | "argument_pointee"
            )
            || (callback.source_kind == "argument_word" && callback.source_offset != 0)
            || !matches!(callback.action.as_str(), "register" | "replace" | "invoke")
            || !matches!(
                callback.instance_kind.as_str(),
                "singleton" | "registration_sequence" | "argument" | "provider_resource"
            )
            || matches!(callback.instance_kind.as_str(), "argument" | "provider_resource")
                && callback.instance_argument.is_none()
            || callback
                .instance_argument
                .is_some_and(|index| index >= row.argument_words)
            || callback
                .previous_result_register
                .is_some_and(|index| index >= 8)
            || !sorted_unique(&callback.sentinels)
            || !sorted_unique(&callback.previous_sentinels)
        {
            return Err(invalid("external callback rule is malformed"));
        }
    }
    let mut dynamic_keys = BTreeSet::new();
    for dynamic in &row.dynamic_export_results {
        validate_text(&dynamic.dll, "dynamic-export DLL")?;
        validate_text(&dynamic.identity, "dynamic-export identity")?;
        validate_text(&dynamic.target, "dynamic-export target")?;
        if dynamic.dll != dynamic.dll.to_lowercase()
            || !dynamic_keys.insert((&dynamic.dll, &dynamic.identity))
        {
            return Err(invalid("dynamic-export catalog is malformed"));
        }
    }
    let _checked_flags = (row.allocation_nullable, row.unknown_guest_memory_write);
    Ok(())
}

fn decode_hex(value: &str) -> PyResult<Vec<u8>> {
    if value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid("object-byte hex is noncanonical"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            Ok(
                (digit(pair[0]).ok_or_else(|| invalid("invalid hex digit"))? << 4)
                    | digit(pair[1]).ok_or_else(|| invalid("invalid hex digit"))?,
            )
        })
        .collect()
}

fn validate_closure_context(
    input: ClosureContextInput,
) -> PyResult<(ClosureInputReceipt, RuntimeClosureContext)> {
    if input.version != 1
        || input.roots.is_empty()
        || !sorted_unique(&input.roots)
        || input.maximum_worklist_steps == 0
        || input.call_string_limit == 0
        || input.authority_bindings.is_empty()
        || input
            .authority_bindings
            .iter()
            .any(|(key, value)| key.is_empty() || !valid_sha256(value))
        || !sorted_unique(&input.runtime_provider_requirements)
        || !sorted_unique(&input.boundary_exit_rvas)
    {
        return Err(invalid(
            "closure policy or authority bindings are malformed",
        ));
    }
    let catalog = input.catalog;
    if catalog.alternative_limit == 0
        || catalog.alternative_limit > STACK_ALTERNATIVE_LIMIT
        || !sorted_unique(&catalog.guest_code_rvas)
    {
        return Err(invalid(
            "reference catalog limits or code inventory are malformed",
        ));
    }
    let roots: BTreeSet<u32> = input.roots.iter().copied().collect();
    let code: BTreeSet<u32> = catalog.guest_code_rvas.iter().copied().collect();
    if !roots.is_subset(&code) {
        return Err(invalid("closure root is outside the guest-code catalog"));
    }
    let boundary_exit_rvas = input
        .boundary_exit_rvas
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if !boundary_exit_rvas.is_subset(&code) {
        return Err(invalid(
            "closure boundary exit is outside the guest-code catalog",
        ));
    }
    let mut checked_exception_transitions = BTreeMap::new();
    let mut previous_exception_key: Option<(String, usize, Option<String>)> = None;
    for row in input.checked_exception_transitions {
        let key = (row.unit_id.clone(), row.effect_index, row.operation.clone());
        let transition_id_valid = row.transition_id.as_ref().is_some_and(|value| {
            value
                .strip_prefix("exceptional-transition-v3:")
                .is_some_and(valid_sha256)
        });
        let handled = row.disposition.as_deref() == Some("handled");
        let checked_escape = row.disposition.as_deref() == Some("terminates")
            && row.resumption_unit_id.is_some();
        let unwind_identities = row.unwind_unit_ids.iter().collect::<BTreeSet<_>>();
        let occurrence_shape = matches!(row.occurrence_kind.as_str(), "effect" | "call")
            && ((row.occurrence_kind == "call") == row.call_index.is_some())
            && (row.operation.is_none()
                || row.operation.as_deref().is_some_and(|operation| {
                    matches!(operation, "divide_if" | "access_violation_if")
                }));
        let complete_shape = row.authorizing
            && transition_id_valid
            && matches!(
                row.disposition.as_deref(),
                Some("handled" | "infeasible" | "terminates")
            )
            && !row.guard.is_null()
            && row.blocker_code.is_none()
            && handled == row.handler_unit_id.is_some()
            && handled == row.handler_rva.is_some()
            && (row.resumption_unit_id.is_some() == row.resumption_rva.is_some())
            && (handled || checked_escape || row.resumption_unit_id.is_none())
            && (row.resumption_unit_id.is_none() || row.native_exception_continuable == Some(true))
            && (handled || row.unwind_unit_ids.is_empty())
            && (handled || checked_escape || row.state_projection.is_none())
            && row
                .state_projection
                .as_ref()
                .is_none_or(ExceptionStateProjectionInput::canonical)
            && occurrence_shape
            && row.state_projection.as_ref().is_none_or(|projection| {
                (projection.exception_record.is_empty() && projection.context.is_empty())
                    || (row.native_exception_code.is_some()
                        && row.native_exception_flags.is_some()
                        && row.native_exception_parameter_count.is_some()
                        && row.native_exception_continuable.is_some())
            })
            && unwind_identities.len() == row.unwind_unit_ids.len()
            && row.unwind_unit_ids.iter().all(|value| !value.is_empty())
            && row.handler_rva.is_none_or(|rva| code.contains(&rva))
            && row.resumption_rva.is_none_or(|rva| code.contains(&rva));
        let incomplete_shape = !row.authorizing
            && occurrence_shape
            && row.disposition.is_none()
            && row.handler_unit_id.is_none()
            && row.handler_rva.is_none()
            && row.resumption_unit_id.is_none()
            && row.resumption_rva.is_none()
            && row.unwind_unit_ids.is_empty()
            && row.state_projection.is_none()
            && row.guard.is_null()
            && row
                .blocker_code
                .as_ref()
                .is_some_and(|value| !value.is_empty());
        if row.unit_id.is_empty()
            || !code.contains(&row.source_rva)
            || !valid_sha256(&row.fault_sha256)
            || previous_exception_key
                .as_ref()
                .is_some_and(|previous| previous >= &key)
            || (!complete_shape && !incomplete_shape)
        {
            return Err(invalid(
                "checked exception-transition inventory is malformed",
            ));
        }
        previous_exception_key = Some(key.clone());
        checked_exception_transitions.insert(key, row);
    }
    let mut external_addresses = BTreeSet::new();
    for row in &catalog.external_functions {
        validate_text(&row.identity, "external function")?;
        if !external_addresses.insert(row.address) {
            return Err(invalid("external function address is duplicated"));
        }
    }
    let mut function_contracts = BTreeSet::new();
    for row in &catalog.external_function_contracts {
        validate_text(&row.function_identity, "external function contract")?;
        validate_text(&row.dll, "external function contract DLL")?;
        validate_text(&row.identity, "external function contract identity")?;
        if row.dll != row.dll.to_lowercase()
            || !function_contracts.insert(row.function_identity.clone())
        {
            return Err(invalid(
                "external function contract is duplicated or noncanonical",
            ));
        }
    }
    let mut object_ids = BTreeSet::new();
    for row in &catalog.objects {
        validate_text(&row.identity, "object")?;
        if row.extent == 0 || !object_ids.insert(row.identity.clone()) {
            return Err(invalid("object range is empty or duplicated"));
        }
        let _checked_address = row.address;
    }
    let mut external_keys = BTreeSet::new();
    for row in &catalog.external_calls {
        validate_external_call(row)?;
        if !external_keys.insert((row.dll.clone(), row.identity.clone())) {
            return Err(invalid("external call identity is duplicated"));
        }
    }
    let mut external_declarations = BTreeMap::new();
    let mut previous_declaration = None;
    for row in input.external_declarations {
        validate_text(&row.dll, "external declaration DLL")?;
        validate_text(&row.identity, "external declaration identity")?;
        let key = (row.dll, row.identity);
        if key.0 != key.0.to_lowercase()
            || !valid_sha256(&row.contract_sha256)
            || row
                .loader_service_contract_sha256
                .as_ref()
                .is_some_and(|digest| !valid_sha256(digest))
            || previous_declaration
                .as_ref()
                .is_some_and(|previous| previous >= &key)
        {
            return Err(invalid(
                "external declaration catalog is malformed or noncanonical",
            ));
        }
        previous_declaration = Some(key.clone());
        external_declarations.insert(
            key,
            (row.contract_sha256, row.loader_service_contract_sha256),
        );
    }
    let initial_memory = rows_to_memory(catalog.initial_memory, "catalog baseline")?;
    let mut byte_owners = BTreeSet::new();
    for row in &catalog.object_bytes {
        validate_text(&row.identity, "object bytes")?;
        if decode_hex(&row.hex).is_err()
            || !byte_owners.insert(row.identity.clone())
            || !object_ids.contains(&row.identity)
        {
            return Err(invalid("object-byte payload is malformed or duplicated"));
        }
    }
    let mut initial_states = BTreeMap::new();
    for row in input.initial_states {
        if !roots.contains(&row.rva) || initial_states.contains_key(&row.rva) {
            return Err(invalid("initial state root is unknown or duplicated"));
        }
        initial_states.insert(
            row.rva,
            ReferenceState::parse(row.state, catalog.alternative_limit)?,
        );
    }
    let receipt = ClosureInputReceipt {
        transfers: 0,
        roots: roots.len(),
        guest_code_rvas: code.len(),
        objects: object_ids.len(),
        external_calls: external_keys.len(),
        external_declarations: external_declarations.len(),
        initial_memory_cells: initial_memory.len(),
        object_byte_owners: byte_owners.len(),
        initial_states: initial_states.len(),
        preexisting_blockers: input.preexisting_blockers.len(),
        checked_exception_transitions: checked_exception_transitions.len(),
    };
    let baseline_memory_index = baseline_memory_index(
        &initial_memory,
        &catalog.objects,
        catalog.alternative_limit,
    )?;
    let runtime_catalog = RuntimeCatalog {
        guest_code_rvas: code,
        guest_image_base: catalog.guest_image_base,
        external_functions: catalog
            .external_functions
            .into_iter()
            .map(|row| (row.address, row.identity))
            .collect(),
        external_function_contracts: catalog
            .external_function_contracts
            .into_iter()
            .map(|row| (row.function_identity, (row.dll, row.identity)))
            .collect(),
        objects: catalog.objects,
        external_calls: catalog
            .external_calls
            .into_iter()
            .map(|row| ((row.dll.clone(), row.identity.clone()), row))
            .collect(),
        initial_memory,
        baseline_memory_index,
        object_bytes: catalog
            .object_bytes
            .into_iter()
            .map(|row| decode_hex(&row.hex).map(|bytes| (row.identity, bytes)))
            .collect::<PyResult<_>>()?,
        alternative_limit: catalog.alternative_limit,
    };
    Ok((
        receipt,
        RuntimeClosureContext {
            roots: input.roots,
            catalog: runtime_catalog,
            initial_states,
            authority_bindings: input.authority_bindings,
            runtime_provider_requirements: input.runtime_provider_requirements,
            external_declarations,
            preexisting_blockers: input.preexisting_blockers,
            maximum_worklist_steps: input.maximum_worklist_steps,
            call_string_limit: input.call_string_limit,
            boundary_exit_rvas,
            checked_exception_transitions,
        },
    ))
}

fn validate_exception_transition_bindings(
    plan: &reference_plan::TransferPlan,
    runtime: &RuntimeClosureContext,
) -> PyResult<()> {
    let transfer_rvas_by_identity = plan
        .transfers
        .iter()
        .map(|transfer| (transfer.identity(), transfer.rva_start()))
        .collect::<BTreeMap<_, _>>();
    let require_total = runtime
        .authority_bindings
        .contains_key("exceptional_transitions_manifest_sha256")
        || runtime
            .authority_bindings
            .contains_key("exception_semantics_sha256");
    let mut observed = BTreeSet::new();
    for transfer in &plan.transfers {
        for (effect_index, operation, call_index, fault_index) in
            transfer_exception_occurrences(transfer)?
        {
            let key = (
                transfer.identity().to_owned(),
                effect_index,
                Some(operation.clone()),
            );
            observed.insert(key.clone());
            let row = runtime.checked_exception_transitions.get(&key).or_else(|| {
                runtime.checked_exception_transitions.get(&(
                    transfer.identity().to_owned(),
                    effect_index,
                    None,
                ))
            });
            let Some(row) = row else {
                if require_total {
                    return Err(invalid(
                        "checked exception-transition inventory omits a transfer occurrence",
                    ));
                }
                continue;
            };
            observed.insert((
                transfer.identity().to_owned(),
                effect_index,
                row.operation.clone(),
            ));
            let expected_kind = if call_index.is_some() {
                "call"
            } else {
                "effect"
            };
            if row.source_rva != transfer.rva_start()
                || row.fault_index != fault_index
                || row.occurrence_kind != expected_kind
                || row.call_index != call_index
                || row
                    .operation
                    .as_deref()
                    .is_some_and(|value| value != operation)
            {
                return Err(invalid(
                    "checked exception transition contradicts its transfer occurrence",
                ));
            }
            if row.authorizing
                && row
                    .transition_sha256
                    .as_ref()
                    .is_none_or(|digest| !is_sha256_digest(digest))
            {
                return Err(invalid(
                    "checked exception transition has no exact transition digest",
                ));
            }
            if row.authorizing
                && ((row.disposition.as_deref() == Some("handled")
                    && (row
                        .handler_unit_id
                        .as_deref()
                        .and_then(|identity| transfer_rvas_by_identity.get(identity).copied())
                        != row.handler_rva
                        || row.unwind_unit_ids.iter().any(|identity| {
                            !transfer_rvas_by_identity.contains_key(identity.as_str())
                        })))
                    || (row.resumption_unit_id.is_some()
                        && row
                            .resumption_unit_id
                            .as_deref()
                            .and_then(|identity| {
                                transfer_rvas_by_identity.get(identity).copied()
                            })
                            != row.resumption_rva))
            {
                return Err(invalid(
                    "checked exception continuation names a non-transfer unit",
                ));
            }
        }
    }
    if runtime
        .checked_exception_transitions
        .keys()
        .any(|key| !observed.contains(key))
    {
        return Err(invalid(
            "checked exception-transition inventory names a non-fault effect",
        ));
    }
    Ok(())
}

fn transfer_exception_occurrences(
    transfer: &reference_plan::Transfer,
) -> PyResult<Vec<(usize, String, Option<usize>, u32)>> {
    let mut rows = Vec::new();
    let mut ordinary_fault_indexes = Vec::new();
    for (effect_index, effect) in transfer.effects.iter().enumerate() {
        if matches!(effect.op.as_str(), "divide_if" | "access_violation_if") {
            ordinary_fault_indexes.push(effect.parameters.aux);
            rows.push((effect_index, effect.op.clone(), None, effect.parameters.aux));
        }
    }
    ordinary_fault_indexes.sort_unstable();
    if ordinary_fault_indexes != (0..ordinary_fault_indexes.len() as u32).collect::<Vec<_>>() {
        return Err(invalid(
            "native-exception effect fault indexes are not contiguous",
        ));
    }
    let mut next_fault_index = ordinary_fault_indexes.len() as u32;
    for (effect_index, effect) in transfer.effects.iter().enumerate() {
        if effect.op != "call" {
            continue;
        }
        let call = &transfer.calls[effect.operands[0]];
        for operation in &call.native_exception_operations {
            rows.push((
                effect_index,
                operation.clone(),
                Some(call.event_index),
                next_fault_index,
            ));
            next_fault_index += 1;
        }
    }
    Ok(rows)
}

fn checked_exception_transition<'a>(
    runtime: &'a RuntimeClosureContext,
    unit_id: &str,
    effect_index: usize,
    operation: &str,
) -> Option<&'a CheckedExceptionTransitionInput> {
    runtime
        .checked_exception_transitions
        .get(&(unit_id.to_owned(), effect_index, Some(operation.to_owned())))
        .or_else(|| {
            runtime
                .checked_exception_transitions
                .get(&(unit_id.to_owned(), effect_index, None))
        })
}

fn boundary_state(mut state: ReferenceState, catalog: &RuntimeCatalog) -> ReferenceState {
    state.call_registers.fill(unknown_value());
    state.call_flags.fill(unknown_value());
    normalize_memory(&mut state, &catalog.initial_memory);
    state
}

fn reference_target_resolution(
    value: &ReferenceValue,
    catalog: &RuntimeCatalog,
) -> Option<(BTreeSet<u32>, BTreeSet<(String, String)>)> {
    if value.kind != "finite" || !value.scalars.is_empty() || value.references.is_empty() {
        return None;
    }
    let mut guest = BTreeSet::new();
    let mut external = BTreeSet::new();
    for atom in &value.references {
        if atom.offset != 0 {
            return None;
        }
        if atom.kind == "guest_code" {
            let target = u32::from_str_radix(atom.identity.strip_prefix("rva:")?, 16).ok()?;
            guest.insert(target);
        } else if atom.kind == "external_function" {
            external.insert(
                catalog
                    .external_function_contracts
                    .get(&*atom.identity)?
                    .clone(),
            );
        } else {
            return None;
        }
    }
    Some((guest, external))
}

fn internal_call_targets(
    call: &reference_plan::Call,
    values: &[ReferenceValue],
) -> Option<BTreeSet<u32>> {
    if call.kind == "external_call" {
        return Some(BTreeSet::new());
    }
    if let Some(index) = call.target_node {
        let value = &values[index];
        if value.kind != "finite" || !value.scalars.is_empty() || value.references.is_empty() {
            return None;
        }
        if value
            .references
            .iter()
            .all(|atom| atom.kind == "external_function" && atom.offset == 0)
        {
            return Some(BTreeSet::new());
        }
        let mut targets = BTreeSet::new();
        for atom in &value.references {
            if atom.kind != "guest_code" || atom.offset != 0 {
                return None;
            }
            targets.insert(u32::from_str_radix(atom.identity.strip_prefix("rva:")?, 16).ok()?);
        }
        return Some(targets);
    }
    (call.target_rva != 0).then(|| [call.target_rva].into_iter().collect())
}

fn external_call_targets(
    call: &reference_plan::Call,
    values: &[ReferenceValue],
    catalog: &RuntimeCatalog,
) -> Option<BTreeSet<(String, String)>> {
    if call.kind == "external_call" {
        let identity = if let Some(symbol) = &call.symbol {
            symbol.clone()
        } else {
            format!("ordinal:{}", call.ordinal?)
        };
        return Some(
            [(
                call.dll.clone().unwrap_or_default().to_lowercase(),
                identity,
            )]
            .into_iter()
            .collect(),
        );
    }
    let Some(index) = call.target_node else {
        return Some(BTreeSet::new());
    };
    let value = &values[index];
    if value.kind != "finite" || !value.scalars.is_empty() || value.references.is_empty() {
        return None;
    }
    let mut targets = BTreeSet::new();
    for atom in &value.references {
        if atom.kind != "external_function" || atom.offset != 0 {
            return None;
        }
        targets.insert(
            catalog
                .external_function_contracts
                .get(&*atom.identity)?
                .clone(),
        );
    }
    Some(targets)
}

fn external_tail_return_state(
    transfer: &reference_plan::Transfer,
    state: &ReferenceState,
    targets: &BTreeSet<(String, String)>,
    catalog: &RuntimeCatalog,
) -> PyResult<Option<ReferenceState>> {
    let rules = targets
        .iter()
        .map(|target| catalog.external_calls.get(target))
        .collect::<Vec<_>>();
    let Some(Some(first)) = rules.first() else {
        return Ok(None);
    };
    if rules.iter().any(|rule| *rule != Some(*first))
        || first.disposition != "returns"
        || !first.write_footprints.is_empty()
        || !first.memory_copies.is_empty()
        || !first.out_pointers.is_empty()
        || first.unknown_guest_memory_write
        || first.callback.is_some()
        || first.module_handle_name_argument.is_some()
        || first.dynamic_export_handle_argument.is_some()
        || !first.preserved_registers.contains(&7)
    {
        return Ok(None);
    }
    let mut registers = vec![unknown_value(); REGISTER_COUNT];
    for register in &first.preserved_registers {
        registers[*register as usize] = state.registers[*register as usize].clone();
    }
    registers[7] = adjust_reference_by_constant(
        &registers[7],
        first.stack_cleanup_bytes as i64 + 4,
        catalog.alternative_limit.max(STACK_ALTERNATIVE_LIMIT),
    )?;
    if let Some(register) = first.allocation_result_register {
        let (dll, identity) = targets.first().expect("checked target");
        registers[register as usize] = finite_value(
            first.allocation_nullable.then_some(0),
            [ReferenceAtom {
                kind: "object".to_owned(),
                identity: format!("external-object:{dll}!{identity}:{}", transfer.identity(),)
                    .into(),
                offset: 0,
            }],
            catalog.alternative_limit,
        )?;
    }
    Ok(Some(ReferenceState {
        registers,
        flags: vec![unknown_value(); FLAG_COUNT],
        memory: state.memory.clone(),
        call_registers: vec![unknown_value(); REGISTER_COUNT],
        call_flags: vec![unknown_value(); FLAG_COUNT],
        invalidated_memory_ranges: state.invalidated_memory_ranges.clone(),
        all_memory_invalidated: state.all_memory_invalidated,
        callback_registry: state.callback_registry.clone(),
        flag_relations: vec![None; FLAG_COUNT],
        scalar_constraints: BTreeMap::new(),
        preserves_inherited_memory: state.preserves_inherited_memory,
        relational_object_bindings: state.relational_object_bindings.clone(),
        written_memory_keys: state.written_memory_keys.clone(),
        effect_invalidated_memory_ranges: state.effect_invalidated_memory_ranges.clone(),
        effect_all_memory_invalidated: state.effect_all_memory_invalidated,
        possible_allocation_identities: state.possible_allocation_identities.clone(),
    }))
}

fn call_arguments_from_values(
    transfer: &reference_plan::Transfer,
    call: &reference_plan::Call,
    values: &[ReferenceValue],
    state: &ReferenceState,
    rule: &ExternalCallPayload,
    catalog: &RuntimeCatalog,
) -> PyResult<Vec<ReferenceValue>> {
    if !call.argument_nodes.is_empty() {
        return Ok(call
            .argument_nodes
            .iter()
            .map(|index| values[*index].clone())
            .collect());
    }
    let base_offset = if transfer.terminator.op == "outcome_external" {
        4
    } else {
        0
    };
    let maximum = call
        .stack_inputs
        .iter()
        .filter(|(offset, _width, _node)| {
            *offset >= base_offset && (*offset - base_offset) % 4 == 0
        })
        .map(|(offset, _width, _node)| ((*offset - base_offset) / 4) as usize)
        .max();
    let count = rule
        .argument_words
        .max(maximum.map_or(0, |index| index + 1));
    let mut arguments = vec![None; count];
    for (offset, width, node) in &call.stack_inputs {
        if *width != 4 || *offset < base_offset || (*offset - base_offset) % 4 != 0 {
            continue;
        }
        let index = ((*offset - base_offset) / 4) as usize;
        if index < count {
            arguments[index] = Some(values[*node].clone());
        }
    }
    let stack = &values[call.register_nodes[7]];
    for (index, argument) in arguments.iter_mut().enumerate() {
        if argument.is_some() {
            continue;
        }
        let address = adjust_reference_by_constant(
            stack,
            base_offset as i64 + index as i64 * 4,
            catalog.alternative_limit,
        )?;
        let Some(keys) = reference_memory_keys(&address, 4) else {
            *argument = Some(unknown_value());
            continue;
        };
        let mut value = bottom_value();
        for key in keys {
            value = join_value(
                &value,
                &reference_memory_value(state, &key, catalog)?,
                catalog.alternative_limit,
            )?;
        }
        *argument = Some(value);
    }
    Ok(arguments.into_iter().map(Option::unwrap).collect())
}

fn callback_source_value(
    callback: &ExternalCallbackPayload,
    arguments: &[ReferenceValue],
    state: &ReferenceState,
    catalog: &RuntimeCatalog,
) -> PyResult<ReferenceValue> {
    let Some(source) = arguments.get(callback.source_argument) else {
        return Ok(unknown_value());
    };
    if callback.source_kind == "argument_word" {
        return Ok(source.clone());
    }
    let address = adjust_reference_by_constant(
        source,
        i64::from(callback.source_offset),
        catalog.alternative_limit,
    )?;
    let Some(keys) = reference_memory_keys(&address, 4) else {
        return Ok(unknown_value());
    };
    let mut value = bottom_value();
    for key in keys {
        value = join_value(
            &value,
            &reference_memory_value(state, &key, catalog)?,
            catalog.alternative_limit,
        )?;
    }
    Ok(value)
}

fn callback_targets(
    callback: &ExternalCallbackPayload,
    arguments: &[ReferenceValue],
    state: &ReferenceState,
    catalog: &RuntimeCatalog,
) -> PyResult<Option<BTreeSet<u32>>> {
    let value = callback_source_value(callback, arguments, state, catalog)?;
    if value.kind != "finite"
        || value
            .scalars
            .iter()
            .any(|scalar| !callback.sentinels.contains(scalar))
    {
        return Ok(None);
    }
    let mut targets = BTreeSet::new();
    for atom in &value.references {
        if atom.kind != "guest_code" || atom.offset != 0 {
            return Ok(None);
        }
        let Some(identity) = atom.identity.strip_prefix("rva:") else {
            return Ok(None);
        };
        let Ok(target) = u32::from_str_radix(identity, 16) else {
            return Ok(None);
        };
        targets.insert(target);
    }
    Ok(Some(targets))
}

fn callback_root_state(target: u32, shared: &ReferenceState) -> PyResult<ReferenceState> {
    let mut state = default_reference_state();
    state.registers[7] = finite_value(
        [],
        [ReferenceAtom {
            kind: "object".into(),
            identity: format!("captured_stack:root:{target:08x}").into(),
            offset: 0,
        }],
        STACK_ALTERNATIVE_LIMIT,
    )?;
    state.memory = shared.memory.clone();
    state.invalidated_memory_ranges = shared.invalidated_memory_ranges.clone();
    state.all_memory_invalidated = shared.all_memory_invalidated;
    state.callback_registry = shared.callback_registry.clone();
    state.relational_object_bindings = shared.relational_object_bindings.clone();
    state.possible_allocation_identities = shared.possible_allocation_identities.clone();
    Ok(state)
}

fn exception_projection_state(
    source: &ReferenceState,
    projection: &ExceptionStateProjectionInput,
    transition: &CheckedExceptionTransitionInput,
    action_values: &[ReferenceValue],
    function_context_identity: &str,
    catalog: &RuntimeCatalog,
) -> PyResult<(ReferenceState, Vec<String>)> {
    const REGISTERS: [&str; REGISTER_COUNT] =
        ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];
    const FLAGS: [&str; 6] = ["cf", "zf", "sf", "of", "pf", "df"];
    let alternative_limit = catalog.alternative_limit;
    let lowered = |values: &[String]| {
        values
            .iter()
            .map(|value| value.to_lowercase())
            .collect::<BTreeSet<_>>()
    };
    let selected_registers = lowered(&projection.registers);
    let selected_flags = lowered(&projection.flags);
    let selected_x87 = lowered(&projection.x87);
    let selected_stack = lowered(&projection.stack);
    let selected_exception_record = lowered(&projection.exception_record);
    let selected_context = lowered(&projection.context);
    let register_names = REGISTERS.into_iter().collect::<BTreeSet<_>>();
    let flag_names = FLAGS.into_iter().collect::<BTreeSet<_>>();
    let mut issues = BTreeSet::new();
    for name in selected_registers
        .iter()
        .filter(|name| !register_names.contains(name.as_str()))
    {
        issues.insert(format!("unsupported_register:{name}"));
    }
    for name in selected_flags
        .iter()
        .filter(|name| name.as_str() != "eflags" && !flag_names.contains(name.as_str()))
    {
        issues.insert(format!("unsupported_flag:{name}"));
    }
    for name in selected_stack.iter().filter(|name| name.as_str() != "esp") {
        issues.insert(format!("unsupported_stack:{name}"));
    }
    let supported_x87 = [
        "all",
        "code_selector",
        "control",
        "control_word",
        "data_offset",
        "data_pointer",
        "data_selector",
        "environment",
        "error_offset",
        "error_selector",
        "instruction_pointer",
        "registers",
        "stack",
        "status",
        "status_word",
        "tag_word",
        "tags",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    for name in selected_x87
        .iter()
        .filter(|name| !supported_x87.contains(name.as_str()))
    {
        issues.insert(format!("unsupported_x87:{name}"));
    }
    let primary_exception_record_fields = [
        "exceptioncode".to_owned(),
        "exceptionflags".to_owned(),
        "exceptionrecord".to_owned(),
        "exceptionaddress".to_owned(),
        "numberparameters".to_owned(),
    ]
    .into_iter()
    .chain((0..15).map(|index| format!("exceptioninformation[{index}]")))
    .collect::<BTreeSet<_>>();
    let parse_record_path = |name: &str| -> Option<(usize, String)> {
        if primary_exception_record_fields.contains(name) {
            return Some((0, name.to_owned()));
        }
        let suffix = name.strip_prefix("exceptionrecord[")?;
        let (depth, field) = suffix.split_once("].")?;
        if depth.is_empty()
            || depth.starts_with('0')
            || !depth.bytes().all(|value| value.is_ascii_digit())
            || !primary_exception_record_fields.contains(field)
        {
            return None;
        }
        Some((depth.parse().ok()?, field.to_owned()))
    };
    let mut exception_record_paths = Vec::new();
    for name in &selected_exception_record {
        match parse_record_path(name) {
            Some((depth, _field)) if depth >= 4 => {
                issues.insert(format!("unsupported_exception_record_depth:{name}"));
            }
            Some(path) => exception_record_paths.push(path),
            None => {
                issues.insert(format!("unsupported_exception_record:{name}"));
            }
        }
    }
    if exception_record_paths
        .iter()
        .any(|(depth, field)| *depth != 0 && field == "exceptionaddress")
    {
        issues.insert("nested_numeric_exception_address_unsupported".to_owned());
    }
    if exception_record_paths
        .iter()
        .any(|(depth, _field)| *depth != 0)
        && transition.occurrence_kind != "call"
    {
        issues.insert("nested_exception_record_source_unavailable".to_owned());
    }
    // Numeric code-address fields are valid semantic projections here.  Native
    // realization still requires pinned layout authority before materializing
    // original numeric values in a candidate image.
    for name in selected_context.iter().filter(|name| {
        name.as_str() != "eflags"
            && name.as_str() != "eip"
            && name.as_str() != "contextflags"
            && !register_names.contains(name.as_str())
    }) {
        issues.insert(format!("unsupported_context:{name}"));
    }
    let mut kept_registers = selected_registers
        .union(
            &selected_context
                .iter()
                .filter(|name| register_names.contains(name.as_str()))
                .cloned()
                .collect(),
        )
        .cloned()
        .collect::<BTreeSet<_>>();
    if selected_stack.contains("esp") {
        kept_registers.insert("esp".to_owned());
    }
    let registers = REGISTERS
        .iter()
        .enumerate()
        .map(|(index, name)| {
            if kept_registers.contains(*name) {
                source.registers[index].clone()
            } else {
                unknown_value()
            }
        })
        .collect::<Vec<_>>();
    let preserve_all_flags =
        selected_flags.contains("eflags") || selected_context.contains("eflags");
    let flags = source
        .flags
        .iter()
        .enumerate()
        .map(|(index, value)| {
            if preserve_all_flags || (index < FLAGS.len() && selected_flags.contains(FLAGS[index]))
            {
                value.clone()
            } else {
                unknown_value()
            }
        })
        .collect::<Vec<_>>();
    let flag_relations = source
        .flag_relations
        .iter()
        .enumerate()
        .map(|(index, relation)| {
            if preserve_all_flags || (index < FLAGS.len() && selected_flags.contains(FLAGS[index]))
            {
                relation.clone()
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let kept_register_indexes = REGISTERS
        .iter()
        .enumerate()
        .filter_map(|(index, name)| kept_registers.contains(*name).then_some(index as u8))
        .collect::<BTreeSet<_>>();
    let mut projected = ReferenceState {
        registers: registers.clone(),
        flags: flags.clone(),
        memory: source.memory.clone(),
        call_registers: registers,
        call_flags: flags,
        invalidated_memory_ranges: source.invalidated_memory_ranges.clone(),
        all_memory_invalidated: source.all_memory_invalidated,
        callback_registry: source.callback_registry.clone(),
        flag_relations,
        scalar_constraints: source
            .scalar_constraints
            .iter()
            .filter(|((register, _mask), _values)| kept_register_indexes.contains(register))
            .map(|(key, values)| (*key, values.clone()))
            .collect(),
        preserves_inherited_memory: source.preserves_inherited_memory,
        relational_object_bindings: source.relational_object_bindings.clone(),
        written_memory_keys: source.written_memory_keys.clone(),
        effect_invalidated_memory_ranges: source.effect_invalidated_memory_ranges.clone(),
        effect_all_memory_invalidated: source.effect_all_memory_invalidated,
        possible_allocation_identities: source.possible_allocation_identities.clone(),
    };
    let materialized_fields = !selected_exception_record.is_empty() || !selected_context.is_empty();
    if materialized_fields
        && (transition.native_exception_code.is_none()
            || transition.native_exception_flags.is_none()
            || transition.native_exception_parameter_count.is_none()
            || transition.native_exception_continuable.is_none())
    {
        issues.insert("native_exception_metadata_unavailable".to_owned());
    }
    if !issues.is_empty() || !materialized_fields {
        return Ok((projected, issues.into_iter().collect()));
    }

    let transition_id = transition
        .transition_id
        .as_ref()
        .expect("authorizing checked exception has a stable identity");
    let record_depth = exception_record_paths
        .iter()
        .map(|(depth, _field)| *depth)
        .max()
        .unwrap_or(0);
    let record_identity = format!("exception_record:{transition_id}:{function_context_identity}");
    let record_identities = (0..=record_depth)
        .map(|depth| {
            if depth == 0 {
                record_identity.clone()
            } else {
                format!("{record_identity}:{depth}")
            }
        })
        .collect::<Vec<_>>();
    let context_identity = format!("exception_context:{transition_id}:{function_context_identity}");
    let frame_identity =
        format!("exception_handler_frame:{transition_id}:{function_context_identity}");
    let scalar = |value| finite_value([value], [], alternative_limit);
    let pointer = |identity: &str| {
        finite_value(
            [],
            [ReferenceAtom {
                kind: "object".to_owned(),
                identity: identity.to_owned().into(),
                offset: 0,
            }],
            alternative_limit,
        )
    };
    let mut memory = (*projected.memory).clone();
    let mut record_values = BTreeMap::from([
        (
            "exceptioncode".to_owned(),
            scalar(transition.native_exception_code.unwrap())?,
        ),
        (
            "exceptionflags".to_owned(),
            scalar(transition.native_exception_flags.unwrap())?,
        ),
        (
            "exceptionrecord".to_owned(),
            if record_depth == 0 {
                scalar(0)?
            } else {
                pointer(&record_identities[1])?
            },
        ),
        (
            "numberparameters".to_owned(),
            scalar(transition.native_exception_parameter_count.unwrap())?,
        ),
    ]);
    let exception_address = if catalog.guest_image_base == 0 {
        transition.source_rva
    } else {
        catalog.guest_image_base.wrapping_add(transition.source_rva)
    };
    record_values.insert(
        "exceptionaddress".to_owned(),
        catalog.classify_scalar(exception_address)?,
    );
    if let Some([operation_parameter, address_parameter]) =
        transition.native_exception_access_violation
    {
        if action_values.len() >= 3 {
            record_values.insert(
                format!("exceptioninformation[{operation_parameter}]"),
                action_values[1].clone(),
            );
            record_values.insert(
                format!("exceptioninformation[{address_parameter}]"),
                action_values[2].clone(),
            );
        }
    }
    let mut record_offsets = BTreeMap::from([
        ("exceptioncode".to_owned(), 0i64),
        ("exceptionflags".to_owned(), 4),
        ("exceptionrecord".to_owned(), 8),
        ("exceptionaddress".to_owned(), 12),
        ("numberparameters".to_owned(), 16),
    ]);
    for index in 0..15 {
        record_offsets.insert(format!("exceptioninformation[{index}]"), 20 + index * 4);
    }
    for depth in 0..record_depth {
        memory.insert(
            MemoryKey::new("object", record_identities[depth].clone(), 8, 4),
            pointer(&record_identities[depth + 1])?,
        );
    }
    for (depth, field) in &exception_record_paths {
        let value = if *depth == 0 {
            let Some(value) = record_values.get(field) else {
                issues.insert(format!("exception_record_value_unavailable:{field}"));
                continue;
            };
            value.clone()
        } else if field == "exceptionrecord" {
            if *depth < record_depth {
                pointer(&record_identities[*depth + 1])?
            } else {
                scalar(0)?
            }
        } else {
            unknown_value()
        };
        memory.insert(
            MemoryKey::new(
                "object",
                record_identities[*depth].clone(),
                record_offsets[field],
                4,
            ),
            value,
        );
    }

    let context_offsets = BTreeMap::from([
        ("edi", 156i64),
        ("esi", 160),
        ("ebx", 164),
        ("edx", 168),
        ("ecx", 172),
        ("eax", 176),
        ("ebp", 180),
        ("eflags", 192),
        ("esp", 196),
    ]);
    for field in &selected_context {
        let (offset, value) = if field == "contextflags" {
            (0, scalar(0x10003)?)
        } else if field == "eflags" {
            (192, source.flags.last().expect("EFLAGS slot").clone())
        } else if field == "eip" {
            (184, catalog.classify_scalar(exception_address)?)
        } else {
            let register_index = REGISTERS
                .iter()
                .position(|name| *name == field)
                .expect("validated CONTEXT register projection");
            (
                context_offsets[field.as_str()],
                source.registers[register_index].clone(),
            )
        };
        memory.insert(
            MemoryKey::new("object", context_identity.clone(), offset, 4),
            value,
        );
    }

    memory.insert(
        MemoryKey::new("object", frame_identity.clone(), 0, 4),
        unknown_value(),
    );
    memory.insert(
        MemoryKey::new("object", frame_identity.clone(), 4, 4),
        pointer(&record_identity)?,
    );
    memory.insert(
        MemoryKey::new("object", frame_identity.clone(), 8, 4),
        unknown_value(),
    );
    memory.insert(
        MemoryKey::new("object", frame_identity.clone(), 12, 4),
        pointer(&context_identity)?,
    );
    memory.insert(
        MemoryKey::new("object", frame_identity.clone(), 16, 4),
        unknown_value(),
    );
    let handler_stack = pointer(&frame_identity)?;
    projected.registers[7] = handler_stack.clone();
    projected.call_registers[7] = handler_stack;
    projected.memory = Arc::new(memory);
    Ok((projected, issues.into_iter().collect()))
}

fn parameterizable_call_value(value: &ReferenceValue) -> bool {
    value.kind == "finite"
        && value.scalars.is_empty()
        && !value.references.is_empty()
        && value.references.iter().all(|atom| {
            atom.kind == "object"
                && (captured_stack_owner(&atom.identity).is_some()
                    || call_parameter_owner(&atom.identity).is_some())
        })
}

fn parameterize_call_value(
    coordinate: &str,
    value: &ReferenceValue,
    relational_word: bool,
    callee_context: &NativeFunctionContext,
    stack_atoms: &[ReferenceAtom],
    catalog: &RuntimeCatalog,
    bindings: &mut BTreeMap<String, ReferenceValue>,
) -> PyResult<ReferenceValue> {
    let identity = format!(
        "call_parameter_object:{}:{coordinate}",
        callee_context.identity(),
    );
    if value.kind == "bottom" || (!relational_word && !parameterizable_call_value(value)) {
        return Ok(value.clone());
    }
    bindings.insert(identity.clone(), value.clone());
    // Callee-saved registers are relational words even when the current
    // abstract value is not a pointer.  This token preserves caller
    // correlation only; it neither assumes ABI preservation nor grants object
    // authority.  Any actual callee mutation destroys the token normally.
    if relational_word {
        return finite_value(
            [],
            [ReferenceAtom {
                kind: "object".into(),
                identity: identity.into(),
                offset: 0,
            }],
            catalog.alternative_limit,
        );
    }
    let stack_bases = stack_atoms
        .iter()
        .map(|atom| (&*atom.identity, atom.offset))
        .collect::<BTreeMap<_, _>>();
    if value
        .references
        .iter()
        .all(|atom| stack_bases.contains_key(&*atom.identity))
    {
        let offsets = value
            .references
            .iter()
            .map(|atom| atom.offset - stack_bases[&*atom.identity] + 4)
            .collect::<Vec<_>>();
        if offsets.iter().all(|offset| *offset >= 4) {
            return finite_value(
                [],
                offsets.into_iter().map(|offset| ReferenceAtom {
                    kind: "object".into(),
                    identity: callee_context.frame_identity().into(),
                    offset,
                }),
                catalog.alternative_limit.max(STACK_ALTERNATIVE_LIMIT),
            );
        }
    }
    finite_value(
        [],
        [ReferenceAtom {
            kind: "object".into(),
            identity: identity.into(),
            offset: 0,
        }],
        catalog.alternative_limit,
    )
}

struct NativeCalleeProjection {
    state: ReferenceState,
    frame_reused: bool,
    projection_exceeded: bool,
    parameter_bindings: BTreeMap<String, ReferenceValue>,
}

fn native_callee_state(
    call: &reference_plan::Call,
    values: &[ReferenceValue],
    caller: &ReferenceState,
    catalog: &RuntimeCatalog,
    callee_context: &NativeFunctionContext,
) -> PyResult<NativeCalleeProjection> {
    const STACK_PROJECTION_LIMIT: i64 = 4096;
    let frame_identity = callee_context.frame_identity();
    let frame_reused = caller.memory.keys().any(|key| {
        key.kind == "object"
            && captured_stack_owner(&key.identity).as_deref() == Some(frame_identity)
    });
    let caller_esp = &values[call.register_nodes[7]];
    let stack_atoms = caller_esp
        .references
        .iter()
        .filter(|atom| atom.kind == "object" && captured_stack_owner(&atom.identity).is_some())
        .cloned()
        .collect::<Vec<_>>();
    let mut projected = BTreeMap::new();
    for (offset, width, node) in &call.stack_inputs {
        let key = MemoryKey::new("object", frame_identity, *offset as i64 + 4, *width);
        let value = values[*node].clone();
        let joined = if let Some(previous) = projected.remove(&key) {
            join_value(&previous, &value, catalog.alternative_limit)?
        } else {
            value
        };
        projected.insert(key, joined);
    }
    for offset in (0..STACK_PROJECTION_LIMIT).step_by(4) {
        let alternatives = stack_atoms
            .iter()
            .map(|atom| {
                caller.memory.get(&MemoryKey::new(
                    "object",
                    atom.identity.clone(),
                    atom.offset + offset,
                    4,
                ))
            })
            .collect::<Vec<_>>();
        if alternatives.is_empty() || alternatives.iter().all(|value| value.is_none()) {
            break;
        }
        let mut value = bottom_value();
        for alternative in alternatives {
            value = join_value(
                &value,
                alternative.unwrap_or(&unknown_value()),
                catalog.alternative_limit,
            )?;
        }
        let key = MemoryKey::new("object", frame_identity, offset + 4, 4);
        // Checked call-frame inputs dominate the broader inferred caller
        // memory projection at the same physical coordinate.
        projected.entry(key).or_insert(value);
    }
    let projection_exceeded = stack_atoms.iter().any(|atom| {
        caller.memory.keys().any(|key| {
            key.kind == "object"
                && key.identity == atom.identity
                && key.offset - atom.offset >= STACK_PROJECTION_LIMIT
        })
    });
    let raw_registers = call
        .register_nodes
        .iter()
        .map(|index| values[*index].clone())
        .collect::<Vec<_>>();
    let mut parameter_bindings = BTreeMap::new();
    let mut registers = raw_registers
        .iter()
        .enumerate()
        .map(|(index, value)| {
            if index == 7 {
                Ok(value.clone())
            } else {
                parameterize_call_value(
                    &format!("register:{index}"),
                    value,
                    matches!(index, 1 | 4 | 5 | 6),
                    callee_context,
                    &stack_atoms,
                    catalog,
                    &mut parameter_bindings,
                )
            }
        })
        .collect::<PyResult<Vec<_>>>()?;
    projected = projected
        .into_iter()
        .map(|(key, value)| {
            let parameterized = parameterize_call_value(
                &format!("stack:{}:{}", key.offset, key.width),
                &value,
                false,
                callee_context,
                &stack_atoms,
                catalog,
                &mut parameter_bindings,
            )?;
            Ok((key, parameterized))
        })
        .collect::<PyResult<BTreeMap<_, _>>>()?;
    registers[7] = finite_value(
        [],
        [ReferenceAtom {
            kind: "object".to_owned(),
            identity: frame_identity.into(),
            offset: 0,
        }],
        STACK_ALTERNATIVE_LIMIT,
    )?;
    let caller_memory = caller
        .memory
        .iter()
        .filter(|(key, _value)| {
            key.kind != "object"
                || captured_stack_owner(&key.identity).as_deref() != Some(frame_identity)
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<MemoryMap>();
    let mut parameter_invalidations = BTreeSet::new();
    for (parameter_identity, binding) in &parameter_bindings {
        for atom in &binding.references {
            for row in caller.invalidated_memory_ranges.iter() {
                if row.kind == "object" && row.identity == atom.identity {
                    parameter_invalidations.insert(MemoryRange::from_coordinates(
                        "object".into(),
                        parameter_identity.as_str().into(),
                        row.start() - i128::from(atom.offset),
                        row.end() - i128::from(atom.offset),
                    ));
                }
            }
        }
    }
    let frame_binding = finite_value(
        [],
        stack_atoms.iter().map(|atom| ReferenceAtom {
            kind: "object".to_owned(),
            identity: atom.identity.clone(),
            offset: atom.offset - 4,
        }),
        STACK_ALTERNATIVE_LIMIT,
    )?;
    let mut live_transients = registers[..7]
        .iter()
        .chain(projected.values())
        .chain(parameter_bindings.values())
        .chain(std::iter::once(&frame_binding))
        .chain(caller.callback_registry.values())
        .chain(
            caller_memory
                .iter()
                .filter(|(key, _value)| transient_owner(&key.identity).is_none())
                .map(|(_key, value)| value),
        )
        .flat_map(|value| &value.references)
        .filter(|atom| matches!(atom.kind.as_str(), "object" | "object_view"))
        .filter_map(|atom| transient_owner(&atom.identity))
        .collect::<BTreeSet<_>>();
    loop {
        let previous = live_transients.len();
        for (key, value) in &caller_memory {
            if transient_owner(&key.identity).is_some_and(|owner| live_transients.contains(&owner))
            {
                live_transients.extend(
                    value
                        .references
                        .iter()
                        .filter(|atom| matches!(atom.kind.as_str(), "object" | "object_view"))
                        .filter_map(|atom| transient_owner(&atom.identity)),
                );
            }
        }
        for (identity, value) in caller.relational_object_bindings.iter() {
            if live_transients.contains(identity) {
                live_transients.extend(
                    value
                        .references
                        .iter()
                        .filter(|atom| matches!(atom.kind.as_str(), "object" | "object_view"))
                        .filter_map(|atom| transient_owner(&atom.identity)),
                );
            }
        }
        if live_transients.len() == previous {
            break;
        }
    }
    let mut memory = caller_memory
        .into_iter()
        .filter(|(key, _value)| {
            transient_owner(&key.identity).is_none_or(|owner| live_transients.contains(&owner))
        })
        .collect::<MemoryMap>();
    memory.extend(projected);
    let mut invalidated = caller
        .invalidated_memory_ranges
        .iter()
        .filter(|row| {
            transient_owner(&row.identity).is_none_or(|owner| live_transients.contains(&owner))
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    invalidated.extend(parameter_invalidations);
    for atom in &stack_atoms {
        for row in caller.invalidated_memory_ranges.iter() {
            if row.kind == "object"
                && row.identity == atom.identity
                && row.end() > i128::from(atom.offset)
            {
                invalidated.insert(MemoryRange::from_coordinates(
                    "object".into(),
                    frame_identity.into(),
                    row
                        .start()
                        .max(i128::from(atom.offset))
                        - i128::from(atom.offset)
                        + 4,
                    row.end() - i128::from(atom.offset) + 4,
                ));
            }
        }
    }
    let mut relational = caller
        .relational_object_bindings
        .iter()
        .filter(|(identity, _value)| live_transients.contains(*identity))
        .map(|(identity, value)| (identity.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    relational.extend(parameter_bindings.clone());
    relational.insert(frame_identity.to_owned(), frame_binding);
    let mut flags = call
        .flag_nodes
        .iter()
        .map(|index| values[*index].clone())
        .collect::<Vec<_>>();
    flags.resize(FLAG_COUNT, unknown_value());
    Ok(NativeCalleeProjection {
        state: ReferenceState {
            registers,
            flags,
            memory: Arc::new(memory),
            call_registers: vec![unknown_value(); REGISTER_COUNT],
            call_flags: vec![unknown_value(); FLAG_COUNT],
            invalidated_memory_ranges: Arc::new(normalize_ranges(invalidated)?),
            all_memory_invalidated: caller.all_memory_invalidated,
            callback_registry: caller.callback_registry.clone(),
            flag_relations: caller.flag_relations.clone(),
            scalar_constraints: caller.scalar_constraints.clone(),
            preserves_inherited_memory: true,
            relational_object_bindings: Arc::new(relational),
            written_memory_keys: Arc::new(MemoryKeySet::default()),
            effect_invalidated_memory_ranges: Arc::new(BTreeSet::new()),
            effect_all_memory_invalidated: false,
            possible_allocation_identities: caller.possible_allocation_identities.clone(),
        },
        frame_reused,
        projection_exceeded,
        parameter_bindings,
    })
}

fn effect_summary_state(mut state: ReferenceState, catalog: &RuntimeCatalog) -> ReferenceState {
    state = boundary_state(state, catalog);
    let removed = state
        .memory
        .keys()
        .filter(|key| !state.written_memory_keys.contains(*key))
        .cloned()
        .collect::<Vec<_>>();
    for key in removed {
        Arc::make_mut(&mut state.memory).remove(&key);
    }
    state.invalidated_memory_ranges = state.effect_invalidated_memory_ranges.clone();
    state.all_memory_invalidated = state.effect_all_memory_invalidated;
    state
}

fn instantiate_parameter_value(
    value: &ReferenceValue,
    bindings: &BTreeMap<String, ReferenceValue>,
    callee_context: &NativeFunctionContext,
    catalog: &RuntimeCatalog,
) -> PyResult<ReferenceValue> {
    if value.kind != "finite" || value.references.is_empty() {
        return Ok(value.clone());
    }
    let mut scalars = value.scalars.iter().copied().collect::<BTreeSet<_>>();
    let mut references = BTreeSet::new();
    let mut direct_bindings = Vec::new();
    let context_prefix = format!("call_parameter_object:{}:", callee_context.identity(),);
    for atom in &value.references {
        let owner = call_parameter_owner(&atom.identity);
        let binding = owner.as_ref().and_then(|identity| bindings.get(identity));
        let Some(binding) = binding else {
            if owner
                .as_deref()
                .is_some_and(|identity| identity.starts_with(&context_prefix))
            {
                return Ok(conflict_value());
            }
            references.insert(atom.clone());
            continue;
        };
        if atom.kind == "object"
            && owner.as_deref() == Some(atom.identity.as_ref())
            && atom.offset == 0
        {
            // Direct word parameters may bind to any abstract word.  Derived
            // identities below remain restricted to exact object bindings.
            direct_bindings.push(binding.clone());
            continue;
        }
        if binding.kind != "finite"
            || !binding.scalars.is_empty()
            || binding
                .references
                .iter()
                .any(|actual| actual.kind != "object")
        {
            return Ok(conflict_value());
        }
        for actual in &binding.references {
            let Some(instantiated) = instantiate_call_parameter_identity(&atom.identity, actual)
            else {
                return Ok(conflict_value());
            };
            references.insert(ReferenceAtom {
                kind: if atom.kind == "object_view" {
                    "object_view".to_owned()
                } else {
                    "object".to_owned()
                },
                identity: instantiated.identity.into(),
                offset: if atom.kind == "object_view" {
                    0
                } else {
                    instantiated.offset + atom.offset
                },
            });
        }
    }
    let mut result = finite_value(
        std::mem::take(&mut scalars),
        references,
        catalog.alternative_limit.max(STACK_ALTERNATIVE_LIMIT),
    )?;
    for binding in direct_bindings {
        result = join_value(
            &result,
            &binding,
            catalog.alternative_limit.max(STACK_ALTERNATIVE_LIMIT),
        )?;
    }
    Ok(result)
}

fn instantiate_parameter_key(
    key: &MemoryKey,
    bindings: &BTreeMap<String, ReferenceValue>,
    callee_context: &NativeFunctionContext,
) -> Option<Vec<MemoryKey>> {
    let owner = call_parameter_owner(&key.identity);
    let binding = owner.as_ref().and_then(|identity| bindings.get(identity));
    if binding.is_none() {
        let context_prefix = format!("call_parameter_object:{}:", callee_context.identity(),);
        return if owner
            .as_deref()
            .is_some_and(|identity| identity.starts_with(&context_prefix))
        {
            None
        } else {
            Some(vec![key.clone()])
        };
    }
    let binding = binding.expect("checked binding");
    if key.kind != "object"
        || binding.kind != "finite"
        || !binding.scalars.is_empty()
        || binding.references.iter().any(|atom| atom.kind != "object")
    {
        return None;
    }
    binding
        .references
        .iter()
        .map(|actual| {
            let instantiated = instantiate_call_parameter_identity(&key.identity, actual)?;
            Some(MemoryKey::new(
                "object",
                instantiated.identity,
                instantiated.offset + key.offset,
                key.width,
            ))
        })
        .collect()
}

fn instantiate_parameter_range(
    row: &MemoryRange,
    bindings: &BTreeMap<String, ReferenceValue>,
    callee_context: &NativeFunctionContext,
) -> Option<Vec<MemoryRange>> {
    let owner = call_parameter_owner(&row.identity);
    let binding = owner.as_ref().and_then(|identity| bindings.get(identity));
    if binding.is_none() {
        let context_prefix = format!("call_parameter_object:{}:", callee_context.identity(),);
        return if owner
            .as_deref()
            .is_some_and(|identity| identity.starts_with(&context_prefix))
        {
            None
        } else {
            Some(vec![row.clone()])
        };
    }
    let binding = binding.expect("checked binding");
    if row.kind != "object"
        || binding.kind != "finite"
        || !binding.scalars.is_empty()
        || binding.references.iter().any(|atom| atom.kind != "object")
    {
        return None;
    }
    binding
        .references
        .iter()
        .map(|actual| {
            let instantiated = instantiate_call_parameter_identity(&row.identity, actual)?;
            Some(MemoryRange::from_coordinates(
                "object".into(),
                instantiated.identity.clone(),
                i128::from(instantiated.offset) + row.start(),
                i128::from(instantiated.offset) + row.end(),
            ))
        })
        .collect()
}

fn restore_callee_value(
    value: &ReferenceValue,
    frame_identity: &str,
    caller_esp: &ReferenceValue,
    bindings: &BTreeMap<String, ReferenceValue>,
    callee_context: &NativeFunctionContext,
    catalog: &RuntimeCatalog,
    alternative_limit: usize,
) -> PyResult<ReferenceValue> {
    let value = instantiate_parameter_value(value, bindings, callee_context, catalog)?;
    if value.kind != "finite" {
        return Ok(value);
    }
    let mut references = BTreeSet::new();
    for atom in &value.references {
        if atom.kind == "object" && atom.identity == frame_identity && atom.offset >= 4 {
            if caller_esp.kind != "finite"
                || !caller_esp.scalars.is_empty()
                || caller_esp
                    .references
                    .iter()
                    .any(|base| base.kind != "object")
            {
                return Ok(conflict_value());
            }
            references.extend(caller_esp.references.iter().map(|base| ReferenceAtom {
                kind: "object".to_owned(),
                identity: base.identity.clone(),
                offset: base.offset + atom.offset - 4,
            }));
        } else if matches!(atom.kind.as_str(), "object" | "object_view")
            && captured_stack_owner(&atom.identity).as_deref() == Some(frame_identity)
        {
            return Ok(conflict_value());
        } else {
            references.insert(atom.clone());
        }
    }
    finite_value(
        value.scalars.iter().copied(),
        references,
        alternative_limit.max(STACK_ALTERNATIVE_LIMIT),
    )
}

fn caller_stack_ranges(
    start: i128,
    end: i128,
    caller_esp: &ReferenceValue,
) -> Option<Vec<MemoryRange>> {
    if end <= 4 {
        return Some(Vec::new());
    }
    if caller_esp.kind != "finite"
        || !caller_esp.scalars.is_empty()
        || caller_esp
            .references
            .iter()
            .any(|atom| atom.kind != "object")
    {
        return None;
    }
    let clipped_start = start.max(4) - 4;
    let clipped_end = end - 4;
    Some(
        caller_esp
            .references
            .iter()
            .map(|atom| {
                MemoryRange::from_coordinates(
                    "object".into(),
                    atom.identity.clone(),
                    i128::from(atom.offset) + clipped_start,
                    i128::from(atom.offset) + clipped_end,
                )
            })
            .collect(),
    )
}

fn native_return_state_for_caller(
    summary: &ReferenceState,
    caller: &ReferenceState,
    caller_esp: &ReferenceValue,
    callee_context: &NativeFunctionContext,
    parameter_bindings: &BTreeMap<String, ReferenceValue>,
    catalog: &RuntimeCatalog,
    failure_detail: &mut Option<String>,
) -> PyResult<Option<ReferenceState>> {
    let frame_identity = callee_context.frame_identity();
    let caller_stack_frames = caller
        .registers
        .iter()
        .chain(caller.memory.values())
        .chain(caller.callback_registry.values())
        .chain(caller.relational_object_bindings.values())
        .flat_map(|value| &value.references)
        .filter(|atom| matches!(atom.kind.as_str(), "object" | "object_view"))
        .filter_map(|atom| captured_stack_owner(&atom.identity))
        .collect::<BTreeSet<_>>();
    let mut registers = summary
        .registers
        .iter()
        .map(|value| {
            restore_callee_value(
                value,
                &frame_identity,
                caller_esp,
                parameter_bindings,
                callee_context,
                catalog,
                catalog.alternative_limit,
            )
        })
        .collect::<PyResult<Vec<_>>>()?;
    registers[7] = caller_esp.clone();
    let mut instantiated_ranges = BTreeSet::new();
    for row in summary.invalidated_memory_ranges.iter() {
        let owner = (row.kind == "object")
            .then(|| captured_stack_owner(&row.identity))
            .flatten();
        if owner.as_deref() == Some(frame_identity) && row.identity != frame_identity {
            continue;
        }
        if row.kind == "object" && row.identity == frame_identity {
            let Some(rows) = caller_stack_ranges(row.start(), row.end(), caller_esp) else {
                *failure_detail = Some(format!(
                    "invalidated_callee_stack_range:esp_kind={}:esp_scalars={}:esp_references={}",
                    caller_esp.kind,
                    caller_esp.scalars.len(),
                    caller_esp
                        .references
                        .iter()
                        .map(|atom| format!("{}:{}", atom.kind, atom.identity))
                        .collect::<Vec<_>>()
                        .join(","),
                ));
                return Ok(None);
            };
            instantiated_ranges.extend(rows);
        } else {
            let Some(rows) = instantiate_parameter_range(row, parameter_bindings, callee_context)
            else {
                *failure_detail = Some("invalidated_parameter_range".to_owned());
                return Ok(None);
            };
            instantiated_ranges.extend(rows);
        }
    }
    let all_memory_invalidated = caller.all_memory_invalidated || summary.all_memory_invalidated;
    let mut memory = if all_memory_invalidated {
        Arc::new(MemoryMap::default())
    } else {
        caller.memory.clone()
    };
    if !all_memory_invalidated {
        let removed = memory
            .keys()
            .filter(|key| {
                instantiated_ranges.iter().any(|row| {
                    row.kind == key.kind
                        && row.identity == key.identity
                        && i128::from(key.offset) < row.end()
                        && row.start() < i128::from(key.offset) + i128::from(key.width)
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        for key in removed {
            Arc::make_mut(&mut memory).remove(&key);
        }
    }
    let mut instantiated_written = BTreeSet::new();
    for (key, value) in summary.memory.iter() {
        let keys = if key.kind == "object" && key.identity == frame_identity {
            if key.offset < 4 {
                continue;
            }
            let Some(rows) =
                caller_stack_ranges(
                    i128::from(key.offset),
                    i128::from(key.offset) + i128::from(key.width),
                    caller_esp,
                )
            else {
                *failure_detail = Some("callee_stack_memory_key".to_owned());
                return Ok(None);
            };
            let mut keys = Vec::with_capacity(rows.len());
            for row in rows {
                let offset = i64::try_from(row.start()).map_err(|_| {
                    invalid("restored caller stack coordinate exceeds signed-64 range")
                })?;
                keys.push(MemoryKey::new(row.kind, row.identity, offset, key.width));
            }
            keys
        } else if key.kind == "object"
            && captured_stack_owner(&key.identity).as_deref() == Some(frame_identity)
        {
            continue;
        } else {
            let Some(keys) = instantiate_parameter_key(key, parameter_bindings, callee_context)
            else {
                *failure_detail = Some(format!(
                    "parameter_memory_key:identity={}:bindings={}",
                    key.identity,
                    parameter_bindings
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(","),
                ));
                return Ok(None);
            };
            keys
        };
        let restored = restore_callee_value(
            value,
            &frame_identity,
            caller_esp,
            parameter_bindings,
            callee_context,
            catalog,
            catalog.alternative_limit,
        )?;
        for instantiated in keys {
            if instantiated.kind == "object"
                && captured_stack_owner(&instantiated.identity)
                    .is_some_and(|owner| !caller_stack_frames.contains(&owner))
            {
                continue;
            }
            let joined = if let Some(previous) = Arc::make_mut(&mut memory).remove(&instantiated) {
                join_value(&previous, &restored, catalog.alternative_limit)?
            } else {
                restored.clone()
            };
            Arc::make_mut(&mut memory).insert(instantiated.clone(), joined);
            instantiated_written.insert(instantiated);
        }
    }
    let callback_registry = Arc::new(
        summary
            .callback_registry
            .iter()
            .map(|(identity, value)| {
                Ok((
                    identity.clone(),
                    restore_callee_value(
                        value,
                        &frame_identity,
                        caller_esp,
                        parameter_bindings,
                        callee_context,
                        catalog,
                        catalog.alternative_limit,
                    )?,
                ))
            })
            .collect::<PyResult<BTreeMap<_, _>>>()?,
    );
    let mut written_memory_keys = caller.written_memory_keys.clone();
    Arc::make_mut(&mut written_memory_keys).extend(instantiated_written);
    let mut invalidated_memory_ranges = caller.invalidated_memory_ranges.clone();
    Arc::make_mut(&mut invalidated_memory_ranges).extend(instantiated_ranges.iter().cloned());
    let mut effect_invalidated_memory_ranges = caller.effect_invalidated_memory_ranges.clone();
    Arc::make_mut(&mut effect_invalidated_memory_ranges).extend(instantiated_ranges);
    let possible_allocation_identities =
        if caller.possible_allocation_identities == summary.possible_allocation_identities {
            caller.possible_allocation_identities.clone()
        } else {
            Arc::new(
                caller
                    .possible_allocation_identities
                    .union(&summary.possible_allocation_identities)
                    .cloned()
                    .collect(),
            )
        };
    Ok(Some(ReferenceState {
        registers,
        flags: summary.flags.clone(),
        memory,
        call_registers: summary.call_registers.clone(),
        call_flags: summary.call_flags.clone(),
        invalidated_memory_ranges: normalize_shared_ranges(invalidated_memory_ranges)?,
        all_memory_invalidated,
        callback_registry,
        flag_relations: summary
            .flag_relations
            .iter()
            .map(|relation| {
                relation
                    .as_ref()
                    .filter(|relation| relation.register_index != 7)
                    .cloned()
            })
            .collect(),
        scalar_constraints: summary
            .scalar_constraints
            .iter()
            .filter(|((register, _mask), _values)| *register != 7)
            .map(|(key, value)| (*key, value.clone()))
            .collect(),
        preserves_inherited_memory: caller.preserves_inherited_memory
            && summary.preserves_inherited_memory,
        relational_object_bindings: caller.relational_object_bindings.clone(),
        written_memory_keys,
        effect_invalidated_memory_ranges: normalize_shared_ranges(
            effect_invalidated_memory_ranges,
        )?,
        effect_all_memory_invalidated: caller.effect_all_memory_invalidated
            || summary.effect_all_memory_invalidated,
        possible_allocation_identities,
    }))
}

fn native_conservative_return_state_for_caller(
    summary: &ReferenceState,
    caller: &ReferenceState,
    caller_esp: &ReferenceValue,
    callee_context: &NativeFunctionContext,
    parameter_bindings: &BTreeMap<String, ReferenceValue>,
    catalog: &RuntimeCatalog,
) -> PyResult<ReferenceState> {
    let frame_identity = callee_context.frame_identity();
    let mut registers = summary
        .registers
        .iter()
        .map(|value| {
            restore_callee_value(
                value,
                &frame_identity,
                caller_esp,
                parameter_bindings,
                callee_context,
                catalog,
                catalog.alternative_limit,
            )
        })
        .collect::<PyResult<Vec<_>>>()?;
    registers[7] = caller_esp.clone();
    let callback_registry = Arc::new(
        summary
            .callback_registry
            .iter()
            .map(|(identity, value)| {
                Ok((
                    identity.clone(),
                    restore_callee_value(
                        value,
                        &frame_identity,
                        caller_esp,
                        parameter_bindings,
                        callee_context,
                        catalog,
                        catalog.alternative_limit,
                    )?,
                ))
            })
            .collect::<PyResult<BTreeMap<_, _>>>()?,
    );
    let possible_allocation_identities = Arc::new(
        caller
            .possible_allocation_identities
            .union(&summary.possible_allocation_identities)
            .cloned()
            .collect(),
    );
    Ok(ReferenceState {
        registers,
        flags: summary.flags.clone(),
        memory: Arc::new(MemoryMap::default()),
        call_registers: summary.call_registers.clone(),
        call_flags: summary.call_flags.clone(),
        invalidated_memory_ranges: Arc::new(BTreeSet::new()),
        all_memory_invalidated: true,
        callback_registry,
        flag_relations: vec![None; summary.flag_relations.len()],
        scalar_constraints: BTreeMap::new(),
        preserves_inherited_memory: false,
        relational_object_bindings: caller.relational_object_bindings.clone(),
        written_memory_keys: Arc::new(MemoryKeySet::default()),
        effect_invalidated_memory_ranges: Arc::new(BTreeSet::new()),
        effect_all_memory_invalidated: true,
        possible_allocation_identities,
    })
}

fn exact_nonlocal_target(value: &ReferenceValue) -> Option<u32> {
    if value.kind != "finite" {
        return None;
    }
    if value.scalars.len() == 1 && value.references.is_empty() {
        return value.scalars.first().copied();
    }
    if !value.scalars.is_empty() || value.references.len() != 1 {
        return None;
    }
    let atom = &value.references[0];
    if atom.kind != "guest_code" || atom.offset != 0 {
        return None;
    }
    u32::from_str_radix(atom.identity.strip_prefix("rva:")?, 16).ok()
}

struct NativeNonlocalCandidate {
    target_context: NativeFunctionContext,
    state: ReferenceState,
    abandoned_frame_ids: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
fn walk_native_nonlocal_frames(
    context: &NativeFunctionContext,
    state: &ReferenceState,
    target_rva: u32,
    abandoned_frame_ids: &[String],
    visited: &BTreeSet<NativeFunctionContext>,
    active_frames: &BTreeMap<
        NativeFunctionContext,
        BTreeMap<(NativeWorkKey, usize), NativeActiveCallFrame>,
    >,
    catalog: &RuntimeCatalog,
    candidates: &mut Vec<NativeNonlocalCandidate>,
    instantiation_failed: &mut bool,
) -> PyResult<()> {
    if visited.contains(context) {
        return Ok(());
    }
    let Some(frames) = active_frames.get(context) else {
        return Ok(());
    };
    let mut next_visited = visited.clone();
    next_visited.insert(context.clone());
    for frame in frames.values() {
        let mut failure_detail = None;
        let Some(restored) = native_return_state_for_caller(
            state,
            &frame.caller_state,
            &frame.caller_esp,
            &frame.callee_context,
            &frame.parameter_bindings,
            catalog,
            &mut failure_detail,
        )?
        else {
            *instantiation_failed = true;
            continue;
        };
        let mut abandoned = abandoned_frame_ids.to_vec();
        abandoned.push(context.frame_identity().to_owned());
        if frame.return_rva == target_rva {
            candidates.push(NativeNonlocalCandidate {
                target_context: frame.caller_key.context.clone(),
                state: restored,
                abandoned_frame_ids: abandoned,
            });
        } else {
            walk_native_nonlocal_frames(
                &frame.caller_key.context,
                &restored,
                target_rva,
                &abandoned,
                &next_visited,
                active_frames,
                catalog,
                candidates,
                instantiation_failed,
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn resolve_native_nonlocal_transition(
    source_key: &NativeWorkKey,
    source_unit_id: &str,
    output: &ReferenceState,
    target_value: &ReferenceValue,
    result_value: &ReferenceValue,
    active_frames: &BTreeMap<
        NativeFunctionContext,
        BTreeMap<(NativeWorkKey, usize), NativeActiveCallFrame>,
    >,
    transfers: &BTreeMap<u32, &reference_plan::Transfer>,
    catalog: &RuntimeCatalog,
) -> PyResult<Result<(JsonValue, ReferenceState, NativeFunctionContext), String>> {
    let Some(target_rva) = exact_nonlocal_target(target_value) else {
        return Ok(Err("target_not_exact".to_owned()));
    };
    let Some(target_transfer) = transfers.get(&target_rva) else {
        return Ok(Err("target_outside_exact_universe".to_owned()));
    };
    let mut candidates = Vec::new();
    let mut instantiation_failed = false;
    walk_native_nonlocal_frames(
        &source_key.context,
        output,
        target_rva,
        &[],
        &BTreeSet::new(),
        active_frames,
        catalog,
        &mut candidates,
        &mut instantiation_failed,
    )?;
    if candidates.len() != 1 {
        return Ok(Err(if candidates.is_empty() && instantiation_failed {
            "state_instantiation_unavailable"
        } else if candidates.is_empty() {
            "active_ancestor_missing"
        } else {
            "active_ancestor_ambiguous"
        }
        .to_owned()));
    }
    let candidate = candidates.pop().expect("one nonlocal candidate");
    let mut core = serde_json::json!({
        "source_unit_id": source_unit_id,
        "source_rva": source_key.rva,
        "source_context_id": source_key.context.identity(),
        "root_rva": source_key.context.root_rva,
        "target_unit_id": target_transfer.identity(),
        "target_rva": target_rva,
        "target_context_id": candidate.target_context.identity(),
        "target_function_entry_rva": candidate.target_context.function_entry_rva,
        "abandoned_frame_ids": candidate.abandoned_frame_ids,
        "value": result_value,
        "cleanup": {
            "kind": "expire_abandoned_stack_frames",
            "unwind_unit_ids": [],
        },
    });
    let transition_id = format!(
        "checked-nonlocal-transition-v1:{}",
        canonical_json_digest(&core)?,
    );
    core.as_object_mut()
        .expect("nonlocal transition is an object")
        .insert("id".to_owned(), JsonValue::String(transition_id));
    Ok(Ok((core, candidate.state, candidate.target_context)))
}

#[allow(clippy::too_many_arguments)]
fn enqueue_native_state(
    source_rva: u32,
    target_rva: u32,
    kind: &str,
    context: &NativeFunctionContext,
    incoming: ReferenceState,
    transfers: &BTreeMap<u32, &reference_plan::Transfer>,
    runtime: &RuntimeClosureContext,
    states: &mut BTreeMap<NativeWorkKey, ReferenceState>,
    pending: &mut NativePending,
    edges: &mut BTreeMap<NativeClosureEdgeRow, BTreeSet<u32>>,
    blockers: &mut Vec<JsonValue>,
) -> PyResult<()> {
    if !transfers.contains_key(&target_rva) {
        blockers.push(serde_json::json!({
            "code": "execution_edge_outside_exact_universe",
            "source_rva": source_rva,
            "target_rva": target_rva,
            "edge_kind": kind,
        }));
        return Ok(());
    }
    edges
        .entry(NativeClosureEdgeRow {
            source_rva,
            target_rva,
            kind: kind.to_owned(),
        })
        .or_default()
        .insert(context.root_rva);
    let key = NativeWorkKey {
        rva: target_rva,
        context: context.clone(),
    };
    let incoming = boundary_state(incoming, &runtime.catalog);
    let joined = if let Some(previous) = states.get(&key) {
        join_state(
            previous.clone(),
            incoming,
            &runtime.catalog.initial_memory,
            &runtime.catalog.baseline_memory_index,
            runtime.catalog.alternative_limit,
        )?
    } else {
        incoming
    };
    if states
        .get(&key)
        .is_none_or(|previous| !reference_states_equal(previous, &joined))
    {
        states.insert(key.clone(), joined);
        pending.queue(key);
    }
    Ok(())
}

fn update_native_return_summary(
    context: &NativeFunctionContext,
    state: ReferenceState,
    runtime: &RuntimeClosureContext,
    summaries: &mut BTreeMap<NativeFunctionContext, ReferenceState>,
    dependents: &BTreeMap<NativeFunctionContext, BTreeSet<NativeWorkKey>>,
    pending: &mut NativePending,
) -> PyResult<()> {
    let summary = effect_summary_state(state, &runtime.catalog);
    let changed = if let Some(previous) = summaries.get(context) {
        let joined = join_state(
            previous.clone(),
            summary,
            &runtime.catalog.initial_memory,
            &runtime.catalog.baseline_memory_index,
            runtime.catalog.alternative_limit,
        )?;
        if !reference_states_equal(previous, &joined) {
            summaries.insert(context.clone(), joined);
            true
        } else {
            false
        }
    } else {
        summaries.insert(context.clone(), summary);
        true
    };
    if changed {
        if let Some(rows) = dependents.get(context) {
            for key in rows {
                pending.queue(key.clone());
            }
        }
    }
    Ok(())
}

fn evaluate_native_closure_frontier(
    plan: &reference_plan::TransferPlan,
    runtime: &RuntimeClosureContext,
    include_states: bool,
    include_reference_facts: bool,
) -> PyResult<NativeClosureEvaluationOutput> {
    let transfers = plan
        .transfers
        .iter()
        .map(|transfer| (transfer.rva_start(), transfer))
        .collect::<BTreeMap<_, _>>();
    let transfer_rvas_by_identity = plan
        .transfers
        .iter()
        .map(|transfer| (transfer.identity().to_owned(), transfer.rva_start()))
        .collect::<BTreeMap<_, _>>();
    let finite_control_targets = plan.finite_control_targets();
    let mut states = BTreeMap::new();
    let mut pending = NativePending::new(&transfers, &runtime.roots);
    let mut edges = BTreeMap::<NativeClosureEdgeRow, BTreeSet<u32>>::new();
    let mut blockers = Vec::new();
    let mut return_summaries = BTreeMap::<NativeFunctionContext, ReferenceState>::new();
    let mut return_dependents = BTreeMap::<NativeFunctionContext, BTreeSet<NativeWorkKey>>::new();
    let mut active_call_frames = BTreeMap::<
        NativeFunctionContext,
        BTreeMap<(NativeWorkKey, usize), NativeActiveCallFrame>,
    >::new();
    let track_nonlocal_call_frames = plan
        .transfers
        .iter()
        .any(|transfer| transfer.terminator.op == "outcome_nonlocal");
    let mut nonlocal_contexts = BTreeMap::<NativeWorkKey, Option<JsonValue>>::new();
    let mut nonlocal_failures = BTreeMap::<NativeWorkKey, JsonValue>::new();
    let mut indirect_contexts =
        BTreeMap::<(u32, String, NativeFunctionContext), NativeTargetResolution>::new();
    let mut indirect_provenance =
        BTreeMap::<(u32, String, NativeFunctionContext), ReferenceValue>::new();
    let mut external_write_failures =
        BTreeMap::<(u32, usize, NativeFunctionContext), NativeExternalWriteFailure>::new();
    let mut return_instantiation_failures = BTreeMap::<
        (u32, usize, NativeFunctionContext, NativeFunctionContext),
        NativeReturnInstantiationFailure,
    >::new();
    let mut external_contracts = BTreeSet::<(String, String)>::new();
    let mut terminal_external_outcomes = BTreeSet::<(u32, String, String)>::new();
    let mut callback_escapes =
        BTreeMap::<(u32, String, String, String), Option<BTreeSet<u32>>>::new();
    let mut callback_metadata =
        BTreeMap::<(u32, String, String, String), ExternalCallbackPayload>::new();
    let mut exception_projection_issues = BTreeMap::<(u32, usize, String), Vec<String>>::new();
    let mut exception_continuation_failures = BTreeMap::<(u32, usize, String), Vec<String>>::new();
    for root in &runtime.roots {
        if !transfers.contains_key(root) {
            blockers.push(serde_json::json!({
                "code": "execution_root_outside_exact_universe",
                "root_rva": root,
            }));
            continue;
        }
        let key = NativeWorkKey {
            rva: *root,
            context: NativeFunctionContext::new(*root, *root, Vec::new()),
        };
        states.insert(
            key.clone(),
            runtime
                .initial_states
                .get(root)
                .cloned()
                .unwrap_or_else(default_reference_state),
        );
        pending.queue(key);
    }
    let mut steps = 0;
    let mut deferred = BTreeMap::<(NativeWorkKey, u32), ReferenceState>::new();
    while steps < runtime.maximum_worklist_steps {
        if pending.is_empty() {
            if deferred.is_empty() {
                break;
            }
            let additions = std::mem::take(&mut deferred);
            for ((source, target), state) in additions {
                enqueue_native_state(
                    source.rva,
                    target,
                    "direct_control",
                    &source.context,
                    state,
                    &transfers,
                    runtime,
                    &mut states,
                    &mut pending,
                    &mut edges,
                    &mut blockers,
                )?;
            }
            if pending.is_empty() {
                break;
            }
        }
        let key = pending.pop().expect("checked pending work");
        steps += 1;
        let transfer = transfers[&key.rva];
        let input = states[&key].clone();
        let mut application = apply_reference_effects(transfer, &input, &runtime.catalog, None)?;
        let mut waiting_for_return = false;
        let mut overrides = BTreeMap::new();
        let mut parameterized_call_inputs =
            BTreeMap::<(usize, NativeFunctionContext), NativeCalleeProjection>::new();
        for call in &transfer.calls {
            if call.kind == "external_call" {
                continue;
            }
            let Some(targets) = internal_call_targets(call, &application.values) else {
                waiting_for_return = true;
                continue;
            };
            if targets.is_empty() {
                continue;
            }
            let caller = &application.call_input_states[&call.event_index];
            let caller_esp = &application.values[call.register_nodes[7]];
            let mut combined = None;
            let mut missing = false;
            for target in targets {
                let callee_context = key.context.child(
                    target,
                    call.instruction_rva,
                    runtime.call_string_limit,
                );
                return_dependents
                    .entry(callee_context.clone())
                    .or_default()
                    .insert(key.clone());
                let Some(summary) = return_summaries.get(&callee_context) else {
                    missing = true;
                    continue;
                };
                let projection = native_callee_state(
                    call,
                    &application.values,
                    caller,
                    &runtime.catalog,
                    &callee_context,
                )?;
                let projection_key = (call.event_index, callee_context.clone());
                parameterized_call_inputs.insert(projection_key.clone(), projection);
                let projection = &parameterized_call_inputs[&projection_key];
                if track_nonlocal_call_frames {
                    active_call_frames
                        .entry(callee_context.clone())
                        .or_default()
                        .insert(
                            (key.clone(), call.event_index),
                            NativeActiveCallFrame {
                                caller_key: key.clone(),
                                callee_context: callee_context.clone(),
                                return_rva: call.return_rva,
                                caller_state: application.call_input_states[&call.event_index]
                                    .clone(),
                                caller_esp: application.values[call.register_nodes[7]].clone(),
                                parameter_bindings: projection.parameter_bindings.clone(),
                            },
                        );
                }
                let mut failure_detail = None;
                let candidate = native_return_state_for_caller(
                    summary,
                    caller,
                    caller_esp,
                    &callee_context,
                    &projection.parameter_bindings,
                    &runtime.catalog,
                    &mut failure_detail,
                )?;
                let failure_key = (
                    key.rva,
                    call.event_index,
                    key.context.clone(),
                    callee_context.clone(),
                );
                let Some(candidate) = candidate else {
                    return_instantiation_failures.insert(failure_key, NativeReturnInstantiationFailure {
                        instruction_rva: call.instruction_rva,
                        reason: failure_detail.unwrap_or_else(|| {
                            "return_state_instantiation_unavailable".to_owned()
                        }),
                        register_inputs: call.register_nodes.iter().map(|index| {
                            application.values[*index].clone()
                        }).collect(),
                        parameter_bindings: projection.parameter_bindings.clone(),
                    });
                    let candidate = native_conservative_return_state_for_caller(
                        summary,
                        caller,
                        caller_esp,
                        &callee_context,
                        &projection.parameter_bindings,
                        &runtime.catalog,
                    )?;
                    combined = Some(if let Some(previous) = combined {
                        join_state(
                            previous,
                            candidate,
                            &runtime.catalog.initial_memory,
                            &runtime.catalog.baseline_memory_index,
                            runtime.catalog.alternative_limit,
                        )?
                    } else {
                        candidate
                    });
                    continue;
                };
                return_instantiation_failures.remove(&failure_key);
                combined = Some(if let Some(previous) = combined {
                    join_state(
                        previous,
                        candidate,
                        &runtime.catalog.initial_memory,
                        &runtime.catalog.baseline_memory_index,
                        runtime.catalog.alternative_limit,
                    )?
                } else {
                    candidate
                });
            }
            if let Some(summary) = combined.filter(|_| !missing) {
                overrides.insert(call.event_index, summary);
            } else {
                waiting_for_return = true;
            }
        }
        if !overrides.is_empty() {
            application =
                apply_reference_effects(transfer, &input, &runtime.catalog, Some(&overrides))?;
            // A return override changes the physical state seen by every
            // later call in this transfer.  Only the first call's projection
            // is necessarily still based on the same pre-call state; mirror
            // the reference evaluator and recompute every later projection
            // from the reapplied values below.  Reusing the stale projections
            // shifts nested stack aliases and loses joined callback facts.
            let first_call_index = transfer.calls.first().map(|call| call.event_index);
            parameterized_call_inputs.retain(|(call_index, _context), _projection| {
                Some(*call_index) == first_call_index
            });
        }
        for (effect_index, operation, call_index, _fault_index) in
            transfer_exception_occurrences(transfer)?
        {
            let effect = &transfer.effects[effect_index];
            let Some(transition) = checked_exception_transition(
                runtime,
                transfer.identity(),
                effect_index,
                &operation,
            )
            .filter(|transition| {
                transition.authorizing
                    && transition.disposition.as_deref() == Some("handled")
                    && transition.handler_rva.is_some()
                    && transition.state_projection.is_some()
            }) else {
                continue;
            };
            let (projected, projection_issues) = exception_projection_state(
                &application.effect_input_states[&effect_index],
                transition
                    .state_projection
                    .as_ref()
                    .expect("filtered checked exception projection"),
                transition,
                &if call_index.is_some() {
                    Vec::new()
                } else {
                    effect
                        .operands
                        .iter()
                        .map(|index| application.values[*index].clone())
                        .collect::<Vec<_>>()
                },
                &key.context.identity(),
                &runtime.catalog,
            )?;
            let issue_key = (
                key.rva, effect_index, key.context.identity().to_owned(),
            );
            if !projection_issues.is_empty() {
                exception_projection_issues.insert(issue_key, projection_issues);
                continue;
            }
            exception_projection_issues.remove(&issue_key);
            let mut continuation_state = projected;
            let mut continuation_source_rva = key.rva;
            let mut continuation_failures = Vec::new();
            for (unwind_index, unwind_unit_id) in transition.unwind_unit_ids.iter().enumerate() {
                let unwind_rva = transfer_rvas_by_identity[unwind_unit_id];
                let unwind_context = NativeFunctionContext::new(
                    key.context.root_rva,
                    unwind_rva,
                    vec![
                        transition
                            .source_rva
                            .wrapping_add(transition.effect_index as u32)
                            .wrapping_add(unwind_index as u32),
                    ],
                );
                return_dependents
                    .entry(unwind_context.clone())
                    .or_default()
                    .insert(key.clone());
                enqueue_native_state(
                    continuation_source_rva,
                    unwind_rva,
                    "exception_unwind",
                    &unwind_context,
                    continuation_state.clone(),
                    &transfers,
                    runtime,
                    &mut states,
                    &mut pending,
                    &mut edges,
                    &mut blockers,
                )?;
                let Some(summary) = return_summaries.get(&unwind_context) else {
                    continuation_failures.push(format!(
                        "unwind_return_summary_unavailable:{unwind_unit_id}"
                    ));
                    break;
                };
                let mut failure_detail = None;
                let composed = native_return_state_for_caller(
                    summary,
                    &continuation_state,
                    &continuation_state.registers[7],
                    &unwind_context,
                    &BTreeMap::new(),
                    &runtime.catalog,
                    &mut failure_detail,
                )?;
                let Some(composed) = composed else {
                    continuation_failures.push(format!(
                        "unwind_return_state_instantiation_unavailable:{unwind_unit_id}"
                    ));
                    break;
                };
                continuation_state = composed;
                continuation_source_rva = unwind_rva;
            }
            if !continuation_failures.is_empty() {
                exception_continuation_failures.insert(issue_key, continuation_failures);
                continue;
            }
            exception_continuation_failures.remove(&issue_key);
            let handler_rva = transition.handler_rva.expect("filtered checked handler");
            let handler_context = NativeFunctionContext::new(
                key.context.root_rva,
                handler_rva,
                Vec::new(),
            );
            if transition.resumption_rva.is_some() {
                return_dependents
                    .entry(handler_context.clone())
                    .or_default()
                    .insert(key.clone());
            }
            enqueue_native_state(
                continuation_source_rva,
                handler_rva,
                "exception_handler",
                &handler_context,
                continuation_state.clone(),
                &transfers,
                runtime,
                &mut states,
                &mut pending,
                &mut edges,
                &mut blockers,
            )?;
            let Some(resumption_rva) = transition.resumption_rva else {
                exception_continuation_failures.remove(&issue_key);
                continue;
            };
            let Some(handler_summary) = return_summaries.get(&handler_context) else {
                exception_continuation_failures.insert(
                    issue_key,
                    vec![format!(
                        "handler_return_summary_unavailable:{}",
                        transition.handler_unit_id.as_deref().unwrap_or("")
                    )],
                );
                continue;
            };
            let mut failure_detail = None;
            let resumed = native_return_state_for_caller(
                handler_summary,
                &continuation_state,
                &continuation_state.registers[7],
                &handler_context,
                &BTreeMap::new(),
                &runtime.catalog,
                &mut failure_detail,
            )?;
            let Some(resumed) = resumed else {
                exception_continuation_failures.insert(
                    issue_key,
                    vec![format!(
                        "handler_return_state_instantiation_unavailable:{}",
                        transition.handler_unit_id.as_deref().unwrap_or("")
                    )],
                );
                continue;
            };
            exception_continuation_failures.remove(&issue_key);
            let resumption_context = NativeFunctionContext::new(
                key.context.root_rva,
                resumption_rva,
                Vec::new(),
            );
            enqueue_native_state(
                handler_rva,
                resumption_rva,
                "exception_resumption",
                &resumption_context,
                resumed,
                &transfers,
                runtime,
                &mut states,
                &mut pending,
                &mut edges,
                &mut blockers,
            )?;
        }
        for call in &transfer.calls {
            let failure_key = (key.rva, call.event_index, key.context.clone());
            external_write_failures.remove(&failure_key);
            if let Some(arguments) = application
                .unresolved_external_writes
                .get(&call.event_index)
            {
                external_write_failures.insert(
                    failure_key,
                    NativeExternalWriteFailure {
                        instruction_rva: call.instruction_rva,
                        arguments: arguments.clone(),
                        external_targets: external_call_targets(
                            call,
                            &application.values,
                            &runtime.catalog,
                        )
                        .unwrap_or_default(),
                    },
                );
            }
            if call.kind != "external_call" {
                if let Some(target_node) = call.target_node {
                    let site = format!("call:{:08x}:{}", call.instruction_rva, call.event_index);
                    let site_key = (key.rva, site, key.context.clone());
                    let resolution = reference_target_resolution(
                        &application.values[target_node],
                        &runtime.catalog,
                    );
                    if let Some((guest, _external)) = &resolution {
                        pending.discover(key.rva, guest.iter().copied());
                    }
                    indirect_contexts.insert(site_key.clone(), resolution);
                    indirect_provenance.insert(site_key, application.values[target_node].clone());
                }
            }
        }
        for call in &transfer.calls {
            if call.kind == "external_call" {
                continue;
            }
            let Some(targets) = internal_call_targets(call, &application.values) else {
                continue;
            };
            for target in targets {
                let callee_context = key.context.child(
                    target,
                    call.instruction_rva,
                    runtime.call_string_limit,
                );
                return_dependents
                    .entry(callee_context.clone())
                    .or_default()
                    .insert(key.clone());
                let projection = parameterized_call_inputs
                    .remove(&(call.event_index, callee_context.clone()))
                    .map(Ok)
                    .unwrap_or_else(|| {
                        native_callee_state(
                            call,
                            &application.values,
                            &application.call_input_states[&call.event_index],
                            &runtime.catalog,
                            &callee_context,
                        )
                    })?;
                if track_nonlocal_call_frames {
                    active_call_frames
                        .entry(callee_context.clone())
                        .or_default()
                        .insert(
                            (key.clone(), call.event_index),
                            NativeActiveCallFrame {
                                caller_key: key.clone(),
                                callee_context: callee_context.clone(),
                                return_rva: call.return_rva,
                                caller_state: application.call_input_states[&call.event_index]
                                    .clone(),
                                caller_esp: application.values[call.register_nodes[7]].clone(),
                                parameter_bindings: projection.parameter_bindings.clone(),
                            },
                        );
                }
                if projection.frame_reused {
                    blockers.push(serde_json::json!({
                        "code": "recursive_stack_frame_context_reused",
                        "source_rva": key.rva,
                        "instruction_rva": call.instruction_rva,
                        "callee_context": callee_context.identity(),
                    }));
                }
                if projection.projection_exceeded {
                    blockers.push(serde_json::json!({
                        "code": "outgoing_stack_projection_bound_exceeded",
                        "source_rva": key.rva,
                        "instruction_rva": call.instruction_rva,
                        "call_index": call.event_index,
                        "caller_context": key.context.identity(),
                        "caller_function_rva": key.context.function_entry_rva,
                        "caller_call_string": key.context.call_string,
                        "qualified_byte_limit": 4096,
                    }));
                }
                enqueue_native_state(
                    key.rva,
                    target,
                    "internal_call",
                    &callee_context,
                    projection.state,
                    &transfers,
                    runtime,
                    &mut states,
                    &mut pending,
                    &mut edges,
                    &mut blockers,
                )?;
            }
        }
        let resolved_external_targets = transfer
            .calls
            .iter()
            .filter_map(|call| external_call_targets(call, &application.values, &runtime.catalog))
            .filter(|targets| !targets.is_empty())
            .collect::<Vec<_>>();
        for targets in &resolved_external_targets {
            external_contracts.extend(targets.iter().cloned());
        }
        let terminal_external_call = resolved_external_targets.iter().any(|targets| {
            let terminates = targets.iter().all(|target| {
                runtime
                    .catalog
                    .external_calls
                    .get(target)
                    .is_some_and(|rule| rule.disposition == "terminates")
            });
            if terminates {
                terminal_external_outcomes.extend(
                    targets
                        .iter()
                        .map(|(dll, identity)| (key.rva, dll.clone(), identity.clone())),
                );
            }
            terminates
        });
        let tail_external_returns = transfer.terminator.op == "outcome_external"
            && resolved_external_targets.len() == 1
            && resolved_external_targets[0].iter().all(|target| {
                runtime
                    .catalog
                    .external_calls
                    .get(target)
                    .is_some_and(|rule| rule.disposition == "returns")
            });
        for call in &transfer.calls {
            let Some(targets) = external_call_targets(call, &application.values, &runtime.catalog)
            else {
                continue;
            };
            for target in targets {
                let Some(rule) = runtime.catalog.external_calls.get(&target) else {
                    continue;
                };
                let Some(callback) = &rule.callback else {
                    continue;
                };
                let arguments = call_arguments_from_values(
                    transfer,
                    call,
                    &application.values,
                    &application.call_input_states[&call.event_index],
                    rule,
                    &runtime.catalog,
                )?;
                let escape_key = (
                    call.instruction_rva,
                    target.0.clone(),
                    target.1.clone(),
                    callback.protocol_id.clone(),
                );
                let callbacks = callback_targets(
                    callback,
                    &arguments,
                    &application.call_input_states[&call.event_index],
                    &runtime.catalog,
                )?;
                match callback_escapes.entry(escape_key.clone()) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(callbacks.clone());
                    }
                    std::collections::btree_map::Entry::Occupied(mut entry) => {
                        let current = entry.get_mut();
                        if current.is_none() || callbacks.is_none() {
                            *current = None;
                        } else {
                            current
                                .as_mut()
                                .expect("checked callback targets")
                                .extend(callbacks.iter().flatten().copied());
                        }
                    }
                }
                callback_metadata.insert(escape_key, callback.clone());
                let Some(callbacks) = callbacks else {
                    continue;
                };
                for target_rva in callbacks {
                    let callback_context = NativeFunctionContext::new(
                        target_rva,
                        target_rva,
                        Vec::new(),
                    );
                    enqueue_native_state(
                        key.rva,
                        target_rva,
                        "callback_escape",
                        &callback_context,
                        callback_root_state(target_rva, &application.state)?,
                        &transfers,
                        runtime,
                        &mut states,
                        &mut pending,
                        &mut edges,
                        &mut blockers,
                    )?;
                }
            }
        }
        if transfer.terminator.op == "outcome_branch" {
            deferred.retain(|(source, _target), _state| source != &key);
        }
        match transfer.terminator.op.as_str() {
            "outcome_fallthrough" | "outcome_jump" => {
                if waiting_for_return
                    || terminal_external_call
                    || runtime.boundary_exit_rvas.contains(&key.rva)
                {
                    continue;
                }
                enqueue_native_state(
                    key.rva,
                    transfer.terminator.operands[0] as u32,
                    "direct_control",
                    &key.context,
                    application.state,
                    &transfers,
                    runtime,
                    &mut states,
                    &mut pending,
                    &mut edges,
                    &mut blockers,
                )?;
            }
            "outcome_branch" => {
                if waiting_for_return
                    || terminal_external_call
                    || runtime.boundary_exit_rvas.contains(&key.rva)
                {
                    continue;
                }
                let condition = &application.values[transfer.terminator.operands[0]];
                let outcomes = if condition.kind == "finite" && condition.references.is_empty() {
                    condition
                        .scalars
                        .iter()
                        .map(|value| *value != 0)
                        .collect::<BTreeSet<_>>()
                } else {
                    [false, true].into_iter().collect()
                };
                for taken in outcomes {
                    let target = transfer.terminator.operands[if taken { 1 } else { 2 }] as u32;
                    let Some(successor) = refine_state_for_branch(
                        transfer,
                        &application.state,
                        &application.values,
                        taken,
                        runtime.catalog.alternative_limit,
                    )?
                    else {
                        continue;
                    };
                    let edge = NativeClosureEdgeRow {
                        source_rva: key.rva,
                        target_rva: target,
                        kind: "direct_control".to_owned(),
                    };
                    if edges.contains_key(&edge) {
                        enqueue_native_state(
                            key.rva,
                            target,
                            "direct_control",
                            &key.context,
                            successor,
                            &transfers,
                            runtime,
                            &mut states,
                            &mut pending,
                            &mut edges,
                            &mut blockers,
                        )?;
                    } else {
                        deferred.insert((key.clone(), target), successor);
                    }
                }
            }
            "outcome_indirect" => {
                if waiting_for_return {
                    continue;
                }
                let value = &application.values[transfer.terminator.operands[0]];
                let inferred_resolution = reference_target_resolution(value, &runtime.catalog);
                let resolution = if let Some(authorized) = finite_control_targets.get(&key.rva) {
                    match inferred_resolution {
                        None => Some((authorized.clone(), BTreeSet::new())),
                        Some((guest, external))
                            if external.is_empty() && guest.is_subset(authorized) =>
                        {
                            Some((guest, external))
                        }
                        Some(_) => {
                            blockers.push(serde_json::json!({
                                "code": "finite_control_route_conflict",
                                "source_rva": key.rva,
                            }));
                            None
                        }
                    }
                } else {
                    inferred_resolution
                };
                let site_key = (key.rva, "terminator".to_owned(), key.context.clone());
                indirect_contexts.insert(site_key.clone(), resolution.clone());
                indirect_provenance.insert(site_key, value.clone());
                if let Some((guest, _external)) = &resolution
                    && !runtime.boundary_exit_rvas.contains(&key.rva)
                {
                    pending.discover(key.rva, guest.iter().copied());
                }
                if let Some((_guest, external)) = &resolution {
                    external_contracts.extend(external.iter().cloned());
                }
                if terminal_external_call || runtime.boundary_exit_rvas.contains(&key.rva) {
                    continue;
                }
                if let Some((guest, external)) = resolution {
                    for target in guest {
                        enqueue_native_state(
                            key.rva,
                            target,
                            "indirect_control",
                            &key.context,
                            application.state.clone(),
                            &transfers,
                            runtime,
                            &mut states,
                            &mut pending,
                            &mut edges,
                            &mut blockers,
                        )?;
                    }
                    if !external.is_empty() {
                        if let Some(summary) = external_tail_return_state(
                            transfer,
                            &application.state,
                            &external,
                            &runtime.catalog,
                        )? {
                            update_native_return_summary(
                                &key.context,
                                summary,
                                runtime,
                                &mut return_summaries,
                                &return_dependents,
                                &mut pending,
                            )?;
                        }
                    }
                }
            }
            "outcome_nonlocal" => {
                let target = &application.values[transfer.terminator.operands[0]];
                let value = &application.values[transfer.terminator.operands[1]];
                match resolve_native_nonlocal_transition(
                    &key,
                    transfer.identity(),
                    &application.state,
                    target,
                    value,
                    &active_call_frames,
                    &transfers,
                    &runtime.catalog,
                )? {
                    Ok((transition, resumed, target_context)) => {
                        nonlocal_contexts.insert(key.clone(), Some(transition));
                        nonlocal_failures.remove(&key);
                        enqueue_native_state(
                            key.rva,
                            exact_nonlocal_target(target).expect("resolved nonlocal target"),
                            "nonlocal_control",
                            &target_context,
                            resumed,
                            &transfers,
                            runtime,
                            &mut states,
                            &mut pending,
                            &mut edges,
                            &mut blockers,
                        )?;
                    }
                    Err(reason) => {
                        nonlocal_contexts.insert(key.clone(), None);
                        nonlocal_failures.insert(
                            key.clone(),
                            serde_json::json!({
                                "code": "reachable_nonlocal_outcome_authority_missing",
                                "source_rva": key.rva,
                                "unit_id": transfer.identity(),
                                "function_context": key.context.identity(),
                                "reason": reason,
                                "target": target,
                                "value": value,
                            }),
                        );
                    }
                }
            }
            "outcome_return" => {
                update_native_return_summary(
                    &key.context,
                    application.state,
                    runtime,
                    &mut return_summaries,
                    &return_dependents,
                    &mut pending,
                )?;
            }
            "outcome_external" => {
                if tail_external_returns {
                    let mut registers = application.state.call_registers.clone();
                    registers[7] = adjust_reference_by_constant(
                        &registers[7],
                        4,
                        runtime.catalog.alternative_limit,
                    )?;
                    let summary = ReferenceState {
                        registers,
                        flags: application.state.call_flags.clone(),
                        memory: application.state.memory.clone(),
                        call_registers: application.state.call_registers.clone(),
                        call_flags: application.state.call_flags.clone(),
                        invalidated_memory_ranges: application
                            .state
                            .invalidated_memory_ranges
                            .clone(),
                        all_memory_invalidated: application.state.all_memory_invalidated,
                        callback_registry: application.state.callback_registry.clone(),
                        flag_relations: vec![None; FLAG_COUNT],
                        scalar_constraints: BTreeMap::new(),
                        preserves_inherited_memory: application.state.preserves_inherited_memory,
                        relational_object_bindings: application
                            .state
                            .relational_object_bindings
                            .clone(),
                        written_memory_keys: application.state.written_memory_keys.clone(),
                        effect_invalidated_memory_ranges: application
                            .state
                            .effect_invalidated_memory_ranges
                            .clone(),
                        effect_all_memory_invalidated: application
                            .state
                            .effect_all_memory_invalidated,
                        possible_allocation_identities: application
                            .state
                            .possible_allocation_identities
                            .clone(),
                    };
                    update_native_return_summary(
                        &key.context,
                        summary,
                        runtime,
                        &mut return_summaries,
                        &return_dependents,
                        &mut pending,
                    )?;
                }
            }
            operation => {
                return Err(invalid(format!(
                    "native closure frontier has an unsupported terminator {operation:?}"
                )));
            }
        }
    }
    if !pending.is_empty() || !deferred.is_empty() {
        blockers.push(serde_json::json!({
            "code": "execution_closure_worklist_bound_exceeded",
            "maximum_steps": runtime.maximum_worklist_steps,
        }));
    }
    for source_rva in states.keys().map(|key| key.rva).collect::<BTreeSet<_>>() {
        let transfer = transfers
            .get(&source_rva)
            .expect("reachable state has an exact transfer");
        let mut seen_call_effects = BTreeSet::new();
        for (effect_index, _operation, call_index, _fault_index) in
            transfer_exception_occurrences(transfer)?
        {
            let Some(call_index) = call_index else {
                continue;
            };
            if !seen_call_effects.insert(effect_index) {
                continue;
            }
            let call = transfer
                .calls
                .iter()
                .find(|call| call.event_index == call_index)
                .expect("call exception occurrence has an exact call");
            let unresolved = call
                .native_exception_operations
                .iter()
                .filter(|operation| {
                    !checked_exception_transition(
                        runtime,
                        transfer.identity(),
                        effect_index,
                        operation,
                    )
                    .is_some_and(|transition| transition.authorizing)
                })
                .cloned()
                .collect::<Vec<_>>();
            if !unresolved.is_empty() {
                blockers.push(serde_json::json!({
                    "code": "reachable_call_exception_authority_missing",
                    "unit_id": transfer.identity(),
                    "source_rva": source_rva,
                    "instruction_rva": call.instruction_rva,
                    "call_index": call.event_index,
                    "call_kind": call.kind,
                    "native_exception_operations": unresolved,
                }));
            }
        }
    }
    let mut final_blockers = BTreeMap::<String, JsonValue>::new();
    for blocker in &runtime.preexisting_blockers {
        insert_native_blocker(&mut final_blockers, blocker.clone())?;
    }
    for blocker in blockers {
        let payload = serde_json::to_value(blocker)
            .map_err(|error| invalid(format!("cannot encode native blocker: {error}")))?;
        insert_native_blocker(&mut final_blockers, payload)?;
    }
    for blocker in nonlocal_failures.into_values() {
        insert_native_blocker(&mut final_blockers, blocker)?;
    }
    let mut exception_continuations = Vec::new();
    for source_rva in states.keys().map(|key| key.rva).collect::<BTreeSet<_>>() {
        let transfer = transfers
            .get(&source_rva)
            .expect("reachable state has an exact transfer");
        let root_rvas = states
            .keys()
            .filter(|key| key.rva == source_rva)
            .map(|key| key.context.root_rva)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        for (effect_index, operation, call_index, _fault_index) in
            transfer_exception_occurrences(transfer)?
        {
            let transition = checked_exception_transition(
                runtime,
                transfer.identity(),
                effect_index,
                &operation,
            );
            let Some(transition) = transition.filter(|row| row.authorizing) else {
                if call_index.is_some() {
                    // The call-site inventory blocker above owns this case.
                    continue;
                }
                let authority_blocker = transition.and_then(|row| row.blocker_code.clone());
                let mut blocker = serde_json::json!({
                        "code": "reachable_exception_outcome_unresolved",
                        "source_rva": source_rva,
                        "effect_index": effect_index,
                        "operation": operation,
                });
                if let Some(authority_blocker) = authority_blocker {
                    blocker
                        .as_object_mut()
                        .expect("exception blocker is an object")
                        .insert(
                            "authority_blocker".to_owned(),
                            JsonValue::String(authority_blocker),
                        );
                }
                insert_native_blocker(&mut final_blockers, blocker)?;
                continue;
            };
            exception_continuations.push(serde_json::json!({
                "unit_id": transition.unit_id,
                "source_rva": transition.source_rva,
                "effect_index": transition.effect_index,
                "fault_index": transition.fault_index,
                "fault_sha256": transition.fault_sha256,
                "transition_id": transition.transition_id,
                "transition_sha256": transition.transition_sha256,
                "occurrence_kind": transition.occurrence_kind,
                "call_index": transition.call_index,
                "operation": operation,
                "disposition": transition.disposition,
                "handler_unit_id": transition.handler_unit_id,
                "handler_rva": transition.handler_rva,
                "resumption_unit_id": transition.resumption_unit_id,
                "resumption_rva": transition.resumption_rva,
                "unwind_unit_ids": transition.unwind_unit_ids,
                "state_projection": transition.state_projection,
                "guard": transition.guard,
                "root_rvas": root_rvas,
            }));
            if transition.disposition.as_deref() == Some("handled") {
                let projection_issues = exception_projection_issues
                    .iter()
                    .filter(|((rva, index, _context), _issues)| {
                        *rva == source_rva && *index == effect_index
                    })
                    .flat_map(|(_key, issues)| issues.iter().cloned())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let continuation_failures = exception_continuation_failures
                    .iter()
                    .filter(|((rva, index, _context), _issues)| {
                        *rva == source_rva && *index == effect_index
                    })
                    .flat_map(|(_key, issues)| issues.iter().cloned())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let code = if transition.state_projection.is_none() {
                    "checked_exception_handler_state_projection_unavailable"
                } else if !projection_issues.is_empty() {
                    "checked_exception_handler_state_projection_unsupported"
                } else if !continuation_failures.is_empty() {
                    "checked_exception_unwind_state_composition_unavailable"
                } else {
                    continue;
                };
                insert_native_blocker(
                    &mut final_blockers,
                    serde_json::json!({
                        "code": code,
                        "source_rva": source_rva,
                        "effect_index": effect_index,
                        "transition_id": transition.transition_id,
                        "handler_unit_id": transition.handler_unit_id,
                        "handler_rva": transition.handler_rva,
                        "resumption_unit_id": transition.resumption_unit_id,
                        "resumption_rva": transition.resumption_rva,
                        "unwind_unit_ids": transition.unwind_unit_ids,
                        "state_projection": transition.state_projection,
                        "projection_issues": projection_issues,
                        "continuation_failures": continuation_failures,
                    }),
                )?;
            }
        }
    }

    let mut indirect_sites = BTreeMap::<(u32, String), NativeTargetResolution>::new();
    let mut site_provenance = BTreeMap::<(u32, String), BTreeMap<String, JsonValue>>::new();
    for ((rva, site, context), resolution) in indirect_contexts {
        let aggregate_key = (rva, site);
        match indirect_sites.entry(aggregate_key.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(resolution);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let current = entry.get_mut();
                if current.is_none() || resolution.is_none() {
                    *current = None;
                } else {
                    let (current_guest, current_external) =
                        current.as_mut().expect("checked finite resolution");
                    let (guest, external) = resolution.expect("checked finite resolution");
                    current_guest.extend(guest);
                    current_external.extend(external);
                }
            }
        }
        let provenance = serde_json::to_value(
            &indirect_provenance[&(aggregate_key.0, aggregate_key.1.clone(), context)],
        )
        .map_err(|error| invalid(format!("cannot encode indirect provenance: {error}")))?;
        site_provenance
            .entry(aggregate_key)
            .or_default()
            .insert(canonical_json_digest(&provenance)?, provenance);
    }
    let indirect_targets = indirect_sites
        .iter()
        .map(|((source_rva, site), resolution)| {
            let provenance = site_provenance
                .get(&(*source_rva, site.clone()))
                .expect("indirect site has provenance")
                .values()
                .cloned()
                .collect::<Vec<_>>();
            let targets = resolution
                .as_ref()
                .map(|(guest, _external)| guest.iter().copied().collect::<Vec<_>>());
            let external_targets = resolution.as_ref().map(|(_guest, external)| {
                external
                    .iter()
                    .map(|(dll, identity)| {
                        serde_json::json!({
                            "dll": dll,
                            "identity": identity,
                        })
                    })
                    .collect::<Vec<_>>()
            });
            serde_json::json!({
                "source_rva": source_rva,
                "site": site,
                "targets": targets,
                "external_targets": external_targets,
                "provenance": provenance,
            })
        })
        .collect::<Vec<_>>();
    for ((source_rva, site), resolution) in &indirect_sites {
        if resolution.is_none() {
            let provenance = site_provenance
                .get(&(*source_rva, site.clone()))
                .expect("indirect site has provenance")
                .values()
                .cloned()
                .collect::<Vec<_>>();
            insert_native_blocker(
                &mut final_blockers,
                serde_json::json!({
                    "code": "unresolved_reachable_indirect_target",
                    "source_rva": source_rva,
                    "site": site,
                    "provenance": provenance,
                }),
            )?;
        }
    }
    for ((instruction_rva, dll, identity, protocol_id), targets) in &callback_escapes {
        if targets.is_none() {
            insert_native_blocker(
                &mut final_blockers,
                serde_json::json!({
                    "code": "unresolved_reachable_callback_target",
                    "instruction_rva": instruction_rva,
                    "dll": dll,
                    "identity": identity,
                    "protocol_id": protocol_id,
                }),
            )?;
        }
    }
    for ((source_rva, call_index, function_context), failure) in external_write_failures {
        let external_targets = failure
            .external_targets
            .into_iter()
            .map(|(dll, identity)| {
                serde_json::json!({
                    "dll": dll,
                    "identity": identity,
                })
            })
            .collect::<Vec<_>>();
        insert_native_blocker(
            &mut final_blockers,
            serde_json::json!({
                "code": "unresolved_external_memory_write_footprint",
                "source_rva": source_rva,
                "instruction_rva": failure.instruction_rva,
                "call_index": call_index,
                "function_context": function_context.identity(),
                "function_entry_rva": function_context.function_entry_rva,
                "call_string": function_context.call_string,
                "external_targets": external_targets,
                "arguments": failure.arguments,
            }),
        )?;
    }
    for ((source_rva, call_index, caller_context, callee_context), failure) in
        return_instantiation_failures
    {
        insert_native_blocker(
            &mut final_blockers,
            serde_json::json!({
                "code": "unresolved_callee_effect_instantiation",
                "source_rva": source_rva,
                "instruction_rva": failure.instruction_rva,
                "call_index": call_index,
                "caller_context": caller_context.identity(),
                "caller_function_rva": caller_context.function_entry_rva,
                "caller_call_string": caller_context.call_string,
                "callee_context": callee_context.identity(),
                "callee_function_rva": callee_context.function_entry_rva,
                "callee_call_string": callee_context.call_string,
                "reason": failure.reason,
                "register_inputs": failure.register_inputs,
                "parameter_bindings": failure.parameter_bindings,
            }),
        )?;
    }
    let final_blockers = final_blockers.into_values().collect::<Vec<_>>();
    let state_contexts = states.len();
    let reachable_rvas: Vec<u32> = states
        .keys()
        .map(|key| key.rva)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let external_contracts = external_contracts
        .into_iter()
        .map(|(dll, identity)| {
            serde_json::json!({
                "dll": dll,
                "identity": identity,
            })
        })
        .collect::<Vec<_>>();
    let callback_escapes = callback_escapes
        .into_iter()
        .map(|(escape_key, targets)| {
            let metadata = &callback_metadata[&escape_key];
            let (instruction_rva, dll, identity, protocol_id) = escape_key;
            serde_json::json!({
                "instruction_rva": instruction_rva,
                "dll": dll,
                "identity": identity,
                "protocol_id": protocol_id,
                "targets": targets.map(|rows| rows.into_iter().collect::<Vec<_>>()),
                "action": metadata.action,
                "lifetime": metadata.lifetime,
                "delivery": {
                    "thread": metadata.delivery_thread,
                    "timing": metadata.delivery_timing,
                },
            })
        })
        .collect::<Vec<_>>();
    let mut unique_nonlocal_transitions = BTreeMap::<String, JsonValue>::new();
    for transition in nonlocal_contexts.into_values().flatten() {
        unique_nonlocal_transitions.insert(canonical_json_digest(&transition)?, transition);
    }
    let nonlocal_transitions = unique_nonlocal_transitions
        .into_values()
        .collect::<Vec<_>>();
    let lifecycle_effects = terminal_external_outcomes
        .into_iter()
        .map(|(source_rva, dll, identity)| {
            serde_json::json!({
                "kind": "external_termination",
                "source_rva": source_rva,
                "dll": dll,
                "identity": identity,
            })
        })
        .collect::<Vec<_>>();
    let witnesses = states
        .keys()
        .map(|key| {
            serde_json::json!({
                "unit_id": transfers[&key.rva].identity(),
                "rva": key.rva,
                "context_id": key.context.identity(),
                "root_rva": key.context.root_rva,
                "function_entry_rva": key.context.function_entry_rva,
                "call_string": key.context.call_string,
            })
        })
        .collect::<Vec<_>>();
    let semantic_metrics = NativeClosureSemanticMetrics {
        reachable_expression_nodes: reachable_rvas
            .iter()
            .map(|rva| transfers[rva].expressions.len())
            .sum(),
        indirect_sites: indirect_sites.len(),
        function_contexts: states
            .keys()
            .map(|key| key.context.clone())
            .collect::<BTreeSet<_>>()
            .len(),
        return_summaries: return_summaries.len(),
        relational_object_bindings: states
            .values()
            .flat_map(|state| state.relational_object_bindings.keys().cloned())
            .collect::<BTreeSet<_>>()
            .len(),
    };
    let reference_facts = if include_reference_facts {
        compact_native_reference_facts(&states, &transfers)?
    } else {
        NativeSemanticReferenceFacts::default()
    };
    let state_rows = if include_states {
        states
            .into_iter()
            .map(|(key, state)| NativeClosureStateRow {
                rva: key.rva,
                root_rva: key.context.root_rva,
                function_entry_rva: key.context.function_entry_rva,
                call_string: key.context.call_string,
                state: state.payload(),
            })
            .collect()
    } else {
        Vec::new()
    };
    let edge_root_provenance = edges
        .iter()
        .map(|(edge, roots)| NativeClosureEdgeProvenanceRow {
            source_rva: edge.source_rva,
            target_rva: edge.target_rva,
            kind: edge.kind.clone(),
            root_rvas: roots.iter().copied().collect(),
        })
        .collect();
    let reachable_edges = edges.into_keys().collect();
    Ok(NativeClosureEvaluationOutput {
        frontier: NativeClosureFrontierReceipt {
            worklist_steps: steps,
            states: state_rows,
            reachable_edges,
            blockers: final_blockers,
        },
        edge_root_provenance,
        state_contexts,
        reachable_rvas,
        indirect_targets,
        external_contracts,
        callback_escapes,
        exception_continuations,
        nonlocal_transitions,
        lifecycle_effects,
        witnesses,
        reference_facts,
        semantic_metrics,
    })
}

#[pyfunction]
pub(crate) fn evaluate_reference_closure_frontier<'py>(
    py: Python<'py>,
    transfer_plan: &Bound<'py, PyBytes>,
    context: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    let _text_scope = SharedTextInterningScope::new();
    let plan = reference_plan::parse_transfer_plan(transfer_plan.as_bytes())?;
    let input: ClosureContextInput = serde_json::from_slice(context.as_bytes())
        .map_err(|error| invalid(format!("cannot decode closure context JSON: {error}")))?;
    let (_receipt, runtime) = validate_closure_context(input)?;
    validate_exception_transition_bindings(&plan, &runtime)?;
    let result = evaluate_native_closure_frontier(&plan, &runtime, true, false)?;
    let encoded = serde_json::to_vec(&result.frontier)
        .map_err(|error| invalid(format!("cannot encode result: {error}")))?;
    Ok(PyBytes::new(py, &encoded))
}

#[pyfunction]
pub(crate) fn evaluate_reference_closure_summary<'py>(
    py: Python<'py>,
    transfer_plan: &Bound<'py, PyBytes>,
    context: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    let _text_scope = SharedTextInterningScope::new();
    let plan = reference_plan::parse_transfer_plan(transfer_plan.as_bytes())?;
    let input: ClosureContextInput = serde_json::from_slice(context.as_bytes())
        .map_err(|error| invalid(format!("cannot decode closure context JSON: {error}")))?;
    let (_receipt, runtime) = validate_closure_context(input)?;
    validate_exception_transition_bindings(&plan, &runtime)?;
    let result = evaluate_native_closure_frontier(&plan, &runtime, false, false)?;
    let summary = NativeClosureSummaryReceipt {
        worklist_steps: result.frontier.worklist_steps,
        state_contexts: result.state_contexts,
        reachable_rvas: result.reachable_rvas,
        reachable_edges: result.frontier.reachable_edges,
        blockers: result.frontier.blockers,
    };
    let encoded = serde_json::to_vec(&summary)
        .map_err(|error| invalid(format!("cannot encode result: {error}")))?;
    Ok(PyBytes::new(py, &encoded))
}

struct SemanticLinkSymbolState {
    kind: String,
    resolution: JsonValue,
    reachable: bool,
    root_rvas: BTreeSet<u32>,
}

struct SemanticLinkRelocationState {
    kind: String,
    source_symbol: String,
    status: String,
    target_symbols: Vec<String>,
    reachable: bool,
}

#[derive(Debug, Eq, PartialEq)]
struct ExpectedTransferRelocation {
    kind: String,
    source_symbol: String,
    source_rva: u32,
    target_symbol: Option<String>,
    target_rva: Option<u32>,
    input_status: String,
    instruction_rva: Option<u32>,
}

fn transfer_function_symbol(unit_id: &str) -> String {
    format!("original:function:{unit_id}")
}

fn expected_transfer_relocations(
    plan: &reference_plan::TransferPlan,
) -> PyResult<BTreeMap<String, ExpectedTransferRelocation>> {
    let symbol_by_rva = plan
        .transfers
        .iter()
        .map(|transfer| {
            (
                transfer.rva_start(),
                transfer_function_symbol(transfer.identity()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut expected = BTreeMap::new();
    let mut edge_occurrences = BTreeMap::<(String, u32, u32), usize>::new();
    for edge in plan.direct_control_edges() {
        if edge.kind == "internal_call" {
            continue;
        }
        if edge.kind != "control" {
            return Err(invalid(
                "transfer plan contains an unsupported direct-control edge",
            ));
        }
        let coordinate = (edge.kind.clone(), edge.source_rva, edge.target_rva);
        let occurrence = edge_occurrences.entry(coordinate).or_default();
        let relocation_id = format!(
            "transfer:{}:{:08x}:{:08x}:{}",
            edge.kind, edge.source_rva, edge.target_rva, occurrence
        );
        *occurrence += 1;
        let source_symbol = symbol_by_rva.get(&edge.source_rva).cloned();
        let target_symbol = symbol_by_rva.get(&edge.target_rva).cloned();
        let Some(source_symbol) = source_symbol else {
            return Err(invalid(
                "transfer direct-control source is outside the transfer universe",
            ));
        };
        expected.insert(
            relocation_id,
            ExpectedTransferRelocation {
                kind: "direct_control".to_owned(),
                source_symbol,
                source_rva: edge.source_rva,
                target_symbol: target_symbol.clone(),
                target_rva: Some(edge.target_rva),
                input_status: if target_symbol.is_some() {
                    "resolved_local".to_owned()
                } else {
                    "unresolved".to_owned()
                },
                instruction_rva: None,
            },
        );
    }
    for transfer in &plan.transfers {
        let source_rva = transfer.rva_start();
        let source_symbol = transfer_function_symbol(transfer.identity());
        for call in &transfer.calls {
            let (relocation_id, kind, target_symbol, target_rva, status) =
                match call.kind.as_str() {
                    "internal_call" => {
                        let target = symbol_by_rva.get(&call.target_rva).cloned();
                        (
                            format!(
                                "transfer:internal-call:{source_rva:08x}:{}:{:08x}:{:08x}",
                                call.id, call.instruction_rva, call.target_rva
                            ),
                            "internal_call",
                            target.clone(),
                            Some(call.target_rva),
                            if target.is_some() {
                                "resolved_local"
                            } else {
                                "unresolved"
                            },
                        )
                    }
                    "indirect_call" => {
                        let target_node = call.target_node.ok_or_else(|| {
                            invalid("transfer indirect call omits its target expression")
                        })?;
                        (
                            format!(
                                "transfer:indirect-call:{source_rva:08x}:{}:{:08x}:{target_node}",
                                call.id, call.instruction_rva
                            ),
                            "indirect_call",
                            None,
                            None,
                            "unresolved_indirect",
                        )
                    }
                    "external_call" => {
                        let identity = serde_json::json!({
                            "dll": call.dll,
                            "symbol": call.symbol,
                            "ordinal": call.ordinal,
                        });
                        let digest = canonical_json_digest(&identity)?;
                        let target = format!("external:function-import:{}", &digest[..24]);
                        (
                            format!(
                                "transfer:external-call:{source_rva:08x}:{}:{:08x}:{}",
                                call.id,
                                call.instruction_rva,
                                &digest[..24]
                            ),
                            "external_call",
                            Some(target),
                            None,
                            "unresolved_external",
                        )
                    }
                    _ => {
                        return Err(invalid(
                            "transfer plan contains an unsupported call kind",
                        ));
                    }
                };
            expected.insert(
                relocation_id,
                ExpectedTransferRelocation {
                    kind: kind.to_owned(),
                    source_symbol: source_symbol.clone(),
                    source_rva,
                    target_symbol,
                    target_rva,
                    input_status: status.to_owned(),
                    instruction_rva: Some(call.instruction_rva),
                },
            );
        }
    }
    for inventory in plan.finite_control_routes() {
        let source_symbol = symbol_by_rva
            .get(&inventory.source_rva)
            .cloned()
            .ok_or_else(|| invalid("finite-control source has no transfer symbol"))?;
        for route in &inventory.routes {
            let target_symbol = symbol_by_rva.get(&route.target_rva).cloned();
            let relocation_id = format!(
                "transfer:finite-control:{:08x}:{:08x}:{:08x}",
                inventory.source_rva, route.selector_value, route.target_rva
            );
            expected.insert(
                relocation_id,
                ExpectedTransferRelocation {
                    kind: "finite_control_target".to_owned(),
                    source_symbol: source_symbol.clone(),
                    source_rva: inventory.source_rva,
                    target_symbol: target_symbol.clone(),
                    target_rva: Some(route.target_rva),
                    input_status: if target_symbol.is_some() {
                        "resolved_local".to_owned()
                    } else {
                        "unresolved".to_owned()
                    },
                    instruction_rva: None,
                },
            );
        }
    }
    Ok(expected)
}

fn validate_transfer_relocations(
    plan: &reference_plan::TransferPlan,
    relocations: &[SemanticLinkRelocationInput],
) -> PyResult<()> {
    let expected = expected_transfer_relocations(plan)?;
    let observed = relocations
        .iter()
        .filter(|row| row.relocation_id.starts_with("transfer:"))
        .map(|row| {
            (
                row.relocation_id.clone(),
                ExpectedTransferRelocation {
                    kind: row.kind.clone(),
                    source_symbol: row.source_symbol.clone(),
                    source_rva: row.source_rva.unwrap_or(u32::MAX),
                    target_symbol: row.target_symbol.clone(),
                    target_rva: row.target_rva,
                    input_status: row.input_status.clone(),
                    instruction_rva: row.instruction_rva,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    if observed.len() != relocations
        .iter()
        .filter(|row| row.relocation_id.starts_with("transfer:"))
        .count()
        || observed != expected
    {
        return Err(invalid(
            "semantic-link transfer relocations contradict the transfer plan",
        ));
    }
    Ok(())
}

fn json_u32(value: Option<&JsonValue>, context: &str) -> PyResult<u32> {
    value
        .and_then(JsonValue::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| invalid(format!("{context} is malformed")))
}

fn json_text<'a>(value: Option<&'a JsonValue>, context: &str) -> PyResult<&'a str> {
    value
        .and_then(JsonValue::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(format!("{context} is malformed")))
}

fn semantic_effect_root_rvas(
    effect: &JsonValue,
    roots_by_unit: &BTreeMap<String, BTreeSet<u32>>,
    roots_by_source_rva: &BTreeMap<u32, BTreeSet<u32>>,
    known_root_rvas: &BTreeSet<u32>,
) -> PyResult<BTreeSet<u32>> {
    let object = effect
        .as_object()
        .ok_or_else(|| invalid("semantic-link effect is malformed"))?;
    let mut roots = BTreeSet::new();
    if let Some(unit_id) = object.get("unit_id") {
        let unit_id = json_text(Some(unit_id), "semantic-link effect unit")?;
        roots.extend(roots_by_unit.get(unit_id).cloned().unwrap_or_default());
    }
    for field in ["source_rva", "instruction_rva"] {
        if let Some(value) = object.get(field) {
            let rva = json_u32(Some(value), "semantic-link effect source RVA")?;
            roots.extend(roots_by_source_rva.get(&rva).cloned().unwrap_or_default());
        }
    }
    if let Some(rows) = object.get("root_rvas") {
        let rows = rows
            .as_array()
            .ok_or_else(|| invalid("semantic-link effect roots are malformed"))?;
        for row in rows {
            let root_rva = json_u32(Some(row), "semantic-link effect root RVA")?;
            if !known_root_rvas.contains(&root_rva) {
                return Err(invalid("semantic-link effect names an unknown root RVA"));
            }
            roots.insert(root_rva);
        }
    }
    Ok(roots)
}

fn semantic_effect_facts(
    kind: &str,
    effects: &[JsonValue],
    roots_by_unit: &BTreeMap<String, BTreeSet<u32>>,
    roots_by_source_rva: &BTreeMap<u32, BTreeSet<u32>>,
    known_root_rvas: &BTreeSet<u32>,
    blockers: &mut BTreeMap<String, JsonValue>,
) -> PyResult<Vec<NativeSemanticLinkEffectFact>> {
    effects
        .iter()
        .map(|effect| {
            let roots = semantic_effect_root_rvas(
                effect,
                roots_by_unit,
                roots_by_source_rva,
                known_root_rvas,
            )?;
            if roots.is_empty() {
                let blocker = serde_json::json!({
                    "code": "reachable_effect_root_provenance_missing",
                    "effect_kind": kind,
                    "effect_sha256": canonical_json_digest(effect)?,
                });
                blockers.insert(canonical_json_digest(&blocker)?, blocker);
            }
            Ok(NativeSemanticLinkEffectFact {
                effect: effect.clone(),
                root_rvas: roots.into_iter().collect(),
            })
        })
        .collect()
}

fn semantic_link_facts(
    plan: &reference_plan::TransferPlan,
    runtime: &RuntimeClosureContext,
    closure: &NativeClosureEvaluationOutput,
    input: SemanticLinkKernelInput,
    references: NativeSemanticReferenceFacts,
) -> PyResult<NativeSemanticLinkFacts> {
    if input.version != 2 {
        return Err(invalid("semantic-link kernel input version is unsupported"));
    }
    validate_transfer_relocations(plan, &input.relocations)?;

    let transfer_by_identity = plan
        .transfers
        .iter()
        .map(|transfer| (transfer.identity(), transfer.rva_start()))
        .collect::<BTreeMap<_, _>>();
    let mut unit_symbol_by_rva = BTreeMap::<u32, String>::new();
    let mut roots_by_unit = BTreeMap::<String, BTreeSet<u32>>::new();
    let mut roots_by_source_rva = BTreeMap::<u32, BTreeSet<u32>>::new();
    for witness in &closure.witnesses {
        let object = witness
            .as_object()
            .ok_or_else(|| invalid("semantic-link witness is malformed"))?;
        let unit_id = json_text(object.get("unit_id"), "semantic-link witness unit")?;
        let rva = json_u32(object.get("rva"), "semantic-link witness RVA")?;
        let root_rva = json_u32(object.get("root_rva"), "semantic-link witness root")?;
        roots_by_unit
            .entry(unit_id.to_owned())
            .or_default()
            .insert(root_rva);
        roots_by_source_rva.entry(rva).or_default().insert(root_rva);
    }
    for transfer in &plan.transfers {
        let roots = roots_by_unit
            .get(transfer.identity())
            .cloned()
            .unwrap_or_default();
        if roots.is_empty() {
            continue;
        }
        roots_by_source_rva
            .entry(transfer.rva_start())
            .or_default()
            .extend(&roots);
        for call in &transfer.calls {
            roots_by_source_rva
                .entry(call.instruction_rva)
                .or_default()
                .extend(&roots);
        }
    }
    let known_root_rvas = roots_by_unit
        .values()
        .flat_map(|roots| roots.iter().copied())
        .collect::<BTreeSet<_>>();

    let provider_by_symbol = input
        .symbols
        .iter()
        .filter_map(|row| {
            row.runtime_provider_id
                .as_ref()
                .map(|provider| (row.symbol_id.as_str(), provider.as_str()))
        })
        .collect::<BTreeMap<_, _>>();
    let unit_by_symbol = input
        .symbols
        .iter()
        .filter_map(|row| {
            row.unit_id
                .as_ref()
                .map(|unit_id| (row.symbol_id.as_str(), unit_id.as_str()))
        })
        .collect::<BTreeMap<_, _>>();
    let symbol_by_unit = unit_by_symbol
        .iter()
        .map(|(symbol, unit)| (*unit, *symbol))
        .collect::<BTreeMap<_, _>>();
    if symbol_by_unit.len() != unit_by_symbol.len() {
        return Err(invalid(
            "semantic-link function symbols repeat a transfer identity",
        ));
    }
    let external_by_symbol = input
        .symbols
        .iter()
        .filter_map(|row| {
            Some((
                row.symbol_id.as_str(),
                (row.external_dll.as_ref()?.as_str(), row.external_identity.as_ref()?.as_str()),
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let mut provider_roots = BTreeMap::<String, BTreeSet<u32>>::new();
    let mut external_roots = BTreeMap::<(String, String), BTreeSet<u32>>::new();
    let mut observed_runtime_dependencies = BTreeMap::<String, BTreeSet<String>>::new();
    let mut previous_provider: Option<&str> = None;
    for dependency in &input.runtime_primitive_dependencies {
        validate_text(&dependency.provider_id, "semantic-link provider identity")?;
        validate_text(&dependency.target_symbol, "semantic-link provider target")?;
        if previous_provider.is_some_and(|previous| previous >= dependency.provider_id.as_str())
            || !sorted_unique(&dependency.source_symbols)
            || dependency.source_symbols.is_empty()
            || provider_by_symbol.get(dependency.target_symbol.as_str()).copied()
                != Some(dependency.provider_id.as_str())
        {
            return Err(invalid(
                "semantic-link runtime dependencies are malformed or noncanonical",
            ));
        }
        previous_provider = Some(dependency.provider_id.as_str());
        for source_symbol in &dependency.source_symbols {
            let unit_id = unit_by_symbol.get(source_symbol.as_str()).ok_or_else(|| {
                invalid("semantic-link runtime dependency source is not a function")
            })?;
            if let Some(roots) = roots_by_unit.get(*unit_id) {
                provider_roots
                    .entry(dependency.provider_id.clone())
                    .or_default()
                    .extend(roots);
            }
            observed_runtime_dependencies
                .entry(dependency.provider_id.clone())
                .or_default()
                .insert(source_symbol.clone());
        }
    }
    let mut expected_runtime_dependencies = BTreeMap::<String, BTreeSet<String>>::new();
    for transfer in &plan.transfers {
        let source_symbol = symbol_by_unit
            .get(transfer.identity())
            .ok_or_else(|| invalid(
                "semantic-link runtime dependencies omit a transfer function"
            ))?;
        for provider in ["checked_memory", "checked_outcomes"] {
            expected_runtime_dependencies
                .entry(provider.to_owned())
                .or_default()
                .insert((*source_symbol).to_owned());
        }
        if !transfer.calls.is_empty() || transfer.effects.iter().any(|row| row.op == "call") {
            expected_runtime_dependencies
                .entry("checked_calls".to_owned())
                .or_default()
                .insert((*source_symbol).to_owned());
        }
        if transfer.effects.iter().any(|row| row.op == "typed_x87") {
            expected_runtime_dependencies
                .entry("typed_x87".to_owned())
                .or_default()
                .insert((*source_symbol).to_owned());
        }
        if transfer.effects.iter().any(|row| {
            row.op == "atomic_compare_exchange" || row.op == "atomic_exchange"
        }) {
            expected_runtime_dependencies
                .entry("checked_atomics".to_owned())
                .or_default()
                .insert((*source_symbol).to_owned());
        }
    }
    let expected_provider_ids = expected_runtime_dependencies
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    if expected_provider_ids != plan.runtime_provider_requirements()
        || observed_runtime_dependencies != expected_runtime_dependencies
    {
        return Err(invalid(
            "semantic-link runtime dependencies contradict the transfer plan",
        ));
    }
    for row in &input.relocations {
        let Some(source_rva) = row.source_rva else {
            continue;
        };
        let roots = roots_by_source_rva
            .get(&source_rva)
            .cloned()
            .unwrap_or_default();
        if roots.is_empty() {
            continue;
        }
        if row.kind == "external_call" {
            let target = row.target_symbol.as_deref().ok_or_else(|| {
                invalid("external-call relocation omits its target symbol")
            })?;
            let (dll, identity) = external_by_symbol.get(target).ok_or_else(|| {
                invalid("external-call relocation target has no external declaration")
            })?;
            validate_text(dll, "semantic-link external DLL")?;
            validate_text(identity, "semantic-link external identity")?;
            external_roots
                .entry(((*dll).to_owned(), (*identity).to_owned()))
                .or_default()
                .extend(roots);
        }
    }
    if provider_roots
        .keys()
        .any(|provider| !runtime.runtime_provider_requirements.contains(provider))
    {
        return Err(invalid(
            "semantic-link provider source names an undeclared runtime provider",
        ));
    }

    for target_set in &closure.indirect_targets {
        let object = target_set
            .as_object()
            .ok_or_else(|| invalid("semantic-link indirect target set is malformed"))?;
        let source_rva = json_u32(
            object.get("source_rva"),
            "semantic-link indirect source RVA",
        )?;
        let roots = roots_by_source_rva
            .get(&source_rva)
            .cloned()
            .unwrap_or_default();
        let Some(externals) = object.get("external_targets").and_then(JsonValue::as_array) else {
            continue;
        };
        for external in externals {
            let external = external
                .as_object()
                .ok_or_else(|| invalid("semantic-link indirect external is malformed"))?;
            let dll = json_text(external.get("dll"), "semantic-link indirect DLL")?;
            let identity = json_text(external.get("identity"), "semantic-link indirect identity")?;
            if !roots.is_empty() {
                external_roots
                    .entry((dll.to_owned(), identity.to_owned()))
                    .or_default()
                    .extend(&roots);
            }
        }
    }
    let reachable_external_contracts = closure
        .external_contracts
        .iter()
        .map(|row| {
            let object = row
                .as_object()
                .ok_or_else(|| invalid("semantic-link external contract is malformed"))?;
            Ok((
                json_text(object.get("dll"), "semantic-link contract DLL")?.to_owned(),
                json_text(object.get("identity"), "semantic-link contract identity")?.to_owned(),
            ))
        })
        .collect::<PyResult<BTreeSet<_>>>()?;

    let mut symbols = BTreeMap::<String, SemanticLinkSymbolState>::new();
    let mut external_symbol_by_identity = BTreeMap::<(String, String), String>::new();
    let mut blockers = BTreeMap::<String, JsonValue>::new();
    for row in input.symbols {
        validate_text(&row.symbol_id, "semantic-link symbol identity")?;
        validate_text(&row.kind, "semantic-link symbol kind")?;
        validate_text(&row.linkage, "semantic-link symbol linkage")?;
        if symbols.contains_key(&row.symbol_id) {
            return Err(invalid(
                "semantic-link symbols contain a duplicate identity",
            ));
        }
        let mut root_rvas = row
            .unit_id
            .as_ref()
            .and_then(|unit_id| roots_by_unit.get(unit_id))
            .cloned()
            .unwrap_or_default();
        let mut reachable = row
            .unit_id
            .as_ref()
            .is_some_and(|unit_id| roots_by_unit.contains_key(unit_id));
        let resolution = if let Some(definition_kind) = row.definition_kind.as_ref() {
            validate_text(definition_kind, "semantic-link definition kind")?;
            serde_json::json!({
                "kind": "semantic_definition",
                "definition_kind": definition_kind,
            })
        } else if row.kind == "runtime_primitive" {
            let provider = row
                .runtime_provider_id
                .as_ref()
                .ok_or_else(|| invalid("semantic-link runtime symbol omits its provider"))?;
            validate_text(provider, "semantic-link runtime provider")?;
            let required_roots = provider_roots.get(provider).cloned().unwrap_or_default();
            let required = !required_roots.is_empty();
            reachable = required;
            root_rvas.extend(required_roots);
            if required && row.provider_qualified != Some(true) {
                let blocker = serde_json::json!({
                    "code": "qualified_runtime_primitive_missing",
                    "symbol_id": row.symbol_id,
                    "provider_id": provider,
                });
                blockers.insert(canonical_json_digest(&blocker)?, blocker);
            }
            serde_json::json!({
                "kind": if required {
                    "qualified_platform_primitive"
                } else {
                    "unselected"
                },
                "provider_id": provider,
            })
        } else if row.linkage == "external" {
            let dll = row
                .external_dll
                .as_ref()
                .ok_or_else(|| invalid("semantic-link external symbol omits its DLL"))?;
            let identity = row
                .external_identity
                .as_ref()
                .ok_or_else(|| invalid("semantic-link external symbol omits its identity"))?;
            validate_text(dll, "semantic-link external DLL")?;
            validate_text(identity, "semantic-link external identity")?;
            let key = (dll.clone(), identity.clone());
            let expected_contract = runtime.external_declarations.get(&key);
            if row.checked_contract_sha256.as_ref()
                != expected_contract.map(|contract| &contract.0)
                || row.loader_service_contract_sha256.as_ref()
                    != expected_contract.and_then(|contract| contract.1.as_ref())
            {
                return Err(invalid(
                    "semantic-link external declaration contradicts the resolved external catalog",
                ));
            }
            let is_reachable = reachable_external_contracts.contains(&key);
            reachable |= is_reachable;
            root_rvas.extend(external_roots.get(&key).cloned().unwrap_or_default());
            if let Some(contract_sha256) = row.checked_contract_sha256.as_ref() {
                if !valid_sha256(contract_sha256) {
                    return Err(invalid(
                        "semantic-link checked contract digest is malformed",
                    ));
                }
                external_symbol_by_identity
                    .entry(key)
                    .or_insert_with(|| row.symbol_id.clone());
            } else if is_reachable {
                let blocker = serde_json::json!({
                    "code": "reachable_external_symbol_unresolved",
                    "symbol_id": row.symbol_id,
                    "dll": dll,
                    "identity": identity,
                });
                blockers.insert(canonical_json_digest(&blocker)?, blocker);
            }
            if row
                .loader_service_contract_sha256
                .as_ref()
                .is_some_and(|digest| !valid_sha256(digest))
            {
                return Err(invalid(
                    "semantic-link loader-service digest is malformed",
                ));
            }
            serde_json::json!({
                "kind": if row.checked_contract_sha256.is_some() {
                    "checked_external_contract"
                } else {
                    "unresolved_external"
                },
                "contract_sha256": row.checked_contract_sha256,
            })
        } else {
            if reachable {
                let blocker = serde_json::json!({
                    "code": "reachable_symbol_unresolved",
                    "symbol_id": row.symbol_id,
                });
                blockers.insert(canonical_json_digest(&blocker)?, blocker);
            }
            serde_json::json!({"kind": "unresolved"})
        };
        if let (Some(unit_id), Some(original_rva)) = (&row.unit_id, row.original_rva) {
            if transfer_by_identity.get(unit_id.as_str()) != Some(&original_rva)
                || unit_symbol_by_rva
                    .insert(original_rva, row.symbol_id.clone())
                    .is_some()
            {
                return Err(invalid(
                    "semantic-link function symbol contradicts the transfer plan",
                ));
            }
        }
        symbols.insert(
            row.symbol_id,
            SemanticLinkSymbolState {
                kind: row.kind,
                resolution,
                reachable,
                root_rvas,
            },
        );
    }
    if unit_symbol_by_rva.len() != plan.transfers.len() {
        return Err(invalid(
            "semantic-link symbols do not cover the transfer plan exactly",
        ));
    }

    let mut indirect_by_source = BTreeMap::<u32, Vec<&JsonValue>>::new();
    for row in &closure.indirect_targets {
        let object = row
            .as_object()
            .ok_or_else(|| invalid("semantic-link indirect target set is malformed"))?;
        let source_rva = json_u32(
            object.get("source_rva"),
            "semantic-link indirect source RVA",
        )?;
        indirect_by_source.entry(source_rva).or_default().push(row);
    }
    let reachable_direct_edges = closure
        .frontier
        .reachable_edges
        .iter()
        .filter(|edge| edge.kind == "direct_control")
        .map(|edge| (edge.source_rva, edge.target_rva))
        .collect::<BTreeSet<_>>();
    let mut relocations = BTreeMap::<String, SemanticLinkRelocationState>::new();
    for row in input.relocations {
        validate_text(&row.relocation_id, "semantic-link relocation identity")?;
        validate_text(&row.kind, "semantic-link relocation kind")?;
        if relocations.contains_key(&row.relocation_id) || !symbols.contains_key(&row.source_symbol)
        {
            return Err(invalid(
                "semantic-link relocation identity or source is malformed",
            ));
        }
        let mut targets = BTreeSet::<String>::new();
        if let Some(target) = row.target_symbol.as_ref() {
            targets.insert(target.clone());
        } else if let Some(target_rva) = row.target_rva {
            if let Some(target) = unit_symbol_by_rva.get(&target_rva) {
                targets.insert(target.clone());
            }
        } else if row.input_status == "unresolved_indirect" {
            let mut candidates = row
                .source_rva
                .and_then(|source_rva| indirect_by_source.get(&source_rva).cloned())
                .unwrap_or_default();
            if let Some(instruction_rva) = row.instruction_rva {
                let prefix = format!("call:{instruction_rva:08x}:");
                let exact = candidates
                    .iter()
                    .copied()
                    .filter(|candidate| {
                        candidate
                            .get("site")
                            .and_then(JsonValue::as_str)
                            .is_some_and(|site| site.starts_with(&prefix))
                    })
                    .collect::<Vec<_>>();
                if !exact.is_empty() {
                    candidates = exact;
                }
            }
            for candidate in candidates {
                if let Some(rows) = candidate.get("targets").and_then(JsonValue::as_array) {
                    for target in rows {
                        let target_rva =
                            json_u32(Some(target), "semantic-link indirect target RVA")?;
                        if let Some(target) = unit_symbol_by_rva.get(&target_rva) {
                            targets.insert(target.clone());
                        }
                    }
                }
                if let Some(rows) = candidate
                    .get("external_targets")
                    .and_then(JsonValue::as_array)
                {
                    for external in rows {
                        let external = external.as_object().ok_or_else(|| {
                            invalid("semantic-link indirect external is malformed")
                        })?;
                        let key = (
                            json_text(external.get("dll"), "semantic-link indirect DLL")?
                                .to_owned(),
                            json_text(external.get("identity"), "semantic-link indirect identity")?
                                .to_owned(),
                        );
                        if let Some(target) = external_symbol_by_identity.get(&key) {
                            targets.insert(target.clone());
                        }
                    }
                }
            }
        }
        if targets.iter().any(|target| !symbols.contains_key(target)) {
            return Err(invalid(
                "semantic-link relocation resolves to an undeclared symbol",
            ));
        }
        // A reachable unit may end in a checked no-return call.  Transfer-v2
        // intentionally retains its syntactic machine fallthrough, but only
        // the same-pass closure can activate that particular control edge.
        let reachable = if row.kind == "direct_control" {
            row.source_rva
                .zip(row.target_rva)
                .is_some_and(|edge| reachable_direct_edges.contains(&edge))
        } else {
            symbols[&row.source_symbol].reachable
        };
        let status = if !targets.is_empty() {
            "resolved"
        } else if row.input_status == "unresolved_external" {
            "external_declaration"
        } else if !reachable {
            "unresolved_unreachable"
        } else {
            "unresolved_reachable"
        };
        relocations.insert(
            row.relocation_id,
            SemanticLinkRelocationState {
                kind: row.kind,
                source_symbol: row.source_symbol,
                status: status.to_owned(),
                target_symbols: targets.into_iter().collect(),
                reachable,
            },
        );
    }

    let initially_reachable_symbols = symbols
        .iter()
        .filter_map(|(symbol_id, symbol)| {
            symbol.reachable.then_some(symbol_id.clone())
        })
        .collect::<BTreeSet<_>>();

    loop {
        let mut changed = false;
        for relocation in relocations.values_mut() {
            let source = symbols
                .get(&relocation.source_symbol)
                .expect("validated relocation source");
            if relocation.kind != "direct_control"
                && relocation.reachable != source.reachable
            {
                relocation.reachable = source.reachable;
                changed = true;
            }
            if !relocation.reachable {
                continue;
            }
            let source_roots = source.root_rvas.clone();
            for target_id in &relocation.target_symbols {
                let target = symbols
                    .get_mut(target_id)
                    .expect("validated relocation target");
                if target.kind == "function" {
                    continue;
                }
                let old_len = target.root_rvas.len();
                target.root_rvas.extend(&source_roots);
                if !target.reachable || target.root_rvas.len() != old_len {
                    target.reachable = true;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }

    for (relocation_id, relocation) in &mut relocations {
        if !relocation.reachable {
            if relocation.status == "unresolved_reachable" {
                relocation.status = "unresolved_unreachable".to_owned();
            }
            continue;
        }
        if relocation.status == "unresolved_unreachable" {
            relocation.status = "unresolved_reachable".to_owned();
        }
        if relocation.status == "unresolved_reachable" && relocation.kind != "indirect_call" {
            let blocker = serde_json::json!({
                "code": "reachable_relocation_unresolved",
                "relocation_id": relocation_id,
                "source_symbol": relocation.source_symbol,
                "kind": relocation.kind,
            });
            blockers.insert(canonical_json_digest(&blocker)?, blocker);
        }
    }
    for (symbol_id, symbol) in &symbols {
        let resolution_kind = symbol
            .resolution
            .get("kind")
            .and_then(JsonValue::as_str);
        if symbol.reachable
            && !initially_reachable_symbols.contains(symbol_id)
            && matches!(resolution_kind, Some("unresolved"))
        {
            let blocker = serde_json::json!({
                "code": "reachable_symbol_unresolved",
                "symbol_id": symbol_id,
            });
            blockers.insert(canonical_json_digest(&blocker)?, blocker);
        }
        if symbol.reachable && symbol.root_rvas.is_empty() {
            let blocker = serde_json::json!({
                "code": "reachable_symbol_root_provenance_missing",
                "symbol_id": symbol_id,
            });
            blockers.insert(canonical_json_digest(&blocker)?, blocker);
        }
    }

    let runtime_providers = provider_roots
        .iter()
        .map(|(provider_id, roots)| NativeSemanticLinkEffectFact {
            effect: serde_json::json!({"provider_id": provider_id}),
            root_rvas: roots.iter().copied().collect(),
        })
        .collect::<Vec<_>>();
    let external_contracts = closure
        .external_contracts
        .iter()
        .map(|effect| {
            let object = effect
                .as_object()
                .ok_or_else(|| invalid("semantic-link external-contract effect is malformed"))?;
            let dll = json_text(object.get("dll"), "semantic-link external-contract DLL")?;
            let identity = json_text(
                object.get("identity"),
                "semantic-link external-contract identity",
            )?;
            let roots = external_roots
                .get(&(dll.to_owned(), identity.to_owned()))
                .cloned()
                .unwrap_or_default();
            if roots.is_empty() {
                let blocker = serde_json::json!({
                    "code": "reachable_effect_root_provenance_missing",
                    "effect_kind": "external_contract",
                    "dll": dll.to_lowercase(),
                    "identity": identity,
                });
                blockers.insert(canonical_json_digest(&blocker)?, blocker);
            }
            Ok(NativeSemanticLinkEffectFact {
                effect: effect.clone(),
                root_rvas: roots.into_iter().collect(),
            })
        })
        .collect::<PyResult<Vec<_>>>()?;
    let effects = NativeSemanticLinkEffects {
        runtime_providers,
        external_contracts,
        indirect_targets: semantic_effect_facts(
            "indirect_target",
            &closure.indirect_targets,
            &roots_by_unit,
            &roots_by_source_rva,
            &known_root_rvas,
            &mut blockers,
        )?,
        callbacks: semantic_effect_facts(
            "callback",
            &closure.callback_escapes,
            &roots_by_unit,
            &roots_by_source_rva,
            &known_root_rvas,
            &mut blockers,
        )?,
        exceptions: semantic_effect_facts(
            "exception",
            &closure.exception_continuations,
            &roots_by_unit,
            &roots_by_source_rva,
            &known_root_rvas,
            &mut blockers,
        )?,
        nonlocal_transitions: semantic_effect_facts(
            "nonlocal_transition",
            &closure.nonlocal_transitions,
            &roots_by_unit,
            &roots_by_source_rva,
            &known_root_rvas,
            &mut blockers,
        )?,
        lifecycle: semantic_effect_facts(
            "lifecycle",
            &closure.lifecycle_effects,
            &roots_by_unit,
            &roots_by_source_rva,
            &known_root_rvas,
            &mut blockers,
        )?,
    };
    let mut seen_object_ids = BTreeSet::new();
    let objects = input
        .objects
        .into_iter()
        .map(|row| {
            validate_text(&row.object_id, "semantic-link object identity")?;
            if !seen_object_ids.insert(row.object_id.clone()) {
                return Err(invalid(
                    "semantic-link objects contain a duplicate identity",
                ));
            }
            let (reachable, root_rvas) = if let Some(symbol_id) = &row.semantic_symbol_id {
                validate_text(symbol_id, "semantic-link object symbol")?;
                let symbol = symbols
                    .get(symbol_id)
                    .ok_or_else(|| invalid("semantic-link object names an undeclared symbol"))?;
                (symbol.reachable, symbol.root_rvas.iter().copied().collect())
            } else {
                (false, Vec::new())
            };
            Ok(NativeSemanticLinkObjectFact {
                object_id: row.object_id,
                semantic_symbol_id: row.semantic_symbol_id,
                reachable,
                root_rvas,
            })
        })
        .collect::<PyResult<Vec<_>>>()?;

    Ok(NativeSemanticLinkFacts {
        symbols: symbols
            .into_iter()
            .map(|(symbol_id, state)| NativeSemanticLinkSymbolFact {
                symbol_id,
                resolution: state.resolution,
                reachable: state.reachable,
                root_rvas: state.root_rvas.into_iter().collect(),
            })
            .collect(),
        relocations: relocations
            .into_iter()
            .map(|(relocation_id, state)| NativeSemanticLinkRelocationFact {
                relocation_id,
                status: state.status,
                target_symbols: state.target_symbols,
                reachable: state.reachable,
            })
            .collect(),
        objects,
        effects,
        references,
        blockers: blockers.into_values().collect(),
    })
}

fn evaluate_reference_closure_receipt_value(
    transfer_bytes: &[u8],
    context_bytes: &[u8],
    semantic_link_bytes: Option<&[u8]>,
) -> PyResult<(
    JsonValue,
    Vec<NativeClosureEdgeProvenanceRow>,
    Option<NativeSemanticLinkFacts>,
)> {
    let started = Instant::now();
    let plan = reference_plan::parse_transfer_plan(transfer_bytes)?;
    let input: ClosureContextInput = serde_json::from_slice(context_bytes)
        .map_err(|error| invalid(format!("cannot decode closure context JSON: {error}")))?;
    let (_input_receipt, runtime) = validate_closure_context(input)?;
    validate_exception_transition_bindings(&plan, &runtime)?;
    let mut result =
        evaluate_native_closure_frontier(&plan, &runtime, false, semantic_link_bytes.is_some())?;
    let references = std::mem::take(&mut result.reference_facts);
    let semantic_link = semantic_link_bytes
        .map(|bytes| {
            let input: SemanticLinkKernelInput =
                serde_json::from_slice(bytes).map_err(|error| {
                    invalid(format!(
                        "cannot decode semantic-link kernel input JSON: {error}"
                    ))
                })?;
            semantic_link_facts(&plan, &runtime, &result, input, references)
        })
        .transpose()?;
    let edge_root_provenance = result.edge_root_provenance.clone();
    let by_rva = plan
        .transfers
        .iter()
        .map(|transfer| (transfer.rva_start(), transfer))
        .collect::<BTreeMap<_, _>>();
    let reachable_units = result
        .reachable_rvas
        .iter()
        .map(|rva| {
            serde_json::json!({
                "unit_id": by_rva[rva].identity(),
                "rva": rva,
            })
        })
        .collect::<Vec<_>>();
    let mut bindings = runtime.authority_bindings.clone();
    bindings.insert(
        "executable_transfer_plan_sha256".to_owned(),
        sha256_hex(transfer_bytes),
    );
    let status = if result.frontier.blockers.is_empty() {
        "complete"
    } else {
        "incomplete"
    };
    let authorizes_execution = result.frontier.blockers.is_empty();
    let metrics = serde_json::json!({
        "elapsed_milliseconds": started.elapsed().as_millis() as u64,
        "worklist_steps": result.frontier.worklist_steps,
        "reachable_units": result.reachable_rvas.len(),
        "reachable_edges": result.frontier.reachable_edges.len(),
        "reachable_expression_nodes": (
            result.semantic_metrics.reachable_expression_nodes
        ),
        "indirect_sites": result.semantic_metrics.indirect_sites,
        "function_contexts": result.semantic_metrics.function_contexts,
        "return_summaries": result.semantic_metrics.return_summaries,
        "relational_object_bindings": (
            result.semantic_metrics.relational_object_bindings
        ),
        "peak_rss_kib": 0,
    });
    let mut receipt = serde_json::json!({
        "format": "spaghetti-extractor-module-execution-closure-v2",
        "status": status,
        "authorizes_execution": authorizes_execution,
        "bindings": bindings,
        "roots": runtime.roots,
        "reachable_units": reachable_units,
        "reachable_edges": result.frontier.reachable_edges,
        "indirect_targets": result.indirect_targets,
        "external_contracts": result.external_contracts,
        "runtime_providers": runtime.runtime_provider_requirements,
        "callback_escapes": result.callback_escapes,
        "exception_continuations": result.exception_continuations,
        "nonlocal_transitions": result.nonlocal_transitions,
        "lifecycle_effects": result.lifecycle_effects,
        "witnesses": result.witnesses,
        "blockers": result.frontier.blockers,
        "metrics": metrics,
        "analysis_policy": {
            "reference_alternative_limit": runtime.catalog.alternative_limit,
            "call_string_limit": runtime.call_string_limit,
            "maximum_worklist_steps": runtime.maximum_worklist_steps,
            "boundary_exit_rvas": runtime.boundary_exit_rvas,
        },
        "authority": (
            "derived exact execution closure; diagnostics and tests remain veto-only"
        ),
    });
    let mut semantic_core = receipt.clone();
    let semantic_metrics = semantic_core
        .get_mut("metrics")
        .and_then(JsonValue::as_object_mut)
        .expect("closure metrics are an object");
    semantic_metrics.remove("elapsed_milliseconds");
    semantic_metrics.remove("peak_rss_kib");
    semantic_metrics.remove("worklist_steps");
    let closure_sha256 = canonical_json_digest(&semantic_core)?;
    receipt
        .as_object_mut()
        .expect("closure receipt is an object")
        .insert(
            "closure_sha256".to_owned(),
            JsonValue::String(closure_sha256),
        );
    Ok((receipt, edge_root_provenance, semantic_link))
}

#[pyfunction]
pub(crate) fn evaluate_reference_closure_receipt<'py>(
    py: Python<'py>,
    transfer_plan: &Bound<'py, PyBytes>,
    context: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    let _text_scope = SharedTextInterningScope::new();
    let (receipt, _edge_root_provenance, _semantic_link) =
        evaluate_reference_closure_receipt_value(
            transfer_plan.as_bytes(),
            context.as_bytes(),
            None,
        )?;
    let encoded = serde_json::to_vec(&receipt)
        .map_err(|error| invalid(format!("cannot encode result: {error}")))?;
    Ok(PyBytes::new(py, &encoded))
}

#[pyfunction]
pub(crate) fn evaluate_semantic_link_closure_receipt<'py>(
    py: Python<'py>,
    transfer_plan: &Bound<'py, PyBytes>,
    context: &Bound<'py, PyBytes>,
    semantic_link: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    let _text_scope = SharedTextInterningScope::new();
    let (closure, edge_root_provenance, semantic_link) = evaluate_reference_closure_receipt_value(
        transfer_plan.as_bytes(),
        context.as_bytes(),
        if semantic_link.as_bytes() == b"null" {
            None
        } else {
            Some(semantic_link.as_bytes())
        },
    )?;
    #[derive(Serialize)]
    struct CombinedSemanticLinkReceipt<'a> {
        closure: &'a JsonValue,
        edge_root_provenance: &'a [NativeClosureEdgeProvenanceRow],
        semantic_link: &'a Option<NativeSemanticLinkFacts>,
    }
    let encoded = serde_json::to_vec(&CombinedSemanticLinkReceipt {
        closure: &closure,
        edge_root_provenance: &edge_root_provenance,
        semantic_link: &semantic_link,
    })
    .map_err(|error| invalid(format!("cannot encode result: {error}")))?;
    Ok(PyBytes::new(py, &encoded))
}

#[pyfunction]
pub(crate) fn inspect_reference_closure_inputs<'py>(
    py: Python<'py>,
    transfer_plan: &Bound<'py, PyBytes>,
    context: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    let _text_scope = SharedTextInterningScope::new();
    let plan = reference_plan::parse_transfer_plan(transfer_plan.as_bytes())?;
    let input: ClosureContextInput = serde_json::from_slice(context.as_bytes())
        .map_err(|error| invalid(format!("cannot decode closure context JSON: {error}")))?;
    let (mut receipt, runtime_context) = validate_closure_context(input)?;
    validate_exception_transition_bindings(&plan, &runtime_context)?;
    receipt.transfers = plan.transfers.len();
    let encoded = serde_json::to_vec(&receipt)
        .map_err(|error| invalid(format!("cannot encode result: {error}")))?;
    Ok(PyBytes::new(py, &encoded))
}

#[pyfunction]
pub(crate) fn evaluate_reference_root_expressions<'py>(
    py: Python<'py>,
    transfer_plan: &Bound<'py, PyBytes>,
    context: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    let _text_scope = SharedTextInterningScope::new();
    let plan = reference_plan::parse_transfer_plan(transfer_plan.as_bytes())?;
    let input: ClosureContextInput = serde_json::from_slice(context.as_bytes())
        .map_err(|error| invalid(format!("cannot decode closure context JSON: {error}")))?;
    let (_receipt, runtime) = validate_closure_context(input)?;
    validate_exception_transition_bindings(&plan, &runtime)?;
    let by_rva = plan
        .transfers
        .iter()
        .map(|transfer| (transfer.rva_start(), transfer))
        .collect::<BTreeMap<_, _>>();
    let default_state = default_reference_state();
    let mut roots = Vec::with_capacity(runtime.roots.len());
    for rva in &runtime.roots {
        let transfer = by_rva
            .get(rva)
            .ok_or_else(|| invalid("closure root is outside the transfer plan"))?;
        let state = runtime.initial_states.get(rva).unwrap_or(&default_state);
        roots.push(RootExpressionRow {
            rva: *rva,
            values: evaluate_transfer_expressions(transfer, state, state, &runtime.catalog)?,
        });
    }
    let encoded = serde_json::to_vec(&RootExpressionReceipt { roots })
        .map_err(|error| invalid(format!("cannot encode result: {error}")))?;
    Ok(PyBytes::new(py, &encoded))
}

#[pyfunction]
pub(crate) fn evaluate_reference_root_effects<'py>(
    py: Python<'py>,
    transfer_plan: &Bound<'py, PyBytes>,
    context: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    let _text_scope = SharedTextInterningScope::new();
    let plan = reference_plan::parse_transfer_plan(transfer_plan.as_bytes())?;
    let input: ClosureContextInput = serde_json::from_slice(context.as_bytes())
        .map_err(|error| invalid(format!("cannot decode closure context JSON: {error}")))?;
    let (_receipt, runtime) = validate_closure_context(input)?;
    validate_exception_transition_bindings(&plan, &runtime)?;
    let by_rva = plan
        .transfers
        .iter()
        .map(|transfer| (transfer.rva_start(), transfer))
        .collect::<BTreeMap<_, _>>();
    let default_state = default_reference_state();
    let mut roots = Vec::with_capacity(runtime.roots.len());
    for rva in &runtime.roots {
        let transfer = by_rva
            .get(rva)
            .ok_or_else(|| invalid("closure root is outside the transfer plan"))?;
        let state = runtime.initial_states.get(rva).unwrap_or(&default_state);
        let (state, values) = apply_basic_reference_effects(transfer, state, &runtime.catalog)?;
        roots.push(RootEffectRow {
            rva: *rva,
            state: state.payload(),
            values,
        });
    }
    let encoded = serde_json::to_vec(&RootEffectReceipt { roots })
        .map_err(|error| invalid(format!("cannot encode result: {error}")))?;
    Ok(PyBytes::new(py, &encoded))
}

#[pyfunction]
pub(crate) fn join_reference_state_batches<'py>(
    py: Python<'py>,
    payload: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    let _text_scope = SharedTextInterningScope::new();
    let input: BatchInput = serde_json::from_slice(payload.as_bytes())
        .map_err(|error| invalid(format!("cannot decode JSON: {error}")))?;
    if input.alternative_limit == 0 || input.alternative_limit > STACK_ALTERNATIVE_LIMIT {
        return Err(invalid("alternative limit is outside the supported range"));
    }
    if input.cases.len() > MAX_BATCH_CASES {
        return Err(invalid("batch exceeds the case limit"));
    }
    let alternative_limit = input.alternative_limit;
    let baseline = rows_to_memory(input.baseline_memory, "baseline")?;
    let baseline_index = baseline_memory_index(&baseline, &[], alternative_limit)?;
    let cases = input.cases;
    let results = py.detach(move || {
        cases
            .into_iter()
            .map(|case| {
                join_state(
                    ReferenceState::parse(case.left, alternative_limit)?,
                    ReferenceState::parse(case.right, alternative_limit)?,
                    &baseline,
                    &baseline_index,
                    alternative_limit,
                )
                .map(ReferenceState::payload)
            })
            .collect::<PyResult<Vec<_>>>()
    })?;
    let encoded = serde_json::to_vec(&BatchOutput { results })
        .map_err(|error| invalid(format!("cannot encode result: {error}")))?;
    Ok(PyBytes::new(py, &encoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finite_value_join_collapses_object_offsets_at_the_bound() {
        let left = ReferenceValue::new(
            "finite",
            Vec::new(),
            vec![ReferenceAtom {
                kind: "object".to_owned(),
                identity: "object:a".into(),
                offset: 1,
            }],
        );
        let right = ReferenceValue::new(
            "finite",
            Vec::new(),
            vec![
                ReferenceAtom {
                    kind: "object".to_owned(),
                    identity: "object:a".into(),
                    offset: 2,
                },
                ReferenceAtom {
                    kind: "object".to_owned(),
                    identity: "object:a".into(),
                    offset: 3,
                },
            ],
        );
        let joined = join_value(&left, &right, 2).unwrap();
        assert_eq!(joined.references.len(), 1);
        assert_eq!(joined.references[0].kind, "object_view");
    }

}
