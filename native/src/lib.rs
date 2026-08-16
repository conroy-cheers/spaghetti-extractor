use pyo3::exceptions::{PyOverflowError, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool, PyBytes, PyDict, PyInt, PyList, PyString, PyTuple};
use sha2::{Digest, Sha256};

mod artifact_json;
mod library_index;

fn write_hex_quad(output: &mut Vec<u8>, value: u16) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    output.extend_from_slice(b"\\u");
    output.push(HEX[((value >> 12) & 0xf) as usize]);
    output.push(HEX[((value >> 8) & 0xf) as usize]);
    output.push(HEX[((value >> 4) & 0xf) as usize]);
    output.push(HEX[(value & 0xf) as usize]);
}

pub(crate) fn write_string(output: &mut Vec<u8>, value: &str) {
    output.push(b'"');
    for character in value.chars() {
        match character {
            '"' => output.extend_from_slice(b"\\\""),
            '\\' => output.extend_from_slice(b"\\\\"),
            '\u{0008}' => output.extend_from_slice(b"\\b"),
            '\u{000c}' => output.extend_from_slice(b"\\f"),
            '\n' => output.extend_from_slice(b"\\n"),
            '\r' => output.extend_from_slice(b"\\r"),
            '\t' => output.extend_from_slice(b"\\t"),
            character if (character as u32) < 0x20 => {
                write_hex_quad(output, character as u16);
            }
            character if (character as u32) <= 0x7f => output.push(character as u8),
            character if (character as u32) <= 0xffff => {
                write_hex_quad(output, character as u16);
            }
            character => {
                let scalar = character as u32 - 0x10000;
                write_hex_quad(output, 0xd800 | ((scalar >> 10) as u16));
                write_hex_quad(output, 0xdc00 | ((scalar & 0x3ff) as u16));
            }
        }
    }
    output.push(b'"');
}

fn write_sequence(output: &mut Vec<u8>, value: &Bound<'_, PyAny>) -> PyResult<()> {
    output.push(b'[');
    let mut first = true;
    for item in value.try_iter()? {
        if first {
            first = false;
        } else {
            output.push(b',');
        }
        write_value(output, &item?)?;
    }
    output.push(b']');
    Ok(())
}

fn write_dict(output: &mut Vec<u8>, value: &Bound<'_, PyDict>) -> PyResult<()> {
    let mut entries = Vec::with_capacity(value.len());
    for (key, item) in value.iter() {
        let key = key
            .cast::<PyString>()
            .map_err(|_| PyTypeError::new_err("canonical JSON objects require string keys"))?;
        entries.push((key.to_str()?.to_owned(), item));
    }
    entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    output.push(b'{');
    for (index, (key, item)) in entries.into_iter().enumerate() {
        if index != 0 {
            output.push(b',');
        }
        write_string(output, &key);
        output.push(b':');
        write_value(output, &item)?;
    }
    output.push(b'}');
    Ok(())
}

fn write_value(output: &mut Vec<u8>, value: &Bound<'_, PyAny>) -> PyResult<()> {
    if value.is_none() {
        output.extend_from_slice(b"null");
        return Ok(());
    }
    if value.is_instance_of::<PyBool>() {
        output.extend_from_slice(if value.is_truthy()? {
            b"true"
        } else {
            b"false"
        });
        return Ok(());
    }
    if let Ok(value) = value.cast::<PyString>() {
        write_string(output, value.to_str()?);
        return Ok(());
    }
    if value.is_instance_of::<PyInt>() {
        let text = value.str()?.to_str()?.to_owned();
        if let Some(digits) = text.strip_prefix('-') {
            if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(PyTypeError::new_err("invalid canonical integer"));
            }
        } else if !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(PyTypeError::new_err("invalid canonical integer"));
        }
        output.extend_from_slice(text.as_bytes());
        return Ok(());
    }
    if let Ok(value) = value.cast::<PyDict>() {
        return write_dict(output, value);
    }
    if value.is_instance_of::<PyList>() || value.is_instance_of::<PyTuple>() {
        return write_sequence(output, value);
    }
    Err(PyTypeError::new_err(format!(
        "unsupported canonical JSON type {}",
        value.get_type().name()?
    )))
}

fn canonical_bytes(value: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let mut output = Vec::with_capacity(256);
    write_value(&mut output, value)?;
    Ok(output)
}

#[pyfunction]
fn canonical_json_bytes<'py>(
    py: Python<'py>,
    value: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new(py, &canonical_bytes(value)?))
}

#[pyfunction]
fn canonical_sha256(value: &Bound<'_, PyAny>) -> PyResult<String> {
    let digest = Sha256::digest(canonical_bytes(value)?);
    let mut result = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        write!(&mut result, "{byte:02x}")
            .map_err(|_| PyOverflowError::new_err("cannot format canonical SHA-256"))?;
    }
    Ok(result)
}

#[pymodule]
fn spaghetti_extractor_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(canonical_json_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(canonical_sha256, module)?)?;
    module.add_function(wrap_pyfunction!(
        artifact_json::parse_canonical_json_lines,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        library_index::retrieve_library_candidates,
        module
    )?)?;
    module.add("NATIVE_API_VERSION", 1_u32)?;
    module.add("LIBRARY_INDEX_API_VERSION", 1_u32)?;
    Ok(())
}
