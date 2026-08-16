use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyInt, PyList, PyString};
use serde_json::Value;

use crate::write_string;

fn write_value(output: &mut Vec<u8>, value: &Value) -> Result<(), &'static str> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => {
            let text = value.to_string();
            let digits = text.strip_prefix('-').unwrap_or(&text);
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("floating-point and non-finite numbers are forbidden");
            }
            output.extend_from_slice(text.as_bytes());
        }
        Value::String(value) => write_string(output, value),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_value(output, value)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_string(output, key);
                output.push(b':');
                write_value(output, value)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn value_to_python<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    Ok(match value {
        Value::Null => py.None().into_bound(py),
        Value::Bool(value) => PyBool::new(py, *value).to_owned().into_any(),
        Value::Number(value) => {
            let text = value.to_string();
            if let Some(value) = value.as_i64() {
                PyInt::new(py, value).into_any()
            } else if let Some(value) = value.as_u64() {
                PyInt::new(py, value).into_any()
            } else {
                py.import("builtins")?.getattr("int")?.call1((text,))?
            }
        }
        Value::String(value) => PyString::new(py, value).into_any(),
        Value::Array(values) => {
            let result = PyList::empty(py);
            for value in values {
                result.append(value_to_python(py, value)?)?;
            }
            result.into_any()
        }
        Value::Object(values) => {
            let result = PyDict::new(py);
            for (key, value) in values {
                result.set_item(key, value_to_python(py, value)?)?;
            }
            result.into_any()
        }
    })
}

#[pyfunction]
pub(crate) fn parse_canonical_json_lines<'py>(
    py: Python<'py>,
    data: &[u8],
    maximum_line_bytes: usize,
) -> PyResult<Bound<'py, PyList>> {
    if data.is_empty() || !data.ends_with(b"\n") {
        return Err(PyValueError::new_err(
            "noncanonical_json: canonical NDJSON must end in one LF",
        ));
    }
    let result = PyList::empty(py);
    for (index, raw) in data.split_inclusive(|byte| *byte == b'\n').enumerate() {
        let line_number = index + 1;
        if raw.len() > maximum_line_bytes + 1 {
            return Err(PyValueError::new_err(format!(
                "oversized_pack_entry: line {line_number} exceeds the configured bound"
            )));
        }
        let line = &raw[..raw.len() - 1];
        if line.is_empty() || line.ends_with(b"\r") {
            return Err(PyValueError::new_err(format!(
                "noncanonical_json: line {line_number} is empty or uses CRLF"
            )));
        }
        let value: Value = serde_json::from_slice(line).map_err(|error| {
            PyValueError::new_err(format!("invalid_json: line {line_number}: {error}"))
        })?;
        let mut canonical = Vec::with_capacity(line.len());
        write_value(&mut canonical, &value).map_err(|error| {
            PyValueError::new_err(format!("noncanonical_json: line {line_number}: {error}"))
        })?;
        if canonical != line {
            return Err(PyValueError::new_err(format!(
                "noncanonical_json: line {line_number} is not canonical"
            )));
        }
        result.append(value_to_python(py, &value)?)?;
    }
    Ok(result)
}
