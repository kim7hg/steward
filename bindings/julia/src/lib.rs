//! Julia bindings for Steward.
//!
//! This module provides Julia language bindings for the Steward governance
//! calculus. Bindings are thin FFI wrappers - all semantics come from
//! `steward-core`.
//!
//! ## Architecture
//!
//! ```text
//! Julia ccall → C ABI functions → steward-core::evaluate() → IR types → JSON
//! ```
//!
//! ## Usage (Julia side)
//!
//! ```julia
//! using Steward
//!
//! contract = Steward.contract_from_yaml(yaml_string)
//! result = Steward.evaluate(contract, "Your order shipped.")
//!
//! if Steward.is_blocked(result)
//!     println("BLOCKED: ", result.violation.rule_id)
//! end
//! ```

use steward_bindings_core::{IREvaluationResult, ToIR};
use steward_core::{Contract, Output};

/// Evaluate output against contract, returning JSON result.
///
/// # Safety
///
/// This function is intended for FFI use. The returned string must be
/// freed by the caller using `steward_free_string`.
#[no_mangle]
pub extern "C" fn steward_evaluate_json(
    contract_yaml: *const std::ffi::c_char,
    output_text: *const std::ffi::c_char,
) -> *mut std::ffi::c_char {
    use std::ffi::{CStr, CString};

    let result = std::panic::catch_unwind(|| {
        // SAFETY: Caller must provide valid C strings
        let contract_yaml = unsafe { CStr::from_ptr(contract_yaml) }
            .to_str()
            .map_err(|e| format!("Invalid contract UTF-8: {}", e))?;

        let output_text = unsafe { CStr::from_ptr(output_text) }
            .to_str()
            .map_err(|e| format!("Invalid output UTF-8: {}", e))?;

        // Parse contract (calls into steward-core)
        let contract = Contract::from_yaml(contract_yaml)
            .map_err(|e| format!("Contract parse error: {}", e))?;

        // Create output
        let output = Output::text(output_text);

        // Evaluate (calls into steward-core - THIS IS WHERE SEMANTICS LIVE)
        let eval_result = steward_core::evaluate(&contract, &output)
            .map_err(|e| format!("Evaluation error: {}", e))?;

        // Convert to IR for FFI
        let ir: IREvaluationResult = eval_result.to_ir();

        // Serialize to JSON
        serde_json::to_string(&ir).map_err(|e| format!("JSON error: {}", e))
    });

    match result {
        Ok(Ok(json)) => CString::new(json)
            .map(|s| s.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Ok(Err(e)) => {
            let error_json = serde_json::json!({ "error": e });
            CString::new(error_json.to_string())
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut())
        }
        Err(_) => {
            let panic_json = serde_json::json!({ "error": "Panic during evaluation" });
            CString::new(panic_json.to_string())
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut())
        }
    }
}

/// Free a string returned by steward functions.
///
/// # Safety
///
/// Only call this on strings returned by other steward_* functions.
#[no_mangle]
pub unsafe extern "C" fn steward_free_string(s: *mut std::ffi::c_char) {
    if !s.is_null() {
        drop(std::ffi::CString::from_raw(s));
    }
}

/// Get the version of the Steward library.
#[no_mangle]
pub extern "C" fn steward_version() -> *const std::ffi::c_char {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr() as *const std::ffi::c_char
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_evaluate_json_proceed() {
        let contract = CString::new(steward_bindings_core::TEST_CONTRACT_YAML).unwrap();
        let output = CString::new("Your order shipped yesterday.").unwrap();

        let result_ptr = steward_evaluate_json(contract.as_ptr(), output.as_ptr());
        assert!(!result_ptr.is_null());

        let result = unsafe { std::ffi::CStr::from_ptr(result_ptr) }
            .to_str()
            .unwrap();

        // Should contain "proceed" state
        assert!(result.contains("proceed") || result.contains("Proceed"));

        unsafe { steward_free_string(result_ptr) };
    }

    #[test]
    fn test_evaluate_json_blocked() {
        let contract = CString::new(steward_bindings_core::TEST_CONTRACT_YAML).unwrap();
        let output = CString::new("Contact john@example.com for help.").unwrap();

        let result_ptr = steward_evaluate_json(contract.as_ptr(), output.as_ptr());
        assert!(!result_ptr.is_null());

        let result = unsafe { std::ffi::CStr::from_ptr(result_ptr) }
            .to_str()
            .unwrap();

        // Should contain "blocked" state
        assert!(result.contains("blocked") || result.contains("Blocked"));

        unsafe { steward_free_string(result_ptr) };
    }
}
