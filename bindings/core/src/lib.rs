//! # steward-bindings-core
//!
//! Shared FFI type definitions for Steward language bindings.
//!
//! This crate provides:
//! - **IR types**: FFI-friendly representations of core types
//! - **Conversions**: Core type → IR type transformations
//! - **Validation**: Test fixtures for binding conformance
//!
//! ## Design Principle
//!
//! **Bindings do not define semantics.**
//!
//! All evaluation logic lives in `steward-core`. This crate only provides
//! data transformations for FFI marshalling. Language bindings are thin
//! wrappers that:
//! 1. Accept FFI-compatible input (strings, primitives)
//! 2. Convert to core types
//! 3. Call `steward_core::evaluate()`
//! 4. Convert result to FFI-compatible output
//!
//! ```text
//! FFI Input → Core Types → steward_core::evaluate() → Core Result → IR Types → FFI Output
//! ```

pub mod conversion;
pub mod types;
pub mod validation;

// Re-export IR types
pub use types::{
    IRBoundaryViolation, IREvidence, IREvidenceSource, IREvaluationResult, IRLensFinding,
    IRLensFindings, IRLensState, IRLensType, IROutput, IRRuleEvaluation, IRRuleResult, IRState,
};

// Re-export conversions
pub use conversion::ToIR;

// Re-export validation fixtures
pub use validation::TEST_CONTRACT_YAML;
