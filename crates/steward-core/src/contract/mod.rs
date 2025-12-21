//! Contract parsing and validation.
//!
//! Stewardship contracts are structured data validated against JSON Schema.
//! This module handles parsing YAML/JSON contracts and validating them.

mod keywords;
mod parser;
mod schema;

pub use keywords::{content_matches_any_rule, content_matches_rule_keywords, extract_keywords};
pub use parser::{Contract, ContractError, Rule};
