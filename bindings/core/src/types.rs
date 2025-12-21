//! Intermediate Representation (IR) types for FFI bindings.
//!
//! These types are designed for maximum FFI compatibility:
//! - String-based enum discrimination
//! - No complex nested generics
//! - Serializable to JSON
//!
//! **These types carry no semantics.** They are pure data representations
//! for marshalling between Rust and foreign languages.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// IR representation of LensType.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IRLensType {
    AccountabilityOwnership,
    BoundariesSafety,
    DignityInclusion,
    RestraintPrivacy,
    TransparencyContestability,
}

impl IRLensType {
    /// String representation for FFI.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AccountabilityOwnership => "accountability_ownership",
            Self::BoundariesSafety => "boundaries_safety",
            Self::DignityInclusion => "dignity_inclusion",
            Self::RestraintPrivacy => "restraint_privacy",
            Self::TransparencyContestability => "transparency_contestability",
        }
    }
}

/// IR representation of RuleResult.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IRRuleResult {
    Satisfied,
    Violated,
    Uncertain,
    NotApplicable,
}

/// IR representation of EvidenceSource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IREvidenceSource {
    Contract,
    Output,
    Context,
    Metadata,
}

/// IR representation of Evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IREvidence {
    pub source: IREvidenceSource,
    pub claim: String,
    pub pointer: String,
}

/// IR representation of RuleEvaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IRRuleEvaluation {
    pub rule_id: String,
    pub rule_text: Option<String>,
    pub result: IRRuleResult,
    pub evidence: Vec<IREvidence>,
    pub rationale: Option<String>,
}

/// IR representation of LensState.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IRLensState {
    Pass,
    Escalate { reason: String },
    Blocked { violation: String },
}

impl IRLensState {
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }

    pub fn is_escalate(&self) -> bool {
        matches!(self, Self::Escalate { .. })
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }
}

/// IR representation of LensFinding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IRLensFinding {
    pub lens: Option<IRLensType>,
    pub question_asked: Option<String>,
    pub state: IRLensState,
    pub rules_evaluated: Vec<IRRuleEvaluation>,
    pub confidence: f64,
}

/// IR representation of LensFindings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IRLensFindings {
    pub dignity_inclusion: IRLensFinding,
    pub boundaries_safety: IRLensFinding,
    pub restraint_privacy: IRLensFinding,
    pub transparency_contestability: IRLensFinding,
    pub accountability_ownership: IRLensFinding,
}

/// IR representation of BoundaryViolation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IRBoundaryViolation {
    pub lens: IRLensType,
    pub rule_id: String,
    pub rule_text: String,
    pub evidence: Vec<IREvidence>,
    pub accountable_human: String,
}

/// IR representation of State.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IRState {
    Proceed {
        summary: String,
    },
    Escalate {
        uncertainty: String,
        decision_point: String,
        options: Vec<String>,
    },
    Blocked {
        violation: IRBoundaryViolation,
    },
}

impl IRState {
    pub fn is_proceed(&self) -> bool {
        matches!(self, Self::Proceed { .. })
    }

    pub fn is_escalate(&self) -> bool {
        matches!(self, Self::Escalate { .. })
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }

    /// State type as string for FFI.
    pub fn state_type(&self) -> &'static str {
        match self {
            Self::Proceed { .. } => "proceed",
            Self::Escalate { .. } => "escalate",
            Self::Blocked { .. } => "blocked",
        }
    }
}

/// IR representation of EvaluationResult.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IREvaluationResult {
    pub state: IRState,
    pub lens_findings: IRLensFindings,
    pub confidence: f64,
    /// ISO 8601 timestamp string.
    pub evaluated_at: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

/// IR representation of Output (read-only view).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IROutput {
    pub content: String,
    pub content_type: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ir_state_serialization() {
        let state = IRState::Proceed {
            summary: "All checks passed".to_string(),
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("\"type\":\"proceed\""));
    }

    #[test]
    fn test_ir_lens_state_helpers() {
        assert!(IRLensState::Pass.is_pass());
        assert!(IRLensState::Escalate {
            reason: "test".to_string()
        }
        .is_escalate());
        assert!(IRLensState::Blocked {
            violation: "test".to_string()
        }
        .is_blocked());
    }
}
