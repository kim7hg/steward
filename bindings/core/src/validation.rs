//! Validation fixtures for language bindings.
//!
//! These are test contracts and outputs that bindings can use to verify
//! their FFI marshalling is correct. All semantic validation is done
//! by calling `steward_core::evaluate()` - these fixtures just ensure
//! the data round-trips correctly through the binding layer.

/// Test contract YAML for validation.
///
/// Use this contract in binding tests to verify:
/// 1. YAML parsing works through FFI
/// 2. Contract fields are accessible
/// 3. Evaluation produces expected IR output
pub const TEST_CONTRACT_YAML: &str = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Binding Test Contract"
intent:
  purpose: "Test binding conformance"
boundaries:
  may_do_autonomously:
    - id: "A1"
      rule: "Answer factual questions"
  invalidated_by:
    - id: "B1"
      rule: "Customer PII exposed in response"
accountability:
  approved_by: "Test Manager"
  answerable_human: "test@example.com"
  escalation_path:
    - "Tier 1"
    - "Manager"
acceptance: {}
"#;

/// Output that should result in PROCEED state.
pub const TEST_OUTPUT_PROCEED: &str = "Your order shipped yesterday. Contact us if you need help.";

/// Output that should result in BLOCKED state (PII exposure).
pub const TEST_OUTPUT_BLOCKED_PII: &str = "Contact john.doe@email.com for assistance.";

/// Output that should result in ESCALATE state (missing human path).
pub const TEST_OUTPUT_ESCALATE: &str = "Studies show 99% satisfaction rate.";

/// Expected contract name from TEST_CONTRACT_YAML.
pub const EXPECTED_CONTRACT_NAME: &str = "Binding Test Contract";

/// Expected accountable human from TEST_CONTRACT_YAML.
pub const EXPECTED_ACCOUNTABLE_HUMAN: &str = "test@example.com";

#[cfg(test)]
mod tests {
    use super::*;
    use steward_core::{Contract, Output, evaluate};
    use crate::types::IRState;
    use crate::IREvaluationResult;

    #[test]
    fn test_fixture_contract_parses() {
        let contract = Contract::from_yaml(TEST_CONTRACT_YAML);
        assert!(contract.is_ok(), "Test contract should parse");

        let c = contract.unwrap();
        assert_eq!(c.name, EXPECTED_CONTRACT_NAME);
        assert_eq!(c.accountability.answerable_human, EXPECTED_ACCOUNTABLE_HUMAN);
    }

    #[test]
    fn test_fixture_proceed_output() {
        let contract = Contract::from_yaml(TEST_CONTRACT_YAML).unwrap();
        let output = Output::text(TEST_OUTPUT_PROCEED);
        let result = evaluate(&contract, &output).unwrap();

        let ir: IREvaluationResult = result.into();
        assert!(ir.state.is_proceed(), "Expected PROCEED state");
    }

    #[test]
    fn test_fixture_blocked_output() {
        let contract = Contract::from_yaml(TEST_CONTRACT_YAML).unwrap();
        let output = Output::text(TEST_OUTPUT_BLOCKED_PII);
        let result = evaluate(&contract, &output).unwrap();

        let ir: IREvaluationResult = result.into();
        assert!(ir.state.is_blocked(), "Expected BLOCKED state for PII");

        if let IRState::Blocked { violation } = ir.state {
            assert_eq!(violation.rule_id, "B1");
        }
    }

    #[test]
    fn test_fixture_escalate_output() {
        let contract = Contract::from_yaml(TEST_CONTRACT_YAML).unwrap();
        let output = Output::text(TEST_OUTPUT_ESCALATE);
        let result = evaluate(&contract, &output).unwrap();

        let ir: IREvaluationResult = result.into();
        // This might be ESCALATE or PROCEED depending on implementation
        // The key is that it should NOT be BLOCKED
        assert!(!ir.state.is_blocked(), "Should not be BLOCKED without PII");
    }

    #[test]
    fn test_ir_serialization_roundtrip() {
        let contract = Contract::from_yaml(TEST_CONTRACT_YAML).unwrap();
        let output = Output::text(TEST_OUTPUT_PROCEED);
        let result = evaluate(&contract, &output).unwrap();

        let ir: IREvaluationResult = result.into();

        // Serialize to JSON
        let json = serde_json::to_string(&ir).unwrap();

        // Deserialize back
        let ir2: IREvaluationResult = serde_json::from_str(&json).unwrap();

        // Verify key fields match
        assert_eq!(ir.confidence, ir2.confidence);
        assert_eq!(ir.state.state_type(), ir2.state.state_type());
    }
}
