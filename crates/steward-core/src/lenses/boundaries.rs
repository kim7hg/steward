//! Boundaries & Safety Lens
//!
//! **Question**: Does this respect defined scope and stop conditions?
//!
//! This is the primary lens for Phase 1, implementing full pattern matching
//! for boundary violations including PII detection.

use lazy_static::lazy_static;

use crate::contract::content_matches_any_rule;
use crate::evidence::Evidence;
use crate::types::{
    EvaluationRequest, LensFinding, LensState, LensType, RuleEvaluation, RuleResult, RuleType,
};

use super::patterns::{
    API_KEY_PATTERN, CREDIT_CARD_PATTERN, EMAIL_PATTERN, PHONE_PATTERN, SSN_PATTERN,
};
use super::Lens;

lazy_static! {
    // Keywords for escalation conditions
    static ref FRUSTRATION_KEYWORDS: Vec<&'static str> = vec![
        "frustrated", "angry", "furious", "annoyed", "upset",
        "terrible", "awful", "horrible", "worst", "unacceptable",
        "ridiculous", "outrageous", "disgusted", "fed up"
    ];

    static ref LEGAL_KEYWORDS: Vec<&'static str> = vec![
        "lawyer", "attorney", "legal", "lawsuit", "sue",
        "court", "litigation", "regulatory", "complaint", "law"
    ];

    static ref MEDICAL_KEYWORDS: Vec<&'static str> = vec![
        "symptom", "doctor", "hospital", "medicine", "medical",
        "diagnosis", "treatment", "prescription", "health", "sick",
        "ibuprofen", "aspirin", "tylenol", "painkiller", "medication",
        "headache", "migraine", "pain", "dosage", "therapy"
    ];

    static ref FINANCIAL_ADVICE_KEYWORDS: Vec<&'static str> = vec![
        "invest", "investment", "stock", "portfolio", "trading",
        "financial advice", "should i buy", "financial plan"
    ];

    // Scope detection for may_do_autonomously (out-of-scope patterns)
    static ref INVESTMENT_ADVICE_PATTERNS: Vec<&'static str> = vec![
        "invest", "investment", "buy stock", "sell stock", "portfolio",
        "financial advice", "trading", "bitcoin", "crypto", "returns"
    ];
}

/// The Boundaries & Safety lens.
pub struct BoundariesLens;

impl BoundariesLens {
    pub fn new() -> Self {
        Self
    }

    /// Check if output contains PII.
    fn check_pii(&self, content: &str) -> Vec<(String, usize, usize)> {
        let mut findings = Vec::new();

        // Check for emails
        for m in EMAIL_PATTERN.find_iter(content) {
            findings.push(("Email address".to_string(), m.start(), m.end()));
        }

        // Check for phone numbers
        for m in PHONE_PATTERN.find_iter(content) {
            findings.push(("Phone number".to_string(), m.start(), m.end()));
        }

        // Check for SSNs
        for m in SSN_PATTERN.find_iter(content) {
            findings.push(("Social Security Number".to_string(), m.start(), m.end()));
        }

        // Check for credit cards
        for m in CREDIT_CARD_PATTERN.find_iter(content) {
            findings.push(("Credit card number".to_string(), m.start(), m.end()));
        }

        findings
    }

    /// Check if output contains API keys or secrets.
    fn check_secrets(&self, content: &str) -> Vec<(String, usize, usize)> {
        let mut findings = Vec::new();

        for m in API_KEY_PATTERN.find_iter(content) {
            findings.push(("API key or secret".to_string(), m.start(), m.end()));
        }

        findings
    }

    /// Check for keyword matches in content.
    fn check_keywords(&self, content: &str, keywords: &[&str]) -> bool {
        let lower = content.to_lowercase();
        keywords.iter().any(|kw| lower.contains(kw))
    }

    /// Check for specific phrase matches.
    fn check_phrase(&self, content: &str, phrase: &str) -> Option<(usize, usize)> {
        let lower_content = content.to_lowercase();
        let lower_phrase = phrase.to_lowercase();

        lower_content.find(&lower_phrase).map(|start| {
            (start, start + phrase.len())
        })
    }

    /// Detect if content contains actual medical advice (not just medical terms).
    /// Returns true only if both medical keywords AND advice-giving patterns are present.
    fn contains_medical_advice(&self, content: &str) -> bool {
        let lower = content.to_lowercase();

        // Must have medical keywords
        if !self.check_keywords(&lower, &MEDICAL_KEYWORDS) {
            return false;
        }

        // AND must have advice-giving patterns
        let advice_patterns = [
            "you should", "i recommend", "i suggest", "take ",
            "try ", "use ", "apply ", "don't ", "avoid ",
            "dosage", "mg", "twice a day", "daily", "per day",
        ];

        advice_patterns.iter().any(|p| lower.contains(p))
    }

    /// Detect if content contains actual legal advice (not just legal terms).
    fn contains_legal_advice(&self, content: &str) -> bool {
        let lower = content.to_lowercase();

        // Must have legal keywords
        if !self.check_keywords(&lower, &LEGAL_KEYWORDS) {
            return false;
        }

        // AND must have advice-giving patterns
        let advice_patterns = [
            "you should", "i advise", "i recommend", "legally",
            "your rights", "you can sue", "file a complaint",
            "you have the right", "you could pursue",
        ];

        advice_patterns.iter().any(|p| lower.contains(p))
    }

    /// Detect if content contains actual financial advice (not just financial terms).
    fn contains_financial_advice(&self, content: &str) -> bool {
        let lower = content.to_lowercase();

        // Must have financial keywords
        if !self.check_keywords(&lower, &FINANCIAL_ADVICE_KEYWORDS) {
            return false;
        }

        // AND must have advice-giving patterns
        let advice_patterns = [
            "you should", "i recommend", "invest in", "buy ",
            "sell ", "hold ", "returns", "profit", "growth",
            "i suggest", "consider investing",
        ];

        advice_patterns.iter().any(|p| lower.contains(p))
    }

    /// Check if output stays within allowed autonomous scope.
    /// Returns Some((rule_id, violation_description, evidence)) if output is OUT OF SCOPE.
    ///
    /// Per spec: "Output operates outside boundaries.may_do_autonomously[]" triggers BLOCKED.
    ///
    /// ## True Allowlist Implementation
    ///
    /// This function implements a **positive scope check**:
    /// 1. If `may_do_autonomously` is empty AND not strict → permissive (backward compat)
    /// 2. If `may_do_autonomously` is empty AND strict → BLOCKED (nothing allowed)
    /// 3. If `may_do_autonomously` has rules AND output matches at least one → PASS
    /// 4. If `may_do_autonomously` has rules AND output matches NONE:
    ///    - Default mode: only block known dangerous content
    ///    - Strict mode: BLOCKED (true allowlist)
    ///
    /// The risky content checks (financial/medical/legal advice) remain as a safety net
    /// for cases where the allowlist check passes but dangerous content is detected.
    fn check_autonomous_scope(
        &self,
        content: &str,
        allowed_rules: &[crate::contract::Rule],
        strict_scope_mode: bool,
    ) -> Option<(String, String, Vec<Evidence>)> {
        // Handle empty may_do_autonomously
        if allowed_rules.is_empty() {
            if strict_scope_mode {
                // Strict mode with no allowed rules = BLOCK everything
                let evidence = vec![Evidence::from_output(
                    "No may_do_autonomously rules defined in strict_scope_mode",
                    0,
                    content.len().min(100),
                )];
                return Some((
                    "SCOPE_VIOLATION".to_string(),
                    "Output blocked: strict_scope_mode enabled but no may_do_autonomously rules defined".to_string(),
                    evidence,
                ));
            }
            // Default: permissive when no rules defined
            return None;
        }

        // TRUE ALLOWLIST CHECK
        // Use keyword extraction to determine if output semantically aligns with allowed scope
        let matches_allowed_scope = content_matches_any_rule(content, allowed_rules);

        let content_lower = content.to_lowercase();

        // Check for dangerous content types that should always be blocked unless explicitly allowed

        // Financial/investment advice check
        let allows_financial = allowed_rules.iter().any(|r| {
            let text = r.rule.to_lowercase();
            text.contains("financial") || text.contains("invest")
        });

        if !allows_financial && self.check_keywords(&content_lower, &INVESTMENT_ADVICE_PATTERNS) {
            if self.appears_to_give_advice(content) {
                let evidence = vec![Evidence::from_output(
                    "Output contains financial/investment advice outside allowed scope",
                    0,
                    content.len().min(100),
                )];
                return Some((
                    "SCOPE_VIOLATION".to_string(),
                    "Output operates outside boundaries.may_do_autonomously[] - contains financial advice".to_string(),
                    evidence,
                ));
            }
        }

        // Medical advice check
        let allows_medical = allowed_rules.iter().any(|r| {
            let text = r.rule.to_lowercase();
            text.contains("medical") || text.contains("health")
        });

        if !allows_medical && self.contains_medical_advice(content) {
            let evidence = vec![Evidence::from_output(
                "Output contains medical advice outside allowed scope",
                0,
                content.len().min(100),
            )];
            return Some((
                "SCOPE_VIOLATION".to_string(),
                "Output operates outside boundaries.may_do_autonomously[] - contains medical advice".to_string(),
                evidence,
            ));
        }

        // Legal advice check
        let allows_legal = allowed_rules.iter().any(|r| {
            let text = r.rule.to_lowercase();
            text.contains("legal")
        });

        if !allows_legal && self.contains_legal_advice(content) {
            let evidence = vec![Evidence::from_output(
                "Output contains legal advice outside allowed scope",
                0,
                content.len().min(100),
            )];
            return Some((
                "SCOPE_VIOLATION".to_string(),
                "Output operates outside boundaries.may_do_autonomously[] - contains legal advice".to_string(),
                evidence,
            ));
        }

        // STRICT SCOPE MODE
        // If strict mode is enabled and output doesn't match any allowed rule, BLOCK
        if strict_scope_mode && !matches_allowed_scope {
            let evidence = vec![Evidence::from_output(
                "Output does not match any may_do_autonomously rule (strict_scope_mode)",
                0,
                content.len().min(100),
            )];
            return Some((
                "SCOPE_VIOLATION".to_string(),
                "Output operates outside boundaries.may_do_autonomously[] - no matching allowed scope rule (strict_scope_mode)".to_string(),
                evidence,
            ));
        }

        None
    }

    /// Heuristic: does the content appear to give advice vs just mention a topic?
    fn appears_to_give_advice(&self, content: &str) -> bool {
        let advice_patterns = [
            "you should", "i recommend", "i suggest", "i advise",
            "take this", "try this", "do this", "don't do",
            "consider ", "my advice", "best option",
        ];
        let lower = content.to_lowercase();
        advice_patterns.iter().any(|p| lower.contains(p))
    }
}

impl Default for BoundariesLens {
    fn default() -> Self {
        Self::new()
    }
}

impl Lens for BoundariesLens {
    fn lens_type(&self) -> LensType {
        LensType::BoundariesSafety
    }

    fn evaluate(&self, request: &EvaluationRequest) -> LensFinding {
        let contract = &request.contract;
        let content = &request.output.content;
        let context = request.context.as_deref().unwrap_or(&[]);

        let mut rules_evaluated = Vec::new();
        let mut blocked_violation: Option<(String, String, Vec<Evidence>)> = None;
        let mut escalate_reason: Option<String> = None;

        // 0. Check may_do_autonomously FIRST (scope check)
        // Per spec: "Output operates outside boundaries.may_do_autonomously[]" triggers BLOCKED
        if let Some((rule_id, violation, evidence)) =
            self.check_autonomous_scope(
                content,
                &contract.boundaries.may_do_autonomously,
                contract.boundaries.strict_scope_mode,
            )
        {
            rules_evaluated.push(RuleEvaluation {
                rule_id: rule_id.clone(),
                rule_text: Some(violation.clone()),
                result: RuleResult::Violated,
                evidence: evidence.clone(),
                rationale: Some("Output operates outside defined autonomous scope".to_string()),
            });

            return LensFinding {
                lens: Some(LensType::BoundariesSafety),
                question_asked: Some(self.question().to_string()),
                state: LensState::Blocked {
                    violation: format!("{}: {}", rule_id, violation),
                },
                rules_evaluated,
                confidence: 0.95,
            };
        }

        // 1. Check invalidated_by rules (most severe - triggers BLOCKED)
        for rule in &contract.boundaries.invalidated_by {
            let rule_lower = rule.rule.to_lowercase();

            // PII exposure check
            if rule_lower.contains("pii") || rule_lower.contains("personal") {
                let pii_found = self.check_pii(content);
                if !pii_found.is_empty() {
                    let (pii_type, start, end) = &pii_found[0];
                    let evidence = vec![Evidence::from_output(
                        format!("{} exposed in response", pii_type),
                        *start,
                        *end,
                    )];

                    rules_evaluated.push(RuleEvaluation {
                        rule_id: rule.id.clone(),
                        rule_text: Some(rule.rule.clone()),
                        result: RuleResult::Violated,
                        evidence: evidence.clone(),
                        rationale: Some(format!("{} found at position {}:{}", pii_type, start, end)),
                    });

                    blocked_violation = Some((rule.id.clone(), rule.rule.clone(), evidence));
                    break;
                }
            }

            // Credential/secret exposure check
            if rule_lower.contains("credential") || rule_lower.contains("secret") {
                let secrets_found = self.check_secrets(content);
                if !secrets_found.is_empty() {
                    let (secret_type, start, end) = &secrets_found[0];
                    let evidence = vec![Evidence::from_output(
                        format!("{} exposed", secret_type),
                        *start,
                        *end,
                    )];

                    rules_evaluated.push(RuleEvaluation {
                        rule_id: rule.id.clone(),
                        rule_text: Some(rule.rule.clone()),
                        result: RuleResult::Violated,
                        evidence: evidence.clone(),
                        rationale: Some(format!("{} found at position {}:{}", secret_type, start, end)),
                    });

                    blocked_violation = Some((rule.id.clone(), rule.rule.clone(), evidence));
                    break;
                }
            }

            // Medical advice check - invalidated_by means BLOCKED when detected
            if rule_lower.contains("medical")
                && rule_lower.contains("advice")
                && self.contains_medical_advice(content)
            {
                let evidence = vec![Evidence::from_output(
                    "Medical advice detected in response",
                    0,
                    content.len().min(100),
                )];

                rules_evaluated.push(RuleEvaluation {
                    rule_id: rule.id.clone(),
                    rule_text: Some(rule.rule.clone()),
                    result: RuleResult::Violated,
                    evidence: evidence.clone(),
                    rationale: Some("Output contains medical advice which invalidates automation".to_string()),
                });

                blocked_violation = Some((rule.id.clone(), rule.rule.clone(), evidence));
                break;
            }

            // Legal advice check - invalidated_by means BLOCKED when detected
            if rule_lower.contains("legal")
                && rule_lower.contains("advice")
                && self.contains_legal_advice(content)
            {
                let evidence = vec![Evidence::from_output(
                    "Legal advice detected in response",
                    0,
                    content.len().min(100),
                )];

                rules_evaluated.push(RuleEvaluation {
                    rule_id: rule.id.clone(),
                    rule_text: Some(rule.rule.clone()),
                    result: RuleResult::Violated,
                    evidence: evidence.clone(),
                    rationale: Some("Output contains legal advice which invalidates automation".to_string()),
                });

                blocked_violation = Some((rule.id.clone(), rule.rule.clone(), evidence));
                break;
            }

            // Financial advice check - invalidated_by means BLOCKED when detected
            if rule_lower.contains("financial")
                && rule_lower.contains("advice")
                && self.contains_financial_advice(content)
            {
                let evidence = vec![Evidence::from_output(
                    "Financial advice detected in response",
                    0,
                    content.len().min(100),
                )];

                rules_evaluated.push(RuleEvaluation {
                    rule_id: rule.id.clone(),
                    rule_text: Some(rule.rule.clone()),
                    result: RuleResult::Violated,
                    evidence: evidence.clone(),
                    rationale: Some("Output contains financial advice which invalidates automation".to_string()),
                });

                blocked_violation = Some((rule.id.clone(), rule.rule.clone(), evidence));
                break;
            }

            // If not matched by any deterministic pattern, classify the rule
            // and handle non-deterministic rules appropriately
            if blocked_violation.is_none() && escalate_reason.is_none() {
                let rule_type = RuleType::classify(&rule.rule);

                match rule_type {
                    RuleType::Deterministic => {
                        // We checked all deterministic patterns above and none matched
                        // This means the rule is satisfied (no violation detected)
                        rules_evaluated.push(RuleEvaluation {
                            rule_id: rule.id.clone(),
                            rule_text: Some(rule.rule.clone()),
                            result: RuleResult::Satisfied,
                            evidence: vec![],
                            rationale: Some("No violation detected by pattern matching".to_string()),
                        });
                    }
                    RuleType::Interpretive | RuleType::Unknown => {
                        // Cannot evaluate deterministically - mark as Uncertain
                        // This triggers ESCALATE via the honesty rule
                        rules_evaluated.push(RuleEvaluation {
                            rule_id: rule.id.clone(),
                            rule_text: Some(rule.rule.clone()),
                            result: RuleResult::Uncertain,
                            evidence: vec![],
                            rationale: Some(format!(
                                "Rule requires human judgment (type: {:?})",
                                rule_type
                            )),
                        });

                        if escalate_reason.is_none() {
                            escalate_reason = Some(format!(
                                "Rule {} requires human judgment: {}",
                                rule.id, rule.rule
                            ));
                        }
                    }
                }
            }
        }

        // If already blocked, return immediately
        if let Some((rule_id, rule_text, _evidence)) = blocked_violation {
            return LensFinding {
                lens: Some(LensType::BoundariesSafety),
                question_asked: Some(self.question().to_string()),
                state: LensState::Blocked {
                    violation: format!("{}: {}", rule_id, rule_text),
                },
                rules_evaluated,
                confidence: 0.98, // High confidence for pattern-matched violations
            };
        }

        // 2. Check must_escalate_when rules
        for rule in &contract.boundaries.must_escalate_when {
            let rule_lower = rule.rule.to_lowercase();

            // Legal/compliance topic
            if rule_lower.contains("legal") || rule_lower.contains("compliance") {
                // Check both output and context
                let has_legal = self.check_keywords(content, &LEGAL_KEYWORDS)
                    || context.iter().any(|c| self.check_keywords(c, &LEGAL_KEYWORDS));

                if has_legal {
                    rules_evaluated.push(RuleEvaluation {
                        rule_id: rule.id.clone(),
                        rule_text: Some(rule.rule.clone()),
                        result: RuleResult::Uncertain,
                        evidence: vec![],
                        rationale: Some("Legal/compliance topic detected".to_string()),
                    });

                    if escalate_reason.is_none() {
                        escalate_reason = Some(format!(
                            "Legal/compliance topic detected (rule {})",
                            rule.id
                        ));
                    }
                }
            }

            // Customer requests human
            if rule_lower.contains("human") && rule_lower.contains("request") {
                let human_phrases = ["talk to a human", "speak to a person", "real person",
                                     "human agent", "customer service", "speak to someone"];

                for phrase in human_phrases {
                    // Check context for human request
                    for (idx, ctx) in context.iter().enumerate() {
                        if let Some((start, end)) = self.check_phrase(ctx, phrase) {
                            rules_evaluated.push(RuleEvaluation {
                                rule_id: rule.id.clone(),
                                rule_text: Some(rule.rule.clone()),
                                result: RuleResult::Uncertain,
                                evidence: vec![Evidence::from_context(
                                    "Customer requested human agent",
                                    idx,
                                    start,
                                    end,
                                )],
                                rationale: Some("Customer explicitly requested human".to_string()),
                            });

                            if escalate_reason.is_none() {
                                escalate_reason = Some(format!(
                                    "Customer explicitly requested human agent (rule {})",
                                    rule.id
                                ));
                            }
                            break;
                        }
                    }
                }
            }
        }

        // 3. Check must_pause_when rules
        // Track pause violations separately for strict_pause_mode handling
        let mut pause_violation: Option<(String, String, Vec<Evidence>)> = None;

        for rule in &contract.boundaries.must_pause_when {
            let rule_lower = rule.rule.to_lowercase();

            // Customer frustration
            if rule_lower.contains("frustrat") || rule_lower.contains("anger") {
                for (idx, ctx) in context.iter().enumerate() {
                    if self.check_keywords(ctx, &FRUSTRATION_KEYWORDS) {
                        let evidence = vec![Evidence::from_context(
                            "Customer frustration detected",
                            idx,
                            0,
                            ctx.len().min(50),
                        )];

                        rules_evaluated.push(RuleEvaluation {
                            rule_id: rule.id.clone(),
                            rule_text: Some(rule.rule.clone()),
                            result: RuleResult::Uncertain,
                            evidence: evidence.clone(),
                            rationale: Some("Frustration keywords detected in context".to_string()),
                        });

                        // In strict mode, pause triggers cause BLOCKED
                        if contract.boundaries.strict_pause_mode {
                            if pause_violation.is_none() {
                                pause_violation = Some((
                                    rule.id.clone(),
                                    rule.rule.clone(),
                                    evidence,
                                ));
                            }
                        } else if escalate_reason.is_none() {
                            // Default behavior: ESCALATE
                            escalate_reason = Some(format!(
                                "Customer frustration detected (rule {})",
                                rule.id
                            ));
                        }
                        break;
                    }
                }
            }
        }

        // In strict_pause_mode, pause triggers return BLOCKED
        if let Some((rule_id, rule_text, _evidence)) = pause_violation {
            return LensFinding {
                lens: Some(LensType::BoundariesSafety),
                question_asked: Some(self.question().to_string()),
                state: LensState::Blocked {
                    violation: format!("{}: {} (strict_pause_mode)", rule_id, rule_text),
                },
                rules_evaluated,
                confidence: 0.95,
            };
        }

        // Build final finding
        let state = if let Some(reason) = escalate_reason {
            LensState::Escalate { reason }
        } else {
            LensState::Pass
        };

        // Calculate confidence based on evidence quality
        let confidence = calculate_confidence(&rules_evaluated);

        LensFinding {
            lens: Some(LensType::BoundariesSafety),
            question_asked: Some(self.question().to_string()),
            state,
            rules_evaluated,
            confidence,
        }
    }
}

/// Calculate confidence based on rule evaluations.
fn calculate_confidence(rules: &[RuleEvaluation]) -> f64 {
    if rules.is_empty() {
        return 0.5; // Default when no rules apply
    }

    let mut confidence: f64 = 1.0;

    for rule in rules {
        match rule.result {
            RuleResult::Satisfied => {
                let penalty: f64 = match rule.evidence.len() {
                    0 => 0.05,
                    1 => 0.02,
                    _ => 0.01,
                };
                confidence -= penalty;
            }
            RuleResult::Uncertain => {
                confidence -= 0.15;
            }
            RuleResult::Violated | RuleResult::NotApplicable => {
                // No penalty for these - BLOCKED handled separately
            }
        }
    }

    confidence.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::Contract;
    use crate::types::Output;

    fn create_test_request(contract_yaml: &str, content: &str) -> EvaluationRequest {
        EvaluationRequest {
            contract: Contract::from_yaml(contract_yaml).unwrap(),
            output: Output::text(content),
            context: None,
            metadata: None,
        }
    }

    #[test]
    fn test_email_detection() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Test"
boundaries:
  invalidated_by:
    - id: "B1"
      rule: "Customer PII exposed in response"
accountability:
  answerable_human: "test@example.com"
"#;

        let request = create_test_request(
            contract,
            "Contact john.doe@email.com for more info.",
        );

        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        assert!(finding.state.is_blocked());
        assert!(finding.rules_evaluated.iter().any(|r| r.rule_id == "B1"));
    }

    #[test]
    fn test_phone_detection() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Test"
boundaries:
  invalidated_by:
    - id: "B1"
      rule: "Customer PII exposed"
accountability:
  answerable_human: "test@example.com"
"#;

        let request = create_test_request(
            contract,
            "Call us at (555) 123-4567.",
        );

        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        assert!(finding.state.is_blocked());
    }

    #[test]
    fn test_no_pii_passes() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Test"
boundaries:
  invalidated_by:
    - id: "B1"
      rule: "Customer PII exposed"
accountability:
  answerable_human: "test@example.com"
"#;

        let request = create_test_request(
            contract,
            "Your order will arrive tomorrow.",
        );

        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        assert!(finding.state.is_pass());
    }

    #[test]
    fn test_frustration_escalation() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Test"
boundaries:
  must_pause_when:
    - id: "P1"
      rule: "Customer expresses frustration"
accountability:
  answerable_human: "test@example.com"
"#;

        let mut request = create_test_request(
            contract,
            "I understand your concern.",
        );
        request.context = Some(vec!["I'm so frustrated with this service!".to_string()]);

        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        assert!(finding.state.is_escalate());
    }

    // Tests: invalidated_by must always return BLOCKED

    #[test]
    fn test_medical_advice_blocked_not_escalated() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Customer support"
boundaries:
  invalidated_by:
    - id: "B2"
      rule: "Medical advice given"
accountability:
  answerable_human: "test@example.com"
"#;
        let request = create_test_request(
            contract,
            "You should take 400mg of ibuprofen twice daily for your headache."
        );
        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        assert!(finding.state.is_blocked(), "Medical advice should BLOCK, not ESCALATE");

        // Verify correct rule is cited
        let violated = finding.rules_evaluated.iter()
            .find(|r| r.result == RuleResult::Violated);
        assert!(violated.is_some());
        assert_eq!(violated.unwrap().rule_id, "B2");
    }

    #[test]
    fn test_medical_mention_without_advice_passes() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Customer support"
boundaries:
  invalidated_by:
    - id: "B2"
      rule: "Medical advice given"
accountability:
  answerable_human: "test@example.com"
"#;
        let request = create_test_request(
            contract,
            "For medical questions, please consult your doctor."
        );
        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        // Mentioning medical topics without giving advice is fine
        assert!(!finding.state.is_blocked(), "Medical mention should not BLOCK");
    }

    #[test]
    fn test_legal_advice_blocked() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Customer support"
boundaries:
  invalidated_by:
    - id: "B2"
      rule: "Legal advice given"
accountability:
  answerable_human: "test@example.com"
"#;
        let request = create_test_request(
            contract,
            "I advise you to sue the company for breach of contract. You have the right to pursue damages."
        );
        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        assert!(finding.state.is_blocked(), "Legal advice should BLOCK");
    }

    #[test]
    fn test_financial_advice_blocked() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Customer support"
boundaries:
  invalidated_by:
    - id: "B3"
      rule: "Financial advice given"
accountability:
  answerable_human: "test@example.com"
"#;
        let request = create_test_request(
            contract,
            "I recommend you invest in Bitcoin. The returns have been excellent."
        );
        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        assert!(finding.state.is_blocked(), "Financial advice should BLOCK");

        let violated = finding.rules_evaluated.iter()
            .find(|r| r.result == RuleResult::Violated);
        assert!(violated.is_some());
        assert_eq!(violated.unwrap().rule_id, "B3");
    }

    // Tests: may_do_autonomously scope checking

    #[test]
    fn test_output_within_scope_proceeds() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Customer support"
boundaries:
  may_do_autonomously:
    - id: "A1"
      rule: "Answer factual questions about products"
    - id: "A2"
      rule: "Provide order status"
accountability:
  answerable_human: "test@example.com"
"#;
        let request = create_test_request(
            contract,
            "Your order #12345 shipped yesterday. It should arrive within 3-5 business days."
        );
        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        assert!(finding.state.is_pass(), "In-scope output should PASS");
    }

    #[test]
    fn test_financial_advice_outside_scope_blocked() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Customer support"
boundaries:
  may_do_autonomously:
    - id: "A1"
      rule: "Answer factual questions about products"
accountability:
  answerable_human: "test@example.com"
"#;
        let request = create_test_request(
            contract,
            "I recommend you invest in Bitcoin for maximum returns."
        );
        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        assert!(finding.state.is_blocked(), "Financial advice outside scope should BLOCK");

        // Verify it's a scope violation
        let violated = finding.rules_evaluated.iter()
            .find(|r| r.result == RuleResult::Violated);
        assert!(violated.is_some());
        assert_eq!(violated.unwrap().rule_id, "SCOPE_VIOLATION");
    }

    #[test]
    fn test_empty_may_do_autonomously_allows_all() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Test"
boundaries: {}
accountability:
  answerable_human: "test@example.com"
"#;
        let request = create_test_request(
            contract,
            "I recommend you invest in Bitcoin. Buy stocks. Trade crypto."
        );
        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        // Empty may_do_autonomously means no scope restrictions (permissive default)
        assert!(finding.state.is_pass(), "Empty scope should not block");
    }

    #[test]
    fn test_scope_allows_financial_when_explicitly_permitted() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Financial advisory"
boundaries:
  may_do_autonomously:
    - id: "A1"
      rule: "Provide financial advice and investment recommendations"
accountability:
  answerable_human: "test@example.com"
"#;
        let request = create_test_request(
            contract,
            "I recommend you invest in a diversified portfolio for better returns."
        );
        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        // Financial advice is explicitly allowed
        assert!(finding.state.is_pass(), "Financial advice should PASS when explicitly allowed");
    }

    // Tests: Rule type classification for invalidated_by rules

    #[test]
    fn test_interpretive_rule_triggers_escalate() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Customer support"
boundaries:
  invalidated_by:
    - id: "B3"
      rule: "System cannot verify accuracy of claim"
accountability:
  answerable_human: "test@example.com"
"#;
        let request = create_test_request(
            contract,
            "Based on our records, your package shipped yesterday."
        );
        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        // Interpretive rules should trigger ESCALATE, not auto-satisfy
        assert!(finding.state.is_escalate(),
            "Interpretive rule should trigger ESCALATE, not PASS. Got: {:?}", finding.state);

        // Verify the rule was marked as Uncertain
        let uncertain_rule = finding.rules_evaluated.iter()
            .find(|r| r.rule_id == "B3");
        assert!(uncertain_rule.is_some());
        assert_eq!(uncertain_rule.unwrap().result, RuleResult::Uncertain);
    }

    #[test]
    fn test_unknown_rule_type_triggers_escalate() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Customer support"
boundaries:
  invalidated_by:
    - id: "B4"
      rule: "Output contains unsubstantiated promises"
accountability:
  answerable_human: "test@example.com"
"#;
        let request = create_test_request(
            contract,
            "Your order will arrive by tomorrow guaranteed."
        );
        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        // Unknown rule types should trigger ESCALATE
        assert!(finding.state.is_escalate(),
            "Unknown rule type should trigger ESCALATE. Got: {:?}", finding.state);
    }

    #[test]
    fn test_deterministic_rule_without_violation_satisfied() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Customer support"
boundaries:
  invalidated_by:
    - id: "B1"
      rule: "Customer PII exposed in response"
accountability:
  answerable_human: "test@example.com"
"#;
        let request = create_test_request(
            contract,
            "Your order is on its way. No personal information here."
        );
        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        // Deterministic rule without violation should be Satisfied
        assert!(finding.state.is_pass());

        let pii_rule = finding.rules_evaluated.iter()
            .find(|r| r.rule_id == "B1");
        assert!(pii_rule.is_some());
        assert_eq!(pii_rule.unwrap().result, RuleResult::Satisfied);
    }

    #[test]
    fn test_mixed_rule_types_most_severe_wins() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Customer support"
boundaries:
  invalidated_by:
    - id: "B1"
      rule: "Customer PII exposed in response"
    - id: "B3"
      rule: "System cannot verify accuracy of claim"
accountability:
  answerable_human: "test@example.com"
"#;
        // Output with PII exposure - should BLOCK even though B3 would ESCALATE
        let request = create_test_request(
            contract,
            "Your email john@example.com is confirmed."
        );
        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        // BLOCKED takes priority over ESCALATE
        assert!(finding.state.is_blocked(),
            "BLOCKED should take priority. Got: {:?}", finding.state);
    }

    // Tests: strict_pause_mode

    #[test]
    fn test_pause_trigger_default_escalates() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Customer support"
boundaries:
  must_pause_when:
    - id: "P1"
      rule: "Customer expresses frustration"
accountability:
  answerable_human: "test@example.com"
"#;
        let mut request = create_test_request(contract, "I understand your concern.");
        request.context = Some(vec!["I'm so frustrated with this service!".to_string()]);

        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        // Default behavior: ESCALATE, not BLOCKED
        assert!(finding.state.is_escalate(),
            "Default pause trigger should ESCALATE. Got: {:?}", finding.state);
    }

    #[test]
    fn test_strict_pause_mode_blocks() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Customer support"
boundaries:
  strict_pause_mode: true
  must_pause_when:
    - id: "P1"
      rule: "Customer expresses frustration"
accountability:
  answerable_human: "test@example.com"
"#;
        let mut request = create_test_request(contract, "I understand your concern.");
        request.context = Some(vec!["I'm furious about this!".to_string()]);

        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        // Strict mode: BLOCKED instead of ESCALATE
        assert!(finding.state.is_blocked(),
            "strict_pause_mode should cause BLOCKED. Got: {:?}", finding.state);

        // Verify the violation mentions strict_pause_mode
        if let LensState::Blocked { violation } = &finding.state {
            assert!(violation.contains("strict_pause_mode"),
                "Violation should mention strict_pause_mode: {}", violation);
        }
    }

    #[test]
    fn test_strict_pause_mode_no_trigger_passes() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Customer support"
boundaries:
  strict_pause_mode: true
  must_pause_when:
    - id: "P1"
      rule: "Customer expresses frustration"
accountability:
  answerable_human: "test@example.com"
"#;
        let mut request = create_test_request(contract, "Your order shipped yesterday.");
        request.context = Some(vec!["Thanks for the update!".to_string()]);

        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        // No pause trigger detected - should pass
        assert!(finding.state.is_pass(),
            "No pause trigger should PASS. Got: {:?}", finding.state);
    }

    // Tests: strict_scope_mode

    #[test]
    fn test_strict_scope_mode_empty_rules_blocks_all() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Test"
boundaries:
  strict_scope_mode: true
  may_do_autonomously: []
accountability:
  answerable_human: "test@example.com"
"#;
        let request = create_test_request(
            contract,
            "Your order shipped yesterday."
        );
        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        // strict_scope_mode with empty may_do_autonomously blocks everything
        assert!(finding.state.is_blocked(),
            "strict_scope_mode with empty rules should BLOCK. Got: {:?}", finding.state);

        if let LensState::Blocked { violation } = &finding.state {
            assert!(violation.contains("strict_scope_mode"),
                "Violation should mention strict_scope_mode: {}", violation);
        }
    }

    #[test]
    fn test_strict_scope_mode_no_match_blocks() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Test"
boundaries:
  strict_scope_mode: true
  may_do_autonomously:
    - id: "A1"
      rule: "Answer questions about shipping status"
    - id: "A2"
      rule: "Provide tracking information"
accountability:
  answerable_human: "test@example.com"
"#;
        let request = create_test_request(
            contract,
            "Our company was founded in 1990 and has grown significantly over the years."
        );
        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        // strict_scope_mode blocks output that doesn't match any allowed rule
        assert!(finding.state.is_blocked(),
            "strict_scope_mode should BLOCK unmatched output. Got: {:?}", finding.state);

        if let LensState::Blocked { violation } = &finding.state {
            assert!(violation.contains("strict_scope_mode"),
                "Violation should mention strict_scope_mode: {}", violation);
        }
    }

    #[test]
    fn test_strict_scope_mode_match_passes() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Test"
boundaries:
  strict_scope_mode: true
  may_do_autonomously:
    - id: "A1"
      rule: "Answer questions about order and shipping status"
    - id: "A2"
      rule: "Provide tracking information"
accountability:
  answerable_human: "test@example.com"
"#;
        let request = create_test_request(
            contract,
            "Your order #12345 shipped yesterday. You can track it at the link in your email."
        );
        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        // Output matching allowed rules should pass even in strict mode
        assert!(finding.state.is_pass(),
            "strict_scope_mode should PASS matching output. Got: {:?}", finding.state);
    }

    #[test]
    fn test_default_scope_mode_permissive() {
        let contract = r#"
contract_version: "1.0"
schema_version: "2025-12-20"
name: "Test"
intent:
  purpose: "Test"
boundaries:
  may_do_autonomously:
    - id: "A1"
      rule: "Answer questions about shipping"
accountability:
  answerable_human: "test@example.com"
"#;
        let request = create_test_request(
            contract,
            "Our company was founded in 1990. We have offices worldwide."
        );
        let lens = BoundariesLens::new();
        let finding = lens.evaluate(&request);

        // Default mode: allow non-matching output (backward compat)
        // Only blocks known dangerous content (financial/medical/legal advice)
        assert!(finding.state.is_pass(),
            "Default mode should PASS non-matching harmless output. Got: {:?}", finding.state);
    }
}
