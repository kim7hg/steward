//! Conversions from steward-core types to IR types.
//!
//! Single source of truth for type mapping. All bindings should convert
//! core types → IR types → FFI types, never core → FFI directly.
//!
//! **These conversions are pure data transformations with no semantic logic.**

use steward_core::{
    BoundaryViolation, Evidence, EvidenceSource, EvaluationResult, LensFinding, LensFindings,
    LensState, LensType, Output, RuleEvaluation, RuleResult, State,
};

use crate::types::*;

/// Trait for converting core types to IR types.
pub trait ToIR<T> {
    fn to_ir(&self) -> T;
}

// --- LensType ---

impl From<LensType> for IRLensType {
    fn from(lt: LensType) -> Self {
        match lt {
            LensType::AccountabilityOwnership => IRLensType::AccountabilityOwnership,
            LensType::BoundariesSafety => IRLensType::BoundariesSafety,
            LensType::DignityInclusion => IRLensType::DignityInclusion,
            LensType::RestraintPrivacy => IRLensType::RestraintPrivacy,
            LensType::TransparencyContestability => IRLensType::TransparencyContestability,
        }
    }
}

impl ToIR<IRLensType> for LensType {
    fn to_ir(&self) -> IRLensType {
        (*self).into()
    }
}

// --- RuleResult ---

impl From<RuleResult> for IRRuleResult {
    fn from(rr: RuleResult) -> Self {
        match rr {
            RuleResult::Satisfied => IRRuleResult::Satisfied,
            RuleResult::Violated => IRRuleResult::Violated,
            RuleResult::Uncertain => IRRuleResult::Uncertain,
            RuleResult::NotApplicable => IRRuleResult::NotApplicable,
        }
    }
}

impl ToIR<IRRuleResult> for RuleResult {
    fn to_ir(&self) -> IRRuleResult {
        (*self).into()
    }
}

// --- EvidenceSource ---

impl From<EvidenceSource> for IREvidenceSource {
    fn from(es: EvidenceSource) -> Self {
        match es {
            EvidenceSource::Contract => IREvidenceSource::Contract,
            EvidenceSource::Output => IREvidenceSource::Output,
            EvidenceSource::Context => IREvidenceSource::Context,
            EvidenceSource::Metadata => IREvidenceSource::Metadata,
        }
    }
}

impl ToIR<IREvidenceSource> for EvidenceSource {
    fn to_ir(&self) -> IREvidenceSource {
        (*self).into()
    }
}

// --- Evidence ---

impl From<Evidence> for IREvidence {
    fn from(e: Evidence) -> Self {
        IREvidence {
            source: e.source.into(),
            claim: e.claim,
            pointer: e.pointer,
        }
    }
}

impl From<&Evidence> for IREvidence {
    fn from(e: &Evidence) -> Self {
        IREvidence {
            source: e.source.into(),
            claim: e.claim.clone(),
            pointer: e.pointer.clone(),
        }
    }
}

impl ToIR<IREvidence> for Evidence {
    fn to_ir(&self) -> IREvidence {
        self.into()
    }
}

// --- RuleEvaluation ---

impl From<RuleEvaluation> for IRRuleEvaluation {
    fn from(re: RuleEvaluation) -> Self {
        IRRuleEvaluation {
            rule_id: re.rule_id,
            rule_text: re.rule_text,
            result: re.result.into(),
            evidence: re.evidence.into_iter().map(Into::into).collect(),
            rationale: re.rationale,
        }
    }
}

impl From<&RuleEvaluation> for IRRuleEvaluation {
    fn from(re: &RuleEvaluation) -> Self {
        IRRuleEvaluation {
            rule_id: re.rule_id.clone(),
            rule_text: re.rule_text.clone(),
            result: re.result.into(),
            evidence: re.evidence.iter().map(Into::into).collect(),
            rationale: re.rationale.clone(),
        }
    }
}

impl ToIR<IRRuleEvaluation> for RuleEvaluation {
    fn to_ir(&self) -> IRRuleEvaluation {
        self.into()
    }
}

// --- LensState ---

impl From<LensState> for IRLensState {
    fn from(ls: LensState) -> Self {
        match ls {
            LensState::Pass => IRLensState::Pass,
            LensState::Escalate { reason } => IRLensState::Escalate { reason },
            LensState::Blocked { violation } => IRLensState::Blocked { violation },
        }
    }
}

impl From<&LensState> for IRLensState {
    fn from(ls: &LensState) -> Self {
        match ls {
            LensState::Pass => IRLensState::Pass,
            LensState::Escalate { reason } => IRLensState::Escalate {
                reason: reason.clone(),
            },
            LensState::Blocked { violation } => IRLensState::Blocked {
                violation: violation.clone(),
            },
        }
    }
}

impl ToIR<IRLensState> for LensState {
    fn to_ir(&self) -> IRLensState {
        self.into()
    }
}

// --- LensFinding ---

impl From<LensFinding> for IRLensFinding {
    fn from(lf: LensFinding) -> Self {
        IRLensFinding {
            lens: lf.lens.map(Into::into),
            question_asked: lf.question_asked,
            state: lf.state.into(),
            rules_evaluated: lf.rules_evaluated.into_iter().map(Into::into).collect(),
            confidence: lf.confidence,
        }
    }
}

impl From<&LensFinding> for IRLensFinding {
    fn from(lf: &LensFinding) -> Self {
        IRLensFinding {
            lens: lf.lens.map(Into::into),
            question_asked: lf.question_asked.clone(),
            state: (&lf.state).into(),
            rules_evaluated: lf.rules_evaluated.iter().map(Into::into).collect(),
            confidence: lf.confidence,
        }
    }
}

impl ToIR<IRLensFinding> for LensFinding {
    fn to_ir(&self) -> IRLensFinding {
        self.into()
    }
}

// --- LensFindings ---

impl From<LensFindings> for IRLensFindings {
    fn from(lf: LensFindings) -> Self {
        IRLensFindings {
            dignity_inclusion: lf.dignity_inclusion.into(),
            boundaries_safety: lf.boundaries_safety.into(),
            restraint_privacy: lf.restraint_privacy.into(),
            transparency_contestability: lf.transparency_contestability.into(),
            accountability_ownership: lf.accountability_ownership.into(),
        }
    }
}

impl From<&LensFindings> for IRLensFindings {
    fn from(lf: &LensFindings) -> Self {
        IRLensFindings {
            dignity_inclusion: (&lf.dignity_inclusion).into(),
            boundaries_safety: (&lf.boundaries_safety).into(),
            restraint_privacy: (&lf.restraint_privacy).into(),
            transparency_contestability: (&lf.transparency_contestability).into(),
            accountability_ownership: (&lf.accountability_ownership).into(),
        }
    }
}

impl ToIR<IRLensFindings> for LensFindings {
    fn to_ir(&self) -> IRLensFindings {
        self.into()
    }
}

// --- BoundaryViolation ---

impl From<BoundaryViolation> for IRBoundaryViolation {
    fn from(bv: BoundaryViolation) -> Self {
        IRBoundaryViolation {
            lens: bv.lens.into(),
            rule_id: bv.rule_id,
            rule_text: bv.rule_text,
            evidence: bv.evidence.into_iter().map(Into::into).collect(),
            accountable_human: bv.accountable_human,
        }
    }
}

impl From<&BoundaryViolation> for IRBoundaryViolation {
    fn from(bv: &BoundaryViolation) -> Self {
        IRBoundaryViolation {
            lens: bv.lens.into(),
            rule_id: bv.rule_id.clone(),
            rule_text: bv.rule_text.clone(),
            evidence: bv.evidence.iter().map(Into::into).collect(),
            accountable_human: bv.accountable_human.clone(),
        }
    }
}

impl ToIR<IRBoundaryViolation> for BoundaryViolation {
    fn to_ir(&self) -> IRBoundaryViolation {
        self.into()
    }
}

// --- State ---

impl From<State> for IRState {
    fn from(state: State) -> Self {
        match state {
            State::Proceed { summary } => IRState::Proceed { summary },
            State::Escalate {
                uncertainty,
                decision_point,
                options,
            } => IRState::Escalate {
                uncertainty,
                decision_point,
                options,
            },
            State::Blocked { violation } => IRState::Blocked {
                violation: violation.into(),
            },
        }
    }
}

impl From<&State> for IRState {
    fn from(state: &State) -> Self {
        match state {
            State::Proceed { summary } => IRState::Proceed {
                summary: summary.clone(),
            },
            State::Escalate {
                uncertainty,
                decision_point,
                options,
            } => IRState::Escalate {
                uncertainty: uncertainty.clone(),
                decision_point: decision_point.clone(),
                options: options.clone(),
            },
            State::Blocked { violation } => IRState::Blocked {
                violation: violation.into(),
            },
        }
    }
}

impl ToIR<IRState> for State {
    fn to_ir(&self) -> IRState {
        self.into()
    }
}

// --- EvaluationResult ---

impl From<EvaluationResult> for IREvaluationResult {
    fn from(er: EvaluationResult) -> Self {
        IREvaluationResult {
            state: er.state.into(),
            lens_findings: er.lens_findings.into(),
            confidence: er.confidence,
            evaluated_at: er.evaluated_at.to_rfc3339(),
            metadata: er.metadata,
        }
    }
}

impl From<&EvaluationResult> for IREvaluationResult {
    fn from(er: &EvaluationResult) -> Self {
        IREvaluationResult {
            state: (&er.state).into(),
            lens_findings: (&er.lens_findings).into(),
            confidence: er.confidence,
            evaluated_at: er.evaluated_at.to_rfc3339(),
            metadata: er.metadata.clone(),
        }
    }
}

impl ToIR<IREvaluationResult> for EvaluationResult {
    fn to_ir(&self) -> IREvaluationResult {
        self.into()
    }
}

// --- Output ---

impl From<&Output> for IROutput {
    fn from(o: &Output) -> Self {
        IROutput {
            content: o.content.clone(),
            content_type: format!("{:?}", o.content_type).to_lowercase(),
            metadata: o.metadata.clone(),
        }
    }
}

impl ToIR<IROutput> for Output {
    fn to_ir(&self) -> IROutput {
        self.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use steward_core::Evidence;

    #[test]
    fn test_lens_type_conversion() {
        assert_eq!(
            IRLensType::from(LensType::DignityInclusion),
            IRLensType::DignityInclusion
        );
        assert_eq!(
            LensType::BoundariesSafety.to_ir(),
            IRLensType::BoundariesSafety
        );
    }

    #[test]
    fn test_evidence_conversion() {
        let evidence = Evidence::from_output("Test claim", 0, 10);
        let ir: IREvidence = evidence.into();
        assert_eq!(ir.claim, "Test claim");
        assert_eq!(ir.source, IREvidenceSource::Output);
        assert_eq!(ir.pointer, "output.content[0:10]");
    }

    #[test]
    fn test_lens_state_conversion() {
        let pass = LensState::Pass;
        assert!(IRLensState::from(pass).is_pass());

        let escalate = LensState::Escalate {
            reason: "needs review".to_string(),
        };
        let ir_escalate = IRLensState::from(escalate);
        assert!(ir_escalate.is_escalate());
        if let IRLensState::Escalate { reason } = ir_escalate {
            assert_eq!(reason, "needs review");
        }
    }
}
