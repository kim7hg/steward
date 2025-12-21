//! Domain-Specific Pattern Extensions
//!
//! This module provides specialized pattern detection for regulated domains.
//! Patterns are activated based on the contract's `policy_pack` field.
//!
//! ## Supported Domains
//!
//! | Domain | Policy Pack | Patterns |
//! |--------|-------------|----------|
//! | Healthcare | `healthcare`, `hipaa` | MRN, NPI, ICD-10, CPT, DEA |
//! | Finance | `finance`, `sec`, `finra` | Account numbers, routing, CUSIP, ISIN |
//! | Legal | `legal`, `ethics` | Privilege markers, Bates numbers, case citations |
//! | Education | `education`, `ferpa`, `coppa` | Student IDs, grade patterns |
//! | HR | `hr`, `employment` | Employee IDs, EIN, I-9 references |

use lazy_static::lazy_static;
use regex::Regex;

/// Severity of a domain pattern match.
///
/// Determines how the RestraintLens handles the detected pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternSeverity {
    /// Pattern violation must block the output (e.g., direct PHI, account numbers)
    Blocking,
    /// Pattern requires human review (e.g., clinical codes, advice language)
    Escalating,
    /// Pattern is informational only, logged for audit (e.g., public records)
    Informational,
}

/// A domain-specific pattern match.
#[derive(Debug, Clone)]
pub struct DomainMatch {
    pub domain: &'static str,
    pub pattern_type: &'static str,
    pub description: &'static str,
    pub severity: PatternSeverity,
    pub start: usize,
    pub end: usize,
}

lazy_static! {
    // =========================================================================
    // HEALTHCARE PATTERNS (HIPAA, PHI identifiers)
    // =========================================================================

    /// Medical Record Number (MRN) - typically 6-10 digits, often with prefix
    static ref MRN_PATTERN: Regex = Regex::new(
        r"(?i)\b(MRN|medical record|patient id)[:\s#]*([A-Z]{0,3}\d{6,10})\b"
    ).unwrap();

    /// National Provider Identifier (NPI) - exactly 10 digits, starts with 1 or 2
    static ref NPI_PATTERN: Regex = Regex::new(
        r"\b(1|2)\d{9}\b"
    ).unwrap();

    /// ICD-10 Diagnosis Codes (e.g., E11.9, J18.9, M54.5)
    static ref ICD10_PATTERN: Regex = Regex::new(
        r"\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b"
    ).unwrap();

    /// CPT Procedure Codes (5 digits, often 90000-99999 for E/M)
    static ref CPT_PATTERN: Regex = Regex::new(
        r"(?i)\b(CPT|procedure)[:\s]*(\d{5})\b"
    ).unwrap();

    /// DEA Number (2 letters + 7 digits)
    static ref DEA_PATTERN: Regex = Regex::new(
        r"\b[A-Z]{2}\d{7}\b"
    ).unwrap();

    /// Health Plan ID / Member ID patterns
    static ref HEALTH_PLAN_ID_PATTERN: Regex = Regex::new(
        r"(?i)\b(member id|health plan|insurance id|subscriber)[:\s#]*([A-Z]{2,3}\d{8,12})\b"
    ).unwrap();

    // =========================================================================
    // FINANCE PATTERNS (SEC, FINRA identifiers)
    // =========================================================================

    /// Bank Account Number (8-17 digits)
    static ref ACCOUNT_NUMBER_PATTERN: Regex = Regex::new(
        r"(?i)\b(account|acct)[:\s#]*(\d{8,17})\b"
    ).unwrap();

    /// ABA Routing Number (9 digits, starts with 0-3)
    static ref ROUTING_NUMBER_PATTERN: Regex = Regex::new(
        r"\b[0-3]\d{8}\b"
    ).unwrap();

    /// CUSIP (9 characters: 6 alphanumeric issuer + 2 issue + 1 check)
    static ref CUSIP_PATTERN: Regex = Regex::new(
        r"\b[A-Z0-9]{6}[A-Z0-9]{2}[0-9]\b"
    ).unwrap();

    /// ISIN (2-letter country + 9 alphanumeric + 1 check digit)
    static ref ISIN_PATTERN: Regex = Regex::new(
        r"\b[A-Z]{2}[A-Z0-9]{9}[0-9]\b"
    ).unwrap();

    /// SWIFT/BIC Code (8 or 11 characters)
    static ref SWIFT_PATTERN: Regex = Regex::new(
        r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?\b"
    ).unwrap();

    /// Investment recommendation language
    static ref INVESTMENT_ADVICE_PATTERN: Regex = Regex::new(
        r"(?i)\b(recommend|should (buy|sell|invest)|guaranteed return|risk[- ]free|no risk)\b"
    ).unwrap();

    // =========================================================================
    // LEGAL PATTERNS (Privilege, case management)
    // =========================================================================

    /// Attorney-Client Privilege markers
    static ref PRIVILEGE_PATTERN: Regex = Regex::new(
        r"(?i)\b(privileged|attorney[- ]client|work product|confidential communication|legal advice)\b"
    ).unwrap();

    /// Bates Numbers (prefix + sequential number)
    static ref BATES_PATTERN: Regex = Regex::new(
        r"\b[A-Z]{2,6}[-_]?\d{6,10}\b"
    ).unwrap();

    /// Case Citations (e.g., 123 F.3d 456, 2024 WL 12345)
    static ref CASE_CITATION_PATTERN: Regex = Regex::new(
        r"\b\d{1,3}\s+[A-Z][a-z]*\.?\s*(?:\d+[a-z]*\.?)?\s+\d{1,4}\b|\b\d{4}\s+WL\s+\d+\b"
    ).unwrap();

    /// Legal conclusion language (indicating advice vs information)
    static ref LEGAL_ADVICE_PATTERN: Regex = Regex::new(
        r"(?i)\b(you should|i advise|legal recommendation|in my legal opinion|you will (win|lose)|liable for)\b"
    ).unwrap();

    // =========================================================================
    // EDUCATION PATTERNS (FERPA, student records)
    // =========================================================================

    /// Student ID patterns (various formats)
    static ref STUDENT_ID_PATTERN: Regex = Regex::new(
        r"(?i)\b(student id|student number|sid)[:\s#]*([A-Z]?\d{7,10})\b"
    ).unwrap();

    /// Grade/GPA patterns
    static ref GRADE_PATTERN: Regex = Regex::new(
        r"(?i)\b(GPA|grade point)[:\s]*(\d\.\d{1,2})\b|\b(received|earned|got)\s+an?\s+[A-F][+-]?\b"
    ).unwrap();

    /// Transcript reference
    static ref TRANSCRIPT_PATTERN: Regex = Regex::new(
        r"(?i)\b(transcript|academic record|grade report|report card)\b"
    ).unwrap();

    /// FERPA directory info indicators
    static ref DIRECTORY_INFO_PATTERN: Regex = Regex::new(
        r"(?i)\b(directory information|student directory|enrollment status)\b"
    ).unwrap();

    // =========================================================================
    // HR PATTERNS (Employment, discrimination)
    // =========================================================================

    /// Employee ID patterns
    static ref EMPLOYEE_ID_PATTERN: Regex = Regex::new(
        r"(?i)\b(employee id|emp id|badge)[:\s#]*([A-Z]?\d{5,8})\b"
    ).unwrap();

    /// EIN (Employer Identification Number) - XX-XXXXXXX
    static ref EIN_PATTERN: Regex = Regex::new(
        r"\b\d{2}-\d{7}\b"
    ).unwrap();

    /// I-9 / Work Authorization references
    static ref I9_PATTERN: Regex = Regex::new(
        r"(?i)\b(I-9|work authorization|employment eligibility|visa status|work permit)\b"
    ).unwrap();

    /// Protected class language (potential discrimination indicators)
    static ref PROTECTED_CLASS_PATTERN: Regex = Regex::new(
        r"(?i)\b(\d{2,3}\s+years?\s+old|too old|too young|pregnant|disability|disabled|religion|religious|national origin|race|gender|sex)\b"
    ).unwrap();

    /// Salary/compensation patterns
    static ref COMPENSATION_PATTERN: Regex = Regex::new(
        r"(?i)\b(salary|compensation|pay rate|hourly rate|annual salary)[:\s$]*(\$?\d{1,3}(?:,\d{3})*(?:\.\d{2})?)\b"
    ).unwrap();
}

/// Check for healthcare-specific patterns (PHI).
pub fn check_healthcare_patterns(content: &str) -> Vec<DomainMatch> {
    let mut matches = Vec::new();

    for m in MRN_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "healthcare",
            pattern_type: "MRN",
            description: "Medical Record Number",
            severity: PatternSeverity::Blocking, // Direct patient identifier
            start: m.start(),
            end: m.end(),
        });
    }

    for m in NPI_PATTERN.find_iter(content) {
        // Additional validation: NPI has a check digit algorithm
        let npi = m.as_str();
        if is_valid_npi(npi) {
            matches.push(DomainMatch {
                domain: "healthcare",
                pattern_type: "NPI",
                description: "National Provider Identifier",
                severity: PatternSeverity::Blocking, // Provider identifier
                start: m.start(),
                end: m.end(),
            });
        }
    }

    for m in ICD10_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "healthcare",
            pattern_type: "ICD-10",
            description: "Diagnosis code",
            severity: PatternSeverity::Escalating, // Clinical code, context-dependent
            start: m.start(),
            end: m.end(),
        });
    }

    for m in CPT_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "healthcare",
            pattern_type: "CPT",
            description: "Procedure code",
            severity: PatternSeverity::Escalating, // Procedure code, context-dependent
            start: m.start(),
            end: m.end(),
        });
    }

    for m in DEA_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "healthcare",
            pattern_type: "DEA",
            description: "DEA registration number",
            severity: PatternSeverity::Blocking, // Controlled substance identifier
            start: m.start(),
            end: m.end(),
        });
    }

    for m in HEALTH_PLAN_ID_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "healthcare",
            pattern_type: "HealthPlanID",
            description: "Health plan member ID",
            severity: PatternSeverity::Blocking, // Direct patient identifier
            start: m.start(),
            end: m.end(),
        });
    }

    matches
}

/// Check for finance-specific patterns.
pub fn check_finance_patterns(content: &str) -> Vec<DomainMatch> {
    let mut matches = Vec::new();

    for m in ACCOUNT_NUMBER_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "finance",
            pattern_type: "AccountNumber",
            description: "Bank account number",
            severity: PatternSeverity::Blocking, // Direct financial access
            start: m.start(),
            end: m.end(),
        });
    }

    for m in ROUTING_NUMBER_PATTERN.find_iter(content) {
        let routing = m.as_str();
        if is_valid_routing_number(routing) {
            matches.push(DomainMatch {
                domain: "finance",
                pattern_type: "RoutingNumber",
                description: "ABA routing number",
                severity: PatternSeverity::Blocking, // Direct financial access
                start: m.start(),
                end: m.end(),
            });
        }
    }

    for m in CUSIP_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "finance",
            pattern_type: "CUSIP",
            description: "Securities identifier",
            severity: PatternSeverity::Escalating, // Securities ID, less PII risk
            start: m.start(),
            end: m.end(),
        });
    }

    for m in ISIN_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "finance",
            pattern_type: "ISIN",
            description: "International securities ID",
            severity: PatternSeverity::Escalating, // Securities ID, less PII risk
            start: m.start(),
            end: m.end(),
        });
    }

    for m in SWIFT_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "finance",
            pattern_type: "SWIFT",
            description: "SWIFT/BIC code",
            severity: PatternSeverity::Escalating, // Bank identifier, context-dependent
            start: m.start(),
            end: m.end(),
        });
    }

    for m in INVESTMENT_ADVICE_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "finance",
            pattern_type: "InvestmentAdvice",
            description: "Investment recommendation language",
            severity: PatternSeverity::Escalating, // Professional advice boundary
            start: m.start(),
            end: m.end(),
        });
    }

    matches
}

/// Check for legal-specific patterns.
pub fn check_legal_patterns(content: &str) -> Vec<DomainMatch> {
    let mut matches = Vec::new();

    for m in PRIVILEGE_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "legal",
            pattern_type: "Privilege",
            description: "Privilege marker",
            severity: PatternSeverity::Blocking, // Attorney-client privilege
            start: m.start(),
            end: m.end(),
        });
    }

    for m in BATES_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "legal",
            pattern_type: "Bates",
            description: "Bates number",
            severity: PatternSeverity::Escalating, // Document tracking, context-dependent
            start: m.start(),
            end: m.end(),
        });
    }

    for m in CASE_CITATION_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "legal",
            pattern_type: "CaseCitation",
            description: "Case citation",
            severity: PatternSeverity::Informational, // Public record
            start: m.start(),
            end: m.end(),
        });
    }

    for m in LEGAL_ADVICE_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "legal",
            pattern_type: "LegalAdvice",
            description: "Legal advice language",
            severity: PatternSeverity::Escalating, // UPL boundary
            start: m.start(),
            end: m.end(),
        });
    }

    matches
}

/// Check for education-specific patterns (FERPA).
pub fn check_education_patterns(content: &str) -> Vec<DomainMatch> {
    let mut matches = Vec::new();

    for m in STUDENT_ID_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "education",
            pattern_type: "StudentID",
            description: "Student identifier",
            severity: PatternSeverity::Blocking, // Direct student identifier
            start: m.start(),
            end: m.end(),
        });
    }

    for m in GRADE_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "education",
            pattern_type: "Grade",
            description: "Grade or GPA",
            severity: PatternSeverity::Escalating, // FERPA protected, context-dependent
            start: m.start(),
            end: m.end(),
        });
    }

    for m in TRANSCRIPT_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "education",
            pattern_type: "Transcript",
            description: "Transcript reference",
            severity: PatternSeverity::Escalating, // FERPA protected, context-dependent
            start: m.start(),
            end: m.end(),
        });
    }

    for m in DIRECTORY_INFO_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "education",
            pattern_type: "DirectoryInfo",
            description: "Directory information reference",
            severity: PatternSeverity::Informational, // FERPA allows directory info
            start: m.start(),
            end: m.end(),
        });
    }

    matches
}

/// Check for HR-specific patterns.
pub fn check_hr_patterns(content: &str) -> Vec<DomainMatch> {
    let mut matches = Vec::new();

    for m in EMPLOYEE_ID_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "hr",
            pattern_type: "EmployeeID",
            description: "Employee identifier",
            severity: PatternSeverity::Blocking, // Direct employee identifier
            start: m.start(),
            end: m.end(),
        });
    }

    for m in EIN_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "hr",
            pattern_type: "EIN",
            description: "Employer Identification Number",
            severity: PatternSeverity::Blocking, // Tax identifier
            start: m.start(),
            end: m.end(),
        });
    }

    for m in I9_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "hr",
            pattern_type: "I9",
            description: "I-9/work authorization reference",
            severity: PatternSeverity::Escalating, // Sensitive but context-dependent
            start: m.start(),
            end: m.end(),
        });
    }

    for m in PROTECTED_CLASS_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "hr",
            pattern_type: "ProtectedClass",
            description: "Protected class reference",
            severity: PatternSeverity::Escalating, // Discrimination risk, context-dependent
            start: m.start(),
            end: m.end(),
        });
    }

    for m in COMPENSATION_PATTERN.find_iter(content) {
        matches.push(DomainMatch {
            domain: "hr",
            pattern_type: "Compensation",
            description: "Salary/compensation data",
            severity: PatternSeverity::Blocking, // Salary is PII
            start: m.start(),
            end: m.end(),
        });
    }

    matches
}

/// Check patterns based on policy pack.
pub fn check_domain_patterns(content: &str, policy_packs: &[String]) -> Vec<DomainMatch> {
    let mut all_matches = Vec::new();

    for pack in policy_packs {
        let pack_lower = pack.to_lowercase();
        match pack_lower.as_str() {
            "healthcare" | "hipaa" => {
                all_matches.extend(check_healthcare_patterns(content));
            }
            "finance" | "sec" | "finra" => {
                all_matches.extend(check_finance_patterns(content));
            }
            "legal" | "ethics" => {
                all_matches.extend(check_legal_patterns(content));
            }
            "education" | "ferpa" | "coppa" => {
                all_matches.extend(check_education_patterns(content));
            }
            "hr" | "employment" | "anti-discrimination" => {
                all_matches.extend(check_hr_patterns(content));
            }
            _ => {} // Unknown policy pack - no additional patterns
        }
    }

    all_matches
}

// =============================================================================
// Validation Helpers
// =============================================================================

/// Validate NPI using Luhn algorithm (mod 10, double-add-double).
fn is_valid_npi(npi: &str) -> bool {
    if npi.len() != 10 {
        return false;
    }

    // NPI validation uses Luhn with prefix "80840"
    let prefixed = format!("80840{}", npi);
    luhn_check(&prefixed)
}

/// Validate ABA routing number using checksum.
fn is_valid_routing_number(routing: &str) -> bool {
    if routing.len() != 9 {
        return false;
    }

    let digits: Vec<u32> = routing.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 9 {
        return false;
    }

    // Checksum: 3(d1 + d4 + d7) + 7(d2 + d5 + d8) + (d3 + d6 + d9) mod 10 == 0
    let sum = 3 * (digits[0] + digits[3] + digits[6])
        + 7 * (digits[1] + digits[4] + digits[7])
        + (digits[2] + digits[5] + digits[8]);

    sum % 10 == 0
}

/// Standard Luhn check digit validation.
fn luhn_check(number: &str) -> bool {
    let digits: Vec<u32> = number.chars().filter_map(|c| c.to_digit(10)).collect();

    if digits.is_empty() {
        return false;
    }

    let mut sum = 0;
    let mut double = false;

    for &digit in digits.iter().rev() {
        let mut d = digit;
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }

    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_healthcare_mrn_detection() {
        let content = "Patient MRN: ABC1234567 admitted today.";
        let matches = check_healthcare_patterns(content);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_type, "MRN");
    }

    #[test]
    fn test_healthcare_icd10_detection() {
        let content = "Diagnosis: E11.9 (Type 2 diabetes without complications)";
        let matches = check_healthcare_patterns(content);
        assert!(matches.iter().any(|m| m.pattern_type == "ICD-10"));
    }

    #[test]
    fn test_finance_account_detection() {
        let content = "Your account: 12345678901234 has been credited.";
        let matches = check_finance_patterns(content);
        assert!(matches.iter().any(|m| m.pattern_type == "AccountNumber"));
    }

    #[test]
    fn test_finance_investment_advice_detection() {
        let content = "I recommend you should buy AAPL stock immediately.";
        let matches = check_finance_patterns(content);
        assert!(matches.iter().any(|m| m.pattern_type == "InvestmentAdvice"));
    }

    #[test]
    fn test_legal_privilege_detection() {
        let content = "This communication is privileged and confidential.";
        let matches = check_legal_patterns(content);
        assert!(matches.iter().any(|m| m.pattern_type == "Privilege"));
    }

    #[test]
    fn test_legal_advice_detection() {
        let content = "In my legal opinion, you should file immediately.";
        let matches = check_legal_patterns(content);
        assert!(matches.iter().any(|m| m.pattern_type == "LegalAdvice"));
    }

    #[test]
    fn test_education_student_id_detection() {
        let content = "Student ID: 1234567890 enrolled in CS101.";
        let matches = check_education_patterns(content);
        assert!(matches.iter().any(|m| m.pattern_type == "StudentID"));
    }

    #[test]
    fn test_education_gpa_detection() {
        let content = "The student's GPA: 3.85 qualifies for honors.";
        let matches = check_education_patterns(content);
        assert!(matches.iter().any(|m| m.pattern_type == "Grade"));
    }

    #[test]
    fn test_hr_employee_id_detection() {
        let content = "Employee ID: E12345678 has been terminated.";
        let matches = check_hr_patterns(content);
        assert!(matches.iter().any(|m| m.pattern_type == "EmployeeID"));
    }

    #[test]
    fn test_hr_protected_class_detection() {
        let content = "The candidate is 58 years old and may not fit.";
        let matches = check_hr_patterns(content);
        assert!(matches.iter().any(|m| m.pattern_type == "ProtectedClass"));
    }

    #[test]
    fn test_hr_ein_detection() {
        let content = "Company EIN: 12-3456789 for tax purposes.";
        let matches = check_hr_patterns(content);
        assert!(matches.iter().any(|m| m.pattern_type == "EIN"));
    }

    #[test]
    fn test_routing_number_validation() {
        // Valid routing number
        assert!(is_valid_routing_number("021000021")); // JPMorgan Chase
        // Invalid routing number
        assert!(!is_valid_routing_number("123456789"));
    }

    #[test]
    fn test_policy_pack_routing() {
        let content = "Patient MRN: ABC1234567 with diagnosis E11.9";

        // Healthcare pack should find matches
        let healthcare_matches = check_domain_patterns(content, &["healthcare".to_string()]);
        assert!(!healthcare_matches.is_empty());

        // Finance pack should not find healthcare patterns
        let finance_matches = check_domain_patterns(content, &["finance".to_string()]);
        assert!(finance_matches.is_empty());
    }
}
