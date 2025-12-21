//! Keyword extraction for rule matching.
//!
//! This module extracts meaningful keywords from rule text for semantic matching.
//! Used by the Boundaries lens to determine if output aligns with allowed scope.
//!
//! ## SOLID Rationale
//!
//! - **SRP**: Keyword extraction is separate from rule evaluation
//! - **OCP**: New stopwords/patterns can be added without changing extraction logic
//! - **DIP**: Lenses depend on this abstraction, not concrete implementations

use lazy_static::lazy_static;
use std::collections::HashSet;

lazy_static! {
    /// Common English stopwords that don't carry semantic meaning for rule matching.
    static ref STOPWORDS: HashSet<&'static str> = {
        let words = [
            // Articles
            "a", "an", "the",
            // Prepositions
            "about", "above", "across", "after", "against", "along", "among", "around",
            "at", "before", "behind", "below", "beneath", "beside", "between", "beyond",
            "by", "down", "during", "except", "for", "from", "in", "inside", "into",
            "near", "of", "off", "on", "onto", "out", "outside", "over", "past",
            "through", "to", "toward", "under", "until", "up", "upon", "with", "within", "without",
            // Conjunctions
            "and", "but", "or", "nor", "so", "yet", "both", "either", "neither",
            // Pronouns
            "i", "me", "my", "myself", "we", "our", "ours", "ourselves",
            "you", "your", "yours", "yourself", "yourselves",
            "he", "him", "his", "himself", "she", "her", "hers", "herself",
            "it", "its", "itself", "they", "them", "their", "theirs", "themselves",
            "what", "which", "who", "whom", "this", "that", "these", "those",
            // Common verbs (non-semantic for rule matching)
            "is", "are", "was", "were", "be", "been", "being",
            "have", "has", "had", "having", "do", "does", "did", "doing",
            "can", "could", "shall", "should", "will", "would", "may", "might", "must",
            // Other common words
            "all", "any", "each", "every", "few", "more", "most", "other", "some", "such",
            "no", "not", "only", "own", "same", "than", "too", "very",
            "just", "also", "now", "here", "there", "when", "where", "why", "how",
        ];
        words.into_iter().collect()
    };

    /// Action verbs commonly found in rules that indicate what the system may/must do.
    /// These are kept even though they're verbs because they carry semantic meaning.
    static ref ACTION_VERBS: HashSet<&'static str> = {
        let verbs = [
            "answer", "provide", "explain", "describe", "help", "assist", "support",
            "create", "generate", "produce", "make", "build", "write",
            "send", "deliver", "transfer", "share", "distribute",
            "check", "verify", "validate", "confirm", "review",
            "update", "modify", "change", "edit", "adjust",
            "delete", "remove", "cancel", "revoke",
            "approve", "authorize", "allow", "permit", "grant",
            "deny", "reject", "block", "prevent", "restrict",
            "notify", "alert", "inform", "warn", "advise",
            "process", "handle", "manage", "execute", "perform",
            "track", "monitor", "log", "record", "audit",
        ];
        verbs.into_iter().collect()
    };
}

/// Extract meaningful keywords from rule text.
///
/// Removes stopwords and keeps nouns, action verbs, and domain-specific terms.
/// Returns keywords in lowercase for case-insensitive matching.
///
/// # Examples
///
/// ```ignore
/// let keywords = extract_keywords("Answer factual questions about products");
/// // Returns: ["answer", "factual", "questions", "products"]
/// ```
pub fn extract_keywords(rule_text: &str) -> Vec<String> {
    rule_text
        .to_lowercase()
        // Split on word boundaries
        .split(|c: char| !c.is_alphanumeric())
        // Filter empty strings and stopwords
        .filter(|word| {
            let word = word.trim();
            !word.is_empty()
                && word.len() > 2  // Skip very short words
                && !STOPWORDS.contains(word)
        })
        .map(String::from)
        .collect()
}

/// Check if content matches a rule based on keyword overlap.
///
/// Returns true if the content contains at least one keyword from the rule.
/// This is a lenient check to avoid false negatives - it's better to allow
/// content that might be in scope than to block content that is in scope.
///
/// # Arguments
///
/// * `content` - The output content to check
/// * `rule_keywords` - Keywords extracted from the rule text
///
/// # Returns
///
/// `true` if content semantically aligns with the rule, `false` otherwise.
pub fn content_matches_rule_keywords(content: &str, rule_keywords: &[String]) -> bool {
    if rule_keywords.is_empty() {
        return false;
    }

    let content_lower = content.to_lowercase();

    // At least one keyword must match
    // This is intentionally lenient to avoid false positives for scope violations
    rule_keywords
        .iter()
        .any(|kw| content_lower.contains(kw.as_str()))
}

/// Check if any rule in a list matches the content.
///
/// Used by `may_do_autonomously` to determine if output is within allowed scope.
///
/// # Arguments
///
/// * `content` - The output content to check
/// * `rules` - List of rules to check against
///
/// # Returns
///
/// `true` if content matches at least one rule, `false` otherwise.
pub fn content_matches_any_rule(content: &str, rules: &[crate::contract::Rule]) -> bool {
    for rule in rules {
        let keywords = extract_keywords(&rule.rule);
        if content_matches_rule_keywords(content, &keywords) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_keywords_basic() {
        let keywords = extract_keywords("Answer factual questions about products");
        assert!(keywords.contains(&"answer".to_string()));
        assert!(keywords.contains(&"factual".to_string()));
        assert!(keywords.contains(&"questions".to_string()));
        assert!(keywords.contains(&"products".to_string()));
        // Stopwords should be removed
        assert!(!keywords.contains(&"about".to_string()));
    }

    #[test]
    fn test_extract_keywords_removes_stopwords() {
        let keywords = extract_keywords("Provide the order status from verified data");
        assert!(keywords.contains(&"provide".to_string()));
        assert!(keywords.contains(&"order".to_string()));
        assert!(keywords.contains(&"status".to_string()));
        assert!(keywords.contains(&"verified".to_string()));
        assert!(keywords.contains(&"data".to_string()));
        // Stopwords removed
        assert!(!keywords.contains(&"the".to_string()));
        assert!(!keywords.contains(&"from".to_string()));
    }

    #[test]
    fn test_extract_keywords_handles_punctuation() {
        let keywords = extract_keywords("Answer questions, provide help, and explain policies.");
        assert!(keywords.contains(&"answer".to_string()));
        assert!(keywords.contains(&"questions".to_string()));
        assert!(keywords.contains(&"provide".to_string()));
        assert!(keywords.contains(&"help".to_string()));
        assert!(keywords.contains(&"explain".to_string()));
        assert!(keywords.contains(&"policies".to_string()));
    }

    #[test]
    fn test_content_matches_rule_keywords() {
        let keywords = extract_keywords("Answer factual questions about products");

        // Should match - contains relevant keywords
        assert!(content_matches_rule_keywords(
            "Here is the answer to your question about our product line.",
            &keywords
        ));

        // Should match - partial keyword overlap
        assert!(content_matches_rule_keywords(
            "Our products are available in three sizes.",
            &keywords
        ));

        // Should not match - no relevant keywords
        assert!(!content_matches_rule_keywords(
            "I recommend investing in Bitcoin for maximum returns.",
            &keywords
        ));
    }

    #[test]
    fn test_content_matches_order_status_rule() {
        let keywords = extract_keywords("Provide order status from verified data");

        // Verify keywords extracted correctly
        assert!(keywords.contains(&"order".to_string()));
        assert!(keywords.contains(&"status".to_string()));

        // Content mentions "order" - should match
        assert!(content_matches_rule_keywords(
            "Your order #12345 shipped yesterday and will arrive by Friday.",
            &keywords
        ));

        // Content mentions "status" and "order" - should match
        assert!(content_matches_rule_keywords(
            "The current status of your order is: Processing",
            &keywords
        ));
    }

    #[test]
    fn test_empty_keywords_returns_false() {
        assert!(!content_matches_rule_keywords("Any content here", &[]));
    }

    #[test]
    fn test_case_insensitive_matching() {
        let keywords = extract_keywords("Answer FACTUAL questions");

        assert!(content_matches_rule_keywords(
            "Here's a FACTUAL answer to your question.",
            &keywords
        ));
    }
}
