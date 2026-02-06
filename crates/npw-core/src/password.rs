use serde::{Deserialize, Serialize};
use zxcvbn::zxcvbn;

pub const MASTER_PASSWORD_MIN_CHARS: usize = 12;
pub const MASTER_PASSWORD_MIN_WORDS: usize = 4;
pub const MASTER_PASSWORD_MIN_SCORE: u8 = 3;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordFeedback {
    pub warning: Option<String>,
    pub suggestions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MasterPasswordAssessment {
    pub score: u8,
    pub char_count: usize,
    pub word_count: usize,
    pub feedback: PasswordFeedback,
}

impl MasterPasswordAssessment {
    #[must_use]
    pub fn meets_min_length(&self) -> bool {
        self.char_count >= MASTER_PASSWORD_MIN_CHARS || self.word_count >= MASTER_PASSWORD_MIN_WORDS
    }

    #[must_use]
    pub fn meets_min_score(&self) -> bool {
        self.score >= MASTER_PASSWORD_MIN_SCORE
    }

    #[must_use]
    pub fn meets_policy(&self) -> bool {
        self.meets_min_length() && self.meets_min_score()
    }

    #[must_use]
    pub fn rejection_message(&self) -> String {
        let mut message = format!(
            "master password rejected: minimum is {MASTER_PASSWORD_MIN_CHARS} characters or {MASTER_PASSWORD_MIN_WORDS} words, and zxcvbn score >= {MASTER_PASSWORD_MIN_SCORE}."
        );
        message.push_str(&format!("\nzxcvbn score: {}", self.score));

        if let Some(warning) = self.feedback.warning.as_deref() {
            let warning = warning.trim();
            if !warning.is_empty() {
                message.push_str(&format!("\nwarning: {warning}"));
            }
        }

        if !self.feedback.suggestions.is_empty() {
            message.push_str("\nsuggestions:");
            for suggestion in &self.feedback.suggestions {
                let suggestion = suggestion.trim();
                if suggestion.is_empty() {
                    continue;
                }
                message.push_str(&format!("\n- {suggestion}"));
            }
        }

        message
    }
}

#[must_use]
pub fn assess_master_password(password: &str) -> MasterPasswordAssessment {
    let char_count = password.chars().count();
    let word_count = password.split_whitespace().count();

    let entropy = zxcvbn(password, &[]);

    let feedback = entropy.feedback();
    let warning = feedback.and_then(|value| value.warning().map(|warning| warning.to_string()));
    let suggestions = feedback
        .map(|value| {
            value
                .suggestions()
                .iter()
                .map(|suggestion| suggestion.to_string())
                .collect()
        })
        .unwrap_or_default();

    MasterPasswordAssessment {
        score: u8::from(entropy.score()),
        char_count,
        word_count,
        feedback: PasswordFeedback {
            warning,
            suggestions,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_password_fails_policy() {
        let assessment = assess_master_password("password");
        assert!(!assessment.meets_policy());
        assert!(assessment.score < MASTER_PASSWORD_MIN_SCORE);
        assert!(
            assessment.feedback.warning.is_some() || !assessment.feedback.suggestions.is_empty()
        );
    }

    #[test]
    fn strong_password_passes_policy() {
        let assessment = assess_master_password("cX9!pQ2@rL7#sZ8$uV1%yT4");
        assert!(assessment.meets_policy());
        assert!(assessment.score >= MASTER_PASSWORD_MIN_SCORE);
    }
}
