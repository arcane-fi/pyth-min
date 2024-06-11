use std::fmt;

/// Standard Rust errors (NOT ANCHOR ERRORS) with the same names and internal debug message as
/// Pyth's expected Errors from the standard sdk. 
#[derive(Debug, PartialEq)]
pub enum GetPriceError {
    PriceTooOld,
    MismatchedFeedId,
    InsufficientVerificationLevel,
    FeedIdMustBe32Bytes,
    FeedIdNonHexCharacter,
}

impl fmt::Display for GetPriceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GetPriceError::PriceTooOld => write!(f, "This price feed update's age exceeds the requested maximum age"),
            GetPriceError::MismatchedFeedId => write!(f, "The price feed update doesn't match the requested feed id"),
            GetPriceError::InsufficientVerificationLevel => write!(f, "This price feed update has a lower verification level than the one requested"),
            GetPriceError::FeedIdMustBe32Bytes => write!(f, "Feed id must be 32 Bytes, that's 64 hex characters or 66 with a 0x prefix"),
            GetPriceError::FeedIdNonHexCharacter => write!(f, "Feed id contains non-hex characters"),
        }
    }
}

impl std::error::Error for GetPriceError {}

pub type Result<T> = std::result::Result<T, GetPriceError>;