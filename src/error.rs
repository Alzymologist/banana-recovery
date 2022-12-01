//! Errors.
use crate::shares::BIT_RANGE;

#[cfg(feature = "std")]
use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
    string::String,
};

#[cfg(not(feature = "std"))]
use core::fmt::{Display, Formatter, Result as FmtResult};

#[cfg(not(feature = "std"))]
use alloc::string::String;

/// Errors in split data recovery.
#[allow(missing_docs)]
#[derive(Debug)]
#[non_exhaustive]
pub enum BananaError {
    BitsOutOfRange(u32),
    DecodedSecretNotString,
    DecodingFailed,
    EmptyShare,
    JsonParsing,
    LogOutOfRange(u32),
    NonceNotBase64,
    NotShareString,
    ParseBit(char),
    ScryptFailed,
    ShareAlreadyInSet,
    ShareBitsDifferent,
    ShareContentLengthDifferent,
    ShareNonceDifferent,
    ShareRequiredSharesDifferent,
    ShareTitleDifferent { set: String, new_share: String },
    ShareTooShort,
    ShareVersionDifferent,
    UndefinedBodyNotHex,
    VersionNotSupported(u8),
    BodyNotBase64,
}

impl BananaError {
    fn error_text(&self) -> String {
        match &self {
            BananaError::BitsOutOfRange(bits) => format!("Bits in share data {} are outside of expected range [{:?}]. Likely the share is damaged.", bits, BIT_RANGE),
            BananaError::DecodedSecretNotString => String::from("Decoded secret could not be displayed as a string."),
            BananaError::DecodingFailed => String::from("Unable to decode the secret."),
            BananaError::EmptyShare => String::from("Share contains no data."),
            BananaError::JsonParsing => String::from("Unable to parse the input as a json object."),
            BananaError::LogOutOfRange(log) => format!("While processing, tried addressing log[{}] out of expected range. Likely the share is damaged.", log),
            BananaError::NonceNotBase64 => String::from("Nonce is not in base64 format."),
            BananaError::NotShareString => String::from("Received QR code could not be read as a string."),
            BananaError::ParseBit(ch) => format!("Unable to parse first data char '{}' as a number in radix36 format.", ch),
            BananaError::ScryptFailed => String::from("Scrypt calculation failed."),
            BananaError::ShareAlreadyInSet => String::from("Share is already in the set."),
            BananaError::ShareBitsDifferent => String::from("Share could not be added to the set. Bits setting is different."),
            BananaError::ShareContentLengthDifferent => String::from("Share could not be added to the set. Content length is different."),
            BananaError::ShareNonceDifferent => String::from("Share could not be added to the set. Nonce is different."),
            BananaError::ShareRequiredSharesDifferent => String::from("Share could not be added to the set. Number of required shares is different."),
            BananaError::ShareTitleDifferent { set, new_share } => format!("Share could not be added to the set. Title in set {} does not match the title of the share {}.", set, new_share),
            BananaError::ShareTooShort => String::from("Share content is too short to separate share id properly. Likely the share is damaged."),
            BananaError::ShareVersionDifferent => String::from("Share could not be added to the set. The version is different."),
            BananaError::UndefinedBodyNotHex => String::from("Share with undefined version was expected to have hexadecimal content."),
            BananaError::VersionNotSupported(version) => format!("Version {} is not supported.", version),
            BananaError::BodyNotBase64 => String::from("Share with version V1 was expected to have content in base64 format."),
        }
    }
}

impl Display for BananaError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.error_text())
    }
}

#[cfg(feature = "std")]
impl Error for BananaError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}
