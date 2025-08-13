#[cfg(feature = "serde")]
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::fmt::{self, Debug, Display};
use std::str::{self, FromStr};

use thiserror::Error;

use crate::constants::*;

/// Type of an audit message, corresponding to the `type=…` part of
/// every Linux Audit log line.
///
/// The implementation uses the same 32bit unsigned integer values
/// that are used by the Linux Audit API. Mappings between numeric and
/// symbolic values is generated using CSV retrieved from the [`Linux
/// Audit Project`]'s documentation.
///
/// [`Linux Audit Project`]: https://github.com/linux-audit/audit-documentation
#[derive(PartialEq, Eq, Hash, Default, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(DeserializeFromStr, SerializeDisplay))]
pub struct MessageType(pub u32);

impl Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match EVENT_NAMES.get(&(self.0)) {
            Some(name) => write!(f, "{name}"),
            None => write!(f, "UNKNOWN[{}]", self.0),
        }
    }
}

impl Debug for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match EVENT_NAMES.get(&(self.0)) {
            Some(name) => write!(f, "MessageType({name})"),
            None => write!(f, "MessageType({})", self.0),
        }
    }
}

/// The error type returned by [MessageType::from_str]
#[derive(Debug, Error)]
pub enum ParseMessageTypeError {
    #[error("unknown identifier ({0})")]
    Unknown(String),
    #[error("malformed UNKNOWN[…] string")]
    MalformedUnknown,
    #[error("cannot parse number ({0}): {1}")]
    Number(String, std::num::ParseIntError),
}

impl FromStr for MessageType {
    type Err = ParseMessageTypeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(id) = EVENT_IDS.get(s.as_bytes()) {
            Ok(MessageType(*id))
        } else {
            let number = s
                .strip_prefix("UNKNOWN[")
                .ok_or_else(|| ParseMessageTypeError::Unknown(s.into()))?
                .strip_suffix(']')
                .ok_or(ParseMessageTypeError::MalformedUnknown)?;
            let id = u32::from_str(number)
                .map_err(|e| ParseMessageTypeError::Number(number.into(), e))?;
            Ok(MessageType(id))
        }
    }
}

include!(concat!(env!("OUT_DIR"), "/message_type_impl.rs"));

impl MessageType {
    /// True for messages that are part of multi-part events from
    /// kernel-space.
    ///
    /// This mimics auparse logic as of version 3.0.6
    pub fn is_multipart(&self) -> bool {
        (1300..2100).contains(&self.0) || self == &MessageType::LOGIN
    }
}
