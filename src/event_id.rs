#[cfg(feature = "serde")]
use serde_with::{DeserializeFromStr, SerializeDisplay};

use std::fmt::{self, Display};
use std::str::FromStr;

use thiserror::Error;

/// The identifier of an audit event, corresponding to the
/// `msg=audit(…)` part of every Linux Audit log line.
///
/// The event ID can reasonably be expected to be unique per system.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy, Default)]
#[cfg_attr(feature = "serde", derive(DeserializeFromStr, SerializeDisplay))]
pub struct EventID {
    /// Unix epoch-based timestamp, with mullisecond-precision
    pub timestamp: u64,
    /// Sequence number
    pub sequence: u32,
}

impl Display for EventID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let sec = self.timestamp / 1000;
        let msec = self.timestamp % 1000;
        let seq = self.sequence;
        write!(f, "{sec}.{msec:03}:{seq}")
    }
}

/// The error type returned by [EventID::from_str]
#[derive(Debug, Error)]
pub enum ParseEventIDError {
    #[error("wrong format (character '{0}' not found)")]
    Format(char),
    #[error("cannot parse number: {0}")]
    Number(std::num::ParseIntError),
}

impl FromStr for EventID {
    type Err = ParseEventIDError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (sec, rest) = s.split_once(".").ok_or(ParseEventIDError::Format('.'))?;
        let (msec, seq) = rest.split_once(":").ok_or(ParseEventIDError::Format(':'))?;
        Ok(EventID {
            timestamp: u64::from_str(sec).map_err(ParseEventIDError::Number)? * 1000
                + u64::from_str(msec).map_err(ParseEventIDError::Number)?,
            sequence: u32::from_str(seq).map_err(ParseEventIDError::Number)?,
        })
    }
}

impl PartialEq<str> for EventID {
    fn eq(&self, other: &str) -> bool {
        format!("{self}") == other
    }
}
