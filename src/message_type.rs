use std::fmt::{self, Debug, Display};

#[cfg(feature = "serde")]
use serde::{Serialize, Serializer};

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

#[cfg(feature = "serde")]
impl Serialize for MessageType {
    #[inline(always)]
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match EVENT_NAMES.get(&(self.0)) {
            Some(name) => s.collect_str(name),
            None => s.collect_str(&format_args!("UNKNOWN[{}]", self.0)),
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
