#[cfg(feature = "serde")]
use serde::{Serialize, Serializer};

use std::fmt::{self, Display};

/// The identifier of an audit event, corresponding to the
/// `msg=audit(…)` part of every Linux Audit log line.
///
/// The event ID can reasonably be expected to be unique per system.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy, Default)]
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

#[cfg(feature = "serde")]
impl Serialize for EventID {
    #[inline(always)]
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&self)
    }
}

impl PartialEq<str> for EventID {
    fn eq(&self, other: &str) -> bool {
        format!("{self}") == other
    }
}
