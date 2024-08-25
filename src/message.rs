use crate::*;

/// A parsed message corresponding to a single line from the Linux Audit log
#[derive(Debug, Clone)]
pub struct Message<'a> {
    /// The identifier of the audit event, corresponding to `msg=audit(…)` in audit log lines
    pub id: EventID,
    /// The optional node name, corresponding to `node=…` in audit log lines
    pub node: Option<Vec<u8>>,
    /// Message type, corresponding to `type=…` in audit log lines
    pub ty: MessageType,
    /// The set of key/value parirs
    pub body: Body<'a>,
}
