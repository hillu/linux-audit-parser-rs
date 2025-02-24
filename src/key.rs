use std::fmt::{self, Debug, Display};
use std::str::{self, FromStr};
use std::convert::Infallible;

#[cfg(feature = "serde")]
use serde_with::{DeserializeFromStr, SerializeDisplay};

/// Common [`Key`]s found in SYSCALL records
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
#[repr(usize)]
pub enum Common {
    Arch,
    Argc,
    CapFe,
    CapFi,
    CapFp,
    CapFver,
    Comm,
    Cwd,
    Dev,
    Exe,
    Exit,
    Inode,
    Item,
    Items,
    Key,
    Mode,
    Msg,
    Name,
    Nametype,
    Pid,
    PPid,
    Ses,
    Subj,
    Success,
    Syscall,
    Tty,
}

const COMMON: &[(&str, Common)] = &[
    ("arch", Common::Arch),
    ("argc", Common::Argc),
    ("cap_fe", Common::CapFe),
    ("cap_fi", Common::CapFi),
    ("cap_fp", Common::CapFp),
    ("cap_fver", Common::CapFver),
    ("comm", Common::Comm),
    ("cwd", Common::Cwd),
    ("dev", Common::Dev),
    ("exe", Common::Exe),
    ("exit", Common::Exit),
    ("inode", Common::Inode),
    ("item", Common::Item),
    ("items", Common::Items),
    ("key", Common::Key),
    ("mode", Common::Mode),
    ("msg", Common::Msg),
    ("name", Common::Name),
    ("nametype", Common::Nametype),
    ("pid", Common::Pid),
    ("ppid", Common::PPid),
    ("ses", Common::Ses),
    ("subj", Common::Subj),
    ("success", Common::Success),
    ("syscall", Common::Syscall),
    ("tty", Common::Tty),
];

impl TryFrom<&[u8]> for Common {
    type Error = &'static str;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let i = COMMON
            .binary_search_by_key(&value, |(s, _)| s.as_bytes())
            .map_err(|_| "unknown key")?;
        Ok(COMMON[i].1)
    }
}

impl From<Common> for &'static str {
    fn from(value: Common) -> Self {
        COMMON[value as usize].0
    }
}

impl Display for Common {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = COMMON[*self as usize].0;
        write!(f, "{c}")
    }
}

pub(crate) type NVec = tinyvec::TinyVec<[u8; 14]>;

/// Representation of the key part of key/value pairs in [`Body`]
///
/// [`Body`]: crate::Body
#[derive(PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(SerializeDisplay, DeserializeFromStr))]
pub enum Key {
    /// regular ASCII-only name as returned by parser
    Name(NVec),
    /// ASCII-only name for UID fields
    NameUID(NVec),
    /// ASCII-only name for GID fields
    NameGID(NVec),
    /// special case for common values
    Common(Common),
    /// regular ASCII-only name, output/serialization in all-caps, for
    /// translated / "enriched" values
    NameTranslated(NVec),
    /// special case for argument lists: `a0`, `a1`, (`SYSCALL` and
    /// `EXECVE`); `a2[0]`, `a2[1]` (`EXECVE`)
    Arg(u32, Option<u16>),
    /// `a0_len` as found in `EXECVE` lines
    ArgLen(u32),
    /// Not returned by parser
    Literal(&'static str),
}

impl Default for Key {
    fn default() -> Self {
        Key::Literal("no_key")
    }
}

impl Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string())
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Key::Arg(x, Some(y)) => write!(f, "a{x}[{y}]"),
            Key::Arg(x, None) => write!(f, "a{x}"),
            Key::ArgLen(x) => write!(f, "a{x}_len"),
            Key::Name(r) | Key::NameUID(r) | Key::NameGID(r) => {
                // safety: The parser guarantees an ASCII-only key.
                let s = unsafe { str::from_utf8_unchecked(r) };
                f.write_str(s)
            }
            Key::Common(c) => write!(f, "{c}"),
            Key::NameTranslated(r) => {
                // safety: The parser guarantees an ASCII-only key.
                let s = unsafe { str::from_utf8_unchecked(r) };
                f.write_str(&str::to_ascii_uppercase(s))
            }
            Key::Literal(s) => f.write_str(s),
        }
    }
}

fn try_parse_a(s: &str) -> Option<Key> {
    match s.strip_prefix("a") {
        Some(s) => {
            if let Some(s) = s.strip_suffix("]") {
                let (x, y) = s.split_once("[")?;
                Some(Key::Arg(
                    u32::from_str(x).ok()?,
                    Some(u16::from_str(y).ok()?),
                ))
            } else if let Some(s) = s.strip_suffix("_len") {
                Some(Key::ArgLen(u32::from_str(s).ok()?))
            } else {
                Some(Key::Arg(u32::from_str(s).ok()?, None))
            }
        }
        _ => None,
    }
}

impl FromStr for Key {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(c) = Common::try_from(s.as_bytes()) {
            Ok(Key::Common(c))
        } else if let Some(k) = try_parse_a(s) {
            Ok(k)
        } else if s.ends_with("uid") {
            Ok(Key::NameUID(s.as_bytes().into()))
        } else if s.ends_with("gid") {
            Ok(Key::NameGID(s.as_bytes().into()))
        } else {
            Ok(Key::from(s.as_bytes()))
        }
    }
}

impl PartialEq<str> for Key {
    fn eq(&self, other: &str) -> bool {
        self == other.as_bytes()
    }
}

impl PartialEq<[u8]> for Key {
    fn eq(&self, other: &[u8]) -> bool {
        match self {
            Key::Name(r) | Key::NameUID(r) | Key::NameGID(r) => r.as_ref() == other,
            _ => self.to_string().as_bytes() == other,
        }
    }
}

impl From<&'static str> for Key {
    fn from(value: &'static str) -> Self {
        Self::Literal(value)
    }
}

impl From<&[u8]> for Key {
    fn from(value: &[u8]) -> Self {
        Self::Name(NVec::from(value))
    }
}
