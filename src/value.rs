use std::convert::{Into, TryFrom};
use std::fmt::{self, Debug, Display};
use std::iter::Iterator;
use std::str;
use std::string::*;

#[cfg(feature = "serde")]
use serde::{ser::SerializeMap, Serialize, Serializer};

use crate::*;

/// Quotes types in [`Value`] strings
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Quote {
    None,
    Single,
    Double,
    Braces,
}

#[derive(Clone)]
/// [`Value`]s parsed as hexadecimal, decimal, or octal numbers
pub enum Number {
    Hex(u64),
    Dec(i64),
    Oct(u64),
}

impl Debug for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Num:<{self}>")
    }
}

impl Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Number::Hex(n) => write!(f, "0x{n:x}"),
            Number::Oct(n) => write!(f, "0o{n:o}"),
            Number::Dec(n) => write!(f, "{n}"),
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for Number {
    #[inline(always)]
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Number::Dec(n) => s.serialize_i64(*n),
            _ => s.collect_str(&self),
        }
    }
}

/// Representation of the value part of key/value pairs in [`Body`]
#[derive(Clone)]
pub enum Value<'a> {
    /// Empty value.
    Empty,
    /// A byte string.
    Str(&'a [u8], Quote),
    /// Parsed number.
    Number(Number),
    /// A list of byte strings.
    List(Vec<Value<'a>>),
    /// A byte string that is not stored within the [`Body`]. Used for
    /// decoded hex-strings.
    Owned(Vec<u8>),
    /// An internal key/value map. Not currently produced by the parser.
    Map(Vec<(Key, Value<'a>)>),
    /// Non-contiguous byte string. Not produced by the parser.
    Segments(Vec<&'a [u8]>),
    StringifiedList(Vec<Value<'a>>),
    /// Elements removed from ARGV lists. Not produced by the parser.
    Skipped((usize, usize)),
    /// A literal string. Not produced by the parser.
    Literal(&'static str),
}

impl Default for Value<'_> {
    fn default() -> Self {
        Self::Empty
    }
}

impl Value<'_> {
    pub fn str_len(&self) -> usize {
        match self {
            Value::Str(r, _) => r.len(),
            Value::Segments(vr) => vr.iter().map(|r| r.len()).sum(),
            _ => 0,
        }
    }
}

impl TryFrom<Value<'_>> for Vec<u8> {
    type Error = &'static str;
    fn try_from(v: Value) -> Result<Self, Self::Error> {
        match v {
            Value::Str(r, Quote::Braces) => {
                let mut s = Vec::with_capacity(r.len() + 2);
                s.push(b'{');
                s.extend(Vec::from(r));
                s.push(b'}');
                Ok(s)
            }
            Value::Str(r, _) => Ok(Vec::from(r)),
            Value::Empty => Ok("".into()),
            Value::Segments(ranges) => {
                let l = ranges.iter().map(|r| r.len()).sum();
                let mut sb = Vec::with_capacity(l);
                for r in ranges {
                    sb.extend(Vec::from(r));
                }
                Ok(sb)
            }
            Value::Number(_) => Err("Won't convert number to string"),
            Value::List(_) | Value::StringifiedList(_) => Err("Can't convert list to scalar"),
            Value::Map(_) => Err("Can't convert map to scalar"),
            Value::Skipped(_) => Err("Can't convert skipped to scalar"),
            Value::Literal(s) => Ok(s.to_string().into()),
            Value::Owned(v) => Ok(v),
        }
    }
}

impl TryFrom<Value<'_>> for Vec<Vec<u8>> {
    type Error = &'static str;
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::List(values) | Value::StringifiedList(values) => {
                let mut rv = Vec::with_capacity(values.len());
                for v in values {
                    let s = Vec::try_from(v)?;
                    rv.push(s);
                }
                Ok(rv)
            }
            _ => Err("not a list"),
        }
    }
}

impl Debug for Value<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Str(r, _q) => write!(f, "Str:<{}>", &String::from_utf8_lossy(r)),
            Value::Empty => write!(f, "Empty"),
            Value::Segments(segs) => {
                write!(f, "Segments<")?;
                for (n, r) in segs.iter().enumerate() {
                    if n > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", String::from_utf8_lossy(r))?;
                }
                write!(f, ">")
            }
            Value::List(vs) => {
                write!(f, "List:<")?;
                for (n, v) in vs.iter().enumerate() {
                    if n > 0 {
                        write!(f, ", ")?;
                    }
                    match v {
                        Value::Str(r, _) => {
                            write!(f, "{}", String::from_utf8_lossy(r))?;
                        }
                        Value::Segments(rs) => {
                            for r in rs {
                                write!(f, "{}", String::from_utf8_lossy(r))?;
                            }
                        }
                        Value::Number(n) => write!(f, "{n:?}")?,
                        Value::Skipped((elems, bytes)) => {
                            write!(f, "Skip<elems{elems} bytes={bytes}>")?;
                        }
                        Value::Empty => panic!("list can't contain empty value"),
                        Value::List(_) | Value::StringifiedList(_) => {
                            panic!("list can't contain list")
                        }
                        Value::Map(_) => panic!("list can't contain map"),
                        Value::Literal(v) => write!(f, "{v:?}")?,
                        Value::Owned(v) => write!(f, "{}", String::from_utf8_lossy(v))?,
                    }
                }
                write!(f, ">")
            }
            Value::StringifiedList(vs) => {
                write!(f, "StringifiedList:<")?;
                for (n, v) in vs.iter().enumerate() {
                    if n > 0 {
                        write!(f, " ")?;
                    }
                    match v {
                        Value::Str(r, _) => {
                            write!(f, "{}", String::from_utf8_lossy(r))?;
                        }
                        Value::Segments(rs) => {
                            for r in rs {
                                write!(f, "{}", String::from_utf8_lossy(r))?;
                            }
                        }
                        Value::Number(n) => write!(f, "{n:?}")?,
                        Value::Skipped((elems, bytes)) => {
                            write!(f, "Skip<elems={elems} bytes={bytes}>")?;
                        }
                        Value::Empty => panic!("list can't contain empty value"),
                        Value::List(_) | Value::StringifiedList(_) => {
                            panic!("list can't contain list")
                        }
                        Value::Map(_) => panic!("List can't contain mapr"),
                        Value::Literal(v) => write!(f, "{v}")?,
                        Value::Owned(v) => write!(f, "{}", String::from_utf8_lossy(v))?,
                    }
                }
                write!(f, ">")
            }
            Value::Map(vs) => {
                write!(f, "Map:<")?;
                for (n, (k, v)) in vs.iter().enumerate() {
                    if n > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{k:?}={v:?}")?;
                }
                write!(f, ">")
            }
            Value::Number(n) => write!(f, "{n:?}"),
            Value::Skipped((elems, bytes)) => write!(f, "Skip<elems={elems} bytes={bytes}>"),
            Value::Literal(s) => write!(f, "{s:?}"),
            Value::Owned(v) => write!(f, "{}", String::from_utf8_lossy(v)),
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for Value<'_> {
    #[inline(always)]
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Value::Empty => s.serialize_none(),
            Value::Str(r, Quote::Braces) => {
                let mut buf = Vec::with_capacity(r.len() + 2);
                buf.push(b'{');
                buf.extend(*r);
                buf.push(b'}');
                s.serialize_bytes(&buf)
            }
            Value::Str(r, _) => s.serialize_bytes(r),
            Value::Segments(segs) => {
                let l = segs.iter().map(|r| r.len()).sum();
                let mut buf = Vec::with_capacity(l);
                for seg in segs {
                    buf.extend(*seg);
                }
                s.serialize_bytes(&buf)
            }
            Value::List(vs) => s.collect_seq(vs.iter()),
            Value::StringifiedList(vs) => {
                let mut buf: Vec<u8> = Vec::with_capacity(vs.len());
                let mut first = true;
                for v in vs {
                    if first {
                        first = false;
                    } else {
                        buf.push(b' ');
                    }
                    if let Value::Skipped((args, bytes)) = v {
                        buf.extend(format!("<<< Skipped: args={args}, bytes={bytes} >>>").bytes());
                    } else {
                        buf.extend(v.clone().try_into().unwrap_or_else(|_| vec![b'x']));
                    }
                }
                s.serialize_bytes(&buf)
            }
            Value::Number(n) => n.serialize(s),
            Value::Map(vs) => s.collect_map(vs.iter().cloned()),
            Value::Skipped((args, bytes)) => {
                let mut map = s.serialize_map(Some(2))?;
                map.serialize_entry("skipped_args", args)?;
                map.serialize_entry("skipped_bytes", bytes)?;
                map.end()
            }
            Value::Literal(v) => s.collect_str(v),
            Value::Owned(v) => Bytes(v).serialize(s),
        }
    }
}

impl PartialEq<str> for Value<'_> {
    fn eq(&self, other: &str) -> bool {
        self == other.as_bytes()
    }
}

impl PartialEq<[u8]> for Value<'_> {
    fn eq(&self, other: &[u8]) -> bool {
        match self {
            Value::Empty => other.is_empty(),
            Value::Str(r, _) => r == &other,
            Value::Segments(segs) => {
                let l = segs.iter().map(|s| s.len()).sum();
                let mut buf: Vec<u8> = Vec::with_capacity(l);
                for s in segs {
                    buf.extend(*s);
                }
                buf == other
            }
            Value::Literal(s) => s.as_bytes() == other,
            Value::Owned(v) => v == other,
            Value::List(_)
            | Value::StringifiedList(_)
            | Value::Map(_)
            | Value::Skipped(_)
            | Value::Number(_) => false,
        }
    }
}

impl<'a> From<&'a [u8]> for Value<'a> {
    fn from(value: &'a [u8]) -> Self {
        Value::Str(value, Quote::None)
    }
}

impl<'a> From<&'a str> for Value<'a> {
    fn from(value: &'a str) -> Self {
        Self::from(value.as_bytes())
    }
}

impl From<Vec<u8>> for Value<'_> {
    fn from(value: Vec<u8>) -> Self {
        Value::Owned(value)
    }
}

impl From<String> for Value<'_> {
    fn from(value: String) -> Self {
        Self::from(Vec::from(value))
    }
}

impl From<i64> for Value<'_> {
    fn from(value: i64) -> Self {
        Value::Number(Number::Dec(value))
    }
}

/// Helper type to enforce that serialize_bytes() is used in serialization.
#[cfg(feature = "serde")]
pub(crate) struct Bytes<'a>(pub &'a [u8]);

#[cfg(feature = "serde")]
impl Serialize for Bytes<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0)
    }
}
