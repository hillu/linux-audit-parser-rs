use std::fmt::{self, Debug};
use std::ops::Range;

#[cfg(feature = "serde")]
use serde::{ser::SerializeMap, Serialize, Serializer};

use crate::*;

/// Parsed body of an Audit message, consisting of [`Key`]/[`Value`] pairs.
pub struct Body<'a> {
    elems: Vec<(Key, Value<'a>)>,
    arena: Vec<Vec<u8>>,
    _pin: std::marker::PhantomPinned,
}

impl Default for Body<'_> {
    fn default() -> Self {
        Body {
            elems: Vec::with_capacity(8),
            arena: vec![],
            _pin: std::marker::PhantomPinned,
        }
    }
}

impl Debug for Body<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut seq = f.debug_struct("Body");
        for (k, v) in self {
            seq.field(&k.to_string(), &v);
        }
        seq.finish()
    }
}

#[cfg(feature = "serde")]
impl Serialize for Body<'_> {
    #[inline(always)]
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(None)?;
        for (k, v) in self.into_iter() {
            match k {
                Key::Arg(_, _) | Key::ArgLen(_) => continue,
                _ => map.serialize_entry(&k, &v)?,
            }
        }
        map.end()
    }
}

impl Body<'_> {
    /// Constructs a new, empty `Body`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Constructs a new, empty `Body` with at least the specified
    /// `capacity` for `Key`/`Value` entries.
    pub fn with_capacity(len: usize) -> Self {
        Self {
            elems: Vec::with_capacity(len),
            ..Self::default()
        }
    }

    fn add_slice<'a, 'i>(&mut self, input: &'i [u8]) -> &'a [u8]
    where
        'a: 'i,
    {
        let ilen = input.len();

        // let changed_buf: &Vec<u8>;
        for buf in self.arena.iter() {
            let Range { start, end } = input.as_ptr_range();
            if buf.as_slice().as_ptr_range().contains(&start)
                && buf.as_slice().as_ptr_range().contains(&end)
            {
                let s = std::ptr::slice_from_raw_parts(start, ilen);
                return unsafe { &*s };
            }
        }
        for buf in self.arena.iter_mut() {
            if buf.capacity() - buf.len() > ilen {
                let e = buf.len();
                buf.extend(input);
                let s = std::ptr::slice_from_raw_parts(buf[e..].as_ptr(), ilen);
                return unsafe { &*s };
            }
        }
        self.arena
            .push(Vec::with_capacity(1014 * (1 + (ilen / 1024))));
        let i = self.arena.len() - 1;
        let new_buf = &mut self.arena[i];
        new_buf.extend(input);
        let s = std::ptr::slice_from_raw_parts(new_buf[..].as_ptr(), ilen);
        unsafe { &*s }
    }

    fn add_value<'a, 'i>(&mut self, v: Value<'i>) -> Value<'a>
    where
        'a: 'i,
    {
        match v {
            Value::Str(s, q) => Value::Str(self.add_slice(s), q),
            Value::Owned(s) => Value::Str(self.add_slice(s.as_slice()), Quote::None),
            Value::List(vs) => Value::List(vs.into_iter().map(|v| self.add_value(v)).collect()),
            Value::StringifiedList(vs) => {
                Value::StringifiedList(vs.into_iter().map(|v| self.add_value(v)).collect())
            }
            Value::Segments(vs) => {
                let vs = vs.iter().map(|s| self.add_slice(s)).collect();
                Value::Segments(vs)
            }
            Value::Map(vs) => Value::Map(
                vs.into_iter()
                    .map(|(k, v)| (k, self.add_value(v)))
                    .collect(),
            ),
            // safety: These enum variants are self-contained.
            Value::Empty | Value::Literal(_) | Value::Number(_) | Value::Skipped(_) => unsafe {
                std::mem::transmute::<Value<'i>, Value<'a>>(v)
            },
        }
    }

    /// Appends `kv` to the back of a Body.
    pub fn push(&mut self, kv: (Key, Value)) {
        let (k, v) = kv;
        let v = self.add_value(v);
        self.elems.push((k, v));
    }

    /// Returns the number of elements in the `Body`.
    pub fn len(&self) -> usize {
        self.elems.len()
    }

    /// Extends Body with the elements of another `Body`.
    pub fn extend(&mut self, other: Self) {
        self.arena.extend(other.arena);
        self.elems.reserve(other.elems.len());
        for (k, v) in other.elems {
            self.push((k, v));
        }
    }

    /// Returns `true` if the `Body` has a length of 0.
    pub fn is_empty(&self) -> bool {
        self.elems.is_empty()
    }

    /// Retrieves the first value found for a given `key`.
    pub fn get<K: AsRef<[u8]>>(&self, key: K) -> Option<&Value> {
        let key = key.as_ref();
        self.elems.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Reserves capacity for at least `additional` more elements.
    pub fn reserve(&mut self, additional: usize) {
        self.elems.reserve(additional);
    }
}

impl<'a> Body<'a> {
    /// Retains only the elements specified by the predicate.
    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&(Key, Value<'a>)) -> bool,
    {
        self.elems.retain(f)
    }
}

impl Clone for Body<'_> {
    fn clone(&self) -> Self {
        let mut new = Body::default();
        self.into_iter()
            .cloned()
            .for_each(|(k, v)| new.push((k, v)));
        new
    }
}

impl<'a> IntoIterator for &'a Body<'a> {
    type Item = &'a (Key, Value<'a>);
    type IntoIter = std::slice::Iter<'a, (Key, Value<'a>)>;
    fn into_iter(self) -> Self::IntoIter {
        self.elems.iter()
    }
}
