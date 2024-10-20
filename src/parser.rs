use std::convert::{From, TryFrom};
use std::str;

use nom::{
    branch::*, bytes::complete::*, character::complete::*, character::*, combinator::*, multi::*,
    sequence::*, IResult,
};

use nom::character::complete::{i64 as dec_i64, u16 as dec_u16, u32 as dec_u32, u64 as dec_u64};

use thiserror::Error;

use crate::constants::*;
use crate::*;

/// Parser for Linux Audit messages, with a few configurable options
#[derive(Debug)]
pub struct Parser {
    /// Process enriched (i.e. ALL-CAPS keys). Default: true
    pub enriched: bool,
    /// Try to process common msg='…' strings into key/value maps. Default: true
    pub split_msg: bool,
}

impl Default for Parser {
    fn default() -> Self {
        Self {
            enriched: true,
            split_msg: true,
        }
    }
}

/// Audit parser error type
#[derive(Debug, Error)]
pub enum ParseError {
    /// The header (`type= … msg=audit(…):`) could not be parsed.
    #[error("cannot parse header: {}", String::from_utf8_lossy(.0))]
    MalformedHeader(Vec<u8>),
    /// The body (everything after the event ID) could not be parsed.
    #[error("cannot parse body: {}", String::from_utf8_lossy(.0))]
    MalformedBody(Vec<u8>),
    /// Garbage text was found at the end of the body.
    #[error("garbage at end of message: {}", String::from_utf8_lossy(.0))]
    TrailingGarbage(Vec<u8>),
    /// A value in hexadecimal encoding could not be converted.
    #[error("{id} ({ty}) can't hex-decode {}", String::from_utf8_lossy(.hex_str))]
    HexDecodeError {
        ty: MessageType,
        id: EventID,
        hex_str: Vec<u8>,
    },
}

/// Parse a single log line as produced by _auditd(8)_
///
/// If `skip_enriched` is set and _auditd_ has been configured to
/// produce `log_format=ENRICHED` logs, i.e. to resolve `uid`, `gid`,
/// `syscall`, `arch`, `sockaddr` fields, those resolved values are
/// dropped by the parser.
///
/// To maintain compatibility, `parse` does not attempt to process
/// single-quoted `msg='…'` strings into key/value maps.
pub fn parse<'a>(raw: &[u8], skip_enriched: bool) -> Result<Message<'a>, ParseError> {
    Parser {
        enriched: !skip_enriched,
        ..Parser::default()
    }
    .parse(raw)
}

impl Parser {
    /// Parse a single log line as produced by _auditd(8)_
    pub fn parse<'a, 'b>(&'a self, raw: &'a [u8]) -> Result<Message<'b>, ParseError> {
        let (rest, (node, ty, id)) =
            parse_header(raw).map_err(|_| ParseError::MalformedHeader(raw.to_vec()))?;

        let (rest, kv) = self
            .parse_body(rest, ty)
            .map_err(|_| ParseError::MalformedBody(rest.to_vec()))?;

        if !rest.is_empty() {
            return Err(ParseError::TrailingGarbage(rest.to_vec()));
        }

        let node = node.map(|s| s.to_vec());

        let mut body = Body::new();
        for (k, v) in kv {
            body.push((k, v));
        }

        Ok(Message { id, node, ty, body })
    }

    /// Recognize the body: Multiple key/value pairs, with special cases
    /// for some irregular messages
    #[inline(always)]
    fn parse_body<'a>(
        &'a self,
        input: &'a [u8],
        ty: MessageType,
    ) -> IResult<&'a [u8], Vec<(Key, Value)>> {
        // Handle some corner cases that don't fit the general key=value
        // scheme.
        let (input, special) = match ty {
            MessageType::AVC => opt(map(
                tuple((
                    preceded(
                        pair(tag("avc:"), space0),
                        alt((tag("granted"), tag("denied"))),
                    ),
                    delimited(
                        tuple((space0, tag("{"), space0)),
                        many1(terminated(parse_identifier, space0)),
                        tuple((tag("}"), space0, tag("for"), space0)),
                    ),
                )),
                |(k, v)| {
                    (
                        Key::Name(NVec::from(k)),
                        Value::List(
                            v.iter()
                                .map(|e| Value::Str(e, Quote::None))
                                .collect::<Vec<_>>(),
                        ),
                    )
                },
            ))(input)?,
            MessageType::TTY => {
                let (input, _) = opt(tag("tty "))(input)?;
                (input, None)
            }
            MessageType::MAC_POLICY_LOAD => {
                let (input, _) = opt(tag("policy loaded "))(input)?;
                (input, None)
            }
            _ => opt(map(
                terminated(tag("netlabel"), pair(tag(":"), space0)),
                |s| (Key::Name(NVec::from(s)), Value::Empty),
            ))(input)?,
        };

        let (input, mut kv) = if !self.enriched {
            terminated(
                separated_list0(tag(b" "), |input| self.parse_kv(input, ty)),
                alt((
                    value(
                        (),
                        tuple((tag("\x1d"), is_not("\n"), alt((tag("\n"), eof)))),
                    ),
                    value((), alt((tag("\n"), eof))),
                )),
            )(input)?
        } else {
            terminated(
                separated_list0(take_while1(|c| c == b' ' || c == b'\x1d'), |input| {
                    self.parse_kv(input, ty)
                }),
                alt((tag("\n"), eof)),
            )(input)?
        };

        if let Some(s) = special {
            kv.push(s)
        }

        Ok((input, kv))
    }

    /// Recognize one key/value pair
    #[inline(always)]
    fn parse_kv<'a>(&'a self, input: &'a [u8], ty: MessageType) -> IResult<&'a [u8], (Key, Value)> {
        let (input, key) = match ty {
            // Special case for execve arguments: aX, aX[Y], aX_len
            MessageType::EXECVE
                if !input.is_empty() && input[0] == b'a' && !input.starts_with(b"argc") =>
            {
                terminated(
                    alt((parse_key_a_x_len, parse_key_a_xy, parse_key_a_x)),
                    tag("="),
                )(input)
            }
            // Special case for syscall params: aX
            MessageType::SYSCALL => terminated(alt((parse_key_a_x, parse_key)), tag("="))(input),
            _ => terminated(parse_key, tag("="))(input),
        }?;

        let (input, value) = match (ty, &key) {
            (MessageType::SYSCALL, Key::Arg(_, None)) => map(
                recognize(terminated(
                    many1_count(take_while1(is_hex_digit)),
                    peek(take_while1(is_sep)),
                )),
                |s| {
                    let ps = unsafe { str::from_utf8_unchecked(s) };
                    match u64::from_str_radix(ps, 16) {
                        Ok(n) => Value::Number(Number::Hex(n)),
                        Err(_) => Value::Str(s, Quote::None),
                    }
                },
            )(input)?,
            (MessageType::SYSCALL, Key::Common(c)) => self.parse_common(input, ty, *c)?,
            (MessageType::EXECVE, Key::Arg(_, _)) => parse_encoded(input)?,
            (MessageType::EXECVE, Key::ArgLen(_)) => parse_dec(input)?,
            (_, Key::Name(name)) => parse_named(input, ty, name)?,
            (_, Key::Common(c)) => self.parse_common(input, ty, *c)?,
            (_, Key::NameUID(name)) | (_, Key::NameGID(name)) => {
                alt((parse_dec, |input| parse_unspec_value(input, ty, name)))(input)?
            }
            _ => parse_encoded(input)?,
        };

        Ok((input, (key, value)))
    }

    #[inline(always)]
    fn parse_common<'a>(
        &'a self,
        input: &'a [u8],
        ty: MessageType,
        c: Common,
    ) -> IResult<&'a [u8], Value> {
        let name = <&str>::from(c).as_bytes();
        match c {
            Common::Arch | Common::CapFi | Common::CapFp | Common::CapFver => {
                alt((parse_hex, |input| parse_unspec_value(input, ty, name)))(input)
            }
            Common::Argc
            | Common::Exit
            | Common::CapFe
            | Common::Inode
            | Common::Item
            | Common::Items
            | Common::Pid
            | Common::PPid
            | Common::Ses
            | Common::Syscall => {
                alt((parse_dec, |input| parse_unspec_value(input, ty, name)))(input)
            }
            Common::Success
            | Common::Cwd
            | Common::Dev
            | Common::Tty
            | Common::Comm
            | Common::Exe
            | Common::Name
            | Common::Nametype
            | Common::Subj
            | Common::Key => {
                alt((parse_encoded, |input| parse_unspec_value(input, ty, name)))(input)
            }
            Common::Mode => alt((parse_oct, |input| parse_unspec_value(input, ty, name)))(input),
            Common::Msg => {
                if self.split_msg {
                    alt((parse_kv_sq_as_map, |input| {
                        parse_unspec_value(input, ty, name)
                    }))(input)
                } else {
                    alt((parse_encoded, |input| parse_unspec_value(input, ty, name)))(input)
                }
            }
        }
    }
}

/// Recognize the header: node, type, event identifier
#[inline(always)]
#[allow(clippy::type_complexity)]
fn parse_header(input: &[u8]) -> IResult<&[u8], (Option<&[u8]>, MessageType, EventID)> {
    tuple((
        opt(terminated(parse_node, is_a(" "))),
        terminated(parse_type, is_a(" ")),
        parse_msgid,
    ))(input)
}

/// Recognize the node name
#[inline(always)]
fn parse_node(input: &[u8]) -> IResult<&[u8], &[u8]> {
    preceded(tag("node="), is_not(" \t\r\n"))(input)
}

/// Recognize event type
#[inline(always)]
fn parse_type(input: &[u8]) -> IResult<&[u8], MessageType> {
    preceded(
        tag("type="),
        alt((
            map_res(
                recognize(many1_count(alt((alphanumeric1, tag("_"))))),
                |s| {
                    EVENT_IDS
                        .get(s)
                        .ok_or(format!("unknown event id {}", String::from_utf8_lossy(s)))
                        .map(|n| MessageType(*n))
                },
            ),
            map(delimited(tag("UNKNOWN["), dec_u32, tag("]")), MessageType),
        )),
    )(input)
}

/// Recognize the "msg=audit(…):" event identifier
#[inline(always)]
fn parse_msgid(input: &[u8]) -> IResult<&[u8], EventID> {
    map(
        tuple((
            preceded(tag("msg=audit("), dec_u64),
            delimited(tag("."), dec_u64, tag(":")),
            terminated(dec_u32, pair(tag("):"), space0)),
        )),
        |(sec, msec, sequence)| EventID {
            timestamp: 1000 * sec + msec,
            sequence,
        },
    )(input)
}

#[inline(always)]
fn parse_named<'a>(input: &'a [u8], ty: MessageType, name: &[u8]) -> IResult<&'a [u8], Value<'a>> {
    match FIELD_TYPES.get(name) {
        Some(&FieldType::Encoded) => {
            alt((parse_encoded, |input| parse_unspec_value(input, ty, name)))(input)
        }
        Some(&FieldType::NumericHex) => {
            alt((parse_hex, |input| parse_unspec_value(input, ty, name)))(input)
        }
        Some(&FieldType::NumericDec) => {
            alt((parse_dec, |input| parse_unspec_value(input, ty, name)))(input)
        }
        Some(&FieldType::NumericOct) => {
            alt((parse_oct, |input| parse_unspec_value(input, ty, name)))(input)
        }
        // FIXME: Some(&FieldType::Numeric)
        _ => alt((parse_encoded, |input| parse_unspec_value(input, ty, name)))(input),
    }
}

/// Recognize encoded value:
///
/// May be double-quoted string, hex-encoded blob, (null), ?.
#[inline(always)]
fn parse_encoded(input: &[u8]) -> IResult<&[u8], Value> {
    alt((
        map(parse_str_dq_safe, |s| Value::Str(s, Quote::Double)),
        terminated(
            map(
                recognize(many1_count(take_while_m_n(2, 2, is_hex_digit))),
                |hexstr: &[u8]| {
                    let mut recoded = Vec::with_capacity(hexstr.len() / 2);
                    for i in 0..hexstr.len() / 2 {
                        let d = unsafe { str::from_utf8_unchecked(&hexstr[2 * i..2 * i + 2]) };
                        recoded.push(u8::from_str_radix(d, 16).unwrap());
                    }
                    Value::Owned(recoded)
                },
            ),
            peek(take_while1(is_sep)),
        ),
        terminated(
            value(Value::Empty, alt((tag("(null)"), tag("?")))),
            peek(take_while1(is_sep)),
        ),
    ))(input)
}

/// Recognize hexadecimal value
#[inline(always)]
fn parse_hex(input: &[u8]) -> IResult<&[u8], Value> {
    map_res(
        terminated(take_while1(is_hex_digit), peek(take_while1(is_sep))),
        |digits| -> Result<_, std::num::ParseIntError> {
            let digits = unsafe { str::from_utf8_unchecked(digits) };
            Ok(Value::Number(Number::Hex(u64::from_str_radix(digits, 16)?)))
        },
    )(input)
}

/// Recognize decimal value
#[inline(always)]
fn parse_dec(input: &[u8]) -> IResult<&[u8], Value> {
    map(terminated(dec_i64, peek(take_while1(is_sep))), |n| {
        Value::Number(Number::Dec(n))
    })(input)
}

/// Recognize octal value
#[inline(always)]
fn parse_oct(input: &[u8]) -> IResult<&[u8], Value> {
    map_res(
        terminated(take_while1(is_oct_digit), peek(take_while1(is_sep))),
        |digits| -> Result<_, std::num::ParseIntError> {
            let digits = unsafe { str::from_utf8_unchecked(digits) };
            Ok(Value::Number(Number::Oct(u64::from_str_radix(digits, 8)?)))
        },
    )(input)
}

#[inline(always)]
fn parse_unspec_value<'a>(
    input: &'a [u8],
    ty: MessageType,
    name: &[u8],
) -> IResult<&'a [u8], Value<'a>> {
    // work around apparent AppArmor breakage
    match (ty, name) {
        (_, b"subj") => {
            if let Ok((input, s)) = recognize(tuple((
                opt(tag("=")),
                parse_str_unq,
                opt(delimited(tag(" ("), parse_identifier, tag(")"))),
            )))(input)
            {
                return Ok((input, Value::Str(s, Quote::None)));
            }
        }
        (MessageType::AVC, b"info") => {
            if let Ok((input, s)) = parse_str_dq(input) {
                return Ok((input, Value::Str(s, Quote::None)));
            }
        }
        (MessageType::SOCKADDR, b"SADDR") => {
            let broken_string: IResult<&[u8], &[u8]> =
                recognize(pair(tag("unknown family"), opt(take_till(is_sep))))(input);
            if let Ok((input, s)) = broken_string {
                return Ok((input, Value::Str(s, Quote::None)));
            }
        }
        _ => (),
    };

    alt((
        terminated(
            map(take_while1(is_safe_unquoted_chr), |s| {
                Value::Str(s, Quote::None)
            }),
            peek(take_while(is_sep)),
        ),
        map(parse_kv_sq, |s| Value::Str(s, Quote::Single)),
        map(parse_str_sq, |s| Value::Str(s, Quote::Single)),
        map(parse_str_dq, |s| Value::Str(s, Quote::Double)),
        map(parse_kv_braced, |s| Value::Str(s, Quote::Braces)),
        map(parse_str_braced, |s| Value::Str(s, Quote::Braces)),
        value(Value::Empty, peek(take_while(is_sep))),
    ))(input)
}

#[inline(always)]
fn parse_str_sq(input: &[u8]) -> IResult<&[u8], &[u8]> {
    delimited(tag("'"), take_while(|c| c != b'\''), tag("'"))(input)
}

#[inline(always)]
fn parse_str_dq_safe(input: &[u8]) -> IResult<&[u8], &[u8]> {
    delimited(tag("\""), take_while(is_safe_chr), tag("\""))(input)
}

#[inline(always)]
fn parse_str_dq(input: &[u8]) -> IResult<&[u8], &[u8]> {
    delimited(tag("\""), take_while(|c| c != b'"'), tag("\""))(input)
}

#[inline(always)]
fn parse_str_braced(input: &[u8]) -> IResult<&[u8], &[u8]> {
    delimited(tag("{ "), take_until(" }"), tag(" }"))(input)
}

#[inline(always)]
fn parse_str_unq(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while(is_safe_chr)(input)
}

#[inline(always)]
fn parse_str_unq_inside_sq(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while(|c| is_safe_chr(c) && c != b'\'')(input)
}

#[inline(always)]
fn parse_str_words_inside_sq(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let mut rest = input;
    loop {
        (rest, _) = take_while(|c| !b"' ".contains(&c))(rest)?;
        if let Ok(_) = alt((recognize(tuple((space1, parse_key, tag("=")))), tag("'")))(rest) {
            break;
        }
        (rest, _) = space1(rest)?;
    }
    let l = input.len() - rest.len();
    Ok((rest, &input[..l]))
}

/// More "correct" variant of parse_str_sq
#[inline(always)]
fn parse_kv_sq(input: &[u8]) -> IResult<&[u8], &[u8]> {
    delimited(
        tag("'"),
        recognize(separated_list0(
            tag(" "),
            tuple((
                recognize(pair(alpha1, many0_count(alt((alphanumeric1, is_a("-_")))))),
                tag("="),
                alt((parse_str_dq, parse_str_braced, parse_str_unq_inside_sq)),
            )),
        )),
        tag("'"),
    )(input)
}

/// Recognize a map enclosed in single quotes
#[inline(always)]
fn parse_kv_sq_as_map(input: &[u8]) -> IResult<&[u8], Value> {
    map(
        delimited(
            tag("'"),
            separated_list0(
                space1,
                alt((separated_pair(
                    parse_key,
                    alt((
                        tag("="),
                        recognize(tuple((tag(":"), space0))), // for 'avc:  mumble mumble mumble …'
                    )),
                    alt((
                        parse_encoded,
                        map(parse_str_words_inside_sq, |v| Value::Str(v, Quote::None)),
                        map(parse_str_unq_inside_sq, |v| Value::Str(v, Quote::None)),
                    )),
                ),)),
            ),
            tag("'"),
        ),
        Value::Map,
    )(input)
}

/// More "correct" variant of parse_str_braced
#[inline(always)]
fn parse_kv_braced(input: &[u8]) -> IResult<&[u8], &[u8]> {
    delimited(
        tag("{ "),
        recognize(separated_list0(
            tag(" "),
            tuple((
                recognize(pair(alpha1, many0_count(alt((alphanumeric1, is_a("-_")))))),
                tag("="),
                alt((parse_str_sq, parse_str_dq, parse_str_unq)),
            )),
        )),
        tag(" }"),
    )(input)
}

/// Recognize regular keys of key/value pairs
#[inline(always)]
fn parse_key(input: &[u8]) -> IResult<&[u8], Key> {
    map(
        recognize(pair(alpha1, many0_count(alt((alphanumeric1, is_a("-_")))))),
        |s: &[u8]| {
            if let Ok(c) = Common::try_from(s) {
                Key::Common(c)
            } else if s.ends_with(b"uid") {
                Key::NameUID(NVec::from(s))
            } else if s.ends_with(b"gid") {
                Key::NameGID(NVec::from(s))
            } else {
                Key::Name(NVec::from(s))
            }
        },
    )(input)
}

/// Recognize length specifier for EXECVE split arguments, e.g. a1_len
#[inline(always)]
fn parse_key_a_x_len(input: &[u8]) -> IResult<&[u8], Key> {
    map(delimited(tag("a"), dec_u32, tag("_len")), Key::ArgLen)(input)
}

/// Recognize EXECVE split arguments, e.g. a1[3]
#[inline(always)]
fn parse_key_a_xy(input: &[u8]) -> IResult<&[u8], Key> {
    map(
        pair(
            preceded(tag("a"), dec_u32),
            delimited(tag("["), dec_u16, tag("]")),
        ),
        |(x, y)| Key::Arg(x, Some(y)),
    )(input)
}

/// Recognize SYSCALL, EXECVE regular argument keys, e.g. a1, a2, a3…
#[inline(always)]
fn parse_key_a_x(input: &[u8]) -> IResult<&[u8], Key> {
    map(preceded(tag("a"), u32), |x| Key::Arg(x, None))(input)
}

/// Recognize identifiers (used in some irregular messages)
/// Like [A-Za-z_][A-Za-z0-9_]*
#[inline(always)]
fn parse_identifier(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(pair(
        alt((alpha1, tag("_"))),
        many0_count(alt((alphanumeric1, tag("_")))),
    ))(input)
}

/// Characters permitted in kernel "encoded" strings that would
/// otherwise be hex-encoded.
#[inline(always)]
fn is_safe_chr(c: u8) -> bool {
    c == b'!' || (b'#'..=b'~').contains(&c)
}

/// Characters permitted in kernel "encoded" strings, minus
/// single-quotes, braces
#[inline(always)]
fn is_safe_unquoted_chr(c: u8) -> bool {
    (b'#'..=b'&').contains(&c) || (b'('..=b'z').contains(&c) || c == b'!' || c == b'|' || c == b'~'
}

/// Separator characters
#[inline(always)]
fn is_sep(c: u8) -> bool {
    c == b' ' || c == b'\x1d' || c == b'\n'
}
