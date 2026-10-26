//! Shared RFC 9110 byte `Range`, `Content-Range`, and `If-Range` helpers.
//!
//! Parse with `FromStr`; `Display` produces canonical field values, without a
//! field name. Byte positions are inclusive and checked `u64`s. Unknown units
//! are explicitly unsupported, never interpreted as bytes. Headers larger than
//! 16 KiB or lists with more than 128 members are refused. Parsing does not
//! decide whether a server should honor a range, merge ranges, or send multipart.
//!
//! ```
//! use ikigai_http::range::{Range, ContentRange, IfRange};
//! let range: Range = "bytes=0-499, -500".parse()?;
//! assert_eq!(range.ranges()[1].resolve(1234), Some((734, 1233)));
//! let content: ContentRange = "bytes 0-499/1234".parse()?;
//! assert_eq!(content.interval(), Some((0, 499)));
//! let validator: IfRange = "\"v1\"".parse()?;
//! assert_eq!(validator.to_string(), "\"v1\"");
//! # Ok::<(), ikigai_http::range::ParseError>(())
//! ```
use std::{fmt, str::FromStr, time::SystemTime};

const MAX_FIELD_BYTES: usize = 16 * 1024;
const MAX_RANGES: usize = 128;

/// A stable, credential-free parse failure; no input is echoed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    Invalid,
    Overflow,
    UnsupportedUnit,
    TooLarge,
    WeakValidator,
}

impl ParseError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::Overflow => "overflow",
            Self::UnsupportedUnit => "unsupported-unit",
            Self::TooLarge => "too-large",
            Self::WeakValidator => "weak-validator",
        }
    }
}
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for ParseError {}

fn field(value: &str) -> Result<&str, ParseError> {
    if value.len() > MAX_FIELD_BYTES {
        return Err(ParseError::TooLarge);
    }
    if value.bytes().any(|b| b == 0x7f || (b < 0x20 && b != b'\t')) {
        return Err(ParseError::Invalid);
    }
    Ok(value.trim_matches([' ', '\t']))
}
fn number(value: &str) -> Result<u64, ParseError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ParseError::Invalid);
    }
    value.parse().map_err(|_| ParseError::Overflow)
}
fn unit(value: &str) -> Result<(), ParseError> {
    if value.eq_ignore_ascii_case("bytes") {
        Ok(())
    } else {
        Err(ParseError::UnsupportedUnit)
    }
}

/// A byte range in a request. Suffix zero is valid syntax but unsatisfiable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteRange {
    Closed { first: u64, last: u64 },
    Open { first: u64 },
    Suffix { length: u64 },
}
impl ByteRange {
    /// Resolve against a representation length; clamp an excessive end/suffix.
    /// Empty representations and suffix zero have no satisfiable interval.
    pub fn resolve(self, length: u64) -> Option<(u64, u64)> {
        if length == 0 {
            return None;
        }
        match self {
            Self::Closed { first, last } if first <= last && first < length => {
                Some((first, last.min(length - 1)))
            }
            Self::Open { first } if first < length => Some((first, length - 1)),
            Self::Suffix { length: suffix } if suffix > 0 => {
                Some((length.saturating_sub(suffix), length - 1))
            }
            _ => None,
        }
    }
}
impl fmt::Display for ByteRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed { first, last } => write!(f, "{first}-{last}"),
            Self::Open { first } => write!(f, "{first}-"),
            Self::Suffix { length } => write!(f, "-{length}"),
        }
    }
}

/// A nonempty, validated byte range set. Ordering and overlaps are preserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Range(Vec<ByteRange>);
impl Range {
    pub fn new(ranges: Vec<ByteRange>) -> Result<Self, ParseError> {
        if ranges.is_empty()
            || ranges
                .iter()
                .any(|r| matches!(r, ByteRange::Closed { first, last } if first > last))
        {
            return Err(ParseError::Invalid);
        }
        if ranges.len() > MAX_RANGES {
            return Err(ParseError::TooLarge);
        }
        Ok(Self(ranges))
    }
    pub fn ranges(&self) -> &[ByteRange] {
        &self.0
    }
}
impl FromStr for Range {
    type Err = ParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (name, value) = field(value)?.split_once('=').ok_or(ParseError::Invalid)?;
        unit(name)?;
        let mut ranges = Vec::new();
        // RFC 9110 §5.6.1.2: ignore a reasonable number of empty list elements.
        for (index, item) in value.split(',').enumerate() {
            if index >= MAX_RANGES {
                return Err(ParseError::TooLarge);
            }
            let item = item.trim_matches([' ', '\t']);
            if item.is_empty() {
                continue;
            }
            let (first, last) = item.split_once('-').ok_or(ParseError::Invalid)?;
            ranges.push(if first.is_empty() {
                ByteRange::Suffix {
                    length: number(last)?,
                }
            } else if last.is_empty() {
                ByteRange::Open {
                    first: number(first)?,
                }
            } else {
                ByteRange::Closed {
                    first: number(first)?,
                    last: number(last)?,
                }
            });
        }
        Self::new(ranges)
    }
}
impl fmt::Display for Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bytes=")?;
        for (index, range) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{range}")?;
        }
        Ok(())
    }
}

/// A byte response interval (206) or unsatisfied range with known length (416).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentRange {
    interval: Option<(u64, u64)>,
    complete_length: Option<u64>,
}
impl ContentRange {
    pub fn satisfied(
        first: u64,
        last: u64,
        complete_length: Option<u64>,
    ) -> Result<Self, ParseError> {
        if first > last || complete_length.is_some_and(|length| last >= length) {
            return Err(ParseError::Invalid);
        }
        Ok(Self {
            interval: Some((first, last)),
            complete_length,
        })
    }
    pub fn unsatisfied(complete_length: u64) -> Self {
        Self {
            interval: None,
            complete_length: Some(complete_length),
        }
    }
    pub fn interval(self) -> Option<(u64, u64)> {
        self.interval
    }
    pub fn complete_length(self) -> Option<u64> {
        self.complete_length
    }
}
impl FromStr for ContentRange {
    type Err = ParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (name, value) = field(value)?.split_once(' ').ok_or(ParseError::Invalid)?;
        unit(name)?;
        let (range, length) = value.split_once('/').ok_or(ParseError::Invalid)?;
        if range == "*" {
            return Ok(Self::unsatisfied(number(length)?));
        }
        let (first, last) = range.split_once('-').ok_or(ParseError::Invalid)?;
        Self::satisfied(
            number(first)?,
            number(last)?,
            if length == "*" {
                None
            } else {
                Some(number(length)?)
            },
        )
    }
}
impl fmt::Display for ContentRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bytes ")?;
        match self.interval {
            Some((first, last)) => write!(f, "{first}-{last}/")?,
            None => f.write_str("*/")?,
        }
        match self.complete_length {
            Some(length) => write!(f, "{length}"),
            None => f.write_str("*"),
        }
    }
}

/// A usable strong entity tag or HTTP-date validator. Weak tags are refused
/// because RFC 9110 §13.1.5 forbids generating them in If-Range. The caller must
/// establish that a date is a strong validator before sending it with Range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfRange(Validator);
#[derive(Clone, Debug, PartialEq, Eq)]
enum Validator {
    EntityTag(String),
    Date(SystemTime),
}
impl IfRange {
    /// An entity tag, including its quotes, or `None` for a date.
    pub fn entity_tag(&self) -> Option<&str> {
        match &self.0 {
            Validator::EntityTag(tag) => Some(tag),
            _ => None,
        }
    }
    pub fn date(&self) -> Option<SystemTime> {
        match self.0 {
            Validator::Date(date) => Some(date),
            _ => None,
        }
    }
}
impl FromStr for IfRange {
    type Err = ParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = field(value)?;
        if value.starts_with("W/\"") {
            return Err(ParseError::WeakValidator);
        }
        if value.starts_with('"') {
            if value.len() < 2
                || !value.ends_with('"')
                || !value.as_bytes()[1..value.len() - 1]
                    .iter()
                    .all(|&b| b == 0x21 || (0x23..=0x7e).contains(&b) || b >= 0x80)
            {
                return Err(ParseError::Invalid);
            }
            Ok(Self(Validator::EntityTag(value.to_string())))
        } else {
            httpdate::parse_http_date(value)
                .map(|date| Self(Validator::Date(date)))
                .map_err(|_| ParseError::Invalid)
        }
    }
}
impl fmt::Display for IfRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Validator::EntityTag(tag) => f.write_str(tag),
            Validator::Date(date) => f.write_str(&httpdate::fmt_http_date(*date)),
        }
    }
}
