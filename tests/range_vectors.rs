//! Shared wire vectors: Python and Deno can pin this JSON byte for byte.
use ikigai_http::range::{ByteRange, ContentRange, IfRange, ParseError, Range};
use serde_json::Value;
use std::{fmt::Display, str::FromStr};

const VECTORS: &str = include_str!("vectors/range_vectors.json");

fn check<T: FromStr<Err = ParseError> + Display>(cases: &Value) {
    for case in cases.as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        match case["input"].as_str().unwrap().parse::<T>() {
            Ok(value) => {
                let canonical = case["canonical"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{name}: accepted invalid field"));
                assert_eq!(value.to_string(), canonical, "{name}");
                assert_eq!(
                    canonical.parse::<T>().ok().unwrap().to_string(),
                    canonical,
                    "{name}: canonical reparses"
                );
            }
            Err(error) => assert_eq!(
                Some(error.code()),
                case["error"].as_str(),
                "{name}: {error}"
            ),
        }
    }
}
#[test]
fn shared_range_vectors() {
    assert!(VECTORS.is_ascii());
    assert!(!VECTORS.contains('\r'));
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["version"], 1);
    check::<Range>(&vectors["range"]);
    check::<ContentRange>(&vectors["content_range"]);
    check::<IfRange>(&vectors["if_range"]);
    for case in vectors["resolve"].as_array().unwrap() {
        let range: Range = case["range"].as_str().unwrap().parse().unwrap();
        let length = case["length"].as_str().unwrap().parse().unwrap();
        let got = range.ranges()[0]
            .resolve(length)
            .map(|(first, last)| vec![first.to_string(), last.to_string()]);
        assert_eq!(
            serde_json::to_value(got).unwrap(),
            case["expect"],
            "{}",
            case["name"]
        );
    }
}

#[test]
fn constructors_and_accessors_preserve_invariants() {
    assert_eq!(Range::new(vec![]), Err(ParseError::Invalid));
    assert_eq!(
        Range::new(vec![ByteRange::Closed { first: 2, last: 1 }]),
        Err(ParseError::Invalid)
    );
    let range = Range::new(vec![ByteRange::Open { first: 4 }]).unwrap();
    assert_eq!(range.to_string(), "bytes=4-");
    assert_eq!(
        ContentRange::satisfied(0, 1, Some(1)),
        Err(ParseError::Invalid)
    );
    let content: ContentRange = "bytes 5-9/10".parse().unwrap();
    assert_eq!(content.interval(), Some((5, 9)));
    assert_eq!(content.complete_length(), Some(10));
    let unsatisfied = ContentRange::unsatisfied(0);
    assert_eq!(unsatisfied.interval(), None);
    assert_eq!(unsatisfied.to_string(), "bytes */0");
    let tag: IfRange = "\"tag\"".parse().unwrap();
    assert_eq!(tag.entity_tag(), Some("\"tag\""));
    assert_eq!(tag.date(), None);
    let date: IfRange = "Sun, 06 Nov 1994 08:49:37 GMT".parse().unwrap();
    assert_eq!(date.entity_tag(), None);
    assert!(date.date().is_some());
}

#[test]
fn field_and_list_limits_are_enforced() {
    assert_eq!(
        format!("bytes={}", vec!["0-0"; 129].join(",")).parse::<Range>(),
        Err(ParseError::TooLarge)
    );
    assert_eq!(
        format!("bytes={}", vec!["0-0"; 128].join(","))
            .parse::<Range>()
            .unwrap()
            .ranges()
            .len(),
        128
    );
    for parse in [
        "x".repeat(16385).parse::<Range>().err(),
        "x".repeat(16385).parse::<ContentRange>().err(),
        "x".repeat(16385).parse::<IfRange>().err(),
    ] {
        assert_eq!(parse, Some(ParseError::TooLarge));
    }
}
