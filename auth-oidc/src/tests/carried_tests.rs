// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The bearer off the module's own lines, cell for cell against the old chain's
//! `carried_credential` over the default inbound style (`authorization` Bearer, `x-api-key`,
//! `x-goog-api-key`).

use super::*;

/// The bearer `lines` (name, value; the first of a name wins, names ASCII case-insensitive) carry.
fn of<'a>(lines: &[(&str, &'a str)]) -> Option<&'a str> {
    carried(|name| {
        lines
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_bytes())
    })
}

#[test]
fn the_bearer_scheme_is_matched_case_insensitively_and_split_on_the_first_space() {
    assert_eq!(bearer("Bearer tok"), Some("tok"));
    assert_eq!(bearer("bearer tok"), Some("tok"));
    assert_eq!(bearer("BEARER tok"), Some("tok"));
    assert_eq!(bearer("Bearer  tok"), Some(" tok"), "nothing is trimmed");
    assert_eq!(bearer("Bearer tok "), Some("tok "), "nothing is trimmed");
    assert_eq!(bearer("Bearer a b"), Some("a b"));
    assert_eq!(bearer("Bearer "), None, "an empty token is none");
    assert_eq!(bearer("Bearer"), None, "no separator is none");
    assert_eq!(bearer("Bearer\ttok"), None, "a tab is no separator");
    assert_eq!(bearer("Basic dXNlcjpwYXNz"), None);
    assert_eq!(bearer("DPoP tok"), None);
    assert_eq!(bearer("Bearertok x"), None);
    assert_eq!(bearer(""), None);
}

#[test]
fn the_lines_are_read_in_the_old_chains_order() {
    assert_eq!(LINES, ["authorization", "x-api-key", "x-goog-api-key"]);
    assert_eq!(of(&[]), None, "no line is none");
    assert_eq!(of(&[("authorization", "Bearer a")]), Some("a"));
    assert_eq!(of(&[("Authorization", "Bearer a")]), Some("a"));
    assert_eq!(of(&[("x-api-key", "k")]), Some("k"));
    assert_eq!(of(&[("x-goog-api-key", "g")]), Some("g"));
    assert_eq!(
        of(&[
            ("x-goog-api-key", "g"),
            ("x-api-key", "k"),
            ("authorization", "Bearer a"),
        ]),
        Some("a"),
        "the Bearer first"
    );
    assert_eq!(
        of(&[("x-goog-api-key", "g"), ("x-api-key", "k")]),
        Some("k"),
        "x-api-key before x-goog-api-key"
    );
    assert_eq!(
        of(&[("authorization", "Basic dXNlcjpwYXNz"), ("x-api-key", "k")]),
        Some("k"),
        "another scheme falls through"
    );
    assert_eq!(
        of(&[("authorization", "DPoP tok"), ("x-goog-api-key", "g")]),
        Some("g"),
        "a DPoP scheme falls through"
    );
    assert_eq!(
        of(&[("authorization", "Bearer "), ("x-api-key", "k")]),
        Some("k"),
        "an empty token falls through"
    );
}

#[test]
fn a_blank_or_unreadable_value_presents_nothing_and_masks_no_later_line() {
    assert_eq!(of(&[("x-api-key", ""), ("x-goog-api-key", "g")]), Some("g"));
    assert_eq!(of(&[("x-api-key", "")]), None);
    assert_eq!(
        of(&[("x-api-key", " "), ("x-goog-api-key", "g")]),
        Some(" "),
        "a space is not blank: the old chain took it raw"
    );
    assert_eq!(
        of(&[("authorization", "Bearer t\u{e9}"), ("x-api-key", "k")]),
        Some("k"),
        "a non-ASCII byte is not visible ASCII"
    );
    assert_eq!(
        of(&[("authorization", "Bearer t\x01"), ("x-api-key", "k")]),
        Some("k"),
        "a control byte is not visible ASCII"
    );
    assert_eq!(
        of(&[("authorization", "Bearer t\x7f"), ("x-api-key", "k")]),
        Some("k"),
        "DEL is not visible ASCII"
    );
    assert_eq!(
        of(&[("x-api-key", "a\tb")]),
        Some("a\tb"),
        "a tab inside a value reads"
    );
}

#[test]
fn only_the_first_line_of_a_name_is_read_and_unnamed_lines_carry_nothing() {
    assert_eq!(
        of(&[
            ("authorization", "Basic dXNlcjpwYXNz"),
            ("authorization", "Bearer a"),
        ]),
        None
    );
    assert_eq!(of(&[("x-admin-token", "t")]), None);
    assert_eq!(of(&[("x-other-key", "t")]), None);
}
