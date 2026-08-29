//! Cross-language agreement matrix. Go, Rust and Python run this identical
//! table of narrowing vectors and must return the same verdict for every cell.
//! The three-hop spend rows distinguish a pairwise reading of the bounds from
//! the effective-ceiling reading; the two-hop rows are the neighbour guard that
//! must not move. The Go twin is verify/xlang_matrix_test.go and the Python
//! twin is tests/test_xlang_matrix.py.
mod common;
use agent_passport::delegation::verify_chain_structure;
use serde_json::{json, Value};

fn mk(by: &str, to: &str, depth: i64, extra: Value) -> Value {
    let mut base = json!({"delegationId": format!("{by}->{to}"), "delegatedBy": by,
                          "delegatedTo": to, "scope": ["data:read"], "currentDepth": depth});
    if let Some(extra) = extra.as_object() {
        for (k, v) in extra {
            base[k] = v.clone();
        }
    }
    base
}
fn d5(mut e: Value) -> Value {
    e["maxDepth"] = json!(5);
    e
}
fn three(a: Value, b: Value, c: Value) -> Vec<Value> {
    vec![
        mk("root", "a", 0, a),
        mk("a", "b", 1, b),
        mk("b", "c", 2, c),
    ]
}
fn two(a: Value, b: Value) -> Vec<Value> {
    vec![mk("root", "a", 0, a), mk("a", "b", 1, b)]
}

#[test]
fn xlang_matrix() {
    let rows: Vec<(&str, Vec<Value>)> = vec![
        (
            "spend/100->absent->1000000",
            three(
                d5(json!({"spendLimit":100})),
                d5(json!({})),
                d5(json!({"spendLimit":1000000})),
            ),
        ),
        (
            "spend/100->absent->50",
            three(
                d5(json!({"spendLimit":100})),
                d5(json!({})),
                d5(json!({"spendLimit":50})),
            ),
        ),
        (
            "spend/100->100->100",
            three(
                d5(json!({"spendLimit":100})),
                d5(json!({"spendLimit":100})),
                d5(json!({"spendLimit":100})),
            ),
        ),
        (
            "spend/100->50->50",
            three(
                d5(json!({"spendLimit":100})),
                d5(json!({"spendLimit":50})),
                d5(json!({"spendLimit":50})),
            ),
        ),
        (
            "spend/100->101->101",
            three(
                d5(json!({"spendLimit":100})),
                d5(json!({"spendLimit":101})),
                d5(json!({"spendLimit":101})),
            ),
        ),
        (
            "spend2/100->100",
            two(d5(json!({"spendLimit":100})), d5(json!({"spendLimit":100}))),
        ),
        (
            "spend2/100->50",
            two(d5(json!({"spendLimit":100})), d5(json!({"spendLimit":50}))),
        ),
        (
            "spend2/100->101",
            two(d5(json!({"spendLimit":100})), d5(json!({"spendLimit":101}))),
        ),
        (
            "unit/USD->absent->JPY50",
            three(
                d5(json!({"spendLimit":100,"spendLimitUnit":"USD"})),
                d5(json!({})),
                d5(json!({"spendLimit":50,"spendLimitUnit":"JPY"})),
            ),
        ),
        (
            "unit/USD->absent->unitless50",
            three(
                d5(json!({"spendLimit":100,"spendLimitUnit":"USD"})),
                d5(json!({})),
                d5(json!({"spendLimit":50})),
            ),
        ),
        (
            "unit/USD->absent->absent",
            three(
                d5(json!({"spendLimit":100,"spendLimitUnit":"USD"})),
                d5(json!({})),
                d5(json!({})),
            ),
        ),
        (
            "unit/USD->absent->USD50",
            three(
                d5(json!({"spendLimit":100,"spendLimitUnit":"USD"})),
                d5(json!({})),
                d5(json!({"spendLimit":50,"spendLimitUnit":"USD"})),
            ),
        ),
        (
            "unit/USD->absent->USD101",
            three(
                d5(json!({"spendLimit":100,"spendLimitUnit":"USD"})),
                d5(json!({})),
                d5(json!({"spendLimit":101,"spendLimitUnit":"USD"})),
            ),
        ),
        (
            "depth/max1->absent->depth2",
            three(json!({"maxDepth":1}), json!({}), json!({})),
        ),
        (
            "depth/max1->99->depth2",
            three(
                json!({"maxDepth":1}),
                json!({"maxDepth":99}),
                json!({"maxDepth":99}),
            ),
        ),
        (
            "depth/max2->absent->depth2",
            three(json!({"maxDepth":2}), json!({}), json!({})),
        ),
        (
            "depth/flat",
            two(d5(json!({})), d5(json!({"currentDepth":0}))),
        ),
        ("depth/increment", two(d5(json!({})), d5(json!({})))),
        (
            "nbf/2026-06->absent->2020",
            three(
                d5(json!({"notBefore":"2026-06-01T00:00:00Z"})),
                d5(json!({})),
                d5(json!({"notBefore":"2020-01-01T00:00:00Z"})),
            ),
        ),
        (
            "nbf/2026-06->absent->absent",
            three(
                d5(json!({"notBefore":"2026-06-01T00:00:00Z"})),
                d5(json!({})),
                d5(json!({})),
            ),
        ),
        (
            "nbf/2026-06->absent->2026-07",
            three(
                d5(json!({"notBefore":"2026-06-01T00:00:00Z"})),
                d5(json!({})),
                d5(json!({"notBefore":"2026-07-01T00:00:00Z"})),
            ),
        ),
        (
            "exp/2030->absent",
            two(
                d5(json!({"expiresAt":"2030-01-01T00:00:00Z"})),
                d5(json!({})),
            ),
        ),
        (
            "exp/2030->2099",
            two(
                d5(json!({"expiresAt":"2030-01-01T00:00:00Z"})),
                d5(json!({"expiresAt":"2099-01-01T00:00:00Z"})),
            ),
        ),
        (
            "exp/2030->2029",
            two(
                d5(json!({"expiresAt":"2030-01-01T00:00:00Z"})),
                d5(json!({"expiresAt":"2029-01-01T00:00:00Z"})),
            ),
        ),
        (
            "scope/read->absent->wildcard",
            three(
                d5(json!({"scope":["data:read"]})),
                d5(json!({"scope":[]})),
                d5(json!({"scope":["data:*"]})),
            ),
        ),
        (
            "scope/read->absent->absent",
            three(
                d5(json!({"scope":["data:read"]})),
                d5(json!({"scope":[]})),
                d5(json!({"scope":[]})),
            ),
        ),
        ("empty-chain", vec![]),
        (
            "malformed/spendLimit-string",
            two(
                d5(json!({"spendLimit":"999"})),
                d5(json!({"spendLimit":1000000})),
            ),
        ),
    ];
    let want: &[(&str, &str)] = &[
        ("spend/100->absent->1000000", "REJECT"),
        ("spend/100->absent->50", "ACCEPT"),
        ("spend/100->100->100", "ACCEPT"),
        ("spend/100->50->50", "ACCEPT"),
        ("spend/100->101->101", "REJECT"),
        ("spend2/100->100", "ACCEPT"),
        ("spend2/100->50", "ACCEPT"),
        ("spend2/100->101", "REJECT"),
        ("unit/USD->absent->JPY50", "REJECT"),
        ("unit/USD->absent->unitless50", "REJECT"),
        ("unit/USD->absent->absent", "ACCEPT"),
        ("unit/USD->absent->USD50", "ACCEPT"),
        ("unit/USD->absent->USD101", "REJECT"),
        ("depth/max1->absent->depth2", "REJECT"),
        ("depth/max1->99->depth2", "REJECT"),
        ("depth/max2->absent->depth2", "ACCEPT"),
        ("depth/flat", "REJECT"),
        ("depth/increment", "ACCEPT"),
        ("nbf/2026-06->absent->2020", "REJECT"),
        ("nbf/2026-06->absent->absent", "ACCEPT"),
        ("nbf/2026-06->absent->2026-07", "ACCEPT"),
        ("exp/2030->absent", "REJECT"),
        ("exp/2030->2099", "REJECT"),
        ("exp/2030->2029", "ACCEPT"),
        ("scope/read->absent->wildcard", "REJECT"),
        ("scope/read->absent->absent", "ACCEPT"),
        ("empty-chain", "REJECT"),
        ("malformed/spendLimit-string", "REJECT"),
    ];
    for (name, chain) in rows {
        let verdict = if verify_chain_structure(&chain).is_err() {
            "REJECT"
        } else {
            "ACCEPT"
        };
        println!("CELL {name} = {verdict}");
        let pinned = want
            .iter()
            .find(|(cell, _)| *cell == name)
            .unwrap_or_else(|| panic!("{name}: no pinned verdict"));
        assert_eq!(verdict, pinned.1, "{name}");
    }
}
