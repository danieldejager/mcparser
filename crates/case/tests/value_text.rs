// Every DuckDB result type must come out of query_table as readable text.
use std::path::Path;

fn one_row(sql: &str) -> Vec<String> {
    let t = case::query_table(Path::new(""), sql).unwrap();
    assert_eq!(t.rows.len(), 1);
    t.rows.into_iter().next().unwrap()
}

#[test]
fn values_of_every_type_render_as_text() {
    let row = one_row(
        "SELECT true, false, NULL::BOOLEAN, NULL, 42, 2.5::DOUBLE, \
         TIMESTAMP '2026-01-01 10:00:00', [1, 2, 3], json_valid('{\"a\":1}'), json_valid('{nope')",
    );
    assert_eq!(row, ["true", "false", "", "", "42", "2.5", "2026-01-01 10:00:00", "[1, 2, 3]", "true", "false"]);
}

#[test]
fn more_types_render_as_text() {
    let row = one_row(
        "SELECT 170141183460469231731687303715884105727::HUGEINT, 12.345::DECIMAL(10,3), 0.1::FLOAT, \
         DATE '2026-11-02', TIME '01:02:03.25', TIMESTAMP '2026-01-01 10:00:00.123456', \
         INTERVAL 1 YEAR + INTERVAL 2 MONTH + INTERVAL 3 DAY, 'MZ\\x00'::BLOB, \
         ['a', NULL], {'k': 1, 's': 'x'}, MAP {'a': 1}, '0123', '1.50'",
    );
    assert_eq!(row, [
        "170141183460469231731687303715884105727", "12.345", "0.1", "2026-11-02", "01:02:03.25",
        "2026-01-01 10:00:00.123456", "1 year 2 months 3 days", "MZ\\x00", "['a', NULL]",
        "{'k': 1, 's': 'x'}", "{'a'=1}", "0123", "1.50",
    ]);
}
