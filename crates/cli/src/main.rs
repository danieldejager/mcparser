fn main() {
    println!(
        "mcparser {} ({}, {}, {}, {})",
        env!("CARGO_PKG_VERSION"),
        evtx_read::name(),
        model::name(),
        case::name(),
        query::name(),
    );
}