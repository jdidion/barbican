//! `barbican-node` — classifier-gated drop-in for `node -e BODY`.
//! See [`barbican::wrappers`] for the implementation.

fn main() -> ! {
    let argv: Vec<String> = std::env::args().collect();
    barbican::wrappers::run(barbican::wrappers::Dialect::Node, &argv);
}
