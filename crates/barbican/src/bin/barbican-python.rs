//! `barbican-python` — classifier-gated drop-in for `python3 -c BODY`.
//! See [`barbican::wrappers`] for the implementation.

fn main() -> ! {
    let argv: Vec<String> = std::env::args().collect();
    barbican::wrappers::run(barbican::wrappers::Dialect::Python, &argv);
}
