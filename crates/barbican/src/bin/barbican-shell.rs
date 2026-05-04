//! `barbican-shell` — classifier-gated drop-in for `bash -c BODY`.
//! See [`barbican::wrappers`] for the implementation.

fn main() -> ! {
    let argv: Vec<String> = std::env::args().collect();
    barbican::wrappers::run(barbican::wrappers::Dialect::Shell, argv);
}
