//! `barbican-ruby` — classifier-gated drop-in for `ruby -e BODY`.
//! See [`barbican::wrappers`] for the implementation.

fn main() -> ! {
    let argv: Vec<String> = std::env::args().collect();
    barbican::wrappers::run(barbican::wrappers::Dialect::Ruby, argv);
}
