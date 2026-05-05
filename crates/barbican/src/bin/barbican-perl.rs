//! `barbican-perl` — classifier-gated drop-in for `perl -e BODY`.
//! See [`barbican::wrappers`] for the implementation.

fn main() -> ! {
    let argv: Vec<String> = std::env::args().collect();
    barbican::wrappers::run(barbican::wrappers::Dialect::Perl, &argv);
}
