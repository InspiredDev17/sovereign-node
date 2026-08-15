#!/bin/sh
set -eu

# Local, reproducible release evidence. This repository does not currently
# authorize hosted CI; branch protection remains an external owner-operated gate.
cargo fmt --all -- --check
cargo test --locked --offline --all-targets --all-features
cargo test --locked --offline --doc --all-features
cargo clippy --locked --offline --all-targets --all-features -- -D warnings
RUSTDOCFLAGS=-Dwarnings cargo doc --locked --offline --no-deps --all-features
cargo build --locked --offline --release --all-features
cargo deny --locked check
