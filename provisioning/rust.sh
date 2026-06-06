#!/bin/bash
# Install Rust with sccache.
set -euxo pipefail

curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --component "rustfmt,clippy"

source "$HOME/.cargo/env"
apt-get install -y --no-install-recommends sccache

echo 'source "$HOME/.cargo/env"' >> .bashrc
echo 'export RUSTC_WRAPPER=sccache' >> .bashrc
