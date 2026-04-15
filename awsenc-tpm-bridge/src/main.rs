// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

#[allow(clippy::print_stderr)]
fn main() {
    let mut server = enclaveapp_tpm_bridge::BridgeServer::new("awsenc", "cache-key");
    if let Err(e) = server.run_stdio() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
