//! Bitcoin mainnet P2P network crawler library (see SPECIFICATION_v2.md).
//!
//! The modules are shared by two binaries: `new-p2p-crawler` (the full crawler,
//! `src/main.rs`) and `probe` (direct connect to an explicit node list,
//! `src/bin/probe.rs`).

pub mod address;
pub mod addrlog;
pub mod crawler;
pub mod dns;
pub mod logging;
pub mod output;
pub mod preflight;
pub mod protocol;
pub mod settings;
pub mod store;
pub mod transport;
