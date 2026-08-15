//! `mcpg-control-plane-license` — the licensing vocabulary of MCPG.
//!
//! License-token claims ([`license::LicenseClaims`]), offline Ed25519
//! verification, plan envelopes, and the plugin entitlement gates. Kept
//! dependency-light on purpose: the gateway consumes it unconditionally
//! (standalone deployments enforce the plugin load gate), while the CP,
//! federation issuer, and CLIs reach it through
//! `mcpg-control-plane-core`'s re-export.

pub mod ids;
pub mod license;
