//! PQ-QKD-Proxy: Post-quantum secure proxy for QKD infrastructure

pub mod auth;
pub mod config;
pub mod crypto;
pub mod proxy;
pub mod qkd_client;
pub mod audit;

pub use config::Config as ProxyConfig;
pub use proxy::{ProxyServer, ClientHello};
pub use auth::Authenticator as AuthManager;
pub use crypto::PqKeyExchange;
pub use qkd_client::QkdClient;
// pub use audit::AuditLogger; // TODO: Implement AuditLogger

pub type Result<T> = anyhow::Result<T>;