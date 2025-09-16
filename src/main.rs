//! PQ-QKD-Proxy: Post-quantum secure proxy for QKD hardware APIs

use anyhow::Result;
use tokio::net::TcpListener;
use tracing::{info, warn, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::sync::Arc;
use std::path::Path;

mod config;
mod crypto;
mod proxy;
mod qkd_client;
mod auth;
mod audit;

use config::Config;
use proxy::ProxyServer;

#[tokio::main]
async fn main() -> Result<()> {
    // Handle command line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "--generate-keys" {
        return generate_proxy_keys();
    }

    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pq_qkd_proxy=info,tower=warn".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting PQ-QKD-Proxy v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config_path = std::env::var("PQ_QKD_PROXY_CONFIG")
        .unwrap_or_else(|_| "/etc/pq-qkd-proxy/config.toml".to_string());

    let config = Config::load(&config_path)?;
    let config = Arc::new(config);

    info!("Loaded configuration from {}", config_path);

    // Initialize audit log
    audit::init(&config.security.audit_log)?;
    audit::log_startup(&config);

    // Create proxy server
    let proxy = ProxyServer::new(config.clone()).await?;

    // Bind to configured address
    let listener = TcpListener::bind(&config.proxy.listen).await?;
    info!("PQ-QKD-Proxy listening on {}", config.proxy.listen);

    // Check vendor API connectivity
    proxy.check_vendor_api().await?;

    // Main accept loop
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!("New connection from {}", addr);
                
                // Check if address is allowed
                if !config.is_allowed_source(&addr) {
                    warn!("Rejected connection from unauthorized address: {}", addr);
                    continue;
                }

                let proxy = proxy.clone();
                tokio::spawn(async move {
                    if let Err(e) = proxy.handle_connection(stream, addr).await {
                        error!("Connection error from {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Accept error: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Generate proxy keys for the server
fn generate_proxy_keys() -> Result<()> {
    use crate::crypto::PqKeyExchange;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    
    println!("Generating PQ-QKD-Proxy keys...");
    
    // Generate new keypair
    let kex = PqKeyExchange::new()?;
    
    // Serialize keys
    use pqcrypto_traits::sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey};
    
    let private_key = bincode::serialize(&(
        {
            use pqcrypto_traits::sign::{SecretKey as SignSecretKey, PublicKey as SignPublicKey};
            kex.falcon_secret_key().as_bytes()
        },
        {
            use pqcrypto_traits::sign::{SecretKey as SignSecretKey, PublicKey as SignPublicKey};
            kex.falcon_pk.as_bytes()
        },
        {
            use pqcrypto_traits::sign::{SecretKey as SignSecretKey, PublicKey as SignPublicKey};
            kex.sphincs_secret_key().as_bytes()
        },
        {
            use pqcrypto_traits::sign::{SecretKey as SignSecretKey, PublicKey as SignPublicKey};
            kex.sphincs_pk.as_bytes()
        },
    ))?;
    
    let public_key = bincode::serialize(&(
        {
            use pqcrypto_traits::sign::{PublicKey as SignPublicKey};
            kex.falcon_pk.as_bytes()
        },
        {
            use pqcrypto_traits::sign::{PublicKey as SignPublicKey};
            kex.sphincs_pk.as_bytes()
        },
    ))?;
    
    // Ensure directories exist
    fs::create_dir_all("/etc/pq-qkd-proxy")?;
    
    // Write private key with restrictive permissions
    let key_path = "/etc/pq-qkd-proxy/proxy.key";
    fs::write(key_path, &private_key)?;
    let mut perms = fs::metadata(key_path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(key_path, perms)?;
    
    // Write certificate/public key
    let cert_path = "/etc/pq-qkd-proxy/proxy.crt";
    fs::write(cert_path, &public_key)?;
    let mut perms = fs::metadata(cert_path)?.permissions();
    perms.set_mode(0o644);
    fs::set_permissions(cert_path, perms)?;
    
    // Generate authorized_keys template
    let auth_keys_path = "/etc/pq-qkd-proxy/authorized_keys";
    if !Path::new(auth_keys_path).exists() {
        let template = r#"# PQ-QKD-Proxy Authorized Keys
# Format: algorithm base64(falcon_pk||sphincs_pk) permissions comment
# 
# Example:
# falcon512+sphincs+ <base64-encoded-public-keys> perm=read,write qssh-client@example.com
#
# To add a QSSH client:
# 1. Get the client's public keys from their qssh installation
# 2. Base64 encode the concatenated Falcon and SPHINCS+ public keys
# 3. Add a line below with appropriate permissions
"#;
        fs::write(auth_keys_path, template)?;
        let mut perms = fs::metadata(auth_keys_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(auth_keys_path, perms)?;
    }
    
    println!("Keys generated successfully:");
    println!("  Private key: {}", key_path);
    println!("  Certificate: {}", cert_path);
    println!("  Authorized keys: {}", auth_keys_path);
    println!("\nNext steps:");
    println!("1. Add QSSH client public keys to {}", auth_keys_path);
    println!("2. Configure /etc/pq-qkd-proxy/config.toml");
    println!("3. Start the proxy: systemctl start pq-qkd-proxy");
    
    Ok(())
}