//! QKD vendor API client (localhost only)

use crate::config::Config;
use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use reqwest::{Client, Certificate};
use serde::{Serialize, Deserialize};
use tracing::{warn, debug};

/// QKD key material
pub struct QkdKey {
    pub key_id: String,
    pub key_data: Vec<u8>,
}

/// Client for vendor QKD API
pub struct QkdClient {
    client: Client,
    base_url: String,
    api_key: Option<String>,
}

/// ETSI GS QKD 014 compatible request
#[derive(Serialize)]
struct GetKeyRequest {
    number: usize,
    size: usize,
}

/// ETSI GS QKD 014 compatible response
#[derive(Deserialize)]
struct GetKeyResponse {
    keys: Vec<KeyData>,
}

#[derive(Deserialize)]
struct KeyData {
    key_id: String,
    key: String, // Base64 encoded
}

impl QkdClient {
    pub fn new(config: &Config) -> Result<Self> {
        // Build HTTP client with vendor certificate
        let mut client_builder = Client::builder()
            .timeout(std::time::Duration::from_secs(config.qkd.key_timeout));
        
        // Add vendor certificate if provided
        if let Some(cert_path) = &config.qkd.vendor_cert {
            let cert_bytes = std::fs::read(cert_path)?;
            let cert = Certificate::from_pem(&cert_bytes)?;
            client_builder = client_builder.add_root_certificate(cert);
        }
        
        // Only allow localhost connections
        client_builder = client_builder
            .danger_accept_invalid_certs(true) // Vendor certs might be self-signed
            .no_proxy(); // Ensure direct connection
        
        let client = client_builder.build()?;
        
        Ok(Self {
            client,
            base_url: config.qkd.vendor_api.clone(),
            api_key: config.qkd.vendor_api_key.clone(),
        })
    }
    
    pub async fn check_connectivity(&self) -> Result<()> {
        let url = format!("{}/api/v1/status", self.base_url);
        
        let mut req = self.client.get(&url);
        
        if let Some(api_key) = &self.api_key {
            req = req.header("X-API-Key", api_key);
        }
        
        let response = req.send().await?;
        
        if response.status().is_success() {
            Ok(())
        } else {
            Err(anyhow!("QKD API returned status: {}", response.status()))
        }
    }
    
    pub async fn get_key(&self, size: usize) -> Result<QkdKey> {
        let url = format!("{}/api/v1/keys", self.base_url);
        
        let request = GetKeyRequest {
            number: 1,
            size,
        };
        
        let mut req = self.client
            .post(&url)
            .json(&request);
        
        if let Some(api_key) = &self.api_key {
            req = req.header("X-API-Key", api_key);
        }
        
        let response = req.send().await?;
        
        if !response.status().is_success() {
            return Err(anyhow!("QKD API error: {}", response.status()));
        }
        
        let key_response: GetKeyResponse = response.json().await?;
        
        if key_response.keys.is_empty() {
            return Err(anyhow!("No keys available from QKD"));
        }
        
        let key_data = &key_response.keys[0];
        let key_bytes = general_purpose::STANDARD.decode(&key_data.key)?;
        
        if key_bytes.len() != size {
            return Err(anyhow!(
                "QKD returned wrong key size: expected {}, got {}",
                size,
                key_bytes.len()
            ));
        }
        
        debug!("Retrieved QKD key: id={}, size={}", key_data.key_id, size);
        
        Ok(QkdKey {
            key_id: key_data.key_id.clone(),
            key_data: key_bytes,
        })
    }
    
    pub async fn get_keys(&self, count: usize, size: usize) -> Result<Vec<QkdKey>> {
        let url = format!("{}/api/v1/keys", self.base_url);
        
        let request = GetKeyRequest {
            number: count,
            size,
        };
        
        let mut req = self.client
            .post(&url)
            .json(&request);
        
        if let Some(api_key) = &self.api_key {
            req = req.header("X-API-Key", api_key);
        }
        
        let response = req.send().await?;
        
        if !response.status().is_success() {
            return Err(anyhow!("QKD API error: {}", response.status()));
        }
        
        let key_response: GetKeyResponse = response.json().await?;
        
        if key_response.keys.len() < count {
            warn!(
                "QKD returned fewer keys than requested: {} < {}",
                key_response.keys.len(),
                count
            );
        }
        
        let mut keys = Vec::new();
        for key_data in key_response.keys {
            let key_bytes = general_purpose::STANDARD.decode(&key_data.key)?;
            
            if key_bytes.len() != size {
                warn!(
                    "Skipping QKD key with wrong size: expected {}, got {}",
                    size,
                    key_bytes.len()
                );
                continue;
            }
            
            keys.push(QkdKey {
                key_id: key_data.key_id,
                key_data: key_bytes,
            });
        }
        
        Ok(keys)
    }
}