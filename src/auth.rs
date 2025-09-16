//! Authentication and authorization

use crate::config::Config;
use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, warn};

/// Authenticator for client connections
pub struct Authenticator {
    authorized_keys: HashMap<String, AuthorizedKey>,
}

#[derive(Clone)]
pub struct AuthorizedKey {
    pub key_id: String,
    pub falcon_public_key: Vec<u8>,
    pub sphincs_public_key: Vec<u8>,
    pub permissions: Vec<String>,
    pub comment: String,
}

impl Authenticator {
    pub fn new(config: &Config) -> Result<Self> {
        let authorized_keys = Self::load_authorized_keys(&config.security.authorized_keys)?;
        
        info!("Loaded {} authorized keys", authorized_keys.len());
        
        Ok(Self {
            authorized_keys,
        })
    }
    
    fn load_authorized_keys(path: &str) -> Result<HashMap<String, AuthorizedKey>> {
        let mut keys = HashMap::new();
        
        if !Path::new(path).exists() {
            warn!("Authorized keys file not found: {}", path);
            return Ok(keys);
        }
        
        let content = std::fs::read_to_string(path)?;
        
        for (line_no, line) in content.lines().enumerate() {
            let line = line.trim();
            
            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            // Parse line: algorithm key_data permissions comment
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                warn!("Invalid authorized_keys line {}: too few fields", line_no + 1);
                continue;
            }
            
            let algorithm = parts[0];
            if algorithm != "falcon512+sphincs+" {
                warn!("Unsupported algorithm on line {}: {}", line_no + 1, algorithm);
                continue;
            }
            
            // Parse base64 encoded keys
            let key_data = parts[1];
            let decoded = match general_purpose::STANDARD.decode(key_data) {
                Ok(d) => d,
                Err(e) => {
                    warn!("Invalid base64 on line {}: {}", line_no + 1, e);
                    continue;
                }
            };
            
            // Expected format: falcon_pk || sphincs_pk
            if decoded.len() < 897 + 32 {  // Falcon-512 + SPHINCS+ sizes
                warn!("Invalid key length on line {}", line_no + 1);
                continue;
            }
            
            let falcon_pk = decoded[..897].to_vec();
            let sphincs_pk = decoded[897..897+32].to_vec();
            
            // Parse permissions
            let permissions = if parts.len() > 2 && parts[2].starts_with("perm=") {
                parts[2][5..].split(',').map(|s| s.to_string()).collect()
            } else {
                vec!["read".to_string()]
            };
            
            // Rest is comment
            let comment = if parts.len() > 3 {
                parts[3..].join(" ")
            } else {
                String::new()
            };
            
            let key_id = format!("key-{}", line_no);
            
            keys.insert(key_id.clone(), AuthorizedKey {
                key_id,
                falcon_public_key: falcon_pk,
                sphincs_public_key: sphincs_pk,
                permissions,
                comment,
            });
        }
        
        Ok(keys)
    }
    
    pub fn verify_client(&self, falcon_pk: &[u8], sphincs_pk: &[u8]) -> Result<&AuthorizedKey> {
        // Find matching key
        for (_, auth_key) in &self.authorized_keys {
            if auth_key.falcon_public_key == falcon_pk &&
               auth_key.sphincs_public_key == sphincs_pk {
                return Ok(auth_key);
            }
        }
        
        Err(anyhow!("Unauthorized client key"))
    }
    
    pub fn check_permission(&self, auth_key: &AuthorizedKey, permission: &str) -> bool {
        auth_key.permissions.contains(&permission.to_string()) ||
        auth_key.permissions.contains(&"*".to_string())
    }
}