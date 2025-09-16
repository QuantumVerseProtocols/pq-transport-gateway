//! Main proxy server implementation

use crate::{
    config::Config,
    crypto::{PqKeyExchange, PqSession, mix_keys, random_bytes},
    qkd_client::QkdClient,
    auth::Authenticator,
    audit,
};
use anyhow::{Result, anyhow, Context};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use std::net::SocketAddr;
use tracing::{info, warn, error, debug};
use serde::{Serialize, Deserialize};

/// Proxy server instance
#[derive(Clone)]
pub struct ProxyServer {
    config: Arc<Config>,
    qkd_client: Arc<QkdClient>,
    authenticator: Arc<Authenticator>,
    host_key: Arc<PqKeyExchange>,
}

/// Protocol messages
#[derive(Serialize, Deserialize)]
pub struct ClientHello {
    pub version: String,
    pub client_random: [u8; 32],
    pub falcon_public_key: Vec<u8>,
    pub sphincs_public_key: Vec<u8>,
    pub requested_key_size: usize,
}

#[derive(Serialize, Deserialize)]
pub struct ServerHello {
    pub version: String,
    pub server_random: [u8; 32],
    pub falcon_public_key: Vec<u8>,
    pub sphincs_public_key: Vec<u8>,
    pub falcon_signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct KeyRequest {
    pub key_id: String,
    pub size: usize,
    pub purpose: String,
}

#[derive(Serialize, Deserialize)]
pub struct KeyResponse {
    pub key_id: String,
    pub key_data: Vec<u8>,
    pub metadata: KeyMetadata,
}

#[derive(Serialize, Deserialize)]
pub struct KeyMetadata {
    pub algorithm: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub qkd_enhanced: bool,
}

impl ProxyServer {
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        // Initialize QKD client
        let qkd_client = QkdClient::new(&config)?;
        
        // Load host keys
        let host_key = Self::load_host_keys(&config)?;
        
        // Initialize authenticator
        let authenticator = Authenticator::new(&config)?;
        
        Ok(Self {
            config,
            qkd_client: Arc::new(qkd_client),
            authenticator: Arc::new(authenticator),
            host_key: Arc::new(host_key),
        })
    }
    
    fn load_host_keys(_config: &Config) -> Result<PqKeyExchange> {
        // In production, load from files
        // For now, generate new keys
        PqKeyExchange::new()
    }
    
    pub async fn check_vendor_api(&self) -> Result<()> {
        info!("Checking vendor QKD API connectivity...");
        
        match self.qkd_client.check_connectivity().await {
            Ok(()) => {
                info!("Successfully connected to vendor QKD API");
                Ok(())
            }
            Err(e) => {
                error!("Failed to connect to vendor QKD API: {}", e);
                Err(e)
            }
        }
    }
    
    pub async fn handle_connection(
        &self,
        mut stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        audit::log_connection(&peer_addr);
        
        // Set timeout for initial handshake
        let timeout = tokio::time::Duration::from_secs(self.config.proxy.connection_timeout);
        
        // Perform post-quantum handshake
        let session = tokio::time::timeout(
            timeout,
            self.perform_handshake(&mut stream, &peer_addr)
        ).await
            .context("Handshake timeout")?
            .context("Handshake failed")?;
        
        info!("Established PQ session with {}", peer_addr);
        
        // Handle requests in this session
        self.handle_session(stream, session, peer_addr).await
    }
    
    async fn perform_handshake(
        &self,
        stream: &mut TcpStream,
        peer_addr: &SocketAddr,
    ) -> Result<PqSession> {
        // Read client hello
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        if len > 8192 {
            return Err(anyhow!("Client hello too large"));
        }
        
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        
        let client_hello: ClientHello = bincode::deserialize(&buf)?;
        
        // Verify version
        if !client_hello.version.starts_with("1.") {
            return Err(anyhow!("Unsupported protocol version"));
        }
        
        // Generate server random
        let server_random = random_bytes::<32>();
        
        // Create response
        let mut handshake_data = Vec::new();
        handshake_data.extend_from_slice(&client_hello.client_random);
        handshake_data.extend_from_slice(&server_random);
        handshake_data.extend_from_slice(&client_hello.falcon_public_key);
        use pqcrypto_traits::sign::PublicKey as SignPublicKey;
        handshake_data.extend_from_slice(self.host_key.falcon_pk.as_bytes());
        
        let falcon_signature = self.host_key.sign_falcon(&handshake_data)?;
        
        let server_hello = ServerHello {
            version: "1.0".to_string(),
            server_random,
            falcon_public_key: {
                use pqcrypto_traits::sign::PublicKey as SignPublicKey;
                self.host_key.falcon_pk.as_bytes().to_vec()
            },
            sphincs_public_key: {
                use pqcrypto_traits::sign::PublicKey as SignPublicKey;
                self.host_key.sphincs_pk.as_bytes().to_vec()
            },
            falcon_signature,
        };
        
        // Send server hello
        let response_data = bincode::serialize(&server_hello)?;
        let len_bytes = (response_data.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        stream.write_all(&response_data).await?;
        stream.flush().await?;
        
        // Compute shared secret
        let pqc_secret = self.host_key.compute_shared_secret(
            &client_hello.falcon_public_key,
            &client_hello.client_random,
            &server_random,
        )?;
        
        // Try to get QKD key if available
        let final_secret = if let Ok(qkd_key) = self.qkd_client.get_key(32).await {
            audit::log_qkd_key_used(peer_addr, &qkd_key.key_id);
            mix_keys(&qkd_key.key_data, &pqc_secret)
        } else {
            warn!("QKD not available, using PQC-only mode");
            pqc_secret
        };
        
        // Create session
        let session_id = random_bytes::<32>();
        
        let client_falcon_pk = {
            use pqcrypto_traits::sign::PublicKey as SignPublicKey;
            pqcrypto_falcon::falcon512::PublicKey::from_bytes(&client_hello.falcon_public_key)
                .map_err(|_| anyhow!("Invalid client Falcon key"))?
        };
        
        let client_sphincs_pk = {
            use pqcrypto_traits::sign::PublicKey as SignPublicKey;
            pqcrypto_sphincsplus::sphincssha256128ssimple::PublicKey::from_bytes(&client_hello.sphincs_public_key)
                .map_err(|_| anyhow!("Invalid client SPHINCS+ key"))?
        };
        
        PqSession::new(&final_secret, session_id, client_falcon_pk, client_sphincs_pk)
    }
    
    async fn handle_session(
        &self,
        mut stream: TcpStream,
        mut session: PqSession,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        loop {
            // Read encrypted request
            let mut len_buf = [0u8; 4];
            match stream.read_exact(&mut len_buf).await {
                Ok(_) => {},
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    debug!("Client disconnected");
                    break;
                }
                Err(e) => return Err(e.into()),
            }
            
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > 1024 * 1024 {
                return Err(anyhow!("Request too large"));
            }
            
            let mut encrypted_data = vec![0u8; len];
            stream.read_exact(&mut encrypted_data).await?;
            
            // Decrypt and verify
            let request_data = session.decrypt_and_verify(&encrypted_data)?;
            
            // Parse request
            let request: KeyRequest = bincode::deserialize(&request_data)?;
            
            audit::log_key_request(&peer_addr, &request.key_id, request.size);
            
            // Process request
            let response = self.process_key_request(request).await?;
            
            // Encrypt response
            let response_data = bincode::serialize(&response)?;
            let encrypted_response = session.sign_and_encrypt(
                &response_data,
                self.host_key.falcon_secret_key()
            )?;
            
            // Send response
            let len_bytes = (encrypted_response.len() as u32).to_be_bytes();
            stream.write_all(&len_bytes).await?;
            stream.write_all(&encrypted_response).await?;
            stream.flush().await?;
        }
        
        Ok(())
    }
    
    async fn process_key_request(&self, request: KeyRequest) -> Result<KeyResponse> {
        // Validate request
        if request.size > self.config.qkd.max_key_size {
            return Err(anyhow!("Requested key size exceeds maximum"));
        }
        
        // Get key from QKD system
        let qkd_key = self.qkd_client.get_key(request.size).await?;
        
        let response = KeyResponse {
            key_id: qkd_key.key_id.clone(),
            key_data: qkd_key.key_data,
            metadata: KeyMetadata {
                algorithm: "QKD-BB84".to_string(),
                created_at: chrono::Utc::now().timestamp(),
                expires_at: None,
                qkd_enhanced: true,
            },
        };
        
        Ok(response)
    }
}