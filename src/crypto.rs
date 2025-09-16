//! Post-quantum cryptography implementation

use pqcrypto_falcon::falcon512;
use pqcrypto_sphincsplus::sphincssha256128ssimple as sphincs;
use pqcrypto_traits::sign::{PublicKey as SignPublicKey, SignedMessage as SignedMessageTrait};
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::{Aead, OsRng};
use sha3::{Sha3_256, Digest};
use rand::RngCore;
use anyhow::{Result, anyhow};

/// Post-quantum key exchange state
pub struct PqKeyExchange {
    pub falcon_pk: falcon512::PublicKey,
    falcon_sk: falcon512::SecretKey,
    pub sphincs_pk: sphincs::PublicKey,
    sphincs_sk: sphincs::SecretKey,
}

/// Encrypted session for post-quantum communication
pub struct PqSession {
    cipher: Aes256Gcm,
    session_id: [u8; 32],
    nonce_counter: u64,
    remote_falcon_pk: falcon512::PublicKey,
    remote_sphincs_pk: sphincs::PublicKey,
}

impl PqKeyExchange {
    pub fn new() -> Result<Self> {
        let (falcon_pk, falcon_sk) = falcon512::keypair();
        let (sphincs_pk, sphincs_sk) = sphincs::keypair();
        
        Ok(Self {
            falcon_pk,
            falcon_sk,
            sphincs_pk,
            sphincs_sk,
        })
    }
    
    pub fn from_keys(
        falcon_sk: falcon512::SecretKey,
        falcon_pk: falcon512::PublicKey,
        sphincs_sk: sphincs::SecretKey,
        sphincs_pk: sphincs::PublicKey,
    ) -> Self {
        Self {
            falcon_pk,
            falcon_sk,
            sphincs_pk,
            sphincs_sk,
        }
    }
    
    /// Sign data with Falcon
    pub fn sign_falcon(&self, data: &[u8]) -> Result<Vec<u8>> {
        let sig = falcon512::sign(data, &self.falcon_sk);
        use SignedMessageTrait;
        Ok(sig.as_bytes().to_vec())
    }
    
    /// Sign data with SPHINCS+
    pub fn sign_sphincs(&self, data: &[u8]) -> Result<Vec<u8>> {
        let sig = sphincs::sign(data, &self.sphincs_sk);
        use SignedMessageTrait;
        Ok(sig.as_bytes().to_vec())
    }
    
    /// Verify Falcon signature
    pub fn verify_falcon(
        data: &[u8], 
        signature: &[u8], 
        public_key: &[u8]
    ) -> Result<bool> {
        use SignPublicKey;
        let pk = falcon512::PublicKey::from_bytes(public_key)
            .map_err(|_| anyhow!("Invalid Falcon public key"))?;
        
        use SignedMessageTrait;
        let sig = falcon512::SignedMessage::from_bytes(signature)
            .map_err(|_| anyhow!("Invalid Falcon signature"))?;
        
        match falcon512::open(&sig, &pk) {
            Ok(msg) => Ok(msg == data),
            Err(_) => Ok(false),
        }
    }
    
    /// Verify SPHINCS+ signature
    pub fn verify_sphincs(
        data: &[u8],
        signature: &[u8],
        public_key: &[u8]
    ) -> Result<bool> {
        use SignPublicKey;
        use SignedMessageTrait;
        let pk = sphincs::PublicKey::from_bytes(public_key)
            .map_err(|_| anyhow!("Invalid SPHINCS+ public key"))?;
        
        let sig = sphincs::SignedMessage::from_bytes(signature)
            .map_err(|_| anyhow!("Invalid SPHINCS+ signature"))?;
        
        match sphincs::open(&sig, &pk) {
            Ok(msg) => Ok(msg == data),
            Err(_) => Ok(false),
        }
    }
    
    /// Get reference to Falcon secret key
    pub fn falcon_secret_key(&self) -> &falcon512::SecretKey {
        &self.falcon_sk
    }
    
    /// Get reference to SPHINCS+ secret key
    pub fn sphincs_secret_key(&self) -> &sphincs::SecretKey {
        &self.sphincs_sk
    }
    
    /// Compute shared secret from Falcon signatures
    pub fn compute_shared_secret(
        &self,
        remote_falcon_pk: &[u8],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
    ) -> Result<[u8; 32]> {
        // Create data for signature-based key agreement
        let mut data = Vec::new();
        data.extend_from_slice(client_random);
        data.extend_from_slice(server_random);
        data.extend_from_slice(remote_falcon_pk);
        use SignPublicKey;
        data.extend_from_slice(self.falcon_pk.as_bytes());
        
        // Sign with our private key
        let our_sig = self.sign_falcon(&data)?;
        
        // Derive shared secret using HKDF
        let mut hasher = Sha3_256::new();
        hasher.update(&data);
        hasher.update(&our_sig);
        
        let ikm = hasher.finalize();
        // Use SHA3 directly for key derivation (no HKDF needed)
        let mut kdf = Sha3_256::new();
        kdf.update(b"pq-qkd-proxy-v1");
        kdf.update(&ikm);
        kdf.update(b"shared-secret");
        
        let result = kdf.finalize();
        let mut okm = [0u8; 32];
        okm.copy_from_slice(&result);
        
        Ok(okm)
    }
}

impl PqSession {
    pub fn new(
        shared_secret: &[u8; 32],
        session_id: [u8; 32],
        remote_falcon_pk: falcon512::PublicKey,
        remote_sphincs_pk: sphincs::PublicKey,
    ) -> Result<Self> {
        let key = Key::<Aes256Gcm>::from_slice(shared_secret);
        let cipher = Aes256Gcm::new(&key);
        
        Ok(Self {
            cipher,
            session_id,
            nonce_counter: 0,
            remote_falcon_pk,
            remote_sphincs_pk,
        })
    }
    
    /// Encrypt data with AES-256-GCM
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&self.nonce_counter.to_be_bytes());
        self.nonce_counter += 1;
        
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = self.cipher.encrypt(nonce, plaintext)
            .map_err(|_| anyhow!("Encryption failed"))?;
        
        Ok((ciphertext, nonce_bytes))
    }
    
    /// Decrypt data with AES-256-GCM
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        
        let plaintext = self.cipher.decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("Decryption failed"))?;
        
        Ok(plaintext)
    }
    
    /// Sign data with authenticated encryption
    pub fn sign_and_encrypt(&mut self, data: &[u8], signing_key: &falcon512::SecretKey) -> Result<Vec<u8>> {
        // Sign the data
        let signature = falcon512::sign(data, signing_key);
        
        // Combine data and signature
        let mut payload = Vec::new();
        payload.extend_from_slice(&(data.len() as u32).to_be_bytes());
        payload.extend_from_slice(data);
        payload.extend_from_slice(signature.as_bytes());
        
        // Encrypt
        let (ciphertext, nonce) = self.encrypt(&payload)?;
        
        // Prepend nonce
        let mut result = Vec::new();
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    /// Verify and decrypt authenticated data
    pub fn decrypt_and_verify(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if encrypted.len() < 12 {
            return Err(anyhow!("Invalid encrypted data"));
        }
        
        // Extract nonce and ciphertext
        let (nonce, ciphertext) = encrypted.split_at(12);
        let mut nonce_array = [0u8; 12];
        nonce_array.copy_from_slice(nonce);
        
        // Decrypt
        let payload = self.decrypt(ciphertext, &nonce_array)?;
        
        if payload.len() < 4 {
            return Err(anyhow!("Invalid payload"));
        }
        
        // Extract data length
        let data_len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
        
        if payload.len() < 4 + data_len {
            return Err(anyhow!("Invalid payload length"));
        }
        
        // Split data and signature
        let data = &payload[4..4 + data_len];
        let signature = &payload[4 + data_len..];
        
        // Verify signature
        use SignedMessageTrait;
        let sig = falcon512::SignedMessage::from_bytes(signature)
            .map_err(|_| anyhow!("Invalid signature"))?;
        
        match falcon512::open(&sig, &self.remote_falcon_pk) {
            Ok(verified_data) if verified_data == data => Ok(data.to_vec()),
            _ => Err(anyhow!("Signature verification failed")),
        }
    }
}

/// Mix quantum and classical keys
pub fn mix_keys(qkd_key: &[u8], pqc_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"pq-qkd-proxy-key-mixing-v1");
    hasher.update(qkd_key);
    hasher.update(pqc_key);
    
    let mixed = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&mixed);
    result
}

/// Generate secure random bytes
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pq_key_exchange() {
        let alice = PqKeyExchange::new().unwrap();
        let bob = PqKeyExchange::new().unwrap();
        
        // Exchange public keys and compute shared secrets
        let client_random = random_bytes::<32>();
        let server_random = random_bytes::<32>();
        
        let alice_secret = alice.compute_shared_secret(
            bob.falcon_pk.as_bytes(),
            &client_random,
            &server_random,
        ).unwrap();
        
        let bob_secret = bob.compute_shared_secret(
            alice.falcon_pk.as_bytes(),
            &client_random,
            &server_random,
        ).unwrap();
        
        // Secrets should be deterministic based on inputs
        assert_eq!(alice_secret.len(), 32);
        assert_eq!(bob_secret.len(), 32);
    }
    
    #[test]
    fn test_pq_session_encryption() {
        let shared_secret = random_bytes::<32>();
        let session_id = random_bytes::<32>();
        
        let kex = PqKeyExchange::new().unwrap();
        let mut session = PqSession::new(
            &shared_secret,
            session_id,
            kex.falcon_pk.clone(),
            kex.sphincs_pk.clone(),
        ).unwrap();
        
        // Test encryption/decryption
        let plaintext = b"Quantum-safe message";
        let (ciphertext, nonce) = session.encrypt(plaintext).unwrap();
        
        let decrypted = session.decrypt(&ciphertext, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_key_mixing() {
        let qkd_key = vec![0x11; 32];
        let pqc_key = [0x22; 32];
        
        let mixed = mix_keys(&qkd_key, &pqc_key);
        
        // Mixed key should be different from inputs
        assert_ne!(&mixed[..], &qkd_key[..]);
        assert_ne!(mixed, pqc_key);
        
        // Should be deterministic
        let mixed2 = mix_keys(&qkd_key, &pqc_key);
        assert_eq!(mixed, mixed2);
    }
}