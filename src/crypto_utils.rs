// src/crypto_utils.rs

use oqs::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use oqs::sig::{PublicKey as SigPublicKey, SecretKey as SigSecretKey};
use oqs::{kem, sig};
use serde::{Serialize, Deserialize};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand_core::{OsRng, RngCore};
use std::fs;
use std::error::Error;
use hkdf::Hkdf;
use sha2::Sha256;
use argon2::Argon2;
use hmac::{Hmac, Mac};
use std::io::Write; // Import Write trait for write_all
use base64::engine::general_purpose;
use base64::Engine;

pub struct QuantumCrypto {
    sig: sig::Sig,
    kem: kem::Kem,
    pub sig_public_key: Option<SigPublicKey>,
    pub sig_private_key: Option<SigSecretKey>,
    pub kem_public_key: Option<KemPublicKey>,
    pub kem_private_key: Option<KemSecretKey>,
}

impl QuantumCrypto {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let sig = sig::Sig::new(sig::Algorithm::Dilithium3)?;
        let kem = kem::Kem::new(kem::Algorithm::Kyber512)?;

        Ok(Self {
            sig,
            kem,
            sig_public_key: None,
            sig_private_key: None,
            kem_public_key: None,
            kem_private_key: None,
        })
    }

    // Generate both signature and KEM keys
    pub fn generate_keys(&mut self) -> Result<(), Box<dyn Error>> {
        let (sig_pk, sig_sk) = self.sig.keypair()?;
        self.sig_public_key = Some(sig_pk);
        self.sig_private_key = Some(sig_sk);

        let (kem_pk, kem_sk) = self.kem.keypair()?;
        self.kem_public_key = Some(kem_pk);
        self.kem_private_key = Some(kem_sk);

        Ok(())
    }

    // Sign a message
    pub fn sign_message(&self, message: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let sk = self.sig_private_key.as_ref().ok_or("Private key not set")?;
        let signature = self.sig.sign(message.as_bytes(), sk)?;
        Ok(signature.as_ref().to_vec())
    }

    // Verify a signature
    pub fn verify_signature(
        &self,
        message: &str,
        signature_bytes: &[u8],
        public_key_bytes: &[u8],
    ) -> Result<bool, Box<dyn Error>> {
        let pk_ref = self
            .sig
            .public_key_from_bytes(public_key_bytes)
            .ok_or("Invalid public key bytes")?;
        let pk = pk_ref.to_owned();

        let signature_ref = self
            .sig
            .signature_from_bytes(signature_bytes)
            .ok_or("Invalid signature bytes")?;
        let signature = signature_ref.to_owned();

        self.sig.verify(message.as_bytes(), &signature, &pk)?;
        Ok(true)
    }

    // Encrypt a message
    pub fn encrypt_message(
        &self,
        message: &str,
        recipient_public_key_bytes: &[u8],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let recipient_pk_ref = self
            .kem
            .public_key_from_bytes(recipient_public_key_bytes)
            .ok_or("Invalid recipient public key bytes")?;
        let recipient_pk = recipient_pk_ref.to_owned();

        let (ciphertext_kem, shared_secret) = self.kem.encapsulate(&recipient_pk)?;

        // Derive AES key using HKDF
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_ref());
        let mut aes_key = [0u8; 32]; // 256 bits for AES-256
        hk.expand(b"AES key", &mut aes_key)
            .map_err(|_| "HKDF expansion failed")?;

        let cipher = Aes256Gcm::new_from_slice(&aes_key)?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, message.as_bytes())
            .map_err(|_| "Encryption failed.")?;

        // Generate MAC
        let mut mac = <Hmac::<Sha256> as Mac>::new_from_slice(&aes_key)
            .map_err(|_| "Failed to create HMAC")?;
        mac.update(ciphertext_kem.as_ref());
        mac.update(&ciphertext);
        mac.update(&nonce_bytes);
        let mac_bytes = mac.finalize().into_bytes();

        let encrypted_data = EncryptedData {
            ciphertext_kem: ciphertext_kem.as_ref().to_vec(),
            ciphertext,
            nonce: nonce_bytes.to_vec(),
            mac: mac_bytes.to_vec(),
        };

        // Serialize using bincode
        let serialized = bincode::serialize(&encrypted_data)?;

        Ok(serialized)
    }

    // Decrypt a message
    pub fn decrypt_message(&self, encrypted_message: &[u8]) -> Result<String, Box<dyn Error>> {
        let sk = self.kem_private_key.as_ref().ok_or("Private key not set")?;

        // Deserialize using bincode
        let encrypted_data: EncryptedData = bincode::deserialize(encrypted_message)?;

        let ciphertext_kem_ref = self
            .kem
            .ciphertext_from_bytes(&encrypted_data.ciphertext_kem)
            .ok_or("Invalid ciphertext KEM bytes")?;
        let ciphertext_kem = ciphertext_kem_ref.to_owned();

        let shared_secret = self.kem.decapsulate(sk, &ciphertext_kem)?;

        // Derive AES key using HKDF
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_ref());
        let mut aes_key = [0u8; 32];
        hk.expand(b"AES key", &mut aes_key)
            .map_err(|_| "HKDF expansion failed")?;

        // Verify MAC
        let mut mac = <Hmac::<Sha256> as Mac>::new_from_slice(&aes_key)
            .map_err(|_| "Failed to create HMAC")?;
        mac.update(&encrypted_data.ciphertext_kem);
        mac.update(&encrypted_data.ciphertext);
        mac.update(&encrypted_data.nonce);
        mac.verify_slice(&encrypted_data.mac)
            .map_err(|_| "Integrity check failed.")?;

        let cipher = Aes256Gcm::new_from_slice(&aes_key)?;

        let nonce = Nonce::from_slice(&encrypted_data.nonce);

        let plaintext = cipher
            .decrypt(nonce, encrypted_data.ciphertext.as_ref())
            .map_err(|_| "Decryption failed.")?;

        Ok(String::from_utf8(plaintext)?)
    }

    // Save keys to files
    pub fn save_keys(
        &self,
        sig_private_key_path: &str,
        sig_public_key_path: &str,
        kem_private_key_path: &str,
        kem_public_key_path: &str,
        passphrase: &str,
    ) -> Result<(), Box<dyn Error>> {
        let sig_sk = self.sig_private_key.as_ref().ok_or("Signature private key not set")?;
        let sig_pk = self.sig_public_key.as_ref().ok_or("Signature public key not set")?;
        let kem_sk = self.kem_private_key.as_ref().ok_or("KEM private key not set")?;
        let kem_pk = self.kem_public_key.as_ref().ok_or("KEM public key not set")?;

        // Derive encryption key using Argon2
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let argon2 = Argon2::default();
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
            .map_err(|_| "Argon2 key derivation failed")?;

        // Encrypt private keys
        let cipher = Aes256Gcm::new_from_slice(&key)?;

        let mut nonce_sig = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_sig);
        let encrypted_sig_sk = cipher
            .encrypt(Nonce::from_slice(&nonce_sig), sig_sk.as_ref())
            .map_err(|_| "Encryption failed.")?;

        let mut nonce_kem = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_kem);
        let encrypted_kem_sk = cipher
            .encrypt(Nonce::from_slice(&nonce_kem), kem_sk.as_ref())
            .map_err(|_| "Encryption failed.")?;

        // Prepare encrypted key data
        let encrypted_sig_key = EncryptedKeyData {
            ciphertext: encrypted_sig_sk,
            nonce: nonce_sig.to_vec(),
            salt: salt.to_vec(),
        };
        let encrypted_kem_key = EncryptedKeyData {
            ciphertext: encrypted_kem_sk,
            nonce: nonce_kem.to_vec(),
            salt: salt.to_vec(),
        };

        // Serialize encrypted keys
        let serialized_sig_sk = bincode::serialize(&encrypted_sig_key)?;
        let serialized_kem_sk = bincode::serialize(&encrypted_kem_key)?;

        // Set file permissions to 0600 (owner read/write only)
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;

        // Save encrypted private keys
        {
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            options.mode(0o600);

            let mut file = options.open(sig_private_key_path)?;
            file.write_all(&serialized_sig_sk)?;
        }
        {
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            options.mode(0o600);

            let mut file = options.open(kem_private_key_path)?;
            file.write_all(&serialized_kem_sk)?;
        }

        // Save public keys (no encryption needed)
        fs::write(
            sig_public_key_path,
            general_purpose::STANDARD.encode(sig_pk.as_ref()),
        )?;
        fs::write(
            kem_public_key_path,
            general_purpose::STANDARD.encode(kem_pk.as_ref()),
        )?;

        Ok(())
    }

    // Load keys from files
    pub fn load_keys(
        &mut self,
        sig_private_key_path: &str,
        sig_public_key_path: &str,
        kem_private_key_path: &str,
        kem_public_key_path: &str,
        passphrase: &str,
    ) -> Result<(), Box<dyn Error>> {
        let sig_sk_data = fs::read(sig_private_key_path)?;
        let sig_pk_encoded = fs::read_to_string(sig_public_key_path)?;
        let kem_sk_data = fs::read(kem_private_key_path)?;
        let kem_pk_encoded = fs::read_to_string(kem_public_key_path)?;

        let sig_pk_bytes = general_purpose::STANDARD.decode(sig_pk_encoded.trim())?;
        let kem_pk_bytes = general_purpose::STANDARD.decode(kem_pk_encoded.trim())?;

        let sig_pk_ref = self
            .sig
            .public_key_from_bytes(&sig_pk_bytes)
            .ok_or("Invalid signature public key bytes")?;
        let sig_pk = sig_pk_ref.to_owned();

        let kem_pk_ref = self
            .kem
            .public_key_from_bytes(&kem_pk_bytes)
            .ok_or("Invalid KEM public key bytes")?;
        let kem_pk = kem_pk_ref.to_owned();

        // Deserialize encrypted keys
        let encrypted_sig_key: EncryptedKeyData = bincode::deserialize(&sig_sk_data)?;
        let encrypted_kem_key: EncryptedKeyData = bincode::deserialize(&kem_sk_data)?;

        // Derive decryption key using Argon2
        let argon2 = Argon2::default();
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), &encrypted_sig_key.salt, &mut key)
            .map_err(|_| "Argon2 key derivation failed")?;

        // Decrypt private keys
        let cipher = Aes256Gcm::new_from_slice(&key)?;

        let sig_sk_bytes = cipher
            .decrypt(
                Nonce::from_slice(&encrypted_sig_key.nonce),
                encrypted_sig_key.ciphertext.as_ref(),
            )
            .map_err(|_| "Decryption failed. Incorrect passphrase or corrupted data.")?;

        let kem_sk_bytes = cipher
            .decrypt(
                Nonce::from_slice(&encrypted_kem_key.nonce),
                encrypted_kem_key.ciphertext.as_ref(),
            )
            .map_err(|_| "Decryption failed. Incorrect passphrase or corrupted data.")?;

        let sig_sk_ref = self
            .sig
            .secret_key_from_bytes(&sig_sk_bytes)
            .ok_or("Invalid signature secret key bytes")?;
        let sig_sk = sig_sk_ref.to_owned();

        let kem_sk_ref = self
            .kem
            .secret_key_from_bytes(&kem_sk_bytes)
            .ok_or("Invalid KEM secret key bytes")?;
        let kem_sk = kem_sk_ref.to_owned();

        self.sig_private_key = Some(sig_sk);
        self.sig_public_key = Some(sig_pk);
        self.kem_private_key = Some(kem_sk);
        self.kem_public_key = Some(kem_pk);

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct EncryptedData {
    ciphertext_kem: Vec<u8>,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    mac: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct EncryptedKeyData {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    salt: Vec<u8>,
}
