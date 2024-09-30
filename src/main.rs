// src/main.rs

mod crypto_utils;
use crate::crypto_utils::QuantumCrypto;
use std::error::Error;
use std::io::{self, Write};
use base64::{engine::general_purpose, Engine as _};

fn main() -> Result<(), Box<dyn Error>> {
    let mut crypto = QuantumCrypto::new()?;

    loop {
        println!("Quantum-Resistant Encryption Tool");
        println!("1. Generate Keys");
        println!("2. Save Keys");
        println!("3. Load Keys");
        println!("4. Encrypt Message");
        println!("5. Decrypt Message");
        println!("6. Sign Message");
        println!("7. Verify Signature");
        println!("8. Exit");
        print!("Enter choice: ");
        io::stdout().flush()?;

        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        let choice = choice.trim();

        match choice {
            "1" => {
                crypto.generate_keys()?;
                println!("Keys generated successfully.");
                if let Some(pk) = &crypto.sig_public_key {
                    println!(
                        "Signature Public Key (base64):\n{}",
                        general_purpose::STANDARD.encode(pk.as_ref())
                    );
                }
                if let Some(pk) = &crypto.kem_public_key {
                    println!(
                        "KEM Public Key (base64):\n{}",
                        general_purpose::STANDARD.encode(pk.as_ref())
                    );
                }
            }
            "2" => {
                println!("Enter signature private key file path:");
                let mut sig_priv_path = String::new();
                io::stdin().read_line(&mut sig_priv_path)?;

                println!("Enter signature public key file path:");
                let mut sig_pub_path = String::new();
                io::stdin().read_line(&mut sig_pub_path)?;

                println!("Enter KEM private key file path:");
                let mut kem_priv_path = String::new();
                io::stdin().read_line(&mut kem_priv_path)?;

                println!("Enter KEM public key file path:");
                let mut kem_pub_path = String::new();
                io::stdin().read_line(&mut kem_pub_path)?;

                println!("Enter passphrase to encrypt private keys:");
                let mut passphrase = String::new();
                io::stdin().read_line(&mut passphrase)?;
                let passphrase = passphrase.trim();

                crypto.save_keys(
                    sig_priv_path.trim(),
                    sig_pub_path.trim(),
                    kem_priv_path.trim(),
                    kem_pub_path.trim(),
                    passphrase,
                )?;
                println!("Keys saved successfully.");
            }
            "3" => {
                println!("Enter signature private key file path:");
                let mut sig_priv_path = String::new();
                io::stdin().read_line(&mut sig_priv_path)?;

                println!("Enter signature public key file path:");
                let mut sig_pub_path = String::new();
                io::stdin().read_line(&mut sig_pub_path)?;

                println!("Enter KEM private key file path:");
                let mut kem_priv_path = String::new();
                io::stdin().read_line(&mut kem_priv_path)?;

                println!("Enter KEM public key file path:");
                let mut kem_pub_path = String::new();
                io::stdin().read_line(&mut kem_pub_path)?;

                println!("Enter passphrase to decrypt private keys:");
                let mut passphrase = String::new();
                io::stdin().read_line(&mut passphrase)?;
                let passphrase = passphrase.trim();

                crypto.load_keys(
                    sig_priv_path.trim(),
                    sig_pub_path.trim(),
                    kem_priv_path.trim(),
                    kem_pub_path.trim(),
                    passphrase,
                )?;
                println!("Keys loaded successfully.");
            }
            "4" => {
                println!("Enter message to encrypt:");
                let mut message = String::new();
                io::stdin().read_line(&mut message)?;
                let message = message.trim();
                if message.is_empty() {
                    println!("Message cannot be empty.");
                    continue;
                }

                println!("Enter recipient's KEM public key (base64):");
                let mut recipient_pk = String::new();
                io::stdin().read_line(&mut recipient_pk)?;
                let recipient_pk_bytes =
                    match general_purpose::STANDARD.decode(recipient_pk.trim()) {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            println!("Invalid base64 input for recipient's public key.");
                            continue;
                        }
                    };

                let encrypted_message = match crypto.encrypt_message(message, &recipient_pk_bytes) {
                    Ok(msg) => msg,
                    Err(e) => {
                        println!("Encryption failed: {}", e);
                        continue;
                    }
                };
                println!(
                    "Encrypted Message (base64):\n{}",
                    general_purpose::STANDARD.encode(&encrypted_message)
                );
            }
            "5" => {
                println!("Enter encrypted message (base64):");
                let mut encrypted_message_b64 = String::new();
                io::stdin().read_line(&mut encrypted_message_b64)?;
                let encrypted_message_bytes =
                    match general_purpose::STANDARD.decode(encrypted_message_b64.trim()) {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            println!("Invalid base64 input for encrypted message.");
                            continue;
                        }
                    };

                let decrypted_message = match crypto.decrypt_message(&encrypted_message_bytes) {
                    Ok(msg) => msg,
                    Err(e) => {
                        println!("Decryption failed: {}", e);
                        continue;
                    }
                };
                println!("Decrypted Message:\n{}", decrypted_message);
            }
            "6" => {
                println!("Enter message to sign:");
                let mut message = String::new();
                io::stdin().read_line(&mut message)?;
                let message = message.trim();
                if message.is_empty() {
                    println!("Message cannot be empty.");
                    continue;
                }

                let signature = match crypto.sign_message(message) {
                    Ok(sig) => sig,
                    Err(e) => {
                        println!("Signing failed: {}", e);
                        continue;
                    }
                };
                println!(
                    "Signature (base64):\n{}",
                    general_purpose::STANDARD.encode(&signature)
                );
            }
            "7" => {
                println!("Enter message to verify:");
                let mut message = String::new();
                io::stdin().read_line(&mut message)?;
                let message = message.trim();
                if message.is_empty() {
                    println!("Message cannot be empty.");
                    continue;
                }

                println!("Enter signature (base64):");
                let mut signature_b64 = String::new();
                io::stdin().read_line(&mut signature_b64)?;
                let signature_bytes =
                    match general_purpose::STANDARD.decode(signature_b64.trim()) {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            println!("Invalid base64 input for signature.");
                            continue;
                        }
                    };

                println!("Enter sender's signature public key (base64):");
                let mut sender_pk = String::new();
                io::stdin().read_line(&mut sender_pk)?;
                let sender_pk_bytes = match general_purpose::STANDARD.decode(sender_pk.trim()) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        println!("Invalid base64 input for sender's public key.");
                        continue;
                    }
                };

                let is_valid =
                    match crypto.verify_signature(message, &signature_bytes, &sender_pk_bytes) {
                        Ok(valid) => valid,
                        Err(e) => {
                            println!("Verification failed: {}", e);
                            continue;
                        }
                    };
                if is_valid {
                    println!("Signature is valid.");
                } else {
                    println!("Signature is invalid.");
                }
            }
            "8" => {
                println!("Exiting.");
                break;
            }
            _ => println!("Invalid choice."),
        }
    }

    Ok(())
}
