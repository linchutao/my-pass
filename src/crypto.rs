use crate::errors::{AppError, AppResult};
use crate::model::{CipherBlob, KdfConfig, CIPHER_ALGORITHM, KDF_ALGORITHM};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const SALT_LEN: usize = 16;

pub fn random_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn random_salt() -> Vec<u8> {
    let mut salt = vec![0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn default_kdf_config(salt: Vec<u8>) -> KdfConfig {
    KdfConfig {
        algorithm: KDF_ALGORITHM.to_string(),
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 1,
        salt: STANDARD.encode(salt),
    }
}

pub fn derive_kek(master_password: &str, config: &KdfConfig) -> AppResult<[u8; KEY_LEN]> {
    if config.algorithm != KDF_ALGORITHM {
        return Err(AppError::UnsupportedAlgorithm);
    }

    let salt = STANDARD
        .decode(&config.salt)
        .map_err(|err| AppError::MalformedVault(format!("invalid KDF salt: {err}")))?;
    if salt.is_empty() {
        return Err(AppError::MalformedVault("KDF salt is empty".to_string()));
    }

    let params = Params::new(
        config.memory_kib,
        config.iterations,
        config.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|err| AppError::MalformedVault(format!("invalid Argon2 parameters: {err}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(master_password.as_bytes(), &salt, &mut key)
        .map_err(|err| AppError::MalformedVault(format!("key derivation failed: {err}")))?;

    Ok(key)
}

pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> AppResult<CipherBlob> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| AppError::AuthenticationFailed)?;

    Ok(CipherBlob {
        algorithm: CIPHER_ALGORITHM.to_string(),
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ciphertext),
    })
}

pub fn decrypt(key: &[u8; KEY_LEN], blob: &CipherBlob) -> AppResult<Vec<u8>> {
    if blob.algorithm != CIPHER_ALGORITHM {
        return Err(AppError::UnsupportedAlgorithm);
    }

    let nonce = STANDARD
        .decode(&blob.nonce)
        .map_err(|err| AppError::MalformedVault(format!("invalid cipher nonce: {err}")))?;
    if nonce.len() != NONCE_LEN {
        return Err(AppError::MalformedVault(format!(
            "invalid cipher nonce length: expected {NONCE_LEN}, got {}",
            nonce.len()
        )));
    }

    let ciphertext = STANDARD
        .decode(&blob.ciphertext)
        .map_err(|err| AppError::MalformedVault(format!("invalid ciphertext: {err}")))?;

    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| AppError::AuthenticationFailed)
}

pub fn wrap_dek(kek: &[u8; KEY_LEN], dek: &[u8; KEY_LEN]) -> AppResult<CipherBlob> {
    encrypt(kek, dek)
}

pub fn unwrap_dek(kek: &[u8; KEY_LEN], encrypted_dek: &CipherBlob) -> AppResult<[u8; KEY_LEN]> {
    let mut plaintext = decrypt(kek, encrypted_dek)?;
    if plaintext.len() != KEY_LEN {
        plaintext.zeroize();
        return Err(AppError::MalformedVault(format!(
            "invalid wrapped DEK length: expected {KEY_LEN}, got {}",
            plaintext.len()
        )));
    }

    let mut dek = [0u8; KEY_LEN];
    dek.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(dek)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_round_trips() {
        let key = random_key();
        let plaintext = b"vault contents";

        let blob = encrypt(&key, plaintext).expect("encrypt plaintext");
        let decrypted = decrypt(&key, &blob).expect("decrypt plaintext");

        assert_eq!(decrypted, plaintext);
        assert_eq!(blob.algorithm, CIPHER_ALGORITHM);
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let key = random_key();
        let wrong_key = random_key();
        let blob = encrypt(&key, b"vault contents").expect("encrypt plaintext");

        let err = decrypt(&wrong_key, &blob).expect_err("wrong key should fail authentication");

        assert!(matches!(err, AppError::AuthenticationFailed));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = random_key();
        let mut blob = encrypt(&key, b"vault contents").expect("encrypt plaintext");
        let mut ciphertext = STANDARD
            .decode(&blob.ciphertext)
            .expect("ciphertext should be base64");
        ciphertext[0] ^= 0x01;
        blob.ciphertext = STANDARD.encode(ciphertext);

        let err = decrypt(&key, &blob).expect_err("tampered ciphertext should fail authentication");

        assert!(matches!(err, AppError::AuthenticationFailed));
    }

    #[test]
    fn password_derivation_is_repeatable_with_same_salt() {
        let config = default_kdf_config(random_salt());

        let first = derive_kek("correct horse battery staple", &config).expect("derive key");
        let second = derive_kek("correct horse battery staple", &config).expect("derive key again");

        assert_eq!(first, second);
    }
}
