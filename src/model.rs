use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const VAULT_VERSION: u32 = 1;
pub const KDF_ALGORITHM: &str = "argon2id";
pub const CIPHER_ALGORITHM: &str = "chacha20poly1305";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultFile {
    pub version: u32,
    pub kdf: KdfConfig,
    pub key_wrap: CipherBlob,
    pub data: CipherBlob,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfConfig {
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CipherBlob {
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultData {
    pub entries: BTreeMap<String, Entry>,
}

impl VaultData {
    pub fn empty() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub username: String,
    pub password: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_file_round_trips_through_json() {
        let vault = VaultFile {
            version: VAULT_VERSION,
            kdf: KdfConfig {
                algorithm: KDF_ALGORITHM.to_string(),
                memory_kib: 65_536,
                iterations: 3,
                parallelism: 1,
                salt: "sample-salt".to_string(),
            },
            key_wrap: CipherBlob {
                algorithm: CIPHER_ALGORITHM.to_string(),
                nonce: "key-wrap-nonce".to_string(),
                ciphertext: "encrypted-dek".to_string(),
            },
            data: CipherBlob {
                algorithm: CIPHER_ALGORITHM.to_string(),
                nonce: "data-nonce".to_string(),
                ciphertext: "vault-ciphertext".to_string(),
            },
        };

        let json = serde_json::to_string(&vault).expect("serialize vault file");
        let round_trip: VaultFile = serde_json::from_str(&json).expect("deserialize vault file");

        assert_eq!(round_trip.version, 1);
        assert_eq!(round_trip.kdf.algorithm, "argon2id");
        assert_eq!(round_trip.key_wrap.ciphertext, "encrypted-dek");
        assert_eq!(round_trip.data.ciphertext, "vault-ciphertext");
    }
}
