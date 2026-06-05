use chrono::{DateTime, Utc};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use zeroize::Zeroize;

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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VaultData {
    pub entries: BTreeMap<String, BTreeMap<String, Entry>>,
}

impl VaultData {
    pub fn empty() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

impl<'de> Deserialize<'de> for VaultData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(VaultDataVisitor)
    }
}

struct VaultDataVisitor;

impl<'de> Visitor<'de> for VaultDataVisitor {
    type Value = VaultData;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("vault data with entries")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut entries = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "entries" => {
                    if entries.is_some() {
                        return Err(de::Error::duplicate_field("entries"));
                    }
                    let raw_entries: BTreeMap<String, serde_json::Value> = map.next_value()?;
                    entries = Some(decode_entries(raw_entries).map_err(de::Error::custom)?);
                }
                _ => {
                    let _ = map.next_value::<serde_json::Value>()?;
                }
            }
        }

        Ok(VaultData {
            entries: entries.unwrap_or_default(),
        })
    }
}

fn decode_entries(
    raw_entries: BTreeMap<String, serde_json::Value>,
) -> Result<BTreeMap<String, BTreeMap<String, Entry>>, serde_json::Error> {
    let mut entries = BTreeMap::new();

    for (service, value) in raw_entries {
        if is_legacy_entry(&value) {
            let entry: Entry = serde_json::from_value(value)?;
            entries
                .entry(service)
                .or_insert_with(BTreeMap::new)
                .insert(entry.username.clone(), entry);
        } else {
            let service_entries: BTreeMap<String, Entry> = serde_json::from_value(value)?;
            entries.insert(service, service_entries);
        }
    }

    Ok(entries)
}

fn is_legacy_entry(value: &serde_json::Value) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.contains_key("username") && object.contains_key("password"))
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub username: String,
    pub password: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Entry")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.password.zeroize();
    }
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

    #[test]
    fn entry_debug_redacts_password() {
        let now = Utc::now();
        let entry = Entry {
            username: "clyde@example.com".to_string(),
            password: "super-secret".to_string(),
            created_at: now,
            updated_at: now,
        };

        let debug = format!("{entry:?}");

        assert!(debug.contains("clyde@example.com"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn vault_data_deserializes_legacy_single_entry_shape() {
        let json = r#"{
            "entries": {
                "github": {
                    "username": "clyde@example.com",
                    "password": "secret",
                    "created_at": "2026-05-28T00:00:00Z",
                    "updated_at": "2026-05-28T00:00:00Z"
                }
            }
        }"#;

        let data: VaultData = serde_json::from_str(json).expect("deserialize legacy data");
        let github = data.entries.get("github").expect("github service");
        let entry = github.get("clyde@example.com").expect("username entry");

        assert_eq!(entry.username, "clyde@example.com");
        assert_eq!(entry.password, "secret");
    }
}
