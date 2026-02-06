use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Cursor;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

const TITLE_MIN_BYTES: usize = 1;
const TITLE_MAX_BYTES: usize = 256;
const USERNAME_MAX_BYTES: usize = 256;
const PASSWORD_MAX_BYTES: usize = 10_000;
const NOTE_BODY_MAX_BYTES: usize = 1_000_000;
const LOGIN_NOTES_MAX_BYTES: usize = 100_000;
const PASSKEY_NOTES_MAX_BYTES: usize = 100_000;
const URL_MIN_BYTES: usize = 1;
const URL_MAX_BYTES: usize = 2_048;
const RP_ID_MAX_BYTES: usize = 256;
const RP_NAME_MAX_BYTES: usize = 256;
const USER_DISPLAY_NAME_MAX_BYTES: usize = 256;
const TAG_MIN_BYTES: usize = 1;
const TAG_MAX_BYTES: usize = 64;
const MAX_ITEM_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("payload encoding failed")]
    EncodeFailure,
    #[error("payload decoding failed")]
    DecodeFailure,
    #[error("unsupported payload schema: {0}")]
    UnsupportedSchema(u8),
    #[error("invalid field `{field}`: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("duplicate item id: {0}")]
    DuplicateItemId(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultPayload {
    pub schema: u8,
    pub app: AppMetadata,
    pub updated_at: u64,
    #[serde(default)]
    pub items: Vec<VaultItem>,
    #[serde(default)]
    pub tombstones: Vec<Tombstone>,
    #[serde(default)]
    pub settings: BTreeMap<String, String>,
    #[serde(default)]
    pub search_index: SearchIndex,
}

impl VaultPayload {
    #[must_use]
    pub fn new(app_name: &str, app_version: &str, now: u64) -> Self {
        Self {
            schema: 1,
            app: AppMetadata {
                name: app_name.to_owned(),
                version: app_version.to_owned(),
            },
            updated_at: now,
            items: Vec::new(),
            tombstones: Vec::new(),
            settings: BTreeMap::new(),
            search_index: SearchIndex::default(),
        }
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ModelError> {
        let mut payload: Self =
            ciborium::de::from_reader(Cursor::new(bytes)).map_err(|_| ModelError::DecodeFailure)?;
        payload.validate()?;
        if payload.search_index.docs.is_empty() && !payload.items.is_empty() {
            payload.rebuild_search_index();
        }
        Ok(payload)
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, ModelError> {
        self.validate()?;
        let mut output = Vec::new();
        ciborium::ser::into_writer(self, &mut output).map_err(|_| ModelError::EncodeFailure)?;
        if output.len() > MAX_ITEM_BYTES {
            return Err(ModelError::InvalidField {
                field: "payload",
                reason: "payload exceeds size limit".to_owned(),
            });
        }
        Ok(output)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.schema != 1 {
            return Err(ModelError::UnsupportedSchema(self.schema));
        }

        let mut seen_ids = HashSet::new();
        for item in &self.items {
            item.validate()?;
            if !seen_ids.insert(item.id().to_owned()) {
                return Err(ModelError::DuplicateItemId(item.id().to_owned()));
            }
        }

        for tombstone in &self.tombstones {
            validate_uuid(&tombstone.id, "tombstones[].id")?;
        }

        Ok(())
    }

    #[must_use]
    pub fn item_count(&self) -> u32 {
        u32::try_from(self.items.len()).unwrap_or(u32::MAX)
    }

    pub fn add_item(&mut self, item: VaultItem, now: u64) -> Result<(), ModelError> {
        item.validate()?;
        if self.items.iter().any(|existing| existing.id() == item.id()) {
            return Err(ModelError::DuplicateItemId(item.id().to_owned()));
        }

        self.items.push(item);
        self.updated_at = now;
        self.rebuild_search_index();
        Ok(())
    }

    pub fn soft_delete_item(&mut self, id: &str, now: u64) -> bool {
        if let Some(index) = self.items.iter().position(|item| item.id() == id) {
            self.items.remove(index);
            self.tombstones.push(Tombstone {
                id: id.to_owned(),
                deleted_at: now,
            });
            self.updated_at = now;
            self.rebuild_search_index();
            return true;
        }

        false
    }

    #[must_use]
    pub fn get_item(&self, id: &str) -> Option<&VaultItem> {
        self.items.iter().find(|item| item.id() == id)
    }

    #[must_use]
    pub fn list_items(&self, filter: Option<ItemTypeFilter>) -> Vec<&VaultItem> {
        self.items
            .iter()
            .filter(|item| match filter {
                Some(ItemTypeFilter::Login) => matches!(item, VaultItem::Login(_)),
                Some(ItemTypeFilter::Note) => matches!(item, VaultItem::Note(_)),
                Some(ItemTypeFilter::PasskeyRef) => matches!(item, VaultItem::PasskeyRef(_)),
                None => true,
            })
            .collect()
    }

    #[must_use]
    pub fn search_items(&self, query: &str) -> Vec<&VaultItem> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() {
            return self.items.iter().collect();
        }

        let id_to_item: HashMap<&str, &VaultItem> =
            self.items.iter().map(|item| (item.id(), item)).collect();
        self.search_index
            .docs
            .iter()
            .filter(|doc| doc.text.contains(&needle))
            .filter_map(|doc| id_to_item.get(doc.id.as_str()).copied())
            .collect()
    }

    pub fn rebuild_search_index(&mut self) {
        self.search_index.docs = self
            .items
            .iter()
            .map(|item| SearchDoc {
                id: item.id().to_owned(),
                text: item.search_text(),
            })
            .collect();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppMetadata {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SearchIndex {
    #[serde(default)]
    pub docs: Vec<SearchDoc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchDoc {
    pub id: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tombstone {
    pub id: String,
    pub deleted_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum VaultItem {
    #[serde(rename = "login")]
    Login(LoginItem),
    #[serde(rename = "note")]
    Note(NoteItem),
    #[serde(rename = "passkey_ref")]
    PasskeyRef(PasskeyRefItem),
}

impl VaultItem {
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Login(item) => &item.id,
            Self::Note(item) => &item.id,
            Self::PasskeyRef(item) => &item.id,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        match self {
            Self::Login(item) => item.validate(),
            Self::Note(item) => item.validate(),
            Self::PasskeyRef(item) => item.validate(),
        }
    }

    #[must_use]
    pub fn search_text(&self) -> String {
        match self {
            Self::Login(item) => {
                let mut chunks = vec![item.title.to_lowercase()];
                for entry in &item.urls {
                    chunks.push(entry.url.to_lowercase());
                }
                if let Some(username) = &item.username {
                    chunks.push(username.to_lowercase());
                }
                for tag in &item.tags {
                    chunks.push(tag.to_lowercase());
                }
                chunks.join(" ")
            }
            Self::Note(item) => {
                let mut chunks = vec![item.title.to_lowercase()];
                for tag in &item.tags {
                    chunks.push(tag.to_lowercase());
                }
                chunks.join(" ")
            }
            Self::PasskeyRef(item) => {
                let mut chunks = vec![item.title.to_lowercase(), item.rp_id.to_lowercase()];
                for tag in &item.tags {
                    chunks.push(tag.to_lowercase());
                }
                chunks.join(" ")
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginItem {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub urls: Vec<UrlEntry>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<TotpConfig>,
    pub notes: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    pub created_at: u64,
    pub updated_at: u64,
}

impl LoginItem {
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_uuid(&self.id, "items[].id")?;
        validate_text_len(
            &self.title,
            TITLE_MIN_BYTES,
            TITLE_MAX_BYTES,
            "items[].title",
        )?;
        for entry in &self.urls {
            entry.validate()?;
        }
        if let Some(username) = &self.username {
            validate_text_len(username, 0, USERNAME_MAX_BYTES, "items[].username")?;
        }
        if let Some(password) = &self.password {
            validate_text_len(password, 0, PASSWORD_MAX_BYTES, "items[].password")?;
        }
        if let Some(notes) = &self.notes {
            validate_text_len(notes, 0, LOGIN_NOTES_MAX_BYTES, "items[].notes")?;
        }
        validate_tags(&self.tags)?;
        if let Some(totp) = &self.totp {
            totp.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UrlEntry {
    pub url: String,
    #[serde(rename = "match")]
    pub match_type: UrlMatchType,
}

impl UrlEntry {
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_text_len(
            &self.url,
            URL_MIN_BYTES,
            URL_MAX_BYTES,
            "items[].urls[].url",
        )?;
        Url::parse(&self.url).map_err(|error| ModelError::InvalidField {
            field: "items[].urls[].url",
            reason: error.to_string(),
        })?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UrlMatchType {
    Exact,
    Domain,
    Subdomain,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpConfig {
    #[serde(with = "serde_bytes")]
    pub seed: Vec<u8>,
    pub issuer: Option<String>,
    pub algorithm: TotpAlgorithm,
    pub digits: u8,
    pub period: u16,
}

impl TotpConfig {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.seed.is_empty() {
            return Err(ModelError::InvalidField {
                field: "items[].totp.seed",
                reason: "seed cannot be empty".to_owned(),
            });
        }
        if let Some(issuer) = &self.issuer {
            validate_text_len(issuer, 0, TITLE_MAX_BYTES, "items[].totp.issuer")?;
        }
        if self.digits != 6 && self.digits != 8 {
            return Err(ModelError::InvalidField {
                field: "items[].totp.digits",
                reason: "must be 6 or 8".to_owned(),
            });
        }
        if self.period != 30 && self.period != 60 {
            return Err(ModelError::InvalidField {
                field: "items[].totp.period",
                reason: "must be 30 or 60".to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum TotpAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NoteItem {
    pub id: String,
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    pub created_at: u64,
    pub updated_at: u64,
}

impl NoteItem {
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_uuid(&self.id, "items[].id")?;
        validate_text_len(
            &self.title,
            TITLE_MIN_BYTES,
            TITLE_MAX_BYTES,
            "items[].title",
        )?;
        validate_text_len(&self.body, 0, NOTE_BODY_MAX_BYTES, "items[].body")?;
        validate_tags(&self.tags)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasskeyRefItem {
    pub id: String,
    pub title: String,
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_display_name: Option<String>,
    #[serde(with = "serde_bytes")]
    pub credential_id: Vec<u8>,
    pub notes: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    pub created_at: u64,
    pub updated_at: u64,
}

impl PasskeyRefItem {
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_uuid(&self.id, "items[].id")?;
        validate_text_len(
            &self.title,
            TITLE_MIN_BYTES,
            TITLE_MAX_BYTES,
            "items[].title",
        )?;
        validate_text_len(
            &self.rp_id,
            TITLE_MIN_BYTES,
            RP_ID_MAX_BYTES,
            "items[].rp_id",
        )?;
        if let Some(rp_name) = &self.rp_name {
            validate_text_len(rp_name, 0, RP_NAME_MAX_BYTES, "items[].rp_name")?;
        }
        if let Some(display_name) = &self.user_display_name {
            validate_text_len(
                display_name,
                0,
                USER_DISPLAY_NAME_MAX_BYTES,
                "items[].user_display_name",
            )?;
        }
        if self.credential_id.is_empty() {
            return Err(ModelError::InvalidField {
                field: "items[].credential_id",
                reason: "credential_id cannot be empty".to_owned(),
            });
        }
        if let Some(notes) = &self.notes {
            validate_text_len(notes, 0, PASSKEY_NOTES_MAX_BYTES, "items[].notes")?;
        }
        validate_tags(&self.tags)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ItemTypeFilter {
    Login,
    Note,
    PasskeyRef,
}

fn validate_uuid(value: &str, field: &'static str) -> Result<(), ModelError> {
    Uuid::parse_str(value).map_err(|error| ModelError::InvalidField {
        field,
        reason: error.to_string(),
    })?;
    Ok(())
}

fn validate_text_len(
    value: &str,
    min: usize,
    max: usize,
    field: &'static str,
) -> Result<(), ModelError> {
    let len = value.len();
    if len < min || len > max {
        return Err(ModelError::InvalidField {
            field,
            reason: format!("length must be between {min} and {max} bytes"),
        });
    }
    Ok(())
}

fn validate_tags(tags: &[String]) -> Result<(), ModelError> {
    for tag in tags {
        let trimmed = tag.trim();
        if trimmed != tag {
            return Err(ModelError::InvalidField {
                field: "items[].tags[]",
                reason: "tags must be trimmed".to_owned(),
            });
        }
        validate_text_len(trimmed, TAG_MIN_BYTES, TAG_MAX_BYTES, "items[].tags[]")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ItemTypeFilter, LoginItem, NoteItem, UrlEntry, UrlMatchType, VaultItem, VaultPayload,
    };

    #[test]
    fn payload_roundtrip_and_search_index() {
        let mut payload = VaultPayload::new("npw", "0.1.0", 10);
        payload
            .add_item(
                VaultItem::Login(LoginItem {
                    id: uuid::Uuid::new_v4().to_string(),
                    title: "Example".to_owned(),
                    urls: vec![UrlEntry {
                        url: "https://example.com".to_owned(),
                        match_type: UrlMatchType::Exact,
                    }],
                    username: Some("user@example.com".to_owned()),
                    password: Some("s3cr3t".to_owned()),
                    totp: None,
                    notes: None,
                    tags: vec!["prod".to_owned()],
                    favorite: false,
                    created_at: 10,
                    updated_at: 10,
                }),
                10,
            )
            .expect("item add should succeed");

        let bytes = payload.to_cbor().expect("encode should succeed");
        let decoded = VaultPayload::from_cbor(&bytes).expect("decode should succeed");
        assert_eq!(decoded.item_count(), 1);
        assert_eq!(decoded.search_items("example").len(), 1);
    }

    #[test]
    fn soft_delete_creates_tombstone() {
        let id = uuid::Uuid::new_v4().to_string();
        let mut payload = VaultPayload::new("npw", "0.1.0", 1);
        payload
            .add_item(
                VaultItem::Note(NoteItem {
                    id: id.clone(),
                    title: "My note".to_owned(),
                    body: "note body".to_owned(),
                    tags: vec![],
                    favorite: false,
                    created_at: 1,
                    updated_at: 1,
                }),
                1,
            )
            .expect("add should succeed");

        let removed = payload.soft_delete_item(&id, 2);
        assert!(removed);
        assert_eq!(payload.items.len(), 0);
        assert_eq!(payload.tombstones.len(), 1);
    }

    #[test]
    fn list_filter_returns_matching_types() {
        let mut payload = VaultPayload::new("npw", "0.1.0", 1);
        payload
            .add_item(
                VaultItem::Note(NoteItem {
                    id: uuid::Uuid::new_v4().to_string(),
                    title: "note".to_owned(),
                    body: "".to_owned(),
                    tags: vec![],
                    favorite: false,
                    created_at: 1,
                    updated_at: 1,
                }),
                1,
            )
            .expect("add should succeed");

        assert_eq!(payload.list_items(Some(ItemTypeFilter::Note)).len(), 1);
        assert_eq!(payload.list_items(Some(ItemTypeFilter::Login)).len(), 0);
    }
}
