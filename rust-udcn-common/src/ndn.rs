//! NDN packet types and structures.
//!
//! This module provides the core data structures that represent NDN packets
//! in the µDCN implementation.

use crate::error::Error;
use crate::tlv::{self, TlvElement};
use bytes::{Buf, Bytes, BytesMut};            // ← removed BufMut (unused)
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{Duration, Instant};

/// Maximum length of an NDN name component.
pub const MAX_NAME_COMPONENT_LENGTH: usize = 255;
/// Maximum number of components in an NDN name.
pub const MAX_NAME_COMPONENTS: usize = 16;
/// Maximum size of an NDN packet.
pub const MAX_NDN_PACKET_SIZE: usize = 8800;

/* ---------------------------------------------------------------- *\
 * Name and NameComponent
\* ---------------------------------------------------------------- */

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NameComponent(pub Bytes);

impl NameComponent {
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        Self(bytes.into())
    }

    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    pub fn to_tlv(&self) -> TlvElement {
        TlvElement::new(tlv::TLV_COMPONENT, self.0.clone())
    }

    pub fn from_tlv(element: &TlvElement) -> Result<Self, Error> {
        if element.tlv_type != tlv::TLV_COMPONENT {
            return Err(Error::NdnPacket(format!(
                "Expected name component TLV type {}, got {}",
                tlv::TLV_COMPONENT, element.tlv_type
            )));
        }
        Ok(Self(element.value.clone()))
    }
}

impl fmt::Display for NameComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let printable = self
            .0
            .iter()
            .all(|&b| (b.is_ascii_graphic() || b == b' '));
        if printable {
            write!(f, "{}", String::from_utf8_lossy(&self.0))
        } else {
            write!(f, "0x")?;
            for &b in &self.0 {
                write!(f, "{:02x}", b)?;
            }
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Name {
    components: Vec<NameComponent>,
}

impl Name {
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
        }
    }

    pub fn from_string(s: &str) -> Self {
        let components = s
            .split('/')
            .filter(|comp| !comp.is_empty())
            .map(|comp| NameComponent::new(comp.as_bytes().to_vec()))
            .collect();
        Self { components }
    }

    pub fn push(&mut self, component: NameComponent) -> &mut Self {
        self.components.push(component);
        self
    }

    pub fn len(&self) -> usize {
        self.components.len()
    }

    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    pub fn components(&self) -> impl Iterator<Item = &NameComponent> {
        self.components.iter()
    }

    pub fn get(&self, index: usize) -> Option<&NameComponent> {
        self.components.get(index)
    }

    pub fn prefix(&self, len: usize) -> Self {
        Self {
            components: self.components.iter().take(len).cloned().collect(),
        }
    }

    pub fn is_prefix_of(&self, other: &Self) -> bool {
        self.components
            .iter()
            .zip(other.components.iter())
            .all(|(a, b)| a == b)
    }

    pub fn to_tlv(&self) -> Result<TlvElement, Error> {
        let mut buf = BytesMut::new();
        for component in &self.components {
            component.to_tlv().encode(&mut buf);
        }
        Ok(TlvElement::new(tlv::TLV_NAME, buf.freeze()))
    }

    pub fn from_tlv(element: &TlvElement) -> Result<Self, Error> {
        if element.tlv_type != tlv::TLV_NAME {
            return Err(Error::NdnPacket(format!(
                "Expected name TLV type {}, got {}",
                tlv::TLV_NAME, element.tlv_type
            )));
        }

        let mut components = Vec::new();
        let mut buf = element.value.clone();
        while buf.has_remaining() {
            let e = TlvElement::decode(&mut buf)?;
            components.push(NameComponent::from_tlv(&e)?);
        }
        Ok(Self { components })
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.components.is_empty() {
            return write!(f, "/");
        }
        for component in &self.components {
            write!(f, "/{}", component)?;
        }
        Ok(())
    }
}

impl Default for Name {
    fn default() -> Self {
        Self::new()
    }
}

/* ---------------------------------------------------------------- *\
 * Interest
\* ---------------------------------------------------------------- */

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interest {
    pub name: Name,
    pub nonce: u32,
    pub lifetime_ms: u32,
    pub hop_limit: Option<u8>,
    pub can_be_prefix: bool,
    pub must_be_fresh: bool,
}

impl Interest {
    pub fn new(name: Name) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0));
        let nonce = (now.as_millis() % u32::MAX as u128) as u32;

        Self {
            name,
            nonce,
            lifetime_ms: 4000,
            hop_limit: Some(32),
            can_be_prefix: false,
            must_be_fresh: true,
        }
    }

    pub fn with_lifetime(mut self, lifetime_ms: u32) -> Self {
        self.lifetime_ms = lifetime_ms;
        self
    }
    pub fn with_nonce(mut self, nonce: u32) -> Self {
        self.nonce = nonce;
        self
    }
    pub fn with_can_be_prefix(mut self, can_be_prefix: bool) -> Self {
        self.can_be_prefix = can_be_prefix;
        self
    }
    pub fn with_must_be_fresh(mut self, must_be_fresh: bool) -> Self {
        self.must_be_fresh = must_be_fresh;
        self
    }

    pub fn wire_size(&self) -> Result<usize, Error> {
        Ok(self.name.to_tlv()?.len() + 20) // rough estimate
    }
}

/* ---------------------------------------------------------------- *\
 * Data
\* ---------------------------------------------------------------- */

/// Helper used only for deserialisation of `Data`.
#[derive(Deserialize)]
struct DataHelper {
    name: Name,
    content: Bytes,
    ttl_ms: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Data {
    pub name: Name,
    pub content: Bytes,
    pub ttl_ms: u32,

    /// Creation timestamp – not serialised, regenerated on deserialisation.
    #[serde(skip_serializing)]
    pub creation_time: Instant,
}

impl<'de> Deserialize<'de> for Data {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = DataHelper::deserialize(deserializer)?;
        Ok(Self {
            name: helper.name,
            content: helper.content,
            ttl_ms: helper.ttl_ms,
            creation_time: Instant::now(), // fresh timestamp
        })
    }
}

impl Data {
    pub fn new(name: Name, content: impl Into<Bytes>) -> Self {
        Self {
            name,
            content: content.into(),
            ttl_ms: 10_000,
            creation_time: Instant::now(),
        }
    }

    pub fn with_ttl(mut self, ttl_ms: u32) -> Self {
        self.ttl_ms = ttl_ms;
        self
    }

    pub fn is_expired(&self) -> bool {
        self.creation_time.elapsed() > Duration::from_millis(self.ttl_ms as u64)
    }

    pub fn wire_size(&self) -> Result<usize, Error> {
        Ok(self.name.to_tlv()?.len() + self.content.len() + 20)
    }
}

/* ---------------------------------------------------------------- *\
 * Misc
\* ---------------------------------------------------------------- */

#[derive(Debug, Clone)]
pub enum InterestResult {
    Forwarded,
    SatisfiedByCs(Data),
    Aggregated,
    Dropped(String),
}
