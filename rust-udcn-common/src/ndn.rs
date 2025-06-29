//! NDN packet types and structures.
//!
//! This module provides the core data structures that represent NDN packets
//! in the µDCN implementation.

use crate::error::Error;
use crate::tlv::{self, TlvElement};
use crate::Result;
use bytes::{Buf, BufMut, Bytes, BytesMut};
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

    pub fn from_tlv(element: &TlvElement) -> Result<Self> {
        if element.tlv_type != tlv::TLV_COMPONENT {
            return Err(Error::NdnPacket(format!(
                "Expected name component TLV type {}, got {}",
                tlv::TLV_COMPONENT,
                element.tlv_type
            )));
        }
        Ok(Self(element.value.clone()))
    }
}

impl fmt::Display for NameComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let printable = self.0.iter().all(|&b| (b.is_ascii_graphic() || b == b' '));
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

    pub fn from_string(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('/').filter(|comp| !comp.is_empty()).collect();

        if parts.len() > MAX_NAME_COMPONENTS {
            return Err(Error::NdnPacket(format!(
                "Name has too many components: {} > {}",
                parts.len(),
                MAX_NAME_COMPONENTS
            )));
        }

        let mut components = Vec::new();
        for comp in parts {
            if comp.as_bytes().len() > MAX_NAME_COMPONENT_LENGTH {
                return Err(Error::NdnPacket(format!(
                    "Name component too long ({} bytes > {})",
                    comp.as_bytes().len(),
                    MAX_NAME_COMPONENT_LENGTH
                )));
            }
            components.push(NameComponent::new(comp.as_bytes().to_vec()));
        }

        Ok(Self { components })
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

    pub fn to_tlv(&self) -> Result<TlvElement> {
        let mut buf = BytesMut::new();
        for component in &self.components {
            component.to_tlv().encode(&mut buf);
        }
        Ok(TlvElement::new(tlv::TLV_NAME, buf.freeze()))
    }

    pub fn from_tlv(element: &TlvElement) -> Result<Self> {
        if element.tlv_type != tlv::TLV_NAME {
            return Err(Error::NdnPacket(format!(
                "Expected name TLV type {}, got {}",
                tlv::TLV_NAME,
                element.tlv_type
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

    pub fn wire_size(&self) -> Result<usize> {
        Ok(self.name.to_tlv()?.len() + 20) // rough estimate
    }

    /// Return the Interest name
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Encode the Interest into TLV wire format
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        let mut inner = BytesMut::new();

        // Name
        self.name.to_tlv()?.encode(&mut inner);

        // Selectors (encode CanBePrefix and MustBeFresh as two bytes)
        let mut selectors = BytesMut::new();
        selectors.put_u8(self.can_be_prefix as u8);
        selectors.put_u8(self.must_be_fresh as u8);
        TlvElement::new(tlv::TLV_SELECTORS, selectors.freeze()).encode(&mut inner);

        // Nonce
        let mut nonce_buf = BytesMut::new();
        nonce_buf.put_u32(self.nonce);
        TlvElement::new(tlv::TLV_NONCE, nonce_buf.freeze()).encode(&mut inner);

        // Lifetime
        let mut life_buf = BytesMut::new();
        life_buf.put_u32(self.lifetime_ms);
        TlvElement::new(tlv::TLV_INTEREST_LIFETIME, life_buf.freeze()).encode(&mut inner);

        // HopLimit if present (TLV type 0x22 as in NDN spec)
        if let Some(hop) = self.hop_limit {
            let mut hop_buf = BytesMut::new();
            hop_buf.put_u8(hop);
            TlvElement::new(0x22, hop_buf.freeze()).encode(&mut inner);
        }

        TlvElement::new(tlv::TLV_INTEREST, inner.freeze()).encode(buf);
        Ok(())
    }

    /// Decode an Interest from TLV wire format
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut buf = Bytes::from(bytes.to_vec());
        let outer = TlvElement::decode(&mut buf)?;
        if outer.tlv_type != tlv::TLV_INTEREST {
            return Err(Error::NdnPacket(format!(
                "Expected Interest type {}, got {}",
                tlv::TLV_INTEREST,
                outer.tlv_type
            )));
        }

        let mut inner = outer.value.clone();
        let mut name = None;
        let mut nonce = None;
        let mut lifetime_ms = None;
        let mut hop_limit = None;
        let mut can_be_prefix = false;
        let mut must_be_fresh = false;

        while inner.has_remaining() {
            let e = TlvElement::decode(&mut inner)?;
            match e.tlv_type {
                tlv::TLV_NAME => {
                    name = Some(Name::from_tlv(&e)?);
                }
                tlv::TLV_NONCE => {
                    let mut nbuf = e.value.clone();
                    if nbuf.remaining() == 4 {
                        nonce = Some(nbuf.get_u32());
                    }
                }
                tlv::TLV_INTEREST_LIFETIME => {
                    let mut lbuf = e.value.clone();
                    if lbuf.remaining() >= 1 && lbuf.remaining() <= 4 {
                        let mut tmp = [0u8; 4];
                        for (i, b) in lbuf.iter().rev().enumerate() {
                            tmp[3 - i] = *b;
                        }
                        lifetime_ms = Some(u32::from_be_bytes(tmp));
                    }
                }
                tlv::TLV_SELECTORS => {
                    if e.value.len() >= 2 {
                        can_be_prefix = e.value[0] != 0;
                        must_be_fresh = e.value[1] != 0;
                    }
                }
                0x22 => {
                    if !e.value.is_empty() {
                        hop_limit = Some(e.value[0]);
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            name: name.ok_or_else(|| Error::NdnPacket("Interest missing name".into()))?,
            nonce: nonce.unwrap_or(0),
            lifetime_ms: lifetime_ms.unwrap_or(4000),
            hop_limit,
            can_be_prefix,
            must_be_fresh,
        })
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
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
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

    pub fn wire_size(&self) -> Result<usize> {
        Ok(self.name.to_tlv()?.len() + self.content.len() + 20)
    }

    /// Return the Data name
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Return the content bytes
    pub fn content(&self) -> &Bytes {
        &self.content
    }

    /// Encode the Data packet into TLV wire format
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        let mut inner = BytesMut::new();

        // Name
        self.name.to_tlv()?.encode(&mut inner);

        // Content
        TlvElement::new(tlv::TLV_CONTENT, self.content.clone()).encode(&mut inner);

        TlvElement::new(tlv::TLV_DATA, inner.freeze()).encode(buf);
        Ok(())
    }

    /// Decode a Data packet from TLV wire format
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut buf = Bytes::from(bytes.to_vec());
        let outer = TlvElement::decode(&mut buf)?;
        if outer.tlv_type != tlv::TLV_DATA {
            return Err(Error::NdnPacket(format!(
                "Expected Data type {}, got {}",
                tlv::TLV_DATA,
                outer.tlv_type
            )));
        }

        let mut inner = outer.value.clone();
        let mut name = None;
        let mut content = Bytes::new();

        while inner.has_remaining() {
            let e = TlvElement::decode(&mut inner)?;
            match e.tlv_type {
                tlv::TLV_NAME => {
                    name = Some(Name::from_tlv(&e)?);
                }
                tlv::TLV_CONTENT => {
                    content = e.value.clone();
                }
                _ => {}
            }
        }

        Ok(Self {
            name: name.ok_or_else(|| Error::NdnPacket("Data missing name".into()))?,
            content,
            ttl_ms: 10_000,
            creation_time: Instant::now(),
        })
    }
}

/* ---------------------------------------------------------------- *\
 * Misc
\* ---------------------------------------------------------------- */

#[derive(Debug, Clone)]
pub enum InterestResult {
    /// The Interest was satisfied with Data
    Data(Data),
    /// The Interest timed out
    Timeout,
    /// The Interest could not be satisfied and was dropped with a reason
    Dropped(String),
}
