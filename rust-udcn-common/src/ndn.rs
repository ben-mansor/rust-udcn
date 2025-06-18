//! NDN packet types and structures.
//!
//! This module provides the core data structures that represent NDN packets
//! in the µDCN implementation.

use crate::error::Error;
use crate::tlv::{self, TlvElement};
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

/// Represents an NDN name component.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NameComponent(pub Bytes);

impl NameComponent {
    /// Creates a new name component from a byte slice.
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        Self(bytes.into())
    }

    /// Returns the component as bytes.
    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    /// Encodes this name component as a TLV element.
    pub fn to_tlv(&self) -> TlvElement {
        TlvElement::new(tlv::TLV_COMPONENT, self.0.clone())
    }

    /// Decodes a name component from a TLV element.
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
        // Print printable ASCII characters directly, otherwise use hex
        let mut printable = true;
        for &b in self.0.iter() {
            if !b.is_ascii_graphic() && b != b' ' {
                printable = false;
                break;
            }
        }

        if printable {
            write!(f, "{}", String::from_utf8_lossy(&self.0))
        } else {
            write!(f, "0x")?;
            for &b in self.0.iter() {
                write!(f, "{:02x}", b)?;
            }
            Ok(())
        }
    }
}

/// Represents an NDN name, which is a sequence of name components.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Name {
    components: Vec<NameComponent>,
}

impl Name {
    /// Creates a new empty NDN name.
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
        }
    }

    /// Creates a name from a string representation with '/' as component separator.
    pub fn from_string(s: &str) -> Self {
        let components = s
            .split('/')
            .filter(|comp| !comp.is_empty())
            .map(|comp| NameComponent::new(comp.as_bytes().to_vec()))
            .collect();

        Self { components }
    }

    /// Adds a component to the name.
    pub fn push(&mut self, component: NameComponent) -> &mut Self {
        self.components.push(component);
        self
    }

    /// Returns the number of components in the name.
    pub fn len(&self) -> usize {
        self.components.len()
    }

    /// Returns true if the name has no components.
    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    /// Returns an iterator over the name components.
    pub fn components(&self) -> impl Iterator<Item = &NameComponent> {
        self.components.iter()
    }

    /// Gets a component at the specified index.
    pub fn get(&self, index: usize) -> Option<&NameComponent> {
        self.components.get(index)
    }

    /// Returns a prefix of this name with the specified length.
    pub fn prefix(&self, len: usize) -> Self {
        Self {
            components: self.components.iter().take(len).cloned().collect(),
        }
    }

    /// Checks if this name is a prefix of another name.
    pub fn is_prefix_of(&self, other: &Self) -> bool {
        if self.len() > other.len() {
            return false;
        }

        for (i, component) in self.components.iter().enumerate() {
            if component != &other.components[i] {
                return false;
            }
        }

        true
    }

    /// Encodes this name as a TLV element.
    pub fn to_tlv(&self) -> Result<TlvElement, Error> {
        let mut buf = BytesMut::new();

        for component in &self.components {
            component.to_tlv().encode(&mut buf);
        }

        Ok(TlvElement::new(tlv::TLV_NAME, buf.freeze()))
    }

    /// Decodes a name from a TLV element.
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
            let element = TlvElement::decode(&mut buf)?;
            components.push(NameComponent::from_tlv(&element)?);
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

/// Represents an NDN Interest packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interest {
    /// The name requested in the Interest.
    pub name: Name,
    
    /// A nonce value to prevent looping.
    pub nonce: u32,
    
    /// Interest lifetime in milliseconds.
    pub lifetime_ms: u32,
    
    /// Hop limit (similar to IP TTL).
    pub hop_limit: Option<u8>,
    
    /// Whether this Interest can be satisfied by cached data.
    pub can_be_prefix: bool,
    
    /// Whether the Interest must be forwarded to the producer.
    pub must_be_fresh: bool,
}

impl Interest {
    /// Creates a new Interest packet.
    pub fn new(name: Name) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0));
        
        let nonce = (now.as_millis() % u32::MAX as u128) as u32;
        
        Self {
            name,
            nonce,
            lifetime_ms: 4000, // Default 4 seconds
            hop_limit: Some(32),
            can_be_prefix: false,
            must_be_fresh: true,
        }
    }

    /// Sets the Interest lifetime.
    pub fn with_lifetime(mut self, lifetime_ms: u32) -> Self {
        self.lifetime_ms = lifetime_ms;
        self
    }

    /// Sets the nonce value.
    pub fn with_nonce(mut self, nonce: u32) -> Self {
        self.nonce = nonce;
        self
    }

    /// Sets the can_be_prefix flag.
    pub fn with_can_be_prefix(mut self, can_be_prefix: bool) -> Self {
        self.can_be_prefix = can_be_prefix;
        self
    }

    /// Sets the must_be_fresh flag.
    pub fn with_must_be_fresh(mut self, must_be_fresh: bool) -> Self {
        self.must_be_fresh = must_be_fresh;
        self
    }

    /// Returns the wire format size of this Interest when encoded.
    pub fn wire_size(&self) -> Result<usize, Error> {
        // Implementation simplified for brevity
        // In a full implementation, this would calculate the exact size
        let name_tlv = self.name.to_tlv()?;
        Ok(name_tlv.len() + 20) // Rough estimate including other fields
    }
}

/// Represents an NDN Data packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Data {
    /// The name of the Data packet.
    pub name: Name,
    
    /// The content of the Data packet.
    pub content: Bytes,
    
    /// Time-to-live in milliseconds.
    pub ttl_ms: u32,
    
    /// When this Data packet was created.
    #[serde(skip)]
    pub creation_time: Instant,
}

impl Data {
    /// Creates a new Data packet.
    pub fn new(name: Name, content: impl Into<Bytes>) -> Self {
        Self {
            name,
            content: content.into(),
            ttl_ms: 10000, // Default 10 seconds
            creation_time: Instant::now(),
        }
    }

    /// Sets the TTL value.
    pub fn with_ttl(mut self, ttl_ms: u32) -> Self {
        self.ttl_ms = ttl_ms;
        self
    }

    /// Checks if this Data packet has expired.
    pub fn is_expired(&self) -> bool {
        self.creation_time.elapsed() > Duration::from_millis(self.ttl_ms as u64)
    }

    /// Returns the wire format size of this Data when encoded.
    pub fn wire_size(&self) -> Result<usize, Error> {
        // Implementation simplified for brevity
        let name_tlv = self.name.to_tlv()?;
        Ok(name_tlv.len() + self.content.len() + 20) // Rough estimate
    }
}

/// The result of processing an Interest packet.
#[derive(Debug, Clone)]
pub enum InterestResult {
    /// The Interest was forwarded.
    Forwarded,
    
    /// The Interest was satisfied by the content store.
    SatisfiedByCs(Data),
    
    /// The Interest was aggregated (merged with a pending Interest).
    Aggregated,
    
    /// The Interest was dropped.
    Dropped(String), // Reason
}
