//! TLV (Type-Length-Value) encoding and decoding utilities.
//!
//! This module provides functions for encoding and decoding NDN TLV packets.

use crate::error::Error;
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// NDN TLV packet types
pub const TLV_INTEREST: u8 = 0x05;
pub const TLV_DATA: u8 = 0x06;
pub const TLV_NACK: u8 = 0x03;
pub const TLV_NAME: u8 = 0x07;
pub const TLV_COMPONENT: u8 = 0x08;
pub const TLV_NONCE: u8 = 0x0A;
pub const TLV_INTEREST_LIFETIME: u8 = 0x0C;
pub const TLV_SELECTORS: u8 = 0x09;
pub const TLV_CONTENT: u8 = 0x15;

/// Encodes a TLV type field.
///
/// Currently only supports single-byte TLV types (0-255).
pub fn encode_tlv_type(tlv_type: u8, buf: &mut BytesMut) {
    buf.put_u8(tlv_type);
}

/// Encodes a TLV length field.
///
/// Supports variable-length encoding:
/// - If length < 253, uses 1 byte
/// - If length <= 65535, uses 3 bytes (253 + 2 bytes)
/// - If length > 65535, uses 5 bytes (254 + 4 bytes)
pub fn encode_tlv_length(length: usize, buf: &mut BytesMut) {
    if length < 253 {
        buf.put_u8(length as u8);
    } else if length <= 65535 {
        buf.put_u8(253);
        buf.put_u16(length as u16);
    } else {
        buf.put_u8(254);
        buf.put_u32(length as u32);
    }
}

/// Decodes a TLV type field.
///
/// Currently only supports single-byte TLV types (0-255).
pub fn decode_tlv_type(buf: &mut impl Buf) -> Result<u8, Error> {
    if !buf.has_remaining() {
        return Err(Error::Tlv("Buffer underflow when decoding TLV type".into()));
    }
    Ok(buf.get_u8())
}

/// Decodes a TLV length field.
///
/// Handles variable-length encoding as per NDN spec.
pub fn decode_tlv_length(buf: &mut impl Buf) -> Result<usize, Error> {
    if !buf.has_remaining() {
        return Err(Error::Tlv("Buffer underflow when decoding TLV length".into()));
    }

    let first_byte = buf.get_u8();

    match first_byte {
        // Small length (< 253)
        0..=252 => Ok(first_byte as usize),
        
        // Medium length (16 bits)
        253 => {
            if buf.remaining() < 2 {
                return Err(Error::Tlv("Buffer underflow when decoding 16-bit TLV length".into()));
            }
            Ok(buf.get_u16() as usize)
        },
        
        // Large length (32 bits)
        254 => {
            if buf.remaining() < 4 {
                return Err(Error::Tlv("Buffer underflow when decoding 32-bit TLV length".into()));
            }
            Ok(buf.get_u32() as usize)
        },
        
        // Very large length (64 bits) - not supported in this implementation
        255 => Err(Error::Tlv("64-bit TLV lengths not supported".into())),
        
        // This branch should be unreachable with u8 values
        _ => Err(Error::Tlv("Invalid TLV length encoding".into())),
    }
}

/// A generic TLV element consisting of a type, length, and value.
#[derive(Debug, Clone, PartialEq)]
pub struct TlvElement {
    pub tlv_type: u8,
    pub value: Bytes,
}

impl TlvElement {
    /// Creates a new TLV element.
    pub fn new(tlv_type: u8, value: impl Into<Bytes>) -> Self {
        Self {
            tlv_type,
            value: value.into(),
        }
    }

    /// Returns the total length of this TLV element when encoded.
    pub fn len(&self) -> usize {
        let value_len = self.value.len();
        // Type (1 byte) + Length (variable) + Value
        1 + tlv_length_size(value_len) + value_len
    }

    /// Encodes this TLV element into the provided buffer.
    pub fn encode(&self, buf: &mut BytesMut) {
        encode_tlv_type(self.tlv_type, buf);
        encode_tlv_length(self.value.len(), buf);
        buf.extend_from_slice(&self.value);
    }

    /// Decodes a TLV element from the provided buffer.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Tlv("Buffer too small for TLV".into()));
        }

        let tlv_type = decode_tlv_type(buf)?;
        let length = decode_tlv_length(buf)?;

        if buf.remaining() < length {
            return Err(Error::Tlv(format!(
                "Buffer underflow: TLV value requires {} bytes but only {} available",
                length,
                buf.remaining()
            )));
        }

        let mut value = BytesMut::with_capacity(length);
        let mut take = buf.take(length);
        value.extend_from_reader(&mut take)?;

        Ok(Self {
            tlv_type,
            value: value.freeze(),
        })
    }
}

/// Returns the number of bytes needed to encode the given length.
fn tlv_length_size(length: usize) -> usize {
    if length < 253 {
        1 // 1 byte for length < 253
    } else if length <= 65535 {
        3 // 1 byte marker (253) + 2 bytes length
    } else {
        5 // 1 byte marker (254) + 4 bytes length
    }
}
