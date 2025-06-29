//! TLV (Type‑Length‑Value) encoding and decoding utilities.
//!
//! This module provides functions for encoding and decoding NDN TLV packets.

use crate::error::Error;
use bytes::{Buf, BufMut, Bytes, BytesMut};

/* ---------------------------------------------------------------- *
 * TLV type constants (single‑byte for µDCN)
 * ---------------------------------------------------------------- */

pub const TLV_INTEREST: u8          = 0x05;
pub const TLV_DATA: u8              = 0x06;
pub const TLV_NACK: u8              = 0x03;
pub const TLV_NAME: u8              = 0x07;
pub const TLV_COMPONENT: u8         = 0x08;
pub const TLV_NONCE: u8             = 0x0A;
pub const TLV_INTEREST_LIFETIME: u8 = 0x0C;
pub const TLV_SELECTORS: u8         = 0x09;
pub const TLV_CONTENT: u8           = 0x15;

/* ---------------------------------------------------------------- *
 * Encoding helpers
 * ---------------------------------------------------------------- */

/// Encode the 1‑byte TLV *type* field.
pub fn encode_tlv_type(tlv_type: u8, buf: &mut BytesMut) {
    buf.put_u8(tlv_type);
}

/// Encode the variable‑width TLV *length* field.
///
/// * `< 253`  → 1 byte
/// * `≤ 65 535`  → marker 253 + 2‑byte length
/// * otherwise → marker 254 + 4‑byte length (max ≈ 4 GB)
pub fn encode_tlv_length(length: usize, buf: &mut BytesMut) {
    if length < 253 {
        buf.put_u8(length as u8);
    } else if length <= 65_535 {
        buf.put_u8(253);
        buf.put_u16(length as u16);
    } else {
        buf.put_u8(254);
        buf.put_u32(length as u32);
    }
}

/* ---------------------------------------------------------------- *
 * Decoding helpers
 * ---------------------------------------------------------------- */

/// Decode the TLV *type* field (single byte).
pub fn decode_tlv_type(buf: &mut impl Buf) -> Result<u8, Error> {
    if !buf.has_remaining() {
        return Err(Error::Tlv("Buffer underflow when decoding TLV type".into()));
    }
    Ok(buf.get_u8())
}

/// Decode the TLV *length* field using NDN variable‑length rules.
pub fn decode_tlv_length(buf: &mut impl Buf) -> Result<usize, Error> {
    if !buf.has_remaining() {
        return Err(Error::Tlv("Buffer underflow when decoding TLV length".into()));
    }

    let first_byte = buf.get_u8();
    match first_byte {
        0..=252 => Ok(first_byte as usize),
        253 => {
            if buf.remaining() < 2 {
                return Err(Error::Tlv("Buffer underflow when decoding 16‑bit TLV length".into()));
            }
            Ok(buf.get_u16() as usize)
        }
        254 => {
            if buf.remaining() < 4 {
                return Err(Error::Tlv("Buffer underflow when decoding 32‑bit TLV length".into()));
            }
            Ok(buf.get_u32() as usize)
        }
        255 => Err(Error::Tlv("64‑bit TLV lengths not supported".into())),
    }
}

/* ---------------------------------------------------------------- *
 * TLV element wrapper
 * ---------------------------------------------------------------- */

/// A generic TLV element consisting of *type*, *length* and *value*.
#[derive(Debug, Clone, PartialEq)]
pub struct TlvElement {
    pub tlv_type: u8,
    pub value: Bytes,
}

impl TlvElement {
    /// Create a new wrapper from raw parts.
    pub fn new(tlv_type: u8, value: impl Into<Bytes>) -> Self {
        Self {
            tlv_type,
            value: value.into(),
        }
    }

    /// Total number of bytes when this element is encoded.
    pub fn len(&self) -> usize {
        let vlen = self.value.len();
        1            // type
        + tlv_length_size(vlen)
        + vlen       // value
    }

    /// Encode this element into `buf`.
    pub fn encode(&self, buf: &mut BytesMut) {
        encode_tlv_type(self.tlv_type, buf);
        encode_tlv_length(self.value.len(), buf);
        buf.extend_from_slice(&self.value);
    }

    /// Decode a single element from `buf` **in‑place**.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Tlv("Buffer too small for TLV header".into()));
        }

        let tlv_type = decode_tlv_type(buf)?;
        let length   = decode_tlv_length(buf)?;

        if buf.remaining() < length {
            return Err(Error::Tlv(format!(
                "Buffer underflow: TLV value requires {} bytes but only {} available",
                length,
                buf.remaining()
            )));
        }

        // bytes 1.*: cheap zero‑copy slice
        let value = buf.copy_to_bytes(length);
        Ok(Self { tlv_type, value })
    }
}

/* ---------------------------------------------------------------- *
 * Helper
 * ---------------------------------------------------------------- */

/// Number of bytes required to encode `length` with the variable‑width scheme.
fn tlv_length_size(length: usize) -> usize {
    if length < 253 {
        1
    } else if length <= 65_535 {
        3
    } else {
        5
    }
}
