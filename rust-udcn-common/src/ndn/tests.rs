//! Unit tests for the NDN packet implementation

#[cfg(test)]
mod tests {
    use super::super::*;
    use bytes::{BufMut, Bytes, BytesMut};

    #[test]
    fn test_name_creation() {
        // Create a name from a string
        let name = Name::from_string("/test/data/1").unwrap();
        
        // Check the components
        assert_eq!(name.components().len(), 3);
        assert_eq!(name.components()[0], b"test");
        assert_eq!(name.components()[1], b"data");
        assert_eq!(name.components()[2], b"1");
        
        // Convert back to string
        assert_eq!(name.to_string(), "/test/data/1");
    }

    #[test]
    fn test_name_compare() {
        let name1 = Name::from_string("/a/b/c").unwrap();
        let name2 = Name::from_string("/a/b/c").unwrap();
        let name3 = Name::from_string("/a/b/d").unwrap();
        let name4 = Name::from_string("/a/b").unwrap();
        
        assert_eq!(name1, name2);
        assert_ne!(name1, name3);
        assert_ne!(name1, name4);
        
        // Test prefix matching
        assert!(name4.is_prefix_of(&name1));
        assert!(!name1.is_prefix_of(&name4));
        assert!(!name3.is_prefix_of(&name1));
    }
    
    #[test]
    fn test_interest_packet() {
        let name = Name::from_string("/test/interest").unwrap();
        let mut interest = Interest::new(name.clone());
        
        // Set Interest parameters
        interest.set_can_be_prefix(true);
        interest.set_must_be_fresh(true);
        interest.set_nonce(42);
        interest.set_lifetime_ms(4000);
        
        // Check the values
        assert_eq!(interest.name(), &name);
        assert_eq!(interest.can_be_prefix(), true);
        assert_eq!(interest.must_be_fresh(), true);
        assert_eq!(interest.nonce(), 42);
        assert_eq!(interest.lifetime_ms(), 4000);
        
        // Create a wire format and parse back
        let wire = interest.to_wire();
        let parsed_interest = Interest::from_wire(&wire).unwrap();
        
        // Check the parsed Interest
        assert_eq!(parsed_interest.name(), &name);
        assert_eq!(parsed_interest.can_be_prefix(), true);
        assert_eq!(parsed_interest.must_be_fresh(), true);
        assert_eq!(parsed_interest.nonce(), 42);
        assert_eq!(parsed_interest.lifetime_ms(), 4000);
    }
    
    #[test]
    fn test_data_packet() {
        let name = Name::from_string("/test/data").unwrap();
        let content = Bytes::from_static(b"Hello, NDN!");
        let mut data = Data::new(name.clone(), content.clone());
        
        // Set Data parameters
        data.set_content_type(0); // BLOB
        data.set_freshness_period_ms(10000);
        
        // Set a simple signature
        let sig_info = SignatureInfo {
            signature_type: SignatureType::DigestSha256,
            key_locator: None,
            validity_period: None,
        };
        data.set_signature_info(sig_info);
        data.set_signature_value(Bytes::from_static(&[0u8; 32]));
        
        // Check the values
        assert_eq!(data.name(), &name);
        assert_eq!(data.content(), &content);
        assert_eq!(data.content_type(), 0);
        assert_eq!(data.freshness_period_ms(), 10000);
        assert_eq!(data.signature_info().signature_type, SignatureType::DigestSha256);
        
        // Create a wire format and parse back
        let wire = data.to_wire();
        let parsed_data = Data::from_wire(&wire).unwrap();
        
        // Check the parsed Data
        assert_eq!(parsed_data.name(), &name);
        assert_eq!(parsed_data.content(), &content);
        assert_eq!(parsed_data.content_type(), 0);
        assert_eq!(parsed_data.freshness_period_ms(), 10000);
        assert_eq!(parsed_data.signature_info().signature_type, SignatureType::DigestSha256);
    }
    
    #[test]
    fn test_tlv_encoding_decoding() {
        // Test TLV encoding and decoding
        let mut encoder = BytesMut::new();
        
        // Encode a TLV with type 1, length 3, value "abc"
        tlv::encode_tlv(&mut encoder, 1, b"abc");
        
        // Check the encoded bytes
        assert_eq!(encoder.len(), 5); // 1 byte type + 1 byte length + 3 bytes value
        assert_eq!(encoder[0], 1);    // Type
        assert_eq!(encoder[1], 3);    // Length
        assert_eq!(&encoder[2..5], b"abc"); // Value
        
        // Decode the TLV
        let (t, v, _) = tlv::decode_tlv(&encoder).unwrap();
        assert_eq!(t, 1);
        assert_eq!(v, b"abc");
    }
    
    #[test]
    fn test_varnum_encoding_decoding() {
        // Test encoding and decoding of variable-length numbers
        let mut buffer = BytesMut::new();
        
        // Small number (fits in 1 byte)
        tlv::encode_var_number(&mut buffer, 100);
        assert_eq!(buffer.len(), 1);
        assert_eq!(buffer[0], 100);
        
        let (val, _) = tlv::decode_var_number(&buffer).unwrap();
        assert_eq!(val, 100);
        
        // Clear buffer
        buffer.clear();
        
        // Medium number (fits in 3 bytes)
        tlv::encode_var_number(&mut buffer, 1000);
        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer[0], 253);  // 253 is marker for 2-byte value
        
        let (val, _) = tlv::decode_var_number(&buffer).unwrap();
        assert_eq!(val, 1000);
        
        // Clear buffer
        buffer.clear();
        
        // Large number (fits in 5 bytes)
        tlv::encode_var_number(&mut buffer, 100000);
        assert_eq!(buffer.len(), 5);
        assert_eq!(buffer[0], 254);  // 254 is marker for 4-byte value
        
        let (val, _) = tlv::decode_var_number(&buffer).unwrap();
        assert_eq!(val, 100000);
    }
}
