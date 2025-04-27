#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose, Engine};
    use core_lib::encryption::{CryptoError, Encryptor};
    use hex_literal::hex;

    // Proper 32-byte test key
    const TEST_KEY: [u8; 32] = hex!(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    );

    fn create_encryptor() -> Encryptor {
        Encryptor::new(&TEST_KEY)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() -> Result<(), CryptoError> {
        let encryptor = create_encryptor();
        let plaintext = "This is a secret message!";

        let ciphertext = encryptor.encrypt(plaintext)?;
        let decrypted = encryptor.decrypt(&ciphertext)?;

        assert_eq!(plaintext, decrypted);
        Ok(())
    }

    #[test]
    fn test_different_nonce_per_encryption() -> Result<(), CryptoError> {
        let encryptor = create_encryptor();
        let plaintext = "Same plaintext";

        let ciphertext1 = encryptor.encrypt(plaintext)?;
        let ciphertext2 = encryptor.encrypt(plaintext)?;

        assert_ne!(ciphertext1, ciphertext2);
        assert_eq!(plaintext, encryptor.decrypt(&ciphertext1)?);
        assert_eq!(plaintext, encryptor.decrypt(&ciphertext2)?);
        Ok(())
    }

    #[test]
    fn test_tampered_ciphertext() -> Result<(), CryptoError> {
        let encryptor = create_encryptor();
        let ciphertext = encryptor.encrypt("Test message")?;

        let (nonce_part, cipher_part) = ciphertext.split_once(':').unwrap();
        let mut decoded = general_purpose::STANDARD.decode(cipher_part).unwrap();
        decoded[0] ^= 0x01; // Flip one bit
        let tampered = format!(
            "{}:{}",
            nonce_part,
            general_purpose::STANDARD.encode(decoded)
        );

        match encryptor.decrypt(&tampered) {
            Err(CryptoError::DecryptionError) => Ok(()),
            Ok(_) => panic!("Tampered ciphertext should not decrypt"),
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = b"too-short-key";
        let encryptor = Encryptor::try_new(short_key);
        match encryptor {
            Err(CryptoError::InvalidKeyLength(len)) => {
                assert_eq!(len, short_key.len());
            }
            _ => panic!("Should return InvalidKeyLength error"),
        }
    }

    #[test]
    fn test_malformed_input() -> Result<(), CryptoError> {
        let encryptor = create_encryptor();
        match encryptor.decrypt("not-a-valid-format") {
            Err(CryptoError::InvalidFormat) => Ok(()),
            Ok(_) => panic!("Malformed input should fail"),
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }

    #[test]
    fn test_empty_string() -> Result<(), CryptoError> {
        let encryptor = create_encryptor();
        let ciphertext = encryptor.encrypt("")?;
        let decrypted = encryptor.decrypt(&ciphertext)?;
        assert_eq!("", decrypted);
        Ok(())
    }
}
