//! Envelope for off-chain messages with multiple signatures.
//! Matches the format from the [proposal spec here](https://github.com/anza-xyz/agave/blob/master/docs/src/proposals/off-chain-message-signing.md).

use {
    crate::OffchainMessage, solana_sanitize::SanitizeError, solana_signature::Signature,
    solana_signer::Signer,
};

/// Envelope for off-chain messages with multiple signatures.
/// All signers listed in the message must provide signatures.
/// This implements the envelope format from the spec:
/// | Field | Start offset | Length (bytes) | Description |
/// | Signature Count | 0x00 | 1 | Number of signatures |
/// | Signatures | 0x01 | `SIG_COUNT` * 64 | ed25519 signatures |
/// | Message Preamble | 0x01 + `SIG_COUNT` * 64 | variable | The message preamble |
/// | Message Body | varies | variable | The message content |
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Envelope {
    signatures: Vec<Signature>,
    message: OffchainMessage,
}

impl Envelope {
    /// Create a new envelope from existing signatures and message.
    pub fn new(message: OffchainMessage, signatures: Vec<Signature>) -> Self {
        Self {
            message,
            signatures,
        }
    }

    /// Create a new envelope by signing with all provided signers
    /// All signers must match the signers list in the message, in order
    pub fn sign_all(
        message: OffchainMessage,
        signers: &[&dyn Signer],
    ) -> Result<Self, SanitizeError> {
        let message_signers = match &message {
            crate::OffchainMessage::V0(msg) => &msg.signers,
        };

        // Verify signer count matches message signer count
        if signers.len() != message_signers.len() {
            return Err(SanitizeError::ValueOutOfBounds);
        }

        // Verify signers match the expected pubkeys in order
        for (i, signer) in signers.iter().enumerate() {
            if signer.pubkey().to_bytes() != message_signers[i] {
                return Err(SanitizeError::InvalidValue);
            }
        }

        // Serialize the message once for all signatures
        let message_bytes = message.serialize()?;

        // Create signatures in the same order as the signers in the message
        let mut signatures = Vec::with_capacity(signers.len());
        for signer in signers {
            signatures.push(signer.sign_message(&message_bytes));
        }

        Ok(Self {
            signatures,
            message,
        })
    }

    /// Verify all signatures in the envelope and message compliance
    #[cfg(feature = "verify")]
    pub fn verify_all(&self) -> Result<bool, SanitizeError> {
        let message_signers = match &self.message {
            crate::OffchainMessage::V0(msg) => &msg.signers,
        };

        if self.signatures.len() != message_signers.len() {
            return Ok(false);
        }

        let message_bytes = self.message.serialize()?;
        let signers = message_signers;

        // Verify each signature matches the corresponding pubkey
        for (signature, signer_bytes) in self.signatures.iter().zip(signers.iter()) {
            let pubkey = ::solana_pubkey::Pubkey::try_from(signer_bytes.as_slice())
                .map_err(|_| SanitizeError::InvalidValue)?;
            if !signature.verify(pubkey.as_ref(), &message_bytes) {
                return Ok(false);
            }
        }

        // Post-verification: re-deserialize to ensure message compliance
        let _verified_message = OffchainMessage::deserialize(&message_bytes)?;

        Ok(true)
    }

    /// Serialize the complete envelope (signatures + message)
    pub fn serialize(&self) -> Result<Vec<u8>, SanitizeError> {
        let message_bytes = self.message.serialize()?;
        let mut data = Vec::with_capacity(
            1_usize
                .saturating_add(self.signatures.len().saturating_mul(64))
                .saturating_add(message_bytes.len()),
        );

        // Signature count (1 byte)
        data.push(self.signatures.len() as u8);

        // Signatures (64 bytes each)
        for signature in &self.signatures {
            data.extend_from_slice(signature.as_ref());
        }

        // Message preamble and body
        data.extend_from_slice(&message_bytes);

        Ok(data)
    }

    /// Deserialize an envelope from bytes with full verification
    pub fn deserialize(data: &[u8]) -> Result<Self, SanitizeError> {
        if data.is_empty() {
            return Err(SanitizeError::ValueOutOfBounds);
        }

        let mut offset = 0;

        // Parse signature count
        let sig_count = data[offset] as usize;
        offset = offset
            .checked_add(1)
            .ok_or(SanitizeError::ValueOutOfBounds)?;

        if sig_count == 0 {
            return Err(SanitizeError::InvalidValue);
        }

        // Check we have enough data for all signatures
        let signatures_size = sig_count
            .checked_mul(64)
            .ok_or(SanitizeError::ValueOutOfBounds)?;
        let required_size = offset
            .checked_add(signatures_size)
            .ok_or(SanitizeError::ValueOutOfBounds)?;
        if data.len() < required_size {
            return Err(SanitizeError::ValueOutOfBounds);
        }

        // Parse signatures
        let mut signatures = Vec::with_capacity(sig_count);
        for _ in 0..sig_count {
            let end_offset = offset
                .checked_add(64)
                .ok_or(SanitizeError::ValueOutOfBounds)?;
            let signature_bytes: [u8; 64] = data[offset..end_offset]
                .try_into()
                .map_err(|_| SanitizeError::ValueOutOfBounds)?;
            signatures.push(Signature::from(signature_bytes));
            offset = end_offset;
        }

        // Parse message
        let message_data = &data[offset..];
        let message = OffchainMessage::deserialize(message_data)?;

        // Verify signature count matches message signer count
        let message_signers = match &message {
            crate::OffchainMessage::V0(msg) => &msg.signers,
        };
        if signatures.len() != message_signers.len() {
            return Err(SanitizeError::InvalidValue);
        }

        let envelope = Self {
            signatures,
            message,
        };

        // Full verification including signature checks
        #[cfg(feature = "verify")]
        {
            if !envelope.verify_all()? {
                return Err(SanitizeError::InvalidValue);
            }
        }

        Ok(envelope)
    }

    /// Get the signatures
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// Get the message
    pub fn message(&self) -> &OffchainMessage {
        &self.message
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::OffchainMessage, solana_keypair::Keypair, solana_signer::Signer};

    #[test]
    fn test_envelope_functionality() {
        let application_domain = [0xEEu8; 32];
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();

        let signer1_pubkey = keypair1.pubkey().to_bytes();
        let signer2_pubkey = keypair2.pubkey().to_bytes();
        let signers_pubkeys = [signer1_pubkey, signer2_pubkey];

        // Create message with multiple signers
        let message = OffchainMessage::new_with_params(
            0,
            application_domain,
            &signers_pubkeys,
            b"Multi-sig test",
        )
        .unwrap();

        // Create envelope with all signatures
        let signers: [&dyn Signer; 2] = [&keypair1, &keypair2];
        let envelope = Envelope::sign_all(message.clone(), &signers).unwrap();

        // Verify envelope
        assert_eq!(envelope.signatures().len(), 2);
        assert_eq!(envelope.message(), &message);

        // Test serialization/deserialization
        let serialized = envelope.serialize().unwrap();
        let deserialized = Envelope::deserialize(&serialized).unwrap();
        assert_eq!(envelope, deserialized);

        // Test verification
        #[cfg(feature = "verify")]
        assert!(envelope.verify_all().unwrap());
    }

    #[test]
    fn test_multi_signer_3_parties_success() {
        // Create 3 keypairs for a 3-party multi-signer message (all must sign)
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();
        let keypair3 = Keypair::new();

        let pubkey1 = keypair1.pubkey().to_bytes();
        let pubkey2 = keypair2.pubkey().to_bytes();
        let pubkey3 = keypair3.pubkey().to_bytes();

        // Create message with all 3 signers listed
        let signers_in_message = [pubkey1, pubkey2, pubkey3];
        let application_domain = [0x42u8; 32];
        let message = OffchainMessage::new_with_params(
            0,
            application_domain,
            &signers_in_message,
            b"3-party multi-signer test",
        )
        .unwrap();

        // Create envelope with all 3 signers
        let signing_keypairs: [&dyn Signer; 3] = [&keypair1, &keypair2, &keypair3];
        let envelope = Envelope::sign_all(message.clone(), &signing_keypairs).unwrap();

        // Verify envelope structure
        assert_eq!(envelope.signatures().len(), 3);
        assert_eq!(envelope.message(), &message);
        assert!(
            matches!(envelope.message(), crate::OffchainMessage::V0(ref msg) if msg.signers.len() == 3)
        );

        // Test serialization/deserialization
        let serialized = envelope.serialize().unwrap();
        let deserialized = Envelope::deserialize(&serialized).unwrap();
        assert_eq!(envelope, deserialized);

        // Test verification
        #[cfg(feature = "verify")]
        assert!(envelope.verify_all().unwrap());
    }

    #[test]
    fn test_multi_signer_partial_signatures() {
        // Create 3 keypairs but only 2 will provide valid signatures
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();
        let keypair3 = Keypair::new(); // This one won't sign

        let pubkey1 = keypair1.pubkey().to_bytes();
        let pubkey2 = keypair2.pubkey().to_bytes();
        let pubkey3 = keypair3.pubkey().to_bytes();

        // Create message with 3 signers listed (but we'll only provide 2 valid signatures)
        let signers_in_message = [pubkey1, pubkey2, pubkey3];
        let message = OffchainMessage::new_with_params(
            0,
            [0x42u8; 32],
            &signers_in_message,
            b"partial signatures test",
        )
        .unwrap();

        // Sign only with first 2 signers, create empty signature for 3rd
        let message_bytes = message.serialize().unwrap();
        let sig1 = keypair1.sign_message(&message_bytes);
        let sig2 = keypair2.sign_message(&message_bytes);
        let empty_sig = Signature::from([0u8; 64]); // Placeholder for missing signature

        // Create envelope manually with partial signatures
        let signatures = vec![sig1, sig2, empty_sig];
        let envelope = Envelope::new(message.clone(), signatures);

        // Verify structure
        assert_eq!(envelope.signatures().len(), 3);
        assert_eq!(envelope.message(), &message);

        // Test serialization (should work even with invalid signatures)
        let serialized = envelope.serialize().unwrap();
        assert!(!serialized.is_empty());

        // Verification should fail due to invalid signature
        #[cfg(feature = "verify")]
        {
            let result = envelope.verify_all();
            assert!(result.is_ok());
            assert!(!result.unwrap()); // Should return false due to invalid signature
        }
    }

    #[test]
    fn test_multi_signer_missing_pubkey_in_message() {
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();
        let keypair3 = Keypair::new();

        let pubkey1 = keypair1.pubkey().to_bytes();
        let pubkey2 = keypair2.pubkey().to_bytes();
        // Note: pubkey3 is intentionally missing from the message

        // Create message with only 2 signers
        let signers_in_message = [pubkey1, pubkey2];
        let message = OffchainMessage::new_with_params(
            0,
            [0x42u8; 32],
            &signers_in_message,
            b"Missing pubkey test",
        )
        .unwrap();

        // Try to sign with 3 signers (including one not in the message)
        let signing_keypairs: [&dyn Signer; 3] = [&keypair1, &keypair2, &keypair3];

        // This should fail because keypair3's pubkey is not in the message
        let result = Envelope::sign_all(message, &signing_keypairs);
        assert!(result.is_err());

        // Verify it's the expected error (signer count mismatch)
        assert!(matches!(
            result.unwrap_err(),
            SanitizeError::ValueOutOfBounds
        ));
    }

    #[test]
    fn test_multi_signer_wrong_signer_order() {
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();
        let keypair3 = Keypair::new();

        let pubkey1 = keypair1.pubkey().to_bytes();
        let pubkey2 = keypair2.pubkey().to_bytes();
        let pubkey3 = keypair3.pubkey().to_bytes();

        // Create message with signers in order: 1, 2, 3
        let signers_in_message = [pubkey1, pubkey2, pubkey3];
        let message = OffchainMessage::new_with_params(
            0,
            [0x42u8; 32],
            &signers_in_message,
            b"Wrong order test",
        )
        .unwrap();

        // Try to sign with signers in wrong order: 2, 1, 3
        let signing_keypairs: [&dyn Signer; 3] = [&keypair2, &keypair1, &keypair3];

        // This should fail because the order doesn't match
        let result = Envelope::sign_all(message, &signing_keypairs);
        assert!(result.is_err());

        // Verify it's the expected error (invalid value due to pubkey mismatch)
        assert!(matches!(result.unwrap_err(), SanitizeError::InvalidValue));
    }
}
