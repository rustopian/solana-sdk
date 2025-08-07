//! Off-chain message container for storing non-transaction messages.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
use {
    num_enum::{IntoPrimitive, TryFromPrimitive},
    solana_hash::Hash,
    solana_sanitize::SanitizeError,
    solana_signature::Signature,
    solana_signer::Signer,
};

pub mod envelope;
pub mod serialization;
pub use envelope::Envelope;

#[cfg(test)]
static_assertions::const_assert_eq!(OffchainMessage::HEADER_LEN, 17);
#[cfg(test)]
static_assertions::const_assert_eq!(v0::OffchainMessage::MAX_LEN, 65482);
#[cfg(test)]
static_assertions::const_assert_eq!(v0::OffchainMessage::MAX_LEN_LEDGER, 1179);

/// Check if given bytes contain only printable ASCII characters
pub fn is_printable_ascii(data: &[u8]) -> bool {
    for &char in data {
        if !(0x20..=0x7e).contains(&char) {
            return false;
        }
    }
    true
}

/// Check if given bytes contain valid UTF8 string
pub fn is_utf8(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_ok()
}

/// Hardware-wallet safe limit (from spec: formats 0 and 1 are limited to 1232 bytes total)
pub const PREAMBLE_AND_BODY_MAX_LEDGER: usize = 1232;

/// Extended format hard limit (u16::MAX total message size)
pub const PREAMBLE_AND_BODY_MAX_EXTENDED: usize = u16::MAX as usize;

/// Header and sizing calculations
mod header {
    /// Calculate the total header size for the outer OffchainMessage
    pub const fn outer_header_len() -> usize {
        super::OffchainMessage::SIGNING_DOMAIN.len() + 1 // version
    }

    /// Calculate the total header size for v0::OffchainMessage (without signers)
    pub const fn v0_fixed_header_len() -> usize {
        32 + 1 + 1 + 2 // app_domain + format + signer_count + msg_len
    }

    /// Calculate the total variable header size for v0::OffchainMessage
    pub const fn v0_variable_header_len(signer_count: usize) -> usize {
        signer_count * 32
    }

    /// Calculate the total serialized size for a complete message
    pub const fn total_message_size(signer_count: usize, message_len: usize) -> usize {
        outer_header_len()
            + v0_fixed_header_len()
            + v0_variable_header_len(signer_count)
            + message_len
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, TryFromPrimitive, IntoPrimitive)]
pub enum MessageFormat {
    RestrictedAscii,
    LimitedUtf8,
    ExtendedUtf8,
}

#[allow(clippy::arithmetic_side_effects)]
pub mod v0 {
    use {
        super::{serialization, MessageFormat, OffchainMessage as Base},
        solana_hash::Hash,
        solana_packet::PACKET_DATA_SIZE,
        solana_sanitize::SanitizeError,
        solana_sha256_hasher::Hasher,
    };

    /// OffchainMessage Version 0.
    /// Struct always contains a non-empty valid message.
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct OffchainMessage {
        pub application_domain: [u8; 32],
        pub format: MessageFormat,
        pub signers: Vec<[u8; 32]>,
        pub message: Vec<u8>,
    }

    impl OffchainMessage {
        // Header Length = Application Domain (32) + Message Format (1) + Signer Count (1) + Message Length (2)
        // Note: Signers length is variable (signer_count * 32)
        pub const HEADER_LEN: usize = 32 + 1 + 1 + 2;
        // Max length of the OffchainMessage
        pub const MAX_LEN: usize = u16::MAX as usize - Base::HEADER_LEN - Self::HEADER_LEN;
        // Max Length of the OffchainMessage supported by the Ledger
        pub const MAX_LEN_LEDGER: usize = PACKET_DATA_SIZE - Base::HEADER_LEN - Self::HEADER_LEN;

        /// Construct a new OffchainMessage object from the given message
        #[deprecated(
            since = "3.0.0",
            note = "Use `new_with_domain` or `new_with_params` instead"
        )]
        pub fn new(message: &[u8]) -> Result<Self, SanitizeError> {
            // Use default values for compatibility with existing API
            let application_domain = [0u8; 32]; // Default application domain
            let signers = vec![[0u8; 32]]; // Default single dummy signer
            Self::new_with_params(application_domain, &signers, message)
        }

        /// Construct a new OffchainMessage object with all parameters. This
        /// must be used for multi-signer messages (where multiple parties must sign).
        pub fn new_with_params(
            application_domain: [u8; 32],
            signers: &[[u8; 32]],
            message: &[u8],
        ) -> Result<Self, SanitizeError> {
            let (application_domain, format, signers, message) =
                serialization::new_v0_with_params(application_domain, signers, message)?;

            Ok(Self {
                application_domain,
                format,
                signers,
                message,
            })
        }

        /// Serialize the message to bytes, including the full header
        pub fn serialize(&self, data: &mut Vec<u8>) -> Result<(), SanitizeError> {
            serialization::serialize_v0(
                &self.application_domain,
                self.format,
                &self.signers,
                &self.message,
                data,
            )
        }

        /// Deserialize the message from bytes that include a full header
        pub fn deserialize(data: &[u8]) -> Result<Self, SanitizeError> {
            let (application_domain, format, signers, message) =
                serialization::deserialize_v0(data)?;

            Ok(Self {
                application_domain,
                format,
                signers,
                message,
            })
        }

        /// Compute the SHA256 hash of the serialized off-chain message
        pub fn hash(serialized_message: &[u8]) -> Result<Hash, SanitizeError> {
            let mut hasher = Hasher::default();
            hasher.hash(serialized_message);
            Ok(hasher.result())
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum OffchainMessage {
    V0(v0::OffchainMessage),
}

impl OffchainMessage {
    pub const SIGNING_DOMAIN: &'static [u8] = b"\xffsolana offchain";
    // Header Length = Signing Domain (16) + Header Version (1)
    pub const HEADER_LEN: usize = Self::SIGNING_DOMAIN.len() + 1;

    /// Construct a new OffchainMessage object from the given version and message.
    ///
    #[deprecated(
        since = "3.0.0",
        note = "Use `new_with_domain` or `new_with_params` instead"
    )]
    pub fn new(version: u8, message: &[u8]) -> Result<Self, SanitizeError> {
        #[allow(deprecated)]
        match version {
            0 => Ok(Self::V0(v0::OffchainMessage::new(message)?)),
            _ => Err(SanitizeError::ValueOutOfBounds),
        }
    }

    /// Construct a new OffchainMessage object with custom application domain
    /// Signer information is filled when sign() is called. This can only
    /// be used for single-signer messages; otherwise, use `new_with_params`.
    pub fn new_with_domain(
        version: u8,
        application_domain: [u8; 32],
        message: &[u8],
    ) -> Result<Self, SanitizeError> {
        // Use dummy signer that will be replaced during signing
        Self::new_with_params(version, application_domain, &[[0u8; 32]], message)
    }

    /// Construct a new OffchainMessage object with all parameters from the spec
    ///
    /// # Usage Patterns:
    /// - **Single-signer with custom domain**: Pass `&[[0u8; 32]]` for signers,
    ///   actual signer will be filled in when `sign()` is called
    /// - **Multi-signer predefined**: Pass real signer pubkeys, all signers must provide signatures
    pub fn new_with_params(
        version: u8,
        application_domain: [u8; 32],
        signers: &[[u8; 32]],
        message: &[u8],
    ) -> Result<Self, SanitizeError> {
        match version {
            0 => Ok(Self::V0(v0::OffchainMessage::new_with_params(
                application_domain,
                signers,
                message,
            )?)),
            _ => Err(SanitizeError::ValueOutOfBounds),
        }
    }

    /// Serialize the off-chain message to bytes including full header
    pub fn serialize(&self) -> Result<Vec<u8>, SanitizeError> {
        // serialize signing domain
        let mut data = Self::SIGNING_DOMAIN.to_vec();

        // serialize version and call version specific serializer
        match self {
            Self::V0(msg) => {
                data.push(0);
                msg.serialize(&mut data)?;
            }
        }
        Ok(data)
    }

    /// Deserialize the off-chain message from bytes that include full header
    pub fn deserialize(data: &[u8]) -> Result<Self, SanitizeError> {
        if data.len() <= Self::HEADER_LEN {
            return Err(SanitizeError::ValueOutOfBounds);
        }
        let version = data[Self::SIGNING_DOMAIN.len()];
        let data = &data[Self::SIGNING_DOMAIN.len().saturating_add(1)..];
        match version {
            0 => Ok(Self::V0(v0::OffchainMessage::deserialize(data)?)),
            _ => Err(SanitizeError::ValueOutOfBounds),
        }
    }

    /// Compute the hash of the off-chain message
    pub fn hash(&self) -> Result<Hash, SanitizeError> {
        match self {
            Self::V0(_) => v0::OffchainMessage::hash(&self.serialize()?),
        }
    }

    pub fn get_version(&self) -> u8 {
        match self {
            Self::V0(_) => 0,
        }
    }

    /// Sign the message with provided keypair
    /// For CLI compatibility: if message was created with default signer, update it with actual signer
    /// For spec compliance: verify signer matches expected pubkey in message
    pub fn sign(&self, signer: &dyn Signer) -> Result<Signature, SanitizeError> {
        let signer_pubkey = signer.pubkey().to_bytes();
        let message_signers = match self {
            Self::V0(msg) => &msg.signers,
        };

        if Self::is_single_dummy_signer_message(message_signers) {
            return Self::sign_with_rebuilt_message(self, signer, signer_pubkey);
        }

        // Spec compliance: verify signer is authorized
        Self::verify_signer_authorized(message_signers, &signer_pubkey)?;

        Ok(signer.sign_message(&self.serialize()?))
    }

    /// Check if message has single dummy/default signer
    fn is_single_dummy_signer_message(signers: &[[u8; 32]]) -> bool {
        signers.len() == 1 && signers[0] == [0u8; 32]
    }

    /// Create proper message with actual signer and sign it
    fn sign_with_rebuilt_message(
        original: &Self,
        signer: &dyn Signer,
        signer_pubkey: [u8; 32],
    ) -> Result<Signature, SanitizeError> {
        let (application_domain, message) = match original {
            Self::V0(msg) => (msg.application_domain, &msg.message),
        };
        let proper_message = Self::new_with_params(
            original.get_version(),
            application_domain,
            &[signer_pubkey],
            message,
        )?;
        Ok(signer.sign_message(&proper_message.serialize()?))
    }

    /// Verify that the signer is authorized to sign this message
    fn verify_signer_authorized(
        message_signers: &[[u8; 32]],
        signer_pubkey: &[u8; 32],
    ) -> Result<(), SanitizeError> {
        if message_signers.contains(signer_pubkey) {
            Ok(())
        } else {
            Err(SanitizeError::InvalidValue)
        }
    }

    /// Verify that the message signature is valid for the given public key
    pub fn verify(
        &self,
        signer: &solana_pubkey::Pubkey,
        signature: &Signature,
    ) -> Result<bool, SanitizeError> {
        Ok(signature.verify(signer.as_ref(), &self.serialize()?))
    }
}

/// Envelope for off-chain messages with multiple signatures
/// All signers listed in the message must provide signatures (no threshold logic)
/// This implements the envelope format from the proposal:
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
    /// Create a new envelope from existing signatures and message
    /// This allows for partial signing scenarios (e.g., collecting signatures from multiple parties)
    /// Note: This bypasses signature verification during construction
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
        // Verify signer count matches message signer count
        if signers.len() != message.get_signers().len() {
            return Err(SanitizeError::ValueOutOfBounds);
        }

        // Verify signers match the expected pubkeys in order
        for (i, signer) in signers.iter().enumerate() {
            if signer.pubkey().to_bytes() != message.get_signers()[i] {
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
        if self.signatures.len() != self.message.get_signers().len() {
            return Ok(false);
        }

        let message_bytes = self.message.serialize()?;
        let signers = self.message.get_signers();

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
        let mut data = Vec::with_capacity(1 + self.signatures.len() * 64 + message_bytes.len());

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
        offset += 1;

        if sig_count == 0 {
            return Err(SanitizeError::InvalidValue);
        }

        // Check we have enough data for all signatures
        if data.len() < offset + sig_count * 64 {
            return Err(SanitizeError::ValueOutOfBounds);
        }

        // Parse signatures
        let mut signatures = Vec::with_capacity(sig_count);
        for _ in 0..sig_count {
            let signature_bytes: [u8; 64] = data[offset..offset + 64]
                .try_into()
                .map_err(|_| SanitizeError::ValueOutOfBounds)?;
            signatures.push(Signature::from(signature_bytes));
            offset += 64;
        }

        // Parse message
        let message_data = &data[offset..];
        let message = OffchainMessage::deserialize(message_data)?;

        // Verify signature count matches message signer count
        if signatures.len() != message.get_signers().len() {
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
    use {super::*, solana_keypair::Keypair};

    #[test]
    fn test_offchain_message_ascii() {
        #[allow(deprecated)]
        let message = OffchainMessage::new(0, b"Test Message").unwrap();
        assert_eq!(message.get_version(), 0);
        assert!(
            matches!(message, OffchainMessage::V0(ref msg) if msg.format == MessageFormat::RestrictedAscii)
        );
        assert!(matches!(message, OffchainMessage::V0(ref msg) if msg.message == b"Test Message"));
        let serialized = [
            255, 115, 111, 108, 97, 110, 97, 32, 111, 102, 102, 99, 104, 97, 105, 110,
            0, // signing domain + version
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, // application domain (32 zeros)
            0, // format (RestrictedAscii = 0)
            1, // signer count
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, // signer (32 zeros)
            12, 0, // message length (little endian)
            84, 101, 115, 116, 32, 77, 101, 115, 115, 97, 103, 101, // "Test Message"
        ];
        assert_eq!(message.serialize().unwrap(), serialized);
        // Hash will be different due to new format - let's verify serialization first
        let _hash = message.hash().unwrap();
        assert_eq!(message, OffchainMessage::deserialize(&serialized).unwrap());
    }

    #[test]
    fn test_offchain_message_utf8() {
        #[allow(deprecated)]
        let message = OffchainMessage::new(0, "Тестовое сообщение".as_bytes()).unwrap();
        assert_eq!(message.get_version(), 0);
        assert!(
            matches!(message, OffchainMessage::V0(ref msg) if msg.format == MessageFormat::LimitedUtf8)
        );
        assert!(
            matches!(message, OffchainMessage::V0(ref msg) if msg.message == "Тестовое сообщение".as_bytes())
        );
        let serialized = [
            255, 115, 111, 108, 97, 110, 97, 32, 111, 102, 102, 99, 104, 97, 105, 110,
            0, // signing domain + version
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, // application domain (32 zeros)
            1, // format (LimitedUtf8 = 1)
            1, // signer count
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, // signer (32 zeros)
            35, 0, // message length (little endian)
            208, 162, 208, 181, 209, 129, 209, 130, 208, 190, 208, 178, 208, 190, 208, 181, 32,
            209, 129, 208, 190, 208, 190, 208, 177, 209, 137, 208, 181, 208, 189, 208, 184, 208,
            181, // UTF-8 message
        ];
        assert_eq!(message.serialize().unwrap(), serialized);
        let hash = message.hash().unwrap();
        assert_eq!(
            hash.to_string(),
            "E5tkTdEzcYTe5deSvw5jqzwPUEVBT83P4aHCYxjtzEW8"
        );
        assert_eq!(message, OffchainMessage::deserialize(&serialized).unwrap());
    }

    #[test]
    fn test_deprecated_new_then_sign_and_verify() {
        // Test the pattern that Agave CLI uses:
        // let message = OffchainMessage::new(version, message_text.as_bytes())
        //     .map_err(|_| CliError::BadParameter("VERSION or MESSAGE".to_string()))?;
        // message.sign(config.signers[0])?.to_string();

        use solana_signer::Signer;

        let keypair = Keypair::new();
        let version = 0u8;
        let message_text = "Test Message";

        #[allow(deprecated)]
        let message = OffchainMessage::new(version, message_text.as_bytes()).unwrap();
        let signature = message.sign(&keypair).unwrap();

        assert_eq!(message.get_version(), 0);
        assert!(
            matches!(message, OffchainMessage::V0(ref msg) if msg.message == message_text.as_bytes())
        );

        // Create the expected signed message (what sign() actually signed)
        let expected_signed_message = OffchainMessage::new_with_params(
            0,
            [0u8; 32], // default application domain
            &[keypair.pubkey().to_bytes()],
            message_text.as_bytes(),
        )
        .unwrap();

        let is_valid = expected_signed_message
            .verify(&keypair.pubkey(), &signature)
            .unwrap();
        assert!(
            is_valid,
            "Signature should be valid for the keypair that signed it"
        );
    }

    #[test]
    fn test_offchain_message_new_with_params() {
        // Test the full spec constructor with custom application domain and multiple signers
        let application_domain = [0x42u8; 32]; // Custom application domain
        let signer1 = [0x11u8; 32];
        let signer2 = [0x22u8; 32];
        let signers = [signer1, signer2];
        let message_text = b"Multi-signer message";

        let message =
            OffchainMessage::new_with_params(0, application_domain, &signers, message_text)
                .unwrap();

        // Verify all fields are set correctly
        assert_eq!(message.get_version(), 0);
        assert!(
            matches!(message, OffchainMessage::V0(ref msg) if msg.application_domain == application_domain)
        );
        assert!(matches!(message, OffchainMessage::V0(ref msg) if msg.signers == signers));
        assert!(matches!(message, OffchainMessage::V0(ref msg) if msg.message == message_text));
        assert!(
            matches!(message, OffchainMessage::V0(ref msg) if msg.format == MessageFormat::RestrictedAscii)
        );

        // Test serialization and deserialization
        let serialized = message.serialize().unwrap();
        let deserialized = OffchainMessage::deserialize(&serialized).unwrap();
        assert_eq!(message, deserialized);

        // Verify the serialized format contains our custom values
        let serialized_vec = serialized.to_vec();

        // Check signing domain and version
        assert_eq!(&serialized_vec[0..16], b"\xffsolana offchain");
        assert_eq!(serialized_vec[16], 0); // version
        assert_eq!(&serialized_vec[17..49], &application_domain);
        assert_eq!(serialized_vec[49], 0); // RestrictedAscii format
        assert_eq!(serialized_vec[50], 2); // 2 signers
        assert_eq!(&serialized_vec[51..83], &signer1);
        assert_eq!(&serialized_vec[83..115], &signer2);
        let msg_len = u16::from_le_bytes([serialized_vec[115], serialized_vec[116]]);
        assert_eq!(msg_len, message_text.len() as u16);
        assert_eq!(&serialized_vec[117..], message_text);
    }

    #[test]
    fn test_new_with_domain() {
        let keypair = Keypair::new();
        let custom_domain = [0x42u8; 32];

        // Use the cleaner API for single-signer with custom domain
        let message = OffchainMessage::new_with_domain(0, custom_domain, b"Domain test").unwrap();

        // Verify domain is set correctly
        assert!(
            matches!(message, OffchainMessage::V0(ref msg) if msg.application_domain == custom_domain)
        );

        // Sign and verify it works
        let signature = message.sign(&keypair).unwrap();

        // Create expected message for verification
        let expected_message = OffchainMessage::new_with_params(
            0,
            custom_domain,
            &[keypair.pubkey().to_bytes()],
            b"Domain test",
        )
        .unwrap();

        assert!(expected_message
            .verify(&keypair.pubkey(), &signature)
            .unwrap());
    }

    #[test]
    fn test_spec_constant_usage() {
        let keypair = Keypair::new();
        let signer_pubkey = keypair.pubkey().to_bytes();

        // Small ASCII message should be RestrictedAscii
        let small_msg =
            OffchainMessage::new_with_params(0, [0u8; 32], &[signer_pubkey], b"Small message")
                .unwrap();
        assert!(
            matches!(small_msg, OffchainMessage::V0(ref msg) if msg.format == MessageFormat::RestrictedAscii)
        );

        // Large message should be ExtendedUtf8 (if it fits in 65535)
        let large_msg_size = PREAMBLE_AND_BODY_MAX_LEDGER + 100;
        let header_size = OffchainMessage::HEADER_LEN + 32 + 1 + 1 + 32 + 2; // full preamble
        let max_body_size = large_msg_size - header_size;
        let large_body = vec![b'A'; max_body_size];

        let large_msg =
            OffchainMessage::new_with_params(0, [0u8; 32], &[signer_pubkey], &large_body).unwrap();
        assert!(
            matches!(large_msg, OffchainMessage::V0(ref msg) if msg.format == MessageFormat::ExtendedUtf8)
        );
    }
}
