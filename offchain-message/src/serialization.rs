//! Serialization, deserialization, validation, and parsing logic for off-chain messages.

use {
    super::{header, MessageFormat, PREAMBLE_AND_BODY_MAX_EXTENDED, PREAMBLE_AND_BODY_MAX_LEDGER},
    solana_sanitize::SanitizeError,
};

/// Components of a v0 message: (application_domain, format, signers, message)
pub type V0MessageComponents = ([u8; 32], MessageFormat, Vec<[u8; 32]>, Vec<u8>);

/// Validate that signers list meets requirements
pub fn validate_signers(signers: &[[u8; 32]]) -> Result<(), SanitizeError> {
    if signers.is_empty() || signers.len() > u8::MAX as usize {
        Err(SanitizeError::ValueOutOfBounds)
    } else {
        Ok(())
    }
}

/// Validate that message body is not empty
pub fn validate_body(message: &[u8]) -> Result<(), SanitizeError> {
    if message.is_empty() {
        Err(SanitizeError::InvalidValue)
    } else {
        Ok(())
    }
}

/// Detect appropriate message format based on size and content
pub fn detect_format(total_size: usize, message: &[u8]) -> Result<MessageFormat, SanitizeError> {
    if total_size <= PREAMBLE_AND_BODY_MAX_LEDGER {
        if super::is_printable_ascii(message) {
            Ok(MessageFormat::RestrictedAscii)
        } else if super::is_utf8(message) {
            Ok(MessageFormat::LimitedUtf8)
        } else {
            Err(SanitizeError::InvalidValue)
        }
    } else if total_size <= PREAMBLE_AND_BODY_MAX_EXTENDED {
        if super::is_utf8(message) {
            Ok(MessageFormat::ExtendedUtf8)
        } else {
            Err(SanitizeError::InvalidValue)
        }
    } else {
        Err(SanitizeError::ValueOutOfBounds)
    }
}

/// Check if total size fits within ledger hardware limits
pub fn fits_ledger_limit(total_size: usize) -> bool {
    total_size <= PREAMBLE_AND_BODY_MAX_LEDGER
}

/// Check if total size fits within extended format limits
pub fn fits_extended_limit(total_size: usize) -> bool {
    total_size <= PREAMBLE_AND_BODY_MAX_EXTENDED
}

/// Parse application domain from data at given offset
pub fn parse_application_domain(
    data: &[u8],
    offset: usize,
) -> Result<([u8; 32], usize), SanitizeError> {
    let end_offset = offset
        .checked_add(32)
        .ok_or(SanitizeError::ValueOutOfBounds)?;
    if data.len() < end_offset {
        return Err(SanitizeError::ValueOutOfBounds);
    }
    let mut application_domain = [0u8; 32];
    application_domain.copy_from_slice(&data[offset..end_offset]);
    Ok((application_domain, end_offset))
}

/// Parse message format from data at given offset
pub fn parse_message_format(
    data: &[u8],
    offset: usize,
) -> Result<(MessageFormat, usize), SanitizeError> {
    if data.len() <= offset {
        return Err(SanitizeError::ValueOutOfBounds);
    }
    let format = MessageFormat::try_from(data[offset]).map_err(|_| SanitizeError::InvalidValue)?;
    let next_offset = offset
        .checked_add(1)
        .ok_or(SanitizeError::ValueOutOfBounds)?;
    Ok((format, next_offset))
}

/// Parse signer count from data at given offset
pub fn parse_signer_count(data: &[u8], offset: usize) -> Result<(usize, usize), SanitizeError> {
    if data.len() <= offset {
        return Err(SanitizeError::ValueOutOfBounds);
    }
    let signer_count = data[offset] as usize;
    if signer_count == 0 {
        return Err(SanitizeError::InvalidValue);
    }
    let next_offset = offset
        .checked_add(1)
        .ok_or(SanitizeError::ValueOutOfBounds)?;
    Ok((signer_count, next_offset))
}

/// Parse signers from data at given offset
pub fn parse_signers(
    data: &[u8],
    offset: usize,
    signer_count: usize,
) -> Result<(Vec<[u8; 32]>, usize), SanitizeError> {
    let signers_size = signer_count
        .checked_mul(32)
        .ok_or(SanitizeError::ValueOutOfBounds)?;
    let end_offset = offset
        .checked_add(signers_size)
        .ok_or(SanitizeError::ValueOutOfBounds)?;
    if data.len() < end_offset {
        return Err(SanitizeError::ValueOutOfBounds);
    }

    let mut signers = Vec::with_capacity(signer_count);
    let mut current_offset = offset;
    for _ in 0..signer_count {
        let mut signer = [0u8; 32];
        let signer_end = current_offset
            .checked_add(32)
            .ok_or(SanitizeError::ValueOutOfBounds)?;
        signer.copy_from_slice(&data[current_offset..signer_end]);
        signers.push(signer);
        current_offset = signer_end;
    }
    Ok((signers, current_offset))
}

/// Parse message length from data at given offset
pub fn parse_message_length(data: &[u8], offset: usize) -> Result<(usize, usize), SanitizeError> {
    let end_offset = offset
        .checked_add(2)
        .ok_or(SanitizeError::ValueOutOfBounds)?;
    if data.len() < end_offset {
        return Err(SanitizeError::ValueOutOfBounds);
    }
    let second_byte_offset = offset
        .checked_add(1)
        .ok_or(SanitizeError::ValueOutOfBounds)?;
    let message_len = u16::from_le_bytes([data[offset], data[second_byte_offset]]) as usize;
    if message_len == 0 {
        return Err(SanitizeError::InvalidValue);
    }
    Ok((message_len, end_offset))
}

/// Parse message body from data at given offset
pub fn parse_message_body(
    data: &[u8],
    offset: usize,
    expected_len: usize,
) -> Result<Vec<u8>, SanitizeError> {
    let expected_total = offset
        .checked_add(expected_len)
        .ok_or(SanitizeError::ValueOutOfBounds)?;
    if expected_total != data.len() {
        return Err(SanitizeError::InvalidValue);
    }
    Ok(data[offset..].to_vec())
}

/// Validate format constraints against parsed data
pub fn validate_format_constraints(
    format: MessageFormat,
    total_size: usize,
    message: &[u8],
) -> Result<(), SanitizeError> {
    let is_valid = match format {
        MessageFormat::RestrictedAscii => {
            fits_ledger_limit(total_size) && super::is_printable_ascii(message)
        }
        MessageFormat::LimitedUtf8 => fits_ledger_limit(total_size) && super::is_utf8(message),
        MessageFormat::ExtendedUtf8 => fits_extended_limit(total_size) && super::is_utf8(message),
    };

    is_valid.then_some(()).ok_or(SanitizeError::InvalidValue)
}

/// Serialize a v0 message to bytes, including the full header
pub fn serialize_v0(
    application_domain: &[u8; 32],
    format: MessageFormat,
    signers: &[[u8; 32]],
    message: &[u8],
    data: &mut Vec<u8>,
) -> Result<(), SanitizeError> {
    assert!(!message.is_empty());
    assert!(!signers.is_empty() && signers.len() <= u8::MAX as usize);

    let reserve_size = super::v0::OffchainMessage::HEADER_LEN
        .saturating_add(signers.len().saturating_mul(32))
        .saturating_add(message.len());
    data.reserve(reserve_size);

    data.extend_from_slice(application_domain);
    data.push(format.into());
    data.push(signers.len() as u8);
    for signer in signers {
        data.extend_from_slice(signer);
    }
    data.extend_from_slice(&(message.len() as u16).to_le_bytes());
    data.extend_from_slice(message);
    Ok(())
}

/// Deserialize a v0 message from bytes that include a full header
pub fn deserialize_v0(data: &[u8]) -> Result<V0MessageComponents, SanitizeError> {
    if data.len() < super::v0::OffchainMessage::HEADER_LEN {
        return Err(SanitizeError::ValueOutOfBounds);
    }

    // Parse each component using helper functions
    let (application_domain, offset) = parse_application_domain(data, 0)?;
    let (format, offset) = parse_message_format(data, offset)?;
    let (signer_count, offset) = parse_signer_count(data, offset)?;
    let (signers, offset) = parse_signers(data, offset, signer_count)?;
    let (message_len, offset) = parse_message_length(data, offset)?;
    let message = parse_message_body(data, offset, message_len)?;

    // Validate format constraints
    let total_size = header::total_message_size(signers.len(), message_len);
    validate_format_constraints(format, total_size, &message)?;

    Ok((application_domain, format, signers, message))
}

/// Construct a new v0 message with validation
pub fn new_v0_with_params(
    application_domain: [u8; 32],
    signers: &[[u8; 32]],
    message: &[u8],
) -> Result<V0MessageComponents, SanitizeError> {
    validate_signers(signers)?;
    validate_body(message)?;
    let total_size = header::total_message_size(signers.len(), message.len());
    let format = detect_format(total_size, message)?;

    Ok((
        application_domain,
        format,
        signers.to_vec(),
        message.to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Validation function tests
    #[test]
    fn test_validation_functions() {
        // Test validate_signers
        assert_eq!(validate_signers(&[]), Err(SanitizeError::ValueOutOfBounds)); // empty
        assert_eq!(
            validate_signers(&vec![[0u8; 32]; 256]),
            Err(SanitizeError::ValueOutOfBounds)
        ); // too many
        assert!(validate_signers(&[[1u8; 32], [2u8; 32]]).is_ok()); // valid

        // Test validate_body
        assert_eq!(validate_body(&[]), Err(SanitizeError::InvalidValue)); // empty
    }

    #[test]
    fn test_detect_format() {
        // Test valid formats
        assert_eq!(
            detect_format(100, b"Hello World!"),
            Ok(MessageFormat::RestrictedAscii)
        );
        assert_eq!(
            detect_format(100, "Привет мир!".as_bytes()),
            Ok(MessageFormat::LimitedUtf8)
        );
        assert_eq!(
            detect_format(PREAMBLE_AND_BODY_MAX_LEDGER + 100, b"Hello World!"),
            Ok(MessageFormat::ExtendedUtf8)
        );

        // Test error cases
        assert_eq!(
            detect_format(100, &[0xff, 0xfe, 0xfd]),
            Err(SanitizeError::InvalidValue)
        ); // invalid UTF-8
        assert_eq!(
            detect_format(PREAMBLE_AND_BODY_MAX_EXTENDED + 1, b"Hello"),
            Err(SanitizeError::ValueOutOfBounds)
        ); // too large
    }

    // Parsing function tests
    #[test]
    fn test_parsing_functions() {
        // Test parse_application_domain
        let domain_data = [0x42u8; 64];
        let (domain, offset) = parse_application_domain(&domain_data, 0).unwrap();
        assert_eq!(domain, [0x42u8; 32]);
        assert_eq!(offset, 32);
        assert_eq!(
            parse_application_domain(&[0x42u8; 16], 0),
            Err(SanitizeError::ValueOutOfBounds)
        ); // insufficient data

        // Test parse_message_format
        assert_eq!(
            parse_message_format(&[255], 0),
            Err(SanitizeError::InvalidValue)
        ); // invalid format

        // Test parse_signer_count
        assert_eq!(
            parse_signer_count(&[0], 0),
            Err(SanitizeError::InvalidValue)
        ); // zero count

        // Test parse_signers
        let mut signer_data = vec![];
        signer_data.extend_from_slice(&[0x11u8; 32]);
        signer_data.extend_from_slice(&[0x22u8; 32]);
        let (signers, offset) = parse_signers(&signer_data, 0, 2).unwrap();
        assert_eq!(signers.len(), 2);
        assert_eq!(signers[0], [0x11u8; 32]);
        assert_eq!(offset, 64);
        assert_eq!(
            parse_signers(&[0u8; 16], 0, 2),
            Err(SanitizeError::ValueOutOfBounds)
        ); // insufficient data

        // Test parse_message_length
        assert_eq!(
            parse_message_length(&[0x00, 0x00], 0),
            Err(SanitizeError::InvalidValue)
        ); // zero length

        // Test parse_message_body
        let body_data = b"Hello World!";
        assert_eq!(
            parse_message_body(body_data, 0, body_data.len()),
            Ok(body_data.to_vec())
        );
        assert_eq!(
            parse_message_body(b"Hello", 0, 10),
            Err(SanitizeError::InvalidValue)
        ); // length mismatch
    }

    // Serialization function tests
    #[test]
    fn test_serialize_deserialize_round_trip() {
        let application_domain = [0x42u8; 32];
        let signers = vec![[0x11u8; 32], [0x22u8; 32]];
        let message = b"Test message".to_vec();
        let format = MessageFormat::RestrictedAscii;

        // Serialize
        let mut serialized = Vec::new();
        serialize_v0(
            &application_domain,
            format,
            &signers,
            &message,
            &mut serialized,
        )
        .unwrap();

        // Deserialize
        let (parsed_domain, parsed_format, parsed_signers, parsed_message) =
            deserialize_v0(&serialized).unwrap();

        // Verify round trip
        assert_eq!(parsed_domain, application_domain);
        assert_eq!(parsed_format, format);
        assert_eq!(parsed_signers, signers);
        assert_eq!(parsed_message, message);
    }

    #[test]
    fn test_new_v0_with_params() {
        let application_domain = [0x42u8; 32];

        // Test success case
        let signers = [[0x11u8; 32]];
        let message = b"Hello World!";
        let (domain, format, parsed_signers, parsed_message) =
            new_v0_with_params(application_domain, &signers, message).unwrap();
        assert_eq!(domain, application_domain);
        assert_eq!(format, MessageFormat::RestrictedAscii);
        assert_eq!(parsed_signers, signers);
        assert_eq!(parsed_message, message);

        // Test error cases
        assert_eq!(
            new_v0_with_params(application_domain, &[], b"Hello World!"),
            Err(SanitizeError::ValueOutOfBounds)
        ); // empty signers
        assert_eq!(
            new_v0_with_params(application_domain, &[[0x11u8; 32]], b""),
            Err(SanitizeError::InvalidValue)
        ); // empty message
    }
}
