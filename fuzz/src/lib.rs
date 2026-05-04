//! Shared utilities for fuzz targets.

use std::fmt;

use bitcoin_consensus_encoding::{decode_from_slice, encode_to_vec, Decode, Decoder, Encode};

/// Checks roundtrip decode -> encode for a type.
///
/// Verifies that for all byte slices that decode successfully, the decoded value
/// re-encodes to a slice that decodes back to the same value.
pub fn check_roundtrip<T>(data: &[u8])
where
    T: Encode + Decode + PartialEq + fmt::Debug,
    <<T as Decode>::Decoder as Decoder>::Error: fmt::Debug,
{
    if let Ok(base_decoded) = decode_from_slice::<T>(data) {
        let encoded = encode_to_vec(&base_decoded);
        let decoded = decode_from_slice::<T>(&encoded).unwrap();
        assert_eq!(base_decoded, decoded);
    }
}

/// Checks roundtrip decode -> encode for a script type that derefs to its encoding target.
///
/// Script `Buf` types (e.g. `ScriptPubKeyBuf`) implement `Encode` via `Deref` to their
/// unsized counterpart (e.g. `ScriptPubKey`), so encoding must go through the deref.
pub fn check_script_roundtrip<T>(data: &[u8])
where
    T: Decode + PartialEq + fmt::Debug + std::ops::Deref,
    <T as std::ops::Deref>::Target: Encode,
    <<T as Decode>::Decoder as Decoder>::Error: fmt::Debug,
{
    if let Ok(base_decoded) = decode_from_slice::<T>(data) {
        let encoded = encode_to_vec(&*base_decoded);
        let decoded = decode_from_slice::<T>(&encoded).unwrap();
        assert_eq!(base_decoded, decoded);
    }
}
