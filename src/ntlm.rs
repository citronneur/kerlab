use md4::{Md4, Digest};
use std::io::Cursor;
use byteorder::{WriteBytesExt, LittleEndian};
use error::KerlabResult;

pub type NtlmHash = Vec<u8>;

/// Compute the MD4 Hash of input vector
///
/// This is a convenient method to respect
/// the initial specification of protocol
///
/// # Example
/// ```rust, ignore
/// let hash = md4(b"foo");
/// ```
fn md4(data: &[u8]) -> Vec<u8> {
    let mut hasher = Md4::new();
    hasher.input(data);
    hasher.result().to_vec()
}

/// Encode a string into utf-16le
///
/// This is a basic algorithm to encode
/// an utf-8 string into utf-16le
///
/// # Example
/// ```rust, ignore
/// let encoded_string = unicode("foo".to_string());
/// ```
fn unicode(data: &String) -> KerlabResult<Vec<u8>> {
    let mut result = Cursor::new(Vec::new());
    for c in data.encode_utf16() {
        result.write_u16::<LittleEndian>(c)?;
    }
    Ok(result.into_inner())
}


/// Compute the NTLM hash
///
/// Compute NTLM hash of the user, use by the AS-REQ
///
/// # Example
/// ```rust
/// use kekeo::ntlm::ntlm;
/// let hash = ntlm(&String::from("foo"));
/// assert_eq!(hash, [172, 142, 101, 127, 131, 223, 130, 190, 234, 93, 67, 189, 175, 120, 0, 204])
/// ```
pub fn ntlm(password: &str) -> KerlabResult<NtlmHash> {
    Ok(md4(unicode(&String::from(password))?.as_slice()))
}