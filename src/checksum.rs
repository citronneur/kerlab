use asn1::{ASN1, Tag, OctetString, SInteger};
use yasna::{DERWriter, BERReader};
use error::KerlabResult;
use rc4hmac::hmac_md5;
use md5::{Md5, Digest};

/// Compute the MD5 Hash of input vector
///
/// This is a convenient method to respect
/// the initial specification of protocol
///
/// # Example
/// ```rust, ignore
/// let hash = md5((b"foo");
/// ```
fn md5(data: &[u8]) -> Vec<u8> {
    let mut hasher = Md5::new();
    hasher.input(data);
    hasher.result().to_vec()
}

/// @see https://datatracker.ietf.org/doc/html/rfc4757
pub fn kerberos_hmac_md5(key: &[u8], key_usage: i32, plaintext: &[u8]) -> Vec<u8> {
    let mut keyword = "signaturekey".to_string().into_bytes();
    keyword.push(0);

    let ksign = hmac_md5(key, &keyword);
    let mut bs = key_usage.to_le_bytes().to_vec();
    bs.append(&mut plaintext.to_vec());
    let tmp = md5(&bs);

    return hmac_md5(&ksign, &tmp);
}

/// @see https://www.freesoft.org/CIE/RFC/1510/77.htm
/// ```asn.1
/// Checksum ::=   SEQUENCE {
///     cksumtype[0]   INTEGER,
///     checksum[1]    OCTET STRING
/// }
/// ```
#[derive(Sequence, Default, Clone, PartialEq)]
pub struct Checksum {
    cksumtype: Tag<0, SInteger>,
    checksum: Tag<1, OctetString>
}

impl Checksum {
    /// constructor
    pub fn new(cksumtype: SInteger, checksum: OctetString) -> Self {
        Self {
            cksumtype: Tag::new(cksumtype),
            checksum: Tag::new(checksum)
        }
    }
}