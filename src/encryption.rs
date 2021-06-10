use asn1::{ASN1, Tag, Integer, OctetString, to_der, from_ber};
use error::{KerlabResult, Error, KerlabErrorKind};
use yasna::{DERWriter, BERReader};
use rc4hmac::Rc4Hmac;
use ntlm::{ntlm};


#[repr(u32)]
pub enum EType {
    NoEncryption = 0,
    DesCbcCrc = 1,
    DesCbcMd5 = 3,
    Aes256CtsHmacSha196 = 18,
    Aes128CtsHmacSha196 = 17,
    Rc4Hmac = 23,
    Rc4HmacExp = 24
}

#[repr(u32)]
#[derive(Copy, Clone)]
pub enum KeyUsage {
    KeyUsageAsReqTimestamp = 1,
    KeyUsageAsRepTicket = 2,
    KeyUsageAsRepEncPart1 = 3,
    KrbKeyUsageTgsReqPaAuthenticator = 7,
    KeyUsageAsRepEncPart = 8
}


/// @see https://www.freesoft.org/CIE/RFC/1510/70.htm
/// ```asn.1
/// EncryptedData   ::= SEQUENCE {
///        etype   [0] INTEGER -- EncryptionType --,
///        kvno    [1] INTEGER OPTIONAL,
///        cipher  [2] OCTET STRING -- ciphertext
/// }
/// ```

#[derive(Sequence, PartialEq, Clone, Default)]
pub struct EncryptedData {
    pub etype: Tag<0, Integer>,
    pub kvno: Option<Tag<1, Integer>>,
    pub cipher: Tag<2, OctetString>
}

impl EncryptedData {
    pub fn new(etype: Integer, cipher: OctetString) -> Self {
        Self {
            etype: Tag::new(etype),
            kvno: None,
            cipher: Tag::new(cipher)
        }
    }

    /// Conveninent function to decrypt a blob as an ASN.1 defined structure
    pub fn decrypt_as<T: ASN1 + Default>(&self, password: &str, key_usage: KeyUsage) -> KerlabResult<T> {
        match self.etype.inner {
            0 => {
                let mut result = T::default();
                from_ber(&mut result, &self.cipher.inner)?;
                Ok(result)
            },
            23 => {
                let plaintext = Rc4Hmac::new(ntlm(password)?, key_usage).decrypt(&self.cipher.inner)?;
                let mut result = T::default();
                from_ber(&mut result, &plaintext)?;
                Ok(result)
            }
            _ => Err(Error::new(KerlabErrorKind::Crypto, "Unsupported Algorithm"))
        }
    }
}

/// @see https://www.freesoft.org/CIE/RFC/1510/71.htm
/// ```asn.1
/// EncryptionKey ::=   SEQUENCE {
///       keytype[0]    INTEGER,
///       keyvalue[1]   OCTET STRING
/// }
#[derive(Sequence, PartialEq, Default, Clone)]
pub struct EncryptionKey {
    pub keytype: Tag<0, Integer>,
    pub keyvalue: Tag<1, OctetString>
}

impl EncryptionKey {
    pub fn new(keytype: EType, keyvalue: OctetString) -> Self {
        Self {
            keytype: Tag::new(keytype as Integer),
            keyvalue: Tag::new(keyvalue)
        }
    }

    pub fn new_no_encryption() -> Self {
        Self {
            keytype: Tag::new(EType::NoEncryption as Integer),
            keyvalue: Tag::new(vec![])
        }
    }

    pub fn new_rc4_hmac(password: &str) -> KerlabResult<Self> {
        Ok(Self {
            keytype: Tag::new(EType::Rc4Hmac as Integer),
            keyvalue: Tag::new(ntlm(password)?)
        })
    }

    pub fn new_rc4_hmac_from_hash(hash: Vec<u8>) -> KerlabResult<Self> {
        Ok(Self {
            keytype: Tag::new(EType::Rc4Hmac as Integer),
            keyvalue: Tag::new(hash)
        })
    }
}

impl EncryptionKey {
    pub fn encrypt(&self, key_usage: KeyUsage, object: &dyn ASN1) -> KerlabResult<EncryptedData> {
        match self.keytype.inner {
            0 => {
                Ok(EncryptedData::new(
                    self.keytype.inner,
                    to_der(object)
                ))
            },
            23 => {
                let cipher = Rc4Hmac::new(self.keyvalue.inner.clone(), key_usage).encrypt(&to_der(object));
                Ok(EncryptedData::new(
                    self.keytype.inner,
                    cipher
                ))
            },
            _ => Err(Error::new(KerlabErrorKind::Crypto, "Unsupported Algorithm"))
        }
    }

    pub fn decrypt<T: ASN1 + Default>(&self, key_usage: KeyUsage, data: &EncryptedData) -> KerlabResult<T> {
        if self.keytype.inner != data.etype.inner {
            return Err(Error::new(KerlabErrorKind::Crypto, "Bad Key"))
        }

        match self.keytype.inner {
            0 => {
                let mut result = T::default();
                from_ber(&mut result, &data.cipher.inner)?;
                Ok(result)
            },
            23 => {
                let plaintext = Rc4Hmac::new(self.keyvalue.inner.clone(), key_usage).decrypt(&data.cipher.inner)?;
                let mut result = T::default();
                from_ber(&mut result, &plaintext)?;
                Ok(result)
            },
            _ => Err(Error::new(KerlabErrorKind::Crypto, "Unsupported Algorithm"))
        }
    }
}