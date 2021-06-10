use asn1::{Tag, Integer, OctetString, ASN1, to_der, GeneralString, SInteger};
use error::{KerlabResult};
use base::{KerberosTime, PrincipalName, Realm};
use yasna::{DERWriter, BERReader};
use chrono::{Utc};
use encryption::{EncryptionKey, KeyUsage};
use checksum::{Checksum, kerberos_hmac_md5};
use std::str::FromStr;

#[repr(u32)]
pub enum PaDataType {
    PaTgsReq = 1,
    PaEncTimestamp = 2,
    PaPwSalt = 3,
    PaEncUnixTime = 5,
    PaSandiaSecureid = 6,
    PaSesame = 7,
    PaOsfDce = 8,
    PaCybersafeSecureid = 9,
    PaAfs3Salt = 10,
    PaEtypeInfo = 11,
    PaSamChallenge = 12,
    PaSamResponse = 13,
    PaPkAsReqOld = 14,
    PaPkAsRepOld = 15,
    PaPkAsReq = 16,
    PaPkAsRep = 17,
    PaEtypeInfo2 = 19,
    PaSvrReferralInfo = 20,
    //PaUseSpecifiedKvno = 20,
    PaSamRedirect = 21,
    PaGetFromTypedData = 22,
    //TdPadata = 22,
    PaSamEtypeInfo = 23,
    PaAltPrinc = 24,
    PaSamChallenge2 = 30,
    PaSamResponse2 = 31,
    PaExtraTgt = 41,
    TdPkinitCmsCertificates = 101,
    TdKrbPrincipal = 102,
    TdKrbRealm = 103,
    TdTrustedCertifiers = 104,
    TdCertificateIndex = 105,
    TdAppDefinedError = 106,
    TdReqNonce = 107,
    TdReqSeq = 108,
    PaPacRequest = 128,
    PaForUser = 129,
    PaFxCookie = 133,
    PaFxFast = 136,
    PaFxError = 137,
    PaEncryptedChallenge = 138,
    KerbKeyListReq = 161,
    KerbKeyListRep = 162,
    PaSupportedEnctypes = 165,
    PaPacOptions = 167
}


/// @see https://www.freesoft.org/CIE/RFC/1510/55.htm
/// ```asn1
/// PA-DATA ::= SEQUENCE {
///     padata-type[1]        INTEGER,
///     padata-value[2]       OCTET STRING,
///                          -- might be encoded AP-REQ
/// }
/// ```
#[derive(Sequence, PartialEq, Clone, Default)]
pub struct PaData {
    pub padata_type: Tag<1, Integer>,
    pub padata_value: Tag<2, OctetString>
}

impl PaData {
    pub fn new(patype: PaDataType, pavalue: &dyn ASN1) -> Self {
        Self {
            padata_type: Tag::new(patype as Integer),
            padata_value: Tag::new(to_der(pavalue))
        }
    }

    /// Use to format an enc timestamp use in pre authentication
    pub fn pa_enc_timestamp(key: &EncryptionKey) -> KerlabResult<Self> {
        Ok(PaData::new(
                PaDataType::PaEncTimestamp,
                &key.encrypt(
                    KeyUsage::KeyUsageAsReqTimestamp,
                    &PaEncTsEnc::now())?
            )
        )
    }

    /// use in S4u protocol extension
    pub fn pa_for_user(user_name: PrincipalName, user_realm: Realm, key: &EncryptionKey) -> KerlabResult<Self>{
        Ok(PaData::new(
                PaDataType::PaForUser,
                &PaForUser::new(
                    user_name,
                    user_realm,
                    key
                )?
            )
        )
    }
}

/// @see https://www.freesoft.org/CIE/RFC/1510/55.htm
/// ```asn1
/// PA-ENC-TS-ENC   ::= SEQUENCE {
///     patimestamp[0]               KerberosTime, -- client's time
///     pausec[1]                    INTEGER OPTIONAL
/// }
/// ```
#[derive(Sequence, PartialEq, Default)]
pub struct PaEncTsEnc {
    pub patimestamp: Tag<0, KerberosTime>,
    pub pausec: Option<Tag<1, Integer>>
}

impl PaEncTsEnc {
    pub fn now() -> Self {
        Self {
            patimestamp: Tag::new(KerberosTime::new( Utc::now())),
            pausec: None
        }
    }
}

/// @see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/aceb70de-40f0-4409-87fa-df00ca145f5a
/// ```asn.1
/// PA-FOR-USER ::= SEQUENCE {
///        -- PA TYPE 129
///        userName              [0] PrincipalName,
///        userRealm              [1] Realm,
///        cksum                 [2] Checksum,
///        auth-package          [3] KerberosString
/// }
/// ```
#[derive(Sequence, PartialEq, Default)]
pub struct PaForUser {
    user_name: Tag<0, PrincipalName>,
    user_realm: Tag<1, Realm>,
    cksum: Tag<2, Checksum>,
    auth_package: Tag<3, GeneralString>
}

impl PaForUser {
    pub fn new(user_name: PrincipalName, user_realm: Realm, key: &EncryptionKey) -> KerlabResult<Self> {

        let package = "Kerberos";
        // compute checksum
        let mut data = vec![];
        data.extend_from_slice(&user_name.name_type.inner.to_le_bytes());
        for s in &user_name.name_string.inner {
            data.extend_from_slice(s.as_bytes());
        }
        data.extend_from_slice(user_realm.as_bytes());
        data.extend_from_slice(package.as_bytes());

        Ok(Self {
            user_name: Tag::new(user_name),
            user_realm: Tag::new(user_realm),
            cksum: Tag::new(Checksum::new(
                -138 as SInteger,
                kerberos_hmac_md5(&key.keyvalue.inner, 17, &data)
            )),
            auth_package: Tag::new(GeneralString::from_str(package)?)
        })
    }
}