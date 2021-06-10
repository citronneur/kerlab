use error::{KerlabResult};
use asn1::{ASN1, Integer, OctetString, SequenceOf, GeneralString, Tag, BitString, GeneralizedTime};
use yasna::{BERReader, DERWriter};

#[repr(u32)]
pub enum MessageType {
    KrbAsReq = 10,
    KrbAsRep = 11,
    KrbTgsReq = 12,
    KrbTgsRep = 13,
    KrbApReq = 14,
    KrbApRep = 15,
    KrbReserved1 = 16,
    KrbReserved17 = 17,
    KrbSafe = 20,
    KrbPriv = 21,
    KrbCred = 22,
    KrbError = 30
}


pub type Realm = GeneralString;

pub type KerberosTime = GeneralizedTime;

pub type KDCOptions = BitString;

pub type TicketFlags = BitString;

#[repr(u32)]
pub enum PrincipalNameType {
    NtUnknown = 0,
    NtPrincipal = 1,
    NtSrvInst = 2,
    NtSrvHst = 3,
    NtSrvXhst = 4,
    NtUid = 5,
    NtX500Principal = 6,
    NtSmtpName = 7,
    NtEnterprise = 10
}

/// Principal name
///
///
/// @see https://www.freesoft.org/CIE/RFC/1510/50.htm
///
/// ```asn.1
/// PrincipalName ::=   SEQUENCE {
///     name-type[0]     INTEGER,
///     name-string[1]   SEQUENCE OF GeneralString
/// }
/// ```
#[derive(Sequence, PartialEq, Clone, Default)]
pub struct PrincipalName {
    pub name_type: Tag<0, Integer>,
    pub name_string: Tag<1, SequenceOf<GeneralString>>
}

impl PrincipalName {
    /// Constructor
    pub fn new(pntype: PrincipalNameType, values: SequenceOf<GeneralString>) -> Self {
        PrincipalName {
            name_type: Tag::new(pntype as Integer),
            name_string: Tag::new(values)
        }
    }
}

/// Address type
///
/// @see https://www.freesoft.org/CIE/RFC/1510/50.htm
///
/// ```asn.1
/// HostAddress ::=     SEQUENCE  {
///     addr-type[0]             INTEGER,
///     address[1]               OCTET STRING
/// }
/// ```
#[derive(Sequence, PartialEq, Default, Clone)]
pub struct HostAddress {
    pub addr_type: Tag<0, Integer>,
    pub address: Tag<1, OctetString>
}

impl HostAddress {
    /// Constructor
    pub fn new() -> Self {
        HostAddress {
            addr_type: Tag::new(0),
            address: Tag::new(OctetString::new())
        }
    }
}

pub type HostAddresses = SequenceOf<HostAddress>;

/// @see https://www.freesoft.org/CIE/RFC/1510/50.htm
///
///
/// ```asn.1
/// LastReq ::=   SEQUENCE OF SEQUENCE {
///     lr-type[0]               INTEGER,
///     lr-value[1]              KerberosTime
/// }
/// ```
#[derive(Sequence, PartialEq, Default, Clone)]
pub struct LastReqBody {
    pub lr_type: Tag<0, Integer>,
    pub lr_value: Tag<1, KerberosTime>
}

pub type LastReq = SequenceOf<LastReqBody>;

/// @see https://www.freesoft.org/CIE/RFC/1510/50.htm
/// ```asn.1
/// AuthorizationData ::=   SEQUENCE OF SEQUENCE {
///     ad-type[0]               INTEGER,
///     ad-data[1]               OCTET STRING
/// }
/// ```
#[derive(Sequence, PartialEq, Default, Clone)]
pub struct AuthorizationDataElement {
    pub ad_type: Tag<0, Integer>,
    pub ad_data: Tag<1, OctetString>
}

pub type AuthorizationData = SequenceOf<AuthorizationDataElement>;

#[cfg(test)]
mod test {
    use super::*;
    use asn1::to_der;

    /// Test format of the first client message
    #[test]
    fn test_principal_name() {
        let mut pn = PrincipalName::default();
        pn.name_type.inner = 2;
        pn.name_string.inner.push(GeneralString::from_ascii("foo").unwrap());
        assert_eq!(to_der(&pn), [48, 14, 160, 3, 2, 1, 2, 161, 7, 48, 5, 27, 3, 102, 111, 111]);
    }
}
