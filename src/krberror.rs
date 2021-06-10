use asn1::{Integer, Tag, GeneralString, OctetString, Application, ASN1};
use yasna::{DERWriter, BERReader};
use base::{KerberosTime, Realm, PrincipalName};
use error::{KerlabResult};

pub type KrbError = Application<30, KrbErrorBody>;

/// @see https://www.freesoft.org/CIE/RFC/1510/68.htm
/// ```asn.1
/// KRB-ERROR ::=   [APPLICATION 30] SEQUENCE {
///     pvno[0]               INTEGER,
///     msg-type[1]           INTEGER,
///     ctime[2]              KerberosTime OPTIONAL,
///     cusec[3]              INTEGER OPTIONAL,
///     stime[4]              KerberosTime,
///     susec[5]              INTEGER,
///     error-code[6]         INTEGER,
///     crealm[7]             Realm OPTIONAL,
///     cname[8]              PrincipalName OPTIONAL,
///     realm[9]              Realm, -- Correct realm
///     sname[10]             PrincipalName, -- Correct name
///     e-text[11]            GeneralString OPTIONAL,
///     e-data[12]            OCTET STRING OPTIONAL
/// }
/// ```
#[derive(Sequence, Default, PartialEq, Clone)]
pub struct KrbErrorBody {
    pub pvno: Tag<0, Integer>,
    pub msg_type: Tag<1, Integer>,
    pub ctime: Option<Tag<2, KerberosTime>>,
    pub cusec: Option<Tag<3, Integer>>,
    pub stime: Tag<4, KerberosTime>,
    pub susec: Tag<5, Integer>,
    pub error_code: Tag<6, Integer>,
    pub crealm: Option<Tag<7, Realm>>,
    pub cname: Option<Tag<8, PrincipalName>>,
    pub realm: Tag<9, Realm>,
    pub sname: Tag<10, PrincipalName>,
    pub e_text: Option<Tag<11, GeneralString>>,
    pub e_data: Option<Tag<12, OctetString>>
}