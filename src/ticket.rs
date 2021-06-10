use asn1::{Tag, Integer, ASN1, Application, OctetString};
use base::{Realm, PrincipalName, TicketFlags, KerberosTime, AuthorizationData, HostAddresses};
use encryption::{EncryptedData, EncryptionKey};
use yasna::{DERWriter, BERReader};
use error::{KerlabResult};

/// @see pub type Ticket = Application<1, TicketBody>;
/// ```asn.1
/// Ticket          ::= [APPLICATION 1] SEQUENCE {
///        tkt-vno         [0] INTEGER (5),
///        realm           [1] Realm,
///        sname           [2] PrincipalName,
///        enc-part        [3] EncryptedData -- EncTicketPart
/// }
/// ```
#[derive(Sequence, PartialEq, Default, Clone)]
pub struct TicketBody {
    pub tkt_vno: Tag<0, Integer>,
    pub realm: Tag<1, Realm>,
    pub sname: Tag<2, PrincipalName>,
    pub enc_part: Tag<3, EncryptedData>
}

pub type Ticket = Application<1, TicketBody>;

/// See https://www.freesoft.org/CIE/RFC/1510/52.htm
/// ```asn.1
/// TransitedEncoding ::= SEQUENCE {
///     tr-type[0]  INTEGER, -- must be registered
///     contents[1]          OCTET STRING
/// }
/// ```
#[derive(Sequence, PartialEq, Default, Clone)]
pub struct TransitedEncoding {
    pub tr_type: Tag<0, Integer>,
    pub contents: Tag<1, OctetString>
}

/// See https://www.freesoft.org/CIE/RFC/1510/52.htm
/// ```asn1
/// -- Encrypted part of ticket
/// EncTicketPart ::= [APPLICATION 3] SEQUENCE {
///     flags[0]             TicketFlags,
///     key[1]               EncryptionKey,
///     crealm[2]            Realm,
///     cname[3]             PrincipalName,
///     transited[4]         TransitedEncoding,
///     authtime[5]          KerberosTime,
///     starttime[6]         KerberosTime OPTIONAL,
///     endtime[7]           KerberosTime,
///     renew-till[8]        KerberosTime OPTIONAL,
///     caddr[9]             HostAddresses OPTIONAL,
///     authorization-data[10]   AuthorizationData OPTIONAL
/// }
/// ```
#[derive(Sequence, PartialEq, Default, Clone)]
pub struct EncTicketPartBody {
    pub flags: Tag<0, TicketFlags>,
    pub key: Tag<1, EncryptionKey>,
    pub crealm: Tag<2, Realm>,
    pub cname: Tag<3, PrincipalName>,
    pub transited: Tag<4, TransitedEncoding>,
    pub authtime: Tag<5, KerberosTime>,
    pub starttime: Option<Tag<6, KerberosTime>>,
    pub endtime: Tag<7, KerberosTime>,
    pub renew_till: Option<Tag<8, KerberosTime>>,
    pub caddr: Option<Tag<9, HostAddresses>>,
    pub authorization_data: Option<Tag<10, AuthorizationData>>
}

pub type EncTicketPart = Application<3, EncTicketPartBody>;


#[repr(u32)]
pub enum AdDataType {
    AdIfRelevant =1,
    AdIntendedForServer =2,
    AdIntendedForApplicationClass =3,
    AdKdcIssued =4,
    AdAndOr =5,
    AdMandatoryTicketExtensions =6,
    AdInTicketExtensions =7,
    AdMandatoryForKdc =8,
    OsfDce =64,
    SESAME=65,
    AdOsfDcePkiCertid =66,
    AdWin2kPac =128,
    AdEtypeNegotiation =129
}

/// ```asn1
/// AD-IF-RELEVANT ::= AuthorizationData
/// ```
pub type AdIfRelevant = AuthorizationData;

