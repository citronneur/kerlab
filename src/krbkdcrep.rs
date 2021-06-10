use asn1::{Tag, Integer, SequenceOf, ASN1, Application};
use padata::PaData;
use base::{PrincipalName, Realm, LastReq, KerberosTime, TicketFlags, HostAddresses};
use ticket::Ticket;
use yasna::{DERWriter, BERReader};
use error::{KerlabResult};
use encryption::{EncryptedData, KeyUsage, EncryptionKey};

/// @see https://www.freesoft.org/CIE/RFC/1510/56.htm
/// ```asn.1
/// KDC-REP ::=   SEQUENCE {
///     pvno[0]                    INTEGER,
///     msg-type[1]                INTEGER,
///     padata[2]                  SEQUENCE OF PA-DATA OPTIONAL,
///     crealm[3]                  Realm,
///     cname[4]                   PrincipalName,
///     ticket[5]                  Ticket,
///     enc-part[6]                EncryptedData
/// }
/// ```
#[derive(Sequence, Default, PartialEq, Clone)]
pub struct KdcRep {
    pub pvno: Tag<0, Integer>,
    pub msg_type: Tag<1, Integer>,
    pub padata: Option<Tag<2, SequenceOf<PaData>>>,
    pub crealm: Tag<3, Realm>,
    pub cname: Tag<4, PrincipalName>,
    pub ticket: Tag<5, Ticket>,
    pub enc_part: Tag<6, EncryptedData>
}

pub type AsRep = Application<11, KdcRep>;

impl AsRep {
    /// decrypt the encrypte part of the response using user password
    pub fn decrypt(&self, password: &str) -> KerlabResult<EncASRepPart>{
        self.inner.enc_part.decrypt_as::<EncASRepPart>(
            password,
            KeyUsage::KeyUsageAsRepEncPart
        )
    }
}

/// @see https://www.freesoft.org/CIE/RFC/1510/56.htm
///```asn1
/// EncKDCRepPart ::=   SEQUENCE {
///     key[0]                       EncryptionKey,
///     last-req[1]                  LastReq,
///     nonce[2]                     INTEGER,
///     key-expiration[3]            KerberosTime OPTIONAL,
///     flags[4]                     TicketFlags,
///     authtime[5]                  KerberosTime,
///     starttime[6]                 KerberosTime OPTIONAL,
///     endtime[7]                   KerberosTime,
///     renew-till[8]                KerberosTime OPTIONAL,
///     srealm[9]                    Realm,
///     sname[10]                    PrincipalName,
///     caddr[11]                    HostAddresses OPTIONAL
/// }
#[derive(Sequence, Default, PartialEq, Clone)]
pub struct EncKDCRepPart {
    pub key: Tag<0, EncryptionKey>,
    pub last_req: Tag<1, LastReq>,
    pub nonce: Tag<2, Integer>,
    pub key_expiration: Option<Tag<3, KerberosTime>>,
    pub flags: Tag<4, TicketFlags>,
    pub authtime: Tag<5, KerberosTime>,
    pub starttime: Option<Tag<6, KerberosTime>>,
    pub endtime: Tag<7, KerberosTime>,
    pub renew_till: Option<Tag<8, KerberosTime>>,
    pub srealm: Tag<9, Realm>,
    pub sname: Tag<10, PrincipalName>,
    pub caddr: Option<Tag<11, HostAddresses>>
}

/// @see https://www.freesoft.org/CIE/RFC/1510/56.htm
///```asn1
/// EncASRepPart ::=    [APPLICATION 25[25]] EncKDCRepPart
/// ```
pub type EncASRepPart = Application<25, EncKDCRepPart>;


/// @see https://www.freesoft.org/CIE/RFC/1510/56.htm
/// TGS response
/// ```asn.1
/// TGS-REP ::=   [APPLICATION 13] KDC-REP
/// ```
pub type TgsRep = Application<13, KdcRep>;

/// @see https://www.freesoft.org/CIE/RFC/1510/56.htm
/// ```asn1
/// EncTGSRepPart ::=   [APPLICATION 26] EncKDCRepPart
/// ```
pub type EncTGSRepPart = Application<26, EncKDCRepPart>;