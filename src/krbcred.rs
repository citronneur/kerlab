use asn1::{Tag, SequenceOf, Integer, Application, ASN1};
use yasna::{BERReader, DERWriter};
use encryption::{EncryptionKey, KeyUsage};
use base::{Realm, PrincipalName, TicketFlags, KerberosTime, HostAddresses, HostAddress, MessageType};
use ticket::Ticket;
use encryption::{EncryptedData};
use error::KerlabResult;
use krbkdcrep::{EncKDCRepPart};

/// @see https://www.freesoft.org/CIE/RFC/1510/66.htm
/// ```asn.1
/// KrbCredInfo      ::=    SEQUENCE {
///     key[0]                 EncryptionKey,
///     prealm[1]              Realm OPTIONAL,
///     pname[2]               PrincipalName OPTIONAL,
///     flags[3]               TicketFlags OPTIONAL,
///     authtime[4]            KerberosTime OPTIONAL,
///     starttime[5]           KerberosTime OPTIONAL,
///     endtime[6]             KerberosTime OPTIONAL
///     renew-till[7]          KerberosTime OPTIONAL,
///     srealm[8]              Realm OPTIONAL,
///     sname[9]               PrincipalName OPTIONAL,
///     caddr[10]              HostAddresses OPTIONAL
/// }
/// ```
#[derive(Sequence, Default, PartialEq, Clone)]
pub struct KrbCredInfo {
    pub key: Tag<0, EncryptionKey>,
    pub prealm: Option<Tag<1, Realm>>,
    pub pname: Option<Tag<2, PrincipalName>>,
    pub flags: Option<Tag<3, TicketFlags>>,
    pub authtime: Option<Tag<4, KerberosTime>>,
    pub starttime: Option<Tag<5, KerberosTime>>,
    pub endtime: Option<Tag<6, KerberosTime>>,
    pub renew_till: Option<Tag<7, KerberosTime>>,
    pub srealm: Option<Tag<8, Realm>>,
    pub sname: Option<Tag<9, PrincipalName>>,
    pub caddr: Option<Tag<10, HostAddresses>>
}

impl KrbCredInfo {
    /// constructor
    fn new(name: PrincipalName, dec: EncKDCRepPart) -> Self {
        Self {
            key: Tag::new(dec.key.inner.clone()),
            prealm: Some(Tag::new(dec.srealm.inner.clone())),
            pname: Some(Tag::new(name)),
            flags: None,
            authtime: Some(Tag::new(dec.authtime.inner)),
            starttime: if let Some(e) = dec.starttime {
                Some(Tag::new(e.inner))
            } else {
                None
            },
            endtime: Some(Tag::new(dec.endtime.inner.clone())),
            renew_till: if let Some(e) = dec.renew_till {
                Some(Tag::new(e.inner))
            } else {
                None
            },
            srealm: Some(Tag::new(dec.srealm.inner.clone())),
            sname: Some(Tag::new(dec.sname.inner.clone())),
            caddr: None
        }
    }
}

/// @see https://www.freesoft.org/CIE/RFC/1510/66.htm
/// ```asn.1
/// EncKrbCredPart   ::= [APPLICATION 29]   SEQUENCE {
///     ticket-info[0]         SEQUENCE OF KrbCredInfo,
///     nonce[1]               INTEGER OPTIONAL,
///     timestamp[2]           KerberosTime OPTIONAL,
///     usec[3]                INTEGER OPTIONAL,
///     s-address[4]           HostAddress OPTIONAL,
///     r-address[5]           HostAddress OPTIONAL
/// }
/// ```
#[derive(Sequence, Default, PartialEq, Clone)]
pub struct EncKrbCredPartBody {
    pub ticket_info: Tag<0, SequenceOf<KrbCredInfo>>,
    pub nonce: Option<Tag<1, Integer>>,
    pub timestamp: Option<Tag<2, KerberosTime>>,
    pub usec: Option<Tag<3, Integer>>,
    pub s_address: Option<Tag<4, HostAddress>>,
    pub r_address: Option<Tag<5, HostAddress>>
}

pub type EncKrbCredPart = Application<29, EncKrbCredPartBody>;

///
/// ```asn.1
/// KRB-CRED         ::= [APPLICATION 22]   SEQUENCE {
///     pvno[0]                INTEGER,
///     msg-type[1]            INTEGER, -- KRB_CRED
///     tickets[2]             SEQUENCE OF Ticket,
///     enc-part[3]            EncryptedData
/// }
/// ```
#[derive(Sequence, Default, PartialEq, Clone)]
pub struct KrbCredBody {
    pub pvno: Tag<0, Integer>,
    pub msg_ticket: Tag<1, Integer>,
    pub tickets: Tag<2, SequenceOf<Ticket>>,
    pub enc_part: Tag<3, EncryptedData>
}

pub type KrbCred = Application<22, KrbCredBody>;

impl KrbCred {
    ///  constructor
    pub fn new(name: PrincipalName, ticket: Ticket, enc_part: EncKDCRepPart) -> KerlabResult<Self> {
        // create a null encryption key to store sensible data !
        let key = EncryptionKey::new_no_encryption();
        Ok(Self {
            inner: KrbCredBody {
                pvno: Tag::new(5 as Integer),
                msg_ticket: Tag::new(MessageType::KrbCred as Integer),
                tickets: Tag::new(vec![
                    ticket
                ]),
                enc_part: Tag::new(
                    key.encrypt(
                        KeyUsage::KeyUsageAsRepEncPart,
                        &EncKrbCredPart {
                            inner: EncKrbCredPartBody {
                                ticket_info: Tag::new(vec![
                                    KrbCredInfo::new(name, enc_part)
                                ]),
                                nonce: None,
                                timestamp: None,
                                usec: None,
                                s_address: None,
                                r_address: None
                            }
                        }
                    )?
                )
            },
        })
    }
}