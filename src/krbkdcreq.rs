/// This file is linked to https://www.freesoft.org/CIE/RFC/1510/55.htm

use base::{PrincipalName, Realm, KerberosTime, HostAddresses, KDCOptions, PrincipalNameType, MessageType};
use yasna::{DERWriter, BERReader};
use asn1::{ASN1, Tag, Integer, SequenceOf, Application, GeneralString};
use error::{KerlabResult};
use encryption::{EncryptedData, EType, EncryptionKey};
use ticket::Ticket;
use chrono::{Utc, Duration, DateTime};
use padata::{PaData, PaDataType};
use rnd::nonce;
use std::str::FromStr;
use krbap::ApReq;


#[repr(u32)]
#[derive(Copy, Clone)]
pub enum KdcOptionsType {
    Validate = 0x00000001,
    Renew = 0x00000002,
    Unused29 = 0x00000004,
    EncTktInsKey = 0x00000008,
    RenewableOk = 0x00000010,
    DisableTransitedCheck = 0x00000020,
    Unused16 = 0x0000FFC0,
    ConstrainedDelegation = 0x00020000,
    Canonocalize = 0x00010000,
    CNameInAddLTkt = 0x00004000,
    OkAsDelegate = 0x00040000,
    Unused12 = 0x00080000,
    OpthardwareAuth = 0x00100000,
    PreAuthent = 0x00200000,
    Initial = 0x00400000,
    Renewable = 0x00800000,
    Unused7 = 0x01000000,
    PostDated = 0x02000000,
    AllowPostDate = 0x04000000,
    Proxy = 0x08000000,
    Proxiable = 0x10000000,
    Forwarded = 0x20000000,
    Forwardable = 0x40000000,
    Reserved = 0x80000000,
}

impl KdcOptionsType {
    fn join(options: &[KdcOptionsType]) -> u32 {
        let mut result = 0;
        for e in options {
            result |= *e as u32;
        }
        result
    }
}

/// @see https://www.freesoft.org/CIE/RFC/1510/55.htm
/// ```asn.1
/// AS-REQ ::=         [APPLICATION 10] KDC-REQ
/// ```
pub type AsReq = Application<10, KdcReq>;

impl AsReq {
    /// constructor
    pub fn new(domain: &str, username: &str, options: &[KdcOptionsType]) -> KerlabResult<AsReq> {
        Ok(AsReq {
            inner: KdcReq {
                pvno: Tag::new(5),
                msg_type: Tag::new(MessageType::KrbAsReq as Integer),
                padata: None,
                req_body: Tag::new(KdcReqBody::new(
                    PrincipalName::new(
                        PrincipalNameType::NtPrincipal,
                        vec![
                            GeneralString::from_str(username)?
                        ],
                    ),
                    domain,
                    PrincipalName::new(
                        PrincipalNameType::NtSrvInst,
                        vec![
                            GeneralString::from_str("krbtgt")?,
                            GeneralString::from_str(domain)?
                        ],
                    ),
                    KdcOptionsType::join(options),
                    Utc::now() + Duration::days(1),
                )?),
            }
        })
    }

    /// Add pre authentication stuff for the request
    /// see padata.rs
    pub fn with_preauth(mut self, key: &EncryptionKey) -> KerlabResult<Self> {
        if let Some(e) = &mut self.inner.padata {
            e.inner.push(PaData::pa_enc_timestamp(key)?);
        } else {
            self.inner.padata = Some(Tag::new(vec![
                PaData::pa_enc_timestamp(key)?
            ]));
        }

        Ok(self)
    }
}

/// ```asn1
/// TGS-REQ ::=        [APPLICATION 12] KDC-REQ
/// ```
pub type TgsReq = Application<12, KdcReq>;

impl TgsReq {
    pub fn new(domain: &str, username: &str, sname: PrincipalName, ap_req: &ApReq, options: &[KdcOptionsType]) -> KerlabResult<TgsReq> {
        Ok(TgsReq {
            inner: KdcReq {
                pvno: Tag::new(5),
                msg_type: Tag::new(MessageType::KrbTgsReq as Integer),
                padata: Some(Tag::new(vec![
                    PaData::new(PaDataType::PaTgsReq, ap_req)
                ])),
                req_body: Tag::new(KdcReqBody::new(
                    PrincipalName::new(
                        PrincipalNameType::NtPrincipal,
                        vec![
                            GeneralString::from_str(username)?
                        ],
                    ),
                    domain,
                    sname,
                    KdcOptionsType::join(options),
                    Utc::now() + Duration::days(1),
                )?),
            }
        })
    }

    pub fn for_user(mut self, user_name: PrincipalName, user_realm: Realm, key: &EncryptionKey) -> KerlabResult<Self> {
        if let Some(e) = &mut self.inner.padata {
            e.inner.push(PaData::pa_for_user(
                user_name,
                user_realm,
                key,
            )?);
        } else {
            self.inner.padata = Some(Tag::new(vec![
                PaData::pa_for_user(
                    user_name,
                    user_realm,
                    key,
                )?
            ]));
        }

        Ok(self)
    }
}

/// ```asn1
/// KDC-REQ ::=        SEQUENCE {
///            pvno[1]               INTEGER,
///            msg-type[2]           INTEGER,
///            padata[3]             SEQUENCE OF PA-DATA OPTIONAL,
///            req-body[4]           KDC-REQ-BODY
/// }
/// ```
#[derive(Sequence, Default, PartialEq, Clone)]
pub struct KdcReq {
    pub pvno: Tag<1, Integer>,
    pub msg_type: Tag<2, Integer>,
    pub padata: Option<Tag<3, SequenceOf<PaData>>>,
    pub req_body: Tag<4, KdcReqBody>,
}

/// ```asn1
/// KDC-REQ-BODY ::=   SEQUENCE {
///             kdc-options[0]       KDCOptions,
///             cname[1]             PrincipalName OPTIONAL,
///                          -- Used only in AS-REQ
///             realm[2]             Realm, -- Server's realm
///                          -- Also client's in AS-REQ
///             sname[3]             PrincipalName OPTIONAL,
///             from[4]              KerberosTime OPTIONAL,
///             till[5]              KerberosTime,
///             rtime[6]             KerberosTime OPTIONAL,
///             nonce[7]             INTEGER,
///             etype[8]             SEQUENCE OF INTEGER, -- EncryptionType,
///                          -- in preference order
///             addresses[9]         HostAddresses OPTIONAL,
///             enc-authorization-data[10]   EncryptedData OPTIONAL,
///                          -- Encrypted AuthorizationData encoding
///             additional-tickets[11]       SEQUENCE OF Ticket OPTIONAL
/// }
/// ```
#[derive(Sequence, PartialEq, Default, Clone)]
pub struct KdcReqBody {
    pub kdc_options: Tag<0, KDCOptions>,
    pub cname: Option<Tag<1, PrincipalName>>,
    pub realm: Tag<2, Realm>,
    pub sname: Option<Tag<3, PrincipalName>>,
    pub from: Option<Tag<4, KerberosTime>>,
    pub till: Tag<5, KerberosTime>,
    pub rtime: Option<Tag<6, KerberosTime>>,
    pub nonce: Tag<7, Integer>,
    pub etype: Tag<8, SequenceOf<Integer>>,
    pub addresses: Option<Tag<9, HostAddresses>>,
    pub enc_authorization_data: Option<Tag<10, EncryptedData>>,
    pub additional_tickets: Option<Tag<11, SequenceOf<Ticket>>>,
}

impl KdcReqBody {
    pub fn new(cname: PrincipalName, domain: &str, sname: PrincipalName, kdc_options: u32, till: DateTime<Utc>) -> KerlabResult<Self> {
        Ok(Self {
            kdc_options: Tag::new(KDCOptions::from_bytes(
                &kdc_options.to_be_bytes()
            )),
            cname: Some(Tag::new(cname)),
            realm: Tag::new(GeneralString::from_str(domain)?),
            sname: Some(Tag::new(sname)),
            from: None,
            till: Tag::new(KerberosTime::new(till)),
            rtime: None,
            nonce: Tag::new(nonce() as Integer),
            etype: Tag::new(vec![
                EType::Rc4Hmac as Integer
            ]),
            addresses: None,
            additional_tickets: None,
            enc_authorization_data: None,
        })
    }
}