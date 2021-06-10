use asn1::{ASN1, Integer, Tag, Application};
use yasna::{DERWriter, BERReader};
use base::{Realm, PrincipalName, KerberosTime, AuthorizationData};
use checksum::Checksum;
use encryption::EncryptionKey;
use error::KerlabResult;
use chrono::Utc;

/// Authenticator use to prove that we can decrypt TGT
///
/// @see https://www.freesoft.org/CIE/RFC/1510/53.htm
///
/// ```asn.1
/// -- Unencrypted authenticator
/// Authenticator ::=    [APPLICATION 2] SEQUENCE    {
///     authenticator-vno[0]          INTEGER,
///     crealm[1]                     Realm,
///     cname[2]                      PrincipalName,
///     cksum[3]                      Checksum OPTIONAL,
///     cusec[4]                      INTEGER,
///     ctime[5]                      KerberosTime,
///     subkey[6]                     EncryptionKey OPTIONAL,
///     seq-number[7]                 INTEGER OPTIONAL,
///     authorization-data[8]         AuthorizationData OPTIONAL
/// }
/// ```
#[derive(Sequence, Default, Clone, PartialEq)]
pub struct AuthenticatorBody {
    pub authenticator_vno: Tag<0, Integer>,
    pub crealm: Tag<1, Realm>,
    pub cname: Tag<2, PrincipalName>,
    pub cksum: Option<Tag<3, Checksum>>,
    pub cusec: Tag<4, Integer>,
    pub ctime: Tag<5, KerberosTime>,
    pub subkey: Option<Tag<6, EncryptionKey>>,
    pub seq_number: Option<Tag<7, Integer>>,
    pub authorization_data: Option<Tag<8, AuthorizationData>>
}

pub type Authenticator = Application<2, AuthenticatorBody>;

impl Authenticator {
    /// Convenient constructor
    pub fn new(crealm: Realm, cname: PrincipalName) -> Self {
        Self {
            inner: AuthenticatorBody {
                authenticator_vno: Tag::new(5),
                crealm: Tag::new(crealm),
                cname: Tag::new(cname),
                cksum: None,
                cusec: Tag::new(0),
                ctime: Tag::new(KerberosTime::new(Utc::now())),
                subkey: None,
                seq_number: None,
                authorization_data: None
            }
        }
    }
}