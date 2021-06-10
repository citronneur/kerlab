use asn1::{ASN1, Integer, Tag, BitString, Application};
use yasna::{DERWriter, BERReader};
use ticket::Ticket;
use encryption::EncryptedData;
use error::KerlabResult;
use base::MessageType;

pub type APOptions = BitString;


/// @see https://www.freesoft.org/CIE/RFC/1510/58.htm
/// ```asn.1
/// AP-REQ ::=      [APPLICATION 14] SEQUENCE {
///     pvno[0]                       INTEGER,
///     msg-type[1]                   INTEGER,
///     ap-options[2]                 APOptions,
///     ticket[3]                     Ticket,
///     authenticator[4]              EncryptedData
/// }
/// ```
#[derive(Sequence, Default, Clone, PartialEq)]
pub struct ApReqBody {
    pub pvno: Tag<0, Integer>,
    pub msg_type: Tag<1, Integer>,
    pub ap_options: Tag<2, APOptions>,
    pub ticket: Tag<3, Ticket>,
    pub authenticator: Tag<4, EncryptedData>
}

pub type ApReq = Application<14, ApReqBody>;

impl ApReq {
    /// constructor
    pub fn new(ticket: Ticket, authenticator: EncryptedData) -> Self {
        Self {
            inner: ApReqBody{
                pvno: Tag::new(5),
                msg_type: Tag::new(MessageType::KrbApReq as Integer),
                ap_options: Tag::new(APOptions::new()),
                ticket: Tag::new(ticket),
                authenticator: Tag::new(authenticator)
            }
        }
    }
}