use krbkdcrep::{KdcRep, EncKDCRepPart};
use asn1::{Tag, Application, SequenceOf, Integer, OctetString, GeneralString, GeneralizedTime, from_der};
use padata::PaData;
use base::{PrincipalName, KDCOptions, HostAddress, LastReqBody, AuthorizationDataElement, AuthorizationData};
use ticket::{TicketBody, EncTicketPartBody, TransitedEncoding};
use encryption::{EncryptedData, EncryptionKey};
use krberror::KrbErrorBody;
use krbkdcreq::{KdcReq, KdcReqBody};
use krbcred::{KrbCredBody, EncKrbCredPartBody, KrbCredInfo};
use pac::{PacType, PacStruct, PacClientInfo, PacSignatureData, UpnDnsInfo, KerbValidationInfo};
use ndr::{FileTime, RpcUnicodeString};

pub struct Formatter {
    indent: u32,
    is_indent: bool,
}

impl Formatter {
    pub fn new() -> Self {
        Self {
            indent: 0,
            is_indent: true,
        }
    }


    fn print_indent(&self) {
        for _ in 0..self.indent {
            print!("\t");
        }
    }

    pub fn println(&mut self, object: &str) {
        if self.is_indent {
            self.print_indent();
        }
        println!("{}", object);
        self.is_indent = true;
    }

    pub fn print(&mut self, object: &str) {
        if self.is_indent {
            self.print_indent();
        }
        print!("{}", object);
        self.is_indent = false;
    }

    pub fn new_line(&mut self) {
        print!("\n");
        self.is_indent = true;
    }

    pub fn indent(&mut self) {
        self.indent += 1;
    }

    pub fn dedent(&mut self) {
        self.is_indent = true;
        self.indent -= 1;
    }
}

pub trait Display {
    fn format(&self, f: &mut Formatter);
}

impl<const N: u64, T: PartialEq + Display + Clone> Display for Tag<{ N }, T> {
    fn format(&self, f: &mut Formatter) {
        f.print(format!("[{}] : ", { N }).as_str());
        self.inner.format(f);
    }
}

impl<const N: u64, T: PartialEq + Display + Default + Clone> Display for Application<{ N }, T> {
    fn format(&self, f: &mut Formatter) {
        f.print(format!("[APPLICATION {}] ", { N }).as_str());
        self.inner.format(f);
        f.new_line();
    }
}

impl Display for KdcRep {
    fn format(&self, f: &mut Formatter) {
        f.print("KDC-REP");
        f.indent();
        f.new_line();
        f.print("pvno       ");
        self.pvno.format(f);
        f.new_line();
        f.print("msg_type   ");
        self.msg_type.format(f);
        f.new_line();
        f.print("padata     ");
        self.padata.format(f);
        f.new_line();
        f.print("crealm     ");
        self.crealm.format(f);
        f.new_line();
        f.print("cname      ");
        self.cname.format(f);
        f.new_line();
        f.print("ticket     ");
        self.ticket.format(f);
        f.new_line();
        f.print("enc-part   ");
        self.enc_part.format(f);
        f.dedent();
    }
}

impl Display for Integer {
    fn format(&self, f: &mut Formatter) {
        f.print(format!("{}", self).as_str())
    }
}

impl<T: Display> Display for SequenceOf<T> {
    fn format(&self, f: &mut Formatter) {
        f.print("SEQUENCE OF");
        f.indent();
        for element in self.iter() {
            f.new_line();
            element.format(f);
        }
        f.dedent();
    }
}

impl<T: Display> Display for Option<T> {
    fn format(&self, f: &mut Formatter) {
        match self {
            Some(e) => e.format(f),
            None => f.print("None")
        }
    }
}

impl Display for PaData {
    fn format(&self, f: &mut Formatter) {
        f.print("PA-DATA");
        f.indent();
        f.new_line();
        f.print("padata-type    ");
        self.padata_type.format(f);
        f.new_line();
        f.print("padata-value   ");
        self.padata_value.format(f);
        f.dedent();
    }
}

impl Display for GeneralString {
    fn format(&self, f: &mut Formatter) {
        f.print(format!("\"{}\"", self.as_str()).as_str());
    }
}

impl Display for PrincipalName {
    fn format(&self, f: &mut Formatter) {
        f.print("PrincipalName");
        f.indent();
        f.new_line();
        f.print("name_type    ");
        self.name_type.format(f);
        f.print(
            match self.name_type.inner {
                0 => " (NtUnknown)",
                1 => " (NtPrincipal)",
                2 => " (NtSrvInst)",
                3 => " (NtSrvHst)",
                4 => " (NtSrvXhst)",
                5 => " (NtUid)",
                6 => " (NtX500Principal)",
                7 => " (NtSmtpName)",
                10 => " (NtEnterprise)",
                _ => " (UNKNOWN)"
            }
        );
        f.new_line();
        f.print("name_string  ");
        self.name_string.format(f);
        f.dedent();
    }
}

impl Display for TicketBody {
    fn format(&self, f: &mut Formatter) {
        f.print("TicketBody");
        f.indent();
        f.new_line();
        f.print("tkt_vno  ");
        self.tkt_vno.format(f);
        f.new_line();
        f.print("realm    ");
        self.realm.format(f);
        f.new_line();
        f.print("sname    ");
        self.sname.format(f);
        f.new_line();
        f.print("enc_part ");
        self.enc_part.format(f);
        f.dedent();
    }
}

impl Display for EncryptedData {
    fn format(&self, f: &mut Formatter) {
        f.print("EncryptedData");
        f.indent();
        f.new_line();
        f.print("etype  ");
        self.etype.format(f);
        f.print(
            match self.etype.inner {
                17 => " (AES-128-CTS-HMAC-SHA-196)",
                18 => " (AES-256-CTS-HMAC-SHA-196)",
                23 => " (RC4-HMAC)",
                _ => " (UNKNOWN)"
            }
        );
        f.new_line();
        f.print("kvno   ");
        self.kvno.format(f);
        f.new_line();
        f.print("cipher ");
        self.cipher.format(f);
        f.dedent();
    }
}

impl Display for OctetString {
    fn format(&self, f: &mut Formatter) {
        f.print(base64::encode(self).as_str());
    }
}

impl Display for KrbErrorBody {
    fn format(&self, f: &mut Formatter) {
        f.print("KrbErrorBody");
        f.indent();
        f.new_line();
        f.print("pvno         ");
        self.pvno.format(f);
        f.new_line();
        f.print("msg-type     ");
        self.msg_type.format(f);
        f.new_line();
        f.print("ctime        ");
        self.ctime.format(f);
        f.new_line();
        f.print("cusec        ");
        self.cusec.format(f);
        f.new_line();
        f.print("stime        ");
        self.stime.format(f);
        f.new_line();
        f.print("susec        ");
        self.susec.format(f);
        f.new_line();
        f.print("error_code   ");
        self.error_code.format(f);
        f.print(
            match self.error_code.inner {
                0 => " (KDC_ERR_NONE: No error)",
                1 => " (KDC_ERR_NAME_EXP: Client's entry in database has expired)",
                2 => " (KDC_ERR_SERVICE_EXP: Server's entry in database has expired)",
                3 => " (KDC_ERR_BAD_PVNO: Requested protocol version number not supported)",
                4 => " (KDC_ERR_C_OLD_MAST_KVNO: Client's key encrypted in old master key)",
                5 => " (KDC_ERR_S_OLD_MAST_KVNO: Server's key encrypted in old master key)",
                6 => " (KDC_ERR_C_PRINCIPAL_UNKNOWN: Client not found in Kerberos database)",
                7 => " (KDC_ERR_S_PRINCIPAL_UNKNOWN: Server not found in Kerberos database)",
                8 => " (KDC_ERR_PRINCIPAL_NOT_UNIQUE: Multiple principal entries in database)",
                9 => " (KDC_ERR_NULL_KEY: The client or server has a null key)",
                10 => " (KDC_ERR_CANNOT_POSTDATE: Ticket not eligible for postdating)",
                11 => " (KDC_ERR_NEVER_VALID: Requested start time is later than end time)",
                12 => " (KDC_ERR_POLICY: KDC policy rejects request)",
                13 => " (KDC_ERR_BADOPTION: KDC cannot accommodate requested option)",
                14 => " (KDC_ERR_ETYPE_NOSUPP: KDC has no support for encryption type)",
                15 => " (KDC_ERR_SUMTYPE_NOSUPP: KDC has no support for checksum type)",
                16 => " (KDC_ERR_PADATA_TYPE_NOSUPP: KDC has no support for padata type)",
                17 => " (KDC_ERR_TRTYPE_NOSUPP: KDC has no support for transited type)",
                18 => " (KDC_ERR_CLIENT_REVOKED: Clients credentials have been revoked)",
                19 => " (KDC_ERR_SERVICE_REVOKED: Credentials for server have been revoked)",
                20 => " (KDC_ERR_TGT_REVOKED: TGT has been revoked)",
                21 => " (KDC_ERR_CLIENT_NOTYET: Client not yet valid - try again later)",
                22 => " (KDC_ERR_SERVICE_NOTYET: Server not yet valid - try again later)",
                23 => " (KDC_ERR_KEY_EXPIRED: Password has expired - change password to reset)",
                24 => " (KDC_ERR_PREAUTH_FAILED: Pre-authentication information was invalid)",
                25 => " (KDC_ERR_PREAUTH_REQUIRED: Additional pre-authentication required)",
                31 => " (KRB_AP_ERR_BAD_INTEGRITY: Integrity check on decrypted field failed)",
                32 => " (KRB_AP_ERR_TKT_EXPIRED: Ticket expired)",
                33 => " (KRB_AP_ERR_TKT_NYV: Ticket not yet valid)",
                34 => " (KRB_AP_ERR_REPEAT: Request is a replay)",
                35 => " (KRB_AP_ERR_NOT_US: The ticket isn't for us)",
                36 => " (KRB_AP_ERR_BADMATCH: Ticket and authenticator don't match)",
                37 => " (KRB_AP_ERR_SKEW: Clock skew too great)",
                38 => " (KRB_AP_ERR_BADADDR: Incorrect net address)",
                39 => " (KRB_AP_ERR_BADVERSION: Protocol version mismatch)",
                40 => " (KRB_AP_ERR_MSG_TYPE: Invalid msg type)",
                41 => " (KRB_AP_ERR_MODIFIED: Message stream modified)",
                42 => " (KRB_AP_ERR_BADORDER: Message out of order)",
                44 => " (KRB_AP_ERR_BADKEYVER: Specified version of key is not available)",
                45 => " (KRB_AP_ERR_NOKEY: Service key not available)",
                46 => " (KRB_AP_ERR_MUT_FAIL: Mutual authentication failed)",
                47 => " (KRB_AP_ERR_BADDIRECTION: Incorrect message direction)",
                48 => " (KRB_AP_ERR_METHOD: Alternative authentication method required)",
                49 => " (KRB_AP_ERR_BADSEQ:  Incorrect sequence number in message)",
                50 => " (KRB_AP_ERR_INAPP_CKSUM: Inappropriate type of checksum in message)",
                60 => " (KRB_ERR_GENERIC: Generic error (description in e-text))",
                61 => " (KRB_ERR_FIELD_TOOLONG: Field is too long for this implementation)",
                _ => " (Unknown)"
            }
        );
        f.new_line();
        f.print("crealm       ");
        self.crealm.format(f);
        f.new_line();
        f.print("realm        ");
        self.realm.format(f);
        f.new_line();
        f.print("sname        ");
        self.sname.format(f);
        f.new_line();
        f.print("e_text       ");
        self.e_text.format(f);
        f.new_line();
        f.print("e_data       ");
        self.e_data.format(f);
        f.dedent();
    }
}

impl Display for GeneralizedTime {
    fn format(&self, f: &mut Formatter) {
        f.print(self.inner.to_rfc2822().as_str());
    }
}

impl Display for KdcReq {
    fn format(&self, f: &mut Formatter) {
        f.print("KdcReq");
        f.indent();
        f.new_line();
        f.print("pvno     ");
        self.pvno.format(f);
        f.new_line();
        f.print("msg_type ");
        self.msg_type.format(f);
        f.new_line();
        f.print("padata   ");
        self.padata.format(f);
        f.new_line();
        f.print("req_body ");
        self.req_body.format(f);
        f.dedent();
    }
}

impl Display for KdcReqBody {
    fn format(&self, f: &mut Formatter) {
        f.print("KdcReqBody");
        f.indent();
        f.new_line();
        f.print("kdc_options  ");
        self.kdc_options.format(f);
        f.new_line();
        f.print("cname        ");
        self.cname.format(f);
        f.new_line();
        f.print("realm        ");
        self.realm.format(f);
        f.new_line();
        f.print("sname        ");
        self.sname.format(f);
        f.new_line();
        f.print("from         ");
        self.from.format(f);
        f.new_line();
        f.print("till         ");
        self.till.format(f);
        f.new_line();
        f.print("rtime        ");
        self.rtime.format(f);
        f.new_line();
        f.print("nonce        ");
        self.nonce.format(f);
        f.new_line();
        f.print("etype        ");
        self.etype.format(f);
        f.new_line();
        f.print("addresses    ");
        self.addresses.format(f);
        f.new_line();
        f.print("enc_authorization_data ");
        self.enc_authorization_data.format(f);
        f.new_line();
        f.print("additional_tickets ");
        self.additional_tickets.format(f);
        f.dedent();
    }
}

impl Display for KDCOptions {
    fn format(&self, _: &mut Formatter) {}
}

impl Display for HostAddress {
    fn format(&self, f: &mut Formatter) {
        f.print("HostAddress");
        f.indent();
        f.new_line();
        f.print("addr_type    ");
        self.addr_type.format(f);
        f.new_line();
        f.print("address      ");
        self.address.format(f);
        f.dedent();
    }
}

impl Display for EncKDCRepPart {
    fn format(&self, f: &mut Formatter) {
        f.print("EncKDCRepPart");
        f.indent();
        f.new_line();
        f.print("key          ");
        self.key.format(f);
        f.new_line();
        f.print("last_req     ");
        self.last_req.format(f);
        f.new_line();
        f.print("nonce        ");
        self.nonce.format(f);
        f.new_line();
        f.print("key_expiration");
        self.key_expiration.format(f);
        f.new_line();
        f.print("authtime     ");
        self.authtime.format(f);
        f.new_line();
        f.print("starttime    ");
        self.starttime.format(f);
        f.new_line();
        f.print("endtime      ");
        self.endtime.format(f);
        f.new_line();
        f.print("renew_till   ");
        self.renew_till.format(f);
        f.new_line();
        f.print("srealm       ");
        self.srealm.format(f);
        f.new_line();
        f.print("sname        ");
        self.sname.format(f);
        f.new_line();
        f.print("caddr        ");
        self.caddr.format(f);
        f.dedent();
    }
}

impl Display for EncryptionKey {
    fn format(&self, f: &mut Formatter) {
        f.print("EncKDCRepPart");
        f.indent();
        f.new_line();
        f.print("keytype  ");
        self.keytype.format(f);
        f.new_line();
        f.print("keyvalue ");
        self.keyvalue.format(f);
        f.dedent();
    }
}

impl Display for LastReqBody {
    fn format(&self, f: &mut Formatter) {
        f.print("LastReqBody");
        f.indent();
        f.new_line();
        f.print("lr_type  ");
        self.lr_type.format(f);
        f.new_line();
        f.print("lr_value ");
        self.lr_type.format(f);
        f.dedent();
    }
}

impl Display for EncTicketPartBody {
    fn format(&self, f: &mut Formatter) {
        f.print("EncTicketPartBody");
        f.indent();
        f.new_line();
        f.print("flags        ");
        self.flags.format(f);
        f.new_line();
        f.print("key        ");
        self.key.format(f);
        f.new_line();
        f.print("crealm       ");
        self.crealm.format(f);
        f.new_line();
        f.print("cname        ");
        self.cname.format(f);
        f.new_line();
        f.print("transited    ");
        self.transited.format(f);
        f.new_line();
        f.print("authtime     ");
        self.authtime.format(f);
        f.new_line();
        f.print("starttime    ");
        self.starttime.format(f);
        f.new_line();
        f.print("endtime      ");
        self.endtime.format(f);
        f.new_line();
        f.print("renew_till   ");
        self.renew_till.format(f);
        f.new_line();
        f.print("caddr        ");
        self.caddr.format(f);
        f.new_line();
        f.print("authorization_data ");
        self.authorization_data.format(f);
        f.dedent();
    }
}

impl Display for TransitedEncoding {
    fn format(&self, f: &mut Formatter) {
        f.print("TransitedEncoding");
        f.indent();
        f.new_line();
        f.print("tr_type  ");
        self.tr_type.format(f);
        f.new_line();
        f.print("contents ");
        self.contents.format(f);
        f.dedent();
    }
}

impl Display for AuthorizationDataElement {
    fn format(&self, f: &mut Formatter) {
        f.print("AuthorizationDataElement");
        f.indent();
        f.new_line();
        f.print("ad_type  ");
        self.ad_type.format(f);
        f.print(
            match self.ad_type.inner {
                1 => " (AD-IF-RELEVANT)",
                2 => " (AD-INTENDED-FOR-SERVER)",
                3 => " (AD-INTENDED-FOR-APPLICATION-CLASS)",
                4 => " (AD-KDC-ISSUED)",
                5 => " (AD-AND-OR)",
                6 => " (AD-MANDATORY-TICKET-EXTENSIONS)",
                7 => " (AD-IN-TICKET-EXTENSIONS)",
                8 => " (AD-MANDATORY-FOR-KDC)",
                64 => " (OSF-DCE)",
                65 => " (SESAME)",
                66 => " (AD-OSF-DCE-PKI-CERTID)",
                128 => " (AD-WIN2K-PAC)",
                129 => " (AD-ETYPE-NEGOTIATION)",
                _ => " (UNKNOWN)"
            }
        );
        f.new_line();
        f.print("ad_data  ");
        match self.ad_type.inner {
            1 => {
                let mut data = AuthorizationData::default();
                from_der(&mut data, &self.ad_data).unwrap();
                data.format(f);
            }
            128 => {
                let pac_data = PacType::from_addata(self.ad_data.inner.clone()).unwrap();
                pac_data.format(f);
            }
            _ => self.ad_data.format(f)
        }

        f.dedent();
    }
}

impl Display for KrbCredBody {
    fn format(&self, f: &mut Formatter) {
        f.print("KrbCredBody");
        f.indent();
        f.new_line();
        f.print("pvno         ");
        self.pvno.format(f);
        f.new_line();
        f.print("msg_ticket   ");
        self.msg_ticket.format(f);
        f.new_line();
        f.print("tickets      ");
        self.tickets.format(f);
        f.new_line();
        f.print("enc_part     ");
        self.enc_part.format(f);
        f.dedent();
    }
}

impl Display for EncKrbCredPartBody {
    fn format(&self, f: &mut Formatter) {
        f.print("EncKrbCredPartBody");
        f.indent();
        f.new_line();
        f.print("ticket_info  ");
        self.ticket_info.format(f);
        f.new_line();
        f.print("nonce        ");
        self.nonce.format(f);
        f.new_line();
        f.print("timestamp    ");
        self.timestamp.format(f);
        f.new_line();
        f.print("usec         ");
        self.usec.format(f);
        f.new_line();
        f.print("s_address    ");
        self.s_address.format(f);
        f.new_line();
        f.print("r_address    ");
        self.r_address.format(f);
        f.dedent();
    }
}

impl Display for KrbCredInfo {
    fn format(&self, f: &mut Formatter) {
        f.print("KrbCredInfo");
        f.indent();
        f.new_line();
        f.print("key          ");
        self.key.format(f);
        f.new_line();
        f.print("prealm       ");
        self.prealm.format(f);
        f.new_line();
        f.print("pname        ");
        self.pname.format(f);
        f.new_line();
        f.print("flags        ");
        self.flags.format(f);
        f.new_line();
        f.print("authtime     ");
        self.authtime.format(f);
        f.new_line();
        f.print("starttime    ");
        self.starttime.format(f);
        f.new_line();
        f.print("endtime      ");
        self.endtime.format(f);
        f.new_line();
        f.print("renew_till   ");
        self.renew_till.format(f);
        f.new_line();
        f.print("srealm       ");
        self.srealm.format(f);
        f.new_line();
        f.print("sname        ");
        self.sname.format(f);
        f.new_line();
        f.print("caddr        ");
        self.caddr.format(f);
        f.dedent();
    }
}

impl Display for PacType {
    fn format(&self, f: &mut Formatter) {
        f.print("PACTYPE");
        f.indent();
        f.new_line();
        f.print("c_buffers  ");
        self.c_buffers.format(f);
        f.new_line();
        f.print("version    ");
        self.version.format(f);
        f.indent();
        for pac in &self.buffers {
            f.new_line();
            pac.format(f);
        }
        f.dedent();
        f.dedent();
    }
}

impl Display for PacStruct {
    fn format(&self, f: &mut Formatter) {
        match self {
            PacStruct::PacClientInfo(e) => {
                e.format(f)
            },
            PacStruct::KDCChecksum(e) => {
                f.print("KDCChecksum    ");
                e.format(f)
            },
            PacStruct::UpnDnsInfo(e) => {
                e.format(f)
            },
            PacStruct::ServerChecksum(e) => {
                f.print("ServerChecksum    ");
                e.format(f)
            },
            PacStruct::KerbValidationInfo(e) => {
                e.format(f)
            }
        }
    }
}

impl Display for PacClientInfo {
    fn format(&self, f: &mut Formatter) {
        f.print("PAC_CLIENT_INFO");
        f.indent();
        f.new_line();
        f.print("ClientId  ");
        self.client_id.format(f);
        f.new_line();
        f.print(&format!("Name  {}", self.name));
        f.dedent()
    }
}

impl Display for PacSignatureData {
    fn format(&self, f: &mut Formatter) {
        f.print("PAC_SIGNATURE_DATA");
        f.indent();
        f.new_line();
        f.print(&format!("signature_type  {}", self.signature_type));
        f.new_line();
        f.print(&format!("signature       {}", base64::encode(&self.signature).as_str()));
        f.dedent()
    }
}

impl Display for UpnDnsInfo {
    fn format(&self, f: &mut Formatter) {
        f.print("UPN_DNS_INFO");
        f.indent();
        f.new_line();
        f.print(&format!("upn  {}", self.upn));
        f.new_line();
        f.print(&format!("dns  {}", self.dns));
        f.dedent()
    }
}

impl Display for KerbValidationInfo {
    fn format(&self, f: &mut Formatter) {
        f.print("KER_VALIDATION_INFO");
        f.indent();
        f.new_line();
        f.print("LogonTime          ");
        self.logon_time.format(f);
        f.new_line();
        f.print("LogoffTime         ");
        self.logoff_time.format(f);
        f.new_line();
        f.print("KickOffTime        ");
        self.kick_off_time.format(f);
        f.new_line();
        f.print("PasswordLastSet    ");
        self.password_last_set.format(f);
        f.new_line();
        f.print("PasswordCanChange  ");
        self.password_can_change.format(f);
        f.new_line();
        f.print("PasswordMustChange ");
        self.password_must_change.format(f);
        f.new_line();
        f.print("EffectiveName ");
        self.effective_name.format(f);
        f.new_line();
        f.print("FullName ");
        //self.full_name.format(f);
        f.dedent()
    }
}

impl Display for FileTime {
    fn format(&self, f: &mut Formatter) {
        f.print("FILETIME");
        f.indent();
        f.new_line();
        f.print(&format!("dwLowDateTime {:#X}", self.dw_low_date_time));
        f.new_line();
        f.print(&format!("dwHighDateTime {:#X}", self.dw_high_date_time));
        f.new_line();
        f.print(&format!("{}", self.datetime()));
        f.dedent()
    }
}

impl Display for RpcUnicodeString {
    fn format(&self, f: &mut Formatter) {
        f.print(&format!("RPC_UNICODE_STRING {}", self.buffer))
    }
}