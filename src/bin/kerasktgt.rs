extern crate kerlab;
extern crate clap;

use kerlab::krbkdcreq::{AsReq, KdcOptionsType};
use kerlab::asn1::to_der;
use std::io::{Write};
use kerlab::display::{Display, Formatter};
use kerlab::request::{KrbResponse, TcpRequest};
use kerlab::krbkdcrep::{AsRep, EncASRepPart};
use clap::{App, Arg};
use kerlab::encryption::{KeyUsage, EncryptionKey};
use std::fs::File;
use kerlab::krbcred::KrbCred;

const APPLICATION_NAME: &str = "kerasktgt";


fn main() {

    let matches = App::new(APPLICATION_NAME)
        .version("0.1.0")
        .author("Sylvain Peyrefitte <citronneur@gmail.com>")
        .about("Kerberos Lab for Fun and Detection")
        .arg(Arg::with_name("dc")
                 .long("dc")
                 .takes_value(true)
                 .help("host IP of the Domain Controller"))
        .arg(Arg::with_name("port")
                 .long("port")
                 .takes_value(true)
                 .default_value("88")
                 .help("Domain Controller Kerberos port"))
        .arg(Arg::with_name("domain")
                 .long("domain")
                 .takes_value(true)
                 .help("Windows Domain"))
        .arg(Arg::with_name("username")
                 .long("username")
                 .takes_value(true)
                 .help("Username of TGT"))
        .arg(Arg::with_name("password")
                 .long("password")
                 .takes_value(true)
                 .help("Username password"))
        .arg(Arg::with_name("ntlm")
                 .long("ntlm")
                 .takes_value(true)
                 .help("NTLM hash for RC4 encryption"))
        .arg(Arg::with_name("outfile")
                 .long("outfile")
                 .takes_value(true)
                 .help("Output file path"))
        .arg(Arg::with_name("forwardable")
                 .long("forwardable")
                 .help("Ask for a forwardable ticket"))
        .arg(Arg::with_name("renewable")
                 .long("renewable")
                 .help("Ask for a renewable ticket"))
        .get_matches();

    let ip = matches.value_of("dc").expect("You need to provide a dc argument");
    let port = matches.value_of("port").unwrap_or_default();

    // compute options
    let mut options = vec![];
    if matches.is_present("renewable") {
        options.push(KdcOptionsType::Renewable);
        options.push(KdcOptionsType::RenewableOk);
    }

    if matches.is_present("forwardable") {
        options.push(KdcOptionsType::Forwardable);
    }

    // create request
    let mut tgt_request = AsReq::new(
        matches.value_of("domain").unwrap(),
        matches.value_of("username").unwrap(),
        &options,
    ).unwrap();

    if let Some(password) = matches.value_of("password") {
        tgt_request = tgt_request.with_preauth(
            &EncryptionKey::new_rc4_hmac(password).unwrap()
        ).unwrap()
    }

    if let Some(ntlm) = matches.value_of("ntlm") {
        tgt_request = tgt_request.with_preauth(
            &EncryptionKey::new_rc4_hmac_from_hash(hex::decode(ntlm).unwrap()).unwrap()
        ).unwrap()
    }

    println!("**************************************************");
    println!("AS-REQ ::=");
    tgt_request.format(&mut Formatter::new());

    let tgt_response = TcpRequest::ask_for::<AsRep, String>(&tgt_request, format!("{}:{}", ip, port)).unwrap();

    match tgt_response {
        KrbResponse::Error(error) => {
            println!("**************************************************");
            println!("KRB-ERROR ::=");
            error.format(&mut Formatter::new());
        }
        KrbResponse::Response(response) => {
            println!("**************************************************");
            println!("AS-REP ::=");
            response.format(&mut Formatter::new());

            let mut key : Option<EncryptionKey> = None;
            if let Some(password) = matches.value_of("password") {
                key = Some(EncryptionKey::new_rc4_hmac(password).unwrap());
            }
            if let Some(ntlm) = matches.value_of("ntlm") {
                key = Some(EncryptionKey::new_rc4_hmac_from_hash(hex::decode(ntlm).unwrap()).unwrap());
            }

            if let Some(key) = key {
                println!("**************************************************");
                println!("Decrypting the KDC-REP.enc-part with the user password");
                let enc_part = key.decrypt::<EncASRepPart>(
                        KeyUsage::KeyUsageAsRepEncPart,
                        &response.enc_part
                    ).unwrap();

                enc_part.format(&mut Formatter::new());

                if let Some(path) = matches.value_of("outfile") {
                    let mut file = File::create(path).unwrap();
                    let credentials = KrbCred::new(
                        response.cname.inner.clone(),
                        response.ticket.inner.clone(),
                        enc_part.inner
                    ).unwrap();
                    file.write_all(&to_der(&credentials)).unwrap();

                    println!("**************************************************");
                    println!("Saving KRB-CRED in {}", path);
                }
            }
        }
    }
    println!("**************************************************");
}