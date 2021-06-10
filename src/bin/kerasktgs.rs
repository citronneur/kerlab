extern crate kerlab;
extern crate clap;

use std::fs;
use clap::{App, Arg};
use kerlab::krbap::ApReq;
use kerlab::asn1::{from_ber, GeneralString, to_der};
use kerlab::krbcred::{KrbCred, EncKrbCredPart};
use kerlab::encryption::{KeyUsage, EncryptionKey};
use kerlab::authenticator::Authenticator;
use kerlab::base::{PrincipalName, PrincipalNameType};
use kerlab::krbkdcreq::{TgsReq, KdcOptionsType};
use kerlab::request::{TcpRequest, KrbResponse};
use kerlab::krbkdcrep::{TgsRep, EncTGSRepPart};
use kerlab::display::{Formatter, Display};
use std::str::FromStr;
use std::fs::File;
use std::io::{Write};

const APPLICATION_NAME: &str = "kerasktgs";

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
        .arg(Arg::with_name("ticket")
            .long("ticket")
            .takes_value(true)
            .help("TGT recorded using kerasktgt"))
        .arg(Arg::with_name("service")
            .long("service")
            .takes_value(true)
            .help("Name of the service"))
        .arg(Arg::with_name("outfile")
            .long("outfile")
            .takes_value(true)
            .help("Output file path"))
        .arg(Arg::with_name("forwardable")
            .long("forwardable")
            .help("Ask for a forwardable ticket"))
        .arg(Arg::with_name("forwarded")
            .long("forwarded")
            .help("Ask for a forwarded ticket"))
        .arg(Arg::with_name("renewable")
            .long("renewable")
            .help("Ask for a renewable ticket"))
        .arg(Arg::with_name("s4u")
            .long("s4u")
            .takes_value(true)
            .help("Ask for a service ticket in place of this user"))
        .arg(Arg::with_name("s4u-realm")
            .long("s4u-realm")
            .takes_value(true)
            .help("Ask for a service ticket in place of this user"))
        .get_matches();

    let ip = matches.value_of("dc").expect("You need to provide the dc argument");
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

    if matches.is_present("forwarded") {
        options.push(KdcOptionsType::Forwarded);
    }

    // load ticket info from tgt
    let contents = fs::read(
        matches.value_of("ticket")
            .expect("ticket argument is mandatory")
    ).unwrap();

    let mut tgt = KrbCred::default();
    from_ber(&mut tgt, &contents).unwrap();

    // retrieve session key from TGT
    let mut krb_cred = EncryptionKey::new_no_encryption().decrypt::<EncKrbCredPart>(
        KeyUsage::KeyUsageAsRepEncPart,
        &tgt.inner.enc_part.inner,
    ).unwrap();

    let ticket_info = krb_cred.ticket_info.pop()
        .expect("There is no ticket info in the recorded TGT");

    let domain = ticket_info.prealm.expect("Unable to found realm in TGT").inner;
    let principal_name = ticket_info.pname.expect("Unable to found principal name in TGT").inner;
    let authenticator = Authenticator::new(
        domain.clone(),
        principal_name.clone(),
    );

    let encrypted_authenticator = ticket_info.key.encrypt(
        KeyUsage::KrbKeyUsageTgsReqPaAuthenticator,
        &authenticator,
    ).expect("Something go wrong during encryption of authenticator");

    // if s4u i ask a ticket that target me as sname
    let sname = if matches.is_present("s4u") {
        principal_name.clone()
    } else {
        let mut service_name_builder = PrincipalName::new(
            PrincipalNameType::NtSrvInst,
            vec![],
        );
        // compute service name
        let service_path = matches.value_of("service").expect("service arg is mandatory");
        for part in service_path.split("/") {
            service_name_builder.name_string.push(
                GeneralString::from_str(part).unwrap()
            )
        }
        service_name_builder
    };


    // create TGS request
    let mut tgs_request = TgsReq::new(
        domain.as_str(),
        principal_name.name_string.inner
            .get(0).expect("Unable to find username in the ticket").as_str(),
        sname,
        &ApReq::new(
            tgt.inner.tickets.inner.pop().unwrap(),
            encrypted_authenticator,
        ),
        &options,
    ).unwrap();

    if let Some(s4u) = matches.value_of("s4u") {
        tgs_request = tgs_request.for_user(
            PrincipalName::new(
                PrincipalNameType::NtPrincipal,
                vec![
                    GeneralString::from_str(s4u).unwrap()
                ],
            ),
            domain,
            &ticket_info.key.inner,
        ).unwrap();
    }

    println!("**************************************************");
    println!("TGS-REQ ::=");
    tgs_request.format(&mut Formatter::new());

    let tgs_response = TcpRequest::ask_for::<TgsRep, String>(
        &tgs_request,
        format!("{}:{}", ip, port),
    ).unwrap();

    match tgs_response {
        KrbResponse::Error(error) => {
            println!("**************************************************");
            println!("KRB-ERROR ::=");
            error.format(&mut Formatter::new());
        }
        KrbResponse::Response(response) => {
            println!("**************************************************");
            println!("TGS-REP ::=");
            response.format(&mut Formatter::new());

            println!("**************************************************");
            println!("Decrypting the KDC-REP.enc-part with session key");
            let enc_part = ticket_info.key.inner.decrypt::<EncTGSRepPart>(
                KeyUsage::KeyUsageAsRepEncPart,
                &response.inner.enc_part.inner,
            ).unwrap();

            enc_part.format(&mut Formatter::new());

            if let Some(path) = matches.value_of("outfile") {
                let mut file = File::create(path).unwrap();
                let credentials = KrbCred::new(
                    response.inner.cname.inner.clone(),
                    response.inner.ticket.inner.clone(),
                    enc_part.inner,
                ).unwrap();
                file.write_all(&to_der(&credentials)).unwrap();
                println!("Saving KRB-CRED in {}", path);
            }
        }
    }
    println!("**************************************************");
}