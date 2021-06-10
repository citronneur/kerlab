extern crate clap;
extern crate kerlab;

use clap::{App, Arg};
use std::fs;
use kerlab::krbcred::{KrbCred, EncKrbCredPart};
use kerlab::asn1::{from_ber};
use kerlab::display::{Formatter, Display};
use kerlab::encryption::{EncryptionKey, KeyUsage};
use kerlab::ticket::EncTicketPart;
use std::fs::File;
use std::io::{Write};

const APPLICATION_NAME: &str = "kerticket";

fn main() {
    let matches = App::new(APPLICATION_NAME)
        .version("0.1.0")
        .author("Sylvain Peyrefitte <citronneur@gmail.com>")
        .about("Kerberos Lab for Fun and Detection")
        .arg(Arg::with_name("ticket")
            .long("ticket")
            .takes_value(true)
            .help("Path to the ticket file"))
        .arg(Arg::with_name("ntlm")
            .long("ntlm")
            .takes_value(true)
            .help("NTLM hash for RC4 encryption de decrypt ticket"))
        .arg(Arg::with_name("password")
            .long("password")
            .takes_value(true)
            .help("Password for RC4 encryption de decrypt ticket"))
        .arg(Arg::with_name("hashcat")
            .long("hashcat")
            .takes_value(true)
            .help("output file for hash cat brute forcing"))
        .get_matches();

    // load ticket info from tgt
    let contents = fs::read(
        matches.value_of("ticket")
            .expect("ticket argument is mandatory")
    ).unwrap();

    let mut ticket = KrbCred::default();
    from_ber(&mut ticket, &contents).unwrap();

    println!("*******************************************");
    println!("KRB-CRED := ");
    ticket.format(&mut Formatter::new());

    println!("*******************************************");
    println!("Decrypting KRB-CRED.enc_part");
    println!("EncKrbCredPart := ");
    let mut body = EncryptionKey::new_no_encryption()
        .decrypt::<EncKrbCredPart>(
            KeyUsage::KeyUsageAsRepEncPart,
            &ticket.enc_part,
        ).unwrap();
    body.format(&mut Formatter::new());


    let mut key: Option<EncryptionKey> = None;
    if let Some(password) = matches.value_of("password") {
        key = Some(EncryptionKey::new_rc4_hmac(password).unwrap());
    }
    if let Some(ntlm) = matches.value_of("ntlm") {
        key = Some(EncryptionKey::new_rc4_hmac_from_hash(hex::decode(ntlm).unwrap()).unwrap());
    }
    let tgs_info = body.ticket_info.pop().unwrap();
    let tgs = ticket.tickets.pop().unwrap();

    if let Some(key) = key {
        println!("**************************************************");
        println!("Trying to decrypt the first ticket.enc-part");
        println!("EncTicketPart := ");
        let ticket_enc_part = key.decrypt::<EncTicketPart>(
                KeyUsage::KeyUsageAsRepTicket,
                &tgs.enc_part,
            ).unwrap();
        ticket_enc_part.format(&mut Formatter::new());


    }

    println!("**************************************************");

    if let Some(hashcat) = matches.value_of("hashcat") {
        let mut file = File::create(hashcat).unwrap();
        file.write_all(format!("$krb5tgs${0}$*{1}${2}${3}*${4}${5}",
                tgs.enc_part.etype.inner,
                tgs_info.pname.unwrap().name_string[0],
                tgs_info.srealm.unwrap().as_str(),
                tgs_info.sname.unwrap().name_string.iter().map(|x| String::from(x.as_str())).collect::<Vec<String>>().join("/"),
                hex::encode(&tgs.enc_part.cipher.inner[0..16]),
                hex::encode(&tgs.enc_part.cipher.inner[16..]
            )
        ).as_bytes()).unwrap();
    }
}