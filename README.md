# Kerlab
A Rust implementation of Kerberos for FUn and Detection

Kerlab was developped just to drill down *kerberos* protocol and better understand it.
The main pupose is to write more targeted detection rules. 
These rules was presented during the [Toulouse Hacking Conference 2021](https://thcon.party/) that took place on 11 of june.

:warning: Kerlab needs the nightly version of rust because we massively use static parameters for template :warning:

## kerasktgt Kerberos Ask Ticket Granting Ticket

Use to ask the first Ticket in kerberos protocol. If the username is not set, the TGT request is made without pre authentication.
It will write the ticket into KRB_CRED format, compatible with rubeus or mimikatz.

```
kerasktgt 0.1.0
Sylvain Peyrefitte <citronneur@gmail.com>
Kerberos Lab for Fun and Detection

USAGE:
    kerasktgt.exe [FLAGS] [OPTIONS]

FLAGS:
        --forwardable    Ask for a forwardable ticket
    -h, --help           Prints help information
        --renewable      Ask for a renewable ticket
    -V, --version        Prints version information

OPTIONS:
        --dc <dc>                host IP of the Domain Controller
        --domain <domain>        Windows Domain
        --ntlm <ntlm>            NTLM hash for RC4 encryption
        --outfile <outfile>      Output file path
        --password <password>    Username password
        --port <port>            Domain Controller Kerberos port [default: 88]
        --username <username>    Username of TGT
```

## kerasktgs Kerberos Ask Ticket Granting Servive

Use to ask a TGS ticket using a saved TGT. `kerasktgs` support S4U protocol extension, through `s4u` options.

```
kerasktgs 0.1.0
Sylvain Peyrefitte <citronneur@gmail.com>
Kerberos Lab for Fun and Detection

USAGE:
    kerasktgs.exe [FLAGS] [OPTIONS]

FLAGS:
        --forwardable    Ask for a forwardable ticket
        --forwarded      Ask for a forwarded ticket
    -h, --help           Prints help information
        --renewable      Ask for a renewable ticket
    -V, --version        Prints version information

OPTIONS:
        --dc <dc>                  host IP of the Domain Controller
        --outfile <outfile>        Output file path
        --port <port>              Domain Controller Kerberos port [default: 88]
        --s4u <s4u>                Ask for a service ticket in place of this user
        --s4u-realm <s4u-realm>    Ask for a service ticket in place of this user
        --service <service>        Name of the service
        --ticket <ticket>          TGT recorded using kerasktgt
```

## kerforce Kerberos Brute Force

Use to perform an online brute force attack. The file attribute is just a file with a password at each line.

```
kerforce 0.1.0
Sylvain Peyrefitte <citronneur@gmail.com>
Kerberos Lab for Fun and Detection

USAGE:
    kerforce.exe [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
        --safe       Stop when account it's first locked
    -V, --version    Prints version information

OPTIONS:
        --dc <dc>                host IP of the Domain Controller
        --domain <domain>        Windows Domain
        --file <file>            File that contain password file
        --port <port>            Domain Controller Kerberos port [default: 88]
        --username <username>    Username of TGT
```

## kerspray Kerberos Password Spraying

Use to perform a Kerberos Password spraying attack using a list of username.

```
kerspray 0.1.0
Sylvain Peyrefitte <citronneur@gmail.com>
Kerberos Lab for Fun and Detection

USAGE:
    kerspray.exe [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
        --safe       Stop when account it's first locked
    -V, --version    Prints version information

OPTIONS:
        --dc <dc>                host IP of the Domain Controller
        --domain <domain>        Windows Domain
        --file <file>            File that contain username
        --password <password>    Password of TGT
        --port <port>            Domain Controller Kerberos port [default: 88]
```

## kerticket Kerberos Ticket Viewer

Print informations of ticket saved on disk. Use to convert a ticket into hashcat compatible format.

```
kerticket 0.1.0
Sylvain Peyrefitte <citronneur@gmail.com>
Kerberos Lab for Fun and Detection

USAGE:
    kerticket.exe [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --hashcat <hashcat>      output file for hash cat brute forcing
        --ntlm <ntlm>            NTLM hash for RC4 encryption de decrypt ticket
        --password <password>    Password for RC4 encryption de decrypt ticket
        --ticket <ticket>        Path to the ticket file
```
