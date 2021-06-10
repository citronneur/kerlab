use error::{KerlabResult};
use asn1::{to_der, from_ber, ASN1};
use std::net::{TcpStream, UdpSocket, ToSocketAddrs};
use std::io::{Write, Read, Cursor};
use byteorder::{ReadBytesExt, BigEndian, WriteBytesExt};
use krberror::{KrbError};

pub enum KrbResponse<T> {
    Error(KrbError),
    Response(T)
}

pub struct TcpRequest;

impl TcpRequest{
    /// Kerberos is available over TCP in most of time
    pub fn ask_for<T: ASN1 + Default, S: ToSocketAddrs>(request: &dyn ASN1, to: S) -> KerlabResult<KrbResponse<T>> {

        let mut stream = TcpStream::connect(to).unwrap();
        let request_encoded = to_der(request);

        stream.write_u32::<BigEndian>(request_encoded.len() as u32).unwrap();
        stream.write(&request_encoded)?;

        let response_length = stream.read_u32::<BigEndian>().unwrap();
        let mut reponse_payload = vec![0; response_length as usize];
        stream.read_exact(&mut reponse_payload).unwrap();

        // Check error
        let mut error = KrbError::default();
        if let Ok(()) = from_ber(&mut error, &reponse_payload) {
            Ok(KrbResponse::Error(error))
        } else {
            let mut response = T::default();
            from_ber(&mut response, &reponse_payload)?;
            Ok(KrbResponse::Response(response))
        }
    }
}

pub struct UdpRequest;
impl UdpRequest{
    /// But sometimes UDP is also available
    pub fn ask_for<T: ASN1 + Default, S: ToSocketAddrs>(request: &dyn ASN1, to: S) -> KerlabResult<KrbResponse<T>> {
        let request_encoded = to_der(request);
        let mut stream = Cursor::new(vec![]);
        stream.write_u32::<BigEndian>(request_encoded.len() as u32).unwrap();
        stream.write(&request_encoded)?;

        let udp_socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        udp_socket.connect(to)?;
        let send_size = udp_socket.send(&stream.into_inner()).unwrap();
        println!("send size {}",send_size);

        let mut ret = vec![0; 4096];

        // actually doesn't work
        let size = udp_socket.recv(&mut ret).unwrap();
        ret.resize(size, 0);
        stream = Cursor::new(ret);

        let response_length = stream.read_u32::<BigEndian>().unwrap();
        let mut reponse_payload = vec![0; response_length as usize];
        stream.read_exact(&mut reponse_payload).unwrap();

        // Check error
        let mut error = KrbError::default();
        if let Ok(()) = from_ber(&mut error, &reponse_payload) {
            Ok(KrbResponse::Error(error))
        } else {
            let mut response = T::default();
            from_ber(&mut response, &reponse_payload)?;
            Ok(KrbResponse::Response(response))
        }
    }
}
