use error::{KerlabResult, Error, KerlabErrorKind};
use encryption::{EType, KeyUsage};
use rnd::random;
use md5::Md5;
use hmac::{Hmac, Mac};

struct Rc4 {
    i: u8,
    j: u8,
    state: [u8; 256]
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Rc4 {
        assert!(key.len() >= 1 && key.len() <= 256);
        let mut rc4 = Rc4 { i: 0, j: 0, state: [0; 256] };
        for (i, x) in rc4.state.iter_mut().enumerate() {
            *x = i as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(rc4.state[i]).wrapping_add(key[i % key.len()]);
            rc4.state.swap(i, j as usize);
        }
        rc4
    }
    fn next(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.state[self.i as usize]);
        self.state.swap(self.i as usize, self.j as usize);
        let k = self.state[(self.state[self.i as usize].wrapping_add(self.state[self.j as usize])) as usize];
        k
    }

    pub fn process(&mut self, input: &[u8], output: &mut [u8]) {
        assert!(input.len() == output.len());
        for (x, y) in input.iter().zip(output.iter_mut()) {
            *y = *x ^ self.next();
        }
    }
}

/// Compute HMAC with MD5 hash algorithm
///
/// This is a convenience method to write
/// algorithm like in specification
/// # Example
/// ```rust, ignore
/// let signature = hmac_md5(b"foo", b"bar");
/// ```
pub fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut stream = Hmac::<Md5>::new_varkey(key).unwrap();
    stream.input(data);
    stream.result().code().to_vec()
}

pub struct Rc4Hmac {
    key: Vec<u8>,
    usage: KeyUsage,
}

impl Rc4Hmac {
    pub fn new(key: Vec<u8>, usage: KeyUsage) -> Self {
        Self {
            key,
            usage
        }
    }
/// Implement https://tools.ietf.org/html/rfc4757
///

    pub fn etype(&self) -> EType {
        EType::Rc4Hmac
    }

    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut edata = Vec::new();

        // generate the Confounder
        edata.append(&mut random(8));
        edata.append(&mut data.to_vec());

        let k1 = hmac_md5(&self.key, &(self.usage as u32).to_le_bytes());
        let k2 = &k1[0..16];
        let mut checksum = hmac_md5(k2, &edata);
        let k3 = hmac_md5(&k1, &checksum);

        let mut result = vec![0; edata.len()];
        Rc4::new(&k3).process(&edata, result.as_mut_slice());
        checksum.append(&mut result);

        checksum
    }

    pub fn decrypt(&mut self, data: &[u8]) -> KerlabResult<Vec<u8>> {
        //compute K1
        let t = self.usage as u32;
        let k1 = hmac_md5(&self.key, &t.to_le_bytes());
        let k2 = &k1[0..16];

        // First 8 bytes are checksum
        let expected_checksum = &data[0..16];
        let k3 = hmac_md5(&k1, &expected_checksum);

        let cipher = &data[16..];
        let mut edata = vec![0; cipher.len()];

        Rc4::new(&k3).process(&cipher, edata.as_mut_slice());
        let checksum = hmac_md5(k2, &edata);

        if expected_checksum != checksum {
            Err(Error::new(KerlabErrorKind::Kerberos, "RC4 HMAC checksum mismatch"))
        }
        else {
            Ok(edata[8..].to_vec())
        }
    }
}