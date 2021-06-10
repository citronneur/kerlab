use std::io::{Read, Write, Cursor};
use byteorder::{LittleEndian, ReadBytesExt};
use error::{KerlabResult, KerlabErrorKind, Error};
use asn1::OctetString;
use ndr::{FileTime, CommonTypeHeader, PrivateHeader, RpcUnicodeString};
use message::{Message, U32LE};

fn read_utf16(buf: &[u8]) -> KerlabResult<String> {
    let mut cursor = Cursor::new(buf);
    let mut raw = vec![];
    for _ in 0..buf.len() / 2 {
        raw.push(cursor.read_u16::<LittleEndian>()?);
    }
    Ok(
        String::from_utf16(&raw)
        .map_err(|_| Error::new(KerlabErrorKind::Parsing, "utf16"))?
    )

}

pub trait ReadFromCursor<T> {
    fn read(&mut self, cursor: &mut Cursor<T>) -> KerlabResult<()>;
}

/// PAC_INFO_BUFFER
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/3341cfa2-6ef5-42e0-b7bc-4544884bf399
pub struct PacInfoBuffer {
    ul_type: u32,
    cb_buffer_size: u32,
    offset: u64
}

impl PacInfoBuffer {
    pub fn into_pac_struct(&self, buffer: &[u8]) -> KerlabResult<PacStruct> {
        let view = &buffer[self.offset as usize..self.offset as usize + self.cb_buffer_size as usize];
        match self.ul_type {
            0x00000001 => Ok(PacStruct::KerbValidationInfo(KerbValidationInfo::from(view)?)),
            0x00000006 => Ok(PacStruct::ServerChecksum(PacSignatureData::from(view)?)),
            0x00000007 => Ok(PacStruct::KDCChecksum(PacSignatureData::from(view)?)),
            0x0000000A => Ok(PacStruct::PacClientInfo(PacClientInfo::from(view)?)),
            0x0000000C => Ok(PacStruct::UpnDnsInfo(UpnDnsInfo::from(view)?)),
            _ => Err(Error::new(KerlabErrorKind::Parsing, &format!("Unimplemented PacDataType {}", self.ul_type)))
        }
    }
}

impl<T: AsRef<[u8]>> ReadFromCursor<T> for PacInfoBuffer {
    fn read(&mut self, cursor: &mut Cursor<T>) -> KerlabResult<()> {
        self.ul_type = cursor.read_u32::<LittleEndian>()?;
        self.cb_buffer_size = cursor.read_u32::<LittleEndian>()?;
        self.offset = cursor.read_u64::<LittleEndian>()?;
        Ok(())
    }
}

impl Default for PacInfoBuffer {
    fn default() -> Self {
        Self {
            ul_type: 0,
            cb_buffer_size: 0,
            offset: 0
        }
    }
}

/// PAC header fields
/// PACTYPE
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/6655b92f-ab06-490b-845d-037e6987275f
pub struct PacType {
    pub c_buffers: u32,
    pub version: u32,
    pub buffers: Vec<PacStruct>,
}

impl PacType {
    /// Read pactype fields
    pub fn from_addata(buffer: OctetString) -> KerlabResult<Self> {
        let mut cursor = Cursor::new(&buffer);
        let c_buffers = cursor.read_u32::<LittleEndian>()?;
        let version = cursor.read_u32::<LittleEndian>()?;
        let mut buffers = vec![];
        for _ in 0..c_buffers {
            let mut pac_info = PacInfoBuffer::default();
            pac_info.read(&mut cursor)?;
            buffers.push(pac_info.into_pac_struct(&buffer)?);
        }
        Ok(Self {
            c_buffers,
            version,
            buffers
        })
    }
}

/// This is the most import information
/// It use RPC marshalling it's partially implemented in kerlab
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/69e86ccc-85e3-41b9-b514-7d969cd0ed73
#[derive(Component, Default)]
pub struct KerbValidationInfo {
    pub common_header: CommonTypeHeader,
    pub private_header: PrivateHeader,
    pub padding: U32LE,
    pub logon_time: FileTime,
    pub logoff_time: FileTime,
    pub kick_off_time: FileTime,
    pub password_last_set: FileTime,
    pub password_can_change: FileTime,
    pub password_must_change: FileTime,
    pub effective_name: RpcUnicodeString,
    /*pub full_name: RpcUnicodeString,
    pub logon_scripts: RpcUnicodeString,
    pub profile_path: RpcUnicodeString,
    pub home_directory: RpcUnicodeString,
    pub home_directory_drive: RpcUnicodeString,
    pub logon_count: u16,
    pub bad_password_count: u16,*/
}

impl KerbValidationInfo {
    fn from(buf: &[u8]) -> KerlabResult<Self> {
        let mut cursor = Cursor::new(buf);
        let mut result = KerbValidationInfo::default();
        result.read(&mut cursor)?;
        Ok(result)
    }
}

/// PAC client information
/// @see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/e465cb27-4bc1-4173-8be0-b5fd64dc9ff7
#[derive(Default)]
pub struct PacClientInfo {
    pub client_id: FileTime,
    name_length: u16,
    pub name: String
}

impl PacClientInfo {
    fn from(buf: &[u8]) -> KerlabResult<Self> {
        let mut cursor = Cursor::new(buf);
        let mut result = PacClientInfo::default();
        result.client_id.read(&mut cursor)?;
        result.name_length = cursor.read_u16::<LittleEndian>()?;
        result.name = read_utf16(&buf[
            cursor.position() as usize..(cursor.position() + result.name_length as u64) as usize
            ]
        )?;
        Ok(result)
    }
}

/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/1c0d6e11-6443-4846-b744-f9f810a504eb
#[derive(Default)]
pub struct UpnDnsInfo {
    upn_length: u16,
    upn_offset: u16,
    dns_domain_name_length: u16,
    dns_domain_name_offset: u16,
    flags: u32,
    pub upn: String,
    pub dns: String
}

impl UpnDnsInfo {
    fn from(buf: &[u8]) -> KerlabResult<Self> {
        let mut cursor = Cursor::new(buf);
        let mut result = UpnDnsInfo::default();

        result.upn_length = cursor.read_u16::<LittleEndian>()?;
        result.upn_offset = cursor.read_u16::<LittleEndian>()?;
        result.dns_domain_name_length = cursor.read_u16::<LittleEndian>()?;
        result.dns_domain_name_offset = cursor.read_u16::<LittleEndian>()?;
        result.flags = cursor.read_u32::<LittleEndian>()?;

        result.upn = read_utf16(&buf[result.upn_offset as usize..(result.upn_offset + result.upn_length) as usize])?;
        result.dns = read_utf16(&buf[result.dns_domain_name_offset as usize..(result.dns_domain_name_offset + result.dns_domain_name_length) as usize])?;
        Ok(result)
    }
}

/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/6e95edd3-af93-41d4-8303-6c7955297315
#[derive(Default)]
pub struct PacSignatureData {
    pub signature_type: u32,
    pub signature: Vec<u8>,
    pub rodcidentifier: Option<u16>
}

impl PacSignatureData {
    fn from(buf: &[u8]) -> KerlabResult<Self> {
        let mut cursor = Cursor::new(buf);
        let mut result = PacSignatureData::default();
        result.signature_type = cursor.read_u32::<LittleEndian>()?;
        match result.signature_type {
            0xFFFFFF76 => result.signature = vec![0; 16],
            0x0000000F => result.signature = vec![0; 12],
            0x00000010 => result.signature = vec![0; 12],
            _ => return Err(Error::new(KerlabErrorKind::Unknown, &format!("Unknown checksum type {}", result.signature_type)))
        };
        cursor.read(&mut result.signature)?;
        if cursor.position() != buf.len() as u64 {
            result.rodcidentifier = Some(cursor.read_u16::<LittleEndian>()?);
        }
        Ok(result)
    }
}

/// Generic PAC structure that encompass all structe handled by kerlab
pub enum PacStruct {
    KerbValidationInfo(KerbValidationInfo),
    PacClientInfo(PacClientInfo),
    UpnDnsInfo(UpnDnsInfo),
    ServerChecksum(PacSignatureData),
    KDCChecksum(PacSignatureData)
}