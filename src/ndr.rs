use message::{Message, U16LE, U32LE};
use std::io::{Write, Read};
use error::KerlabResult;
use chrono::{DateTime, Utc, NaiveDateTime};

/// Very basic NDR parser
/// Need to be improved
#[derive(Component, Default)]
pub struct CommonTypeHeader {
    version: u8,
    endianness: u8,
    common_header_length: U16LE,
    filler: U32LE
}

#[derive(Component, Default)]
pub struct PrivateHeader {
    object_buffer_length: U32LE,
    filler: U32LE
}

#[derive(Component, Default)]
pub struct FileTime {
    pub dw_low_date_time: U32LE,
    pub dw_high_date_time: U32LE
}

impl FileTime {
    pub fn datetime(&self) -> DateTime<Utc> {
        if self.dw_high_date_time == 0x7FFFFFFF
            || self.dw_low_date_time == 0xFFFFFFFF
            || self.dw_high_date_time == 0
            || self.dw_low_date_time == 0 {
            return DateTime::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc)
        }

        let mut timestamp: u64 = (self.dw_high_date_time as u64) << 32;
        timestamp |=  self.dw_low_date_time as u64;
        let result = (timestamp - 116444736000000000) / 10000000;
        DateTime::from_utc(NaiveDateTime::from_timestamp(result as i64, 0), Utc)
    }
}

#[derive(Component, Default)]
pub struct RpcUnicodeString {
    pub length: U16LE,
    pub maximum_length: U16LE,
    pub buffer: U32LE
}