use std::io::{Write, Read};
use error::KerlabResult;
use byteorder::{WriteBytesExt, LittleEndian, ReadBytesExt};

pub trait Message {
    fn write(&self, writer: &mut dyn Write) -> KerlabResult<()>;
    fn read(&mut self, reader: &mut dyn Read) -> KerlabResult<()>;
}

pub type U16LE = u16;

impl Message for U16LE {
    fn write(&self, writer: &mut dyn Write) -> KerlabResult<()> {
        Ok(writer.write_u16::<LittleEndian>(*self)?)
    }

    fn read(&mut self, reader: &mut dyn Read) -> KerlabResult<()> {
        *self = reader.read_u16::<LittleEndian>()?;
        Ok(())
    }
}

impl Message for u8 {
    fn write(&self, writer: &mut dyn Write) -> KerlabResult<()> {
        Ok(writer.write_u8(*self)?)
    }

    fn read(&mut self, reader: &mut dyn Read) -> KerlabResult<()> {
        *self = reader.read_u8()?;
        Ok(())
    }
}

pub type U32LE = u32;

impl Message for U32LE {
    fn write(&self, writer: &mut dyn Write) -> KerlabResult<()> {
        Ok(writer.write_u32::<LittleEndian>(*self)?)
    }

    fn read(&mut self, reader: &mut dyn Read) -> KerlabResult<()> {
        *self = reader.read_u32::<LittleEndian>()?;
        Ok(())
    }
}
