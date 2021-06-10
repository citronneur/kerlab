use yasna::{Tag as YasnaTag, DERWriter, BERReader, ASN1Error, ASN1ErrorKind};
use error::{KerlabResult};
use yasna::tags::{TAG_GENERALSTRING, TAG_GENERALIZEDTIME};
use ascii::AsciiString;
use bit_vec::BitVec;
use chrono::{Utc, DateTime, NaiveDateTime};
use std::ops::{Deref, DerefMut};

/// This trait is a wrapper around
/// the yasna library to better declare
/// ASN1 type
pub trait ASN1 {
    /// write type into a DERWriter stream
    fn write_asn1(&self, writer: DERWriter) -> KerlabResult<()>;
    /// Read the type from an ASN1 BER reader
    fn read_asn1(&mut self, reader: BERReader) -> KerlabResult<()>;
}

/// This type is used to declare an ASN1 type
/// of SEQUENCE OF
///
/// # Example
/// ```
/// use kerlab::asn1::{SequenceOf, Integer};
/// pub type sequence_of_integer = SequenceOf<Integer>;
/// ```
pub type SequenceOf<T> = Vec<T>;

impl<T: ASN1 + Default> ASN1 for SequenceOf<T> {
    /// Write in asn1 format a SequenceOf
    fn write_asn1(&self, writer: DERWriter) -> KerlabResult<()> {
        writer.write_sequence_of(|sequence| {
            for child in self {
                child.write_asn1(sequence.next()).unwrap();
            }
        });
        Ok(())
    }

    /// Read asn1 sequence
    fn read_asn1(&mut self, reader: BERReader) -> KerlabResult<()> {
        reader.read_sequence_of(|reader| {
            let mut element : T = Default::default();
            element.read_asn1(reader)?;
            self.push(element);
            Ok(())
        })?;
        Ok(())
    }
}

pub type OctetString = Vec<u8>;

impl ASN1 for OctetString {

    fn write_asn1(&self, writer: DERWriter) -> KerlabResult<()> {
        writer.write_bytes(self.as_slice());
        Ok(())
    }

    fn read_asn1(&mut self, reader: BERReader) -> KerlabResult<()> {
        *self = reader.read_bytes()?;
        Ok(())
    }
}

/// Tag is use to mark a field of
/// Sequence with the apropriate number
/// It use a nightly feature
#[derive(PartialEq, Debug, Clone)]
pub struct Tag<const N: u64, T: PartialEq + Clone> {
    /// The inner object
    pub inner: T
}

impl<const N: u64, T: PartialEq + Clone> Tag<{ N }, T> {
    /// Constructoer
    pub fn new(inner: T) -> Self {
        Tag {
            inner
        }
    }
}

/// Convenient default constructor for type implemented defautl
/// Use very often when reading structure
impl<const N: u64, T: Default + PartialEq + Clone> Default for Tag<{ N }, T> {
    fn default() -> Self {
        Tag::new(T::default())
    }
}

/// ASN1 implementation
impl<const N: u64, T: ASN1 + PartialEq + Clone> ASN1 for Tag<{ N }, T> {
    /// Write a tag
    fn write_asn1(&self, writer: DERWriter) -> KerlabResult<()> {
        writer.write_tagged(YasnaTag::context({ N }), |writer| {
            self.inner.write_asn1(writer)
        })
    }

    /// Read a tag with appropriate number
    fn read_asn1(&mut self, reader: BERReader) -> KerlabResult<()> {
        reader.read_tagged(YasnaTag::context({ N }), |tag_reader| {
            Ok(self.inner.read_asn1(tag_reader)?)
        })?;
        Ok(())
    }
}

/// We never handle tag directly but the inner reference
/// A common way to avoid .inner call everywhere
impl<const N: u64, T: ASN1 + PartialEq + Default + Clone> Deref for Tag<{ N }, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// We never handle tag directly but the inner reference
/// A common way to avoid .inner call everywhere
impl<const N: u64, T: ASN1 + PartialEq + Default + Clone> DerefMut for Tag<{ N }, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// Application is the top message for an ASN1 message
#[derive(Default, PartialEq, Clone)]
pub struct Application<const N: u64, T: Default + PartialEq + Clone> {
    /// The inner node
    pub inner: T
}

/// ASN1 implementation
impl<const N: u64, T: ASN1 + Default + PartialEq + Clone> ASN1 for Application<{ N }, T> {
    /// Write an application tag
    fn write_asn1(&self, writer: DERWriter) -> KerlabResult<()> {
        writer.write_tagged(
            YasnaTag::application({ N }),
            |writer| {
                self.inner.write_asn1(writer)
            }
        )
    }

    /// Read an application tag
    fn read_asn1(&mut self, reader: BERReader) -> KerlabResult<()> {
        reader.read_tagged(
            YasnaTag::application({ N }),
            |tag_reader| {
                Ok(self.inner.read_asn1(tag_reader)?)
            }
        )?;
        Ok(())
    }
}

/// Use to avoid call of .inner everywhere
impl<const N: u64, T: ASN1 + PartialEq + Default + Clone> Deref for Application<{ N }, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Use to avoid call of .inner everywhere
impl<const N: u64, T: ASN1 + PartialEq + Default + Clone> DerefMut for Application<{ N }, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// An ASN1 Integer
pub type Integer = u32;

impl ASN1 for Integer {

    /// Write an ASN1 Integer Node
    /// using a DERWriter
    fn write_asn1(&self, writer: DERWriter) -> KerlabResult<()> {
        writer.write_u32(*self);
        Ok(())
    }

    /// Read an ASN1 Integer
    /// using a BerReader
    fn read_asn1(&mut self, reader: BERReader) -> KerlabResult<()> {
        *self = reader.read_u32()?;
        Ok(())
    }
}

/// An ASN1 Integer
pub type SInteger = i32;

impl ASN1 for SInteger {

    /// Write an ASN1 Integer Node
    /// using a DERWriter
    fn write_asn1(&self, writer: DERWriter) -> KerlabResult<()> {
        writer.write_i32(*self);
        Ok(())
    }

    /// Read an ASN1 Integer
    /// using a BerReader
    fn read_asn1(&mut self, reader: BERReader) -> KerlabResult<()> {
        *self = reader.read_i32()?;
        Ok(())
    }
}

/// ASN1 for boolean
impl ASN1 for bool {

    /// Write an ASN1 boolean Node
    /// using a DERWriter
    fn write_asn1(&self, writer: DERWriter) -> KerlabResult<()> {
        writer.write_bool(*self);
        Ok(())
    }

    /// Read an ASN1 Boolean
    /// using a BerReader
    fn read_asn1(&mut self, reader: BERReader) -> KerlabResult<()> {
        *self = reader.read_bool()?;
        Ok(())
    }
}

/// An ASN1 Enumerate
pub type Enumerate = i64;

impl ASN1 for Enumerate {

    /// Write an ASN1 Enumerate Node
    /// using a DERWriter
    fn write_asn1(&self, writer: DERWriter) -> KerlabResult<()> {
        writer.write_enum(*self);
        Ok(())
    }

    /// Read an ASN1 Enumerate
    /// using a BerReader
    fn read_asn1(&mut self, reader: BERReader) -> KerlabResult<()> {
        *self = reader.read_enum()?;
        Ok(())
    }
}

/// General string is an alias for ascii string in kerbertos
pub type GeneralString = AsciiString;

/// ASN1 implementation
impl ASN1 for GeneralString {
    /// Write ASN1
    fn write_asn1(&self, writer: DERWriter) -> KerlabResult<()> {
        writer.write_tagged_implicit(TAG_GENERALSTRING, |writer| {
            writer.write_bytes(self.as_bytes())
        });
        Ok(())
    }

    /// Read ASN1
    fn read_asn1(&mut self, reader: BERReader) -> KerlabResult<()> {
        *self = reader.read_tagged_implicit(TAG_GENERALSTRING, |reader| {
            let bytes = reader.read_bytes()?;
            match AsciiString::from_ascii(bytes) {
                Ok(string) => Ok(string),
                Err(_) => Err(ASN1Error::new(ASN1ErrorKind::Invalid)),
            }
        })?;
        Ok(())
    }
}

/// Optional field
/// Optional field can be processed or not
/// during sequence reading
impl<T: ASN1 + Default> ASN1 for Option<T> {
    /// write ASN1
    fn write_asn1(&self, writer: DERWriter) -> KerlabResult<()> {
        if let Some(inner) = self {
            inner.write_asn1(writer)
        }
        else {
            Ok(())
        }
    }

    /// Read ASN1
    fn read_asn1(&mut self, reader: BERReader) -> KerlabResult<()> {
        let mut result =T::default();
        if let Ok(()) = result.read_asn1(reader) {
            *self = Some(result);
        }
        Ok(())
    }
}

/// A wrapper to handle Rust time
/// to use in ASN1
#[derive(PartialEq, Clone)]
pub struct GeneralizedTime {
    pub inner : DateTime<Utc>
}

impl GeneralizedTime {
    /// constructor
    pub fn new(date: DateTime<Utc>) -> Self {
        Self {
            inner: date
        }
    }
}

impl Default for GeneralizedTime {
    /// Default use Utc::now time
    fn default() -> Self {
        Self {
            inner: Utc::now()
        }
    }
}

/// ASN1 implementation
impl ASN1 for GeneralizedTime {

    /// Write ASN1
    fn write_asn1(&self, writer: DERWriter) -> KerlabResult<()> {
        writer.write_tagged_implicit(TAG_GENERALIZEDTIME, |writer| {
            writer.write_bytes(self.inner.format("%Y%m%d%H%M%SZ").to_string().as_bytes())
        });
        Ok(())
    }

    /// Read ASN1
    fn read_asn1(&mut self, reader: BERReader) -> KerlabResult<()> {
        *self = reader.read_tagged_implicit(TAG_GENERALIZEDTIME, |reader| {
            let bytes = reader.read_bytes()?;
            match NaiveDateTime::parse_from_str(AsciiString::from_ascii(bytes).unwrap().as_str(), "%Y%m%d%H%M%SZ") {
                Ok(date) => Ok(Self::new(DateTime::<Utc>::from_utc(date, Utc))),
                Err(_) => Err(ASN1Error::new(ASN1ErrorKind::Invalid)),
            }
        })?;
        Ok(())
    }
}

/// Use Bitvec for Bitstring
pub type BitString = BitVec;

impl ASN1 for BitString {
    fn write_asn1(&self, writer: DERWriter) -> KerlabResult<()> {
        writer.write_bitvec(self);
        Ok(())
    }

    fn read_asn1(&mut self, reader: BERReader) -> KerlabResult<()> {
        *self = reader.read_bitvec()?;
        Ok(())
    }
}

/// Serialize an ASN1 message into der stream
pub fn to_der(message: &dyn ASN1) -> Vec<u8> {
    yasna::construct_der(|writer| {
        message.write_asn1(writer).unwrap();
    })
}

/// Deserialize an ASN1 message from a stream
pub fn from_der(message: &mut dyn ASN1, stream: &[u8]) -> KerlabResult<()> {
    Ok(yasna::parse_der(stream, |reader| {
            Ok(message.read_asn1(reader)?)
        })?
    )
}

/// Deserialize an ASN1 message from a stream using BER
pub fn from_ber(message: &mut dyn ASN1, stream: &[u8]) -> KerlabResult<()> {
    Ok(yasna::parse_ber(stream, |reader| {
            Ok(message.read_asn1(reader)?)
        })?
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use asn1::to_der;

    #[derive(Sequence)]
    pub struct TestOption {
        field_1: Tag<0, Integer>,
        field_2: Option<Tag<1, Integer>>,
        field_3: Tag<2, Integer>
    }

    impl TestOption {
        pub fn new() -> Self {
            Self {
                field_1: Tag::new(0),
                field_2: None,
                field_3: Tag::new(0)
            }
        }
    }

    /// Test format of the first client message
    #[test]
    fn test_optional_field() {
        let mut read_without = TestOption::new();
        from_ber(&mut read_without, &[48, 10, 160, 3, 2, 1, 1, 162, 3, 2, 1, 3]).unwrap();
        assert_eq!(read_without.field_2, None);

        let mut read_with = TestOption::new();
        from_ber(&mut read_with, &[48, 15, 160, 3, 2, 1, 1, 161, 3, 2, 1, 2, 162, 3, 2, 1, 3]).unwrap();
        assert_eq!(*read_with.field_2.unwrap(), 2);
    }
}
