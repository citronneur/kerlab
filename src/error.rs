use yasna::{ASN1Error, ASN1ErrorKind};
use std;
use ascii::AsAsciiStrError;
use chrono::ParseError;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum KerlabErrorKind {
    Unknown,
    Kerberos,
    Crypto,
    Parsing,
    InvalidConst
}

#[derive(Debug)]
pub struct KerlabError {
    /// Kind of error
    kind: KerlabErrorKind,
    /// Associated message of the context
    message: String
}

impl KerlabError {
    /// create a new Kekeo error
    /// # Example
    /// ```
    /// use error::{KerlabError, KerlabErrorKind};
    /// let error = KerlabError::new(KerlabErrorKind::Unknown, "Unknown");
    /// ```
    pub fn new (kind: KerlabErrorKind, message: &str) -> Self {
        KerlabError {
            kind,
            message: String::from(message)
        }
    }

    /// Return the kind of error
    ///
    /// # Example
    /// ```
    /// use error::{KerlabError, KerlabErrorKind};
    /// let error = KerlabError::new(KerlabErrorKind::Disconnect, "disconnected");
    /// assert_eq!(error.kind(), KekeoErrorKind::Disconnect)
    /// ```
    pub fn kind(&self) -> KerlabErrorKind {
        self.kind
    }
}

#[derive(Debug)]
pub enum Error {
    /// kerlab error
    KerlabError(KerlabError),
    /// ASN1 parser error
    ASN1Error(ASN1Error),
    Io(std::io::Error),
    AsAsciiStrError(AsAsciiStrError),
    ChronoParseError(ParseError)
}

impl Error {
    pub fn new(kind: KerlabErrorKind, message: &str) -> Self {
        Error::KerlabError(KerlabError::new(kind, message))
    }
}

impl From<ASN1Error> for Error {
    fn from(e: ASN1Error) -> Error {
        Error::ASN1Error(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<AsAsciiStrError> for Error {
    fn from(e: AsAsciiStrError) -> Self {
        Error::AsAsciiStrError(e)
    }
}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        Error::ChronoParseError(e)
    }
}
impl From<Error> for ASN1Error {
    fn from(e: Error) -> Self {
        match e {
            Error::ASN1Error(e) => e,
            _ => ASN1Error::new(ASN1ErrorKind::Extra)
        }
    }
}

pub type KerlabResult<T> = Result<T, Error>;
