use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::handshake::{
    ClientExtension, ClientHelloPayload, HandshakeMessagePayload, HandshakePayload,
    ServerExtension, ServerHelloPayload,
};
use rustls::internal::msgs::message::{Message, MessageError, MessagePayload, OpaqueMessage};
use rustls::{Error as RustlsError, InvalidMessage, ProtocolVersion};

use std::fmt;
use std::str::FromStr;

pub fn get_server_tls_version(shp: &ServerHelloPayload) -> Option<ProtocolVersion> {
    shp.extensions
        .iter()
        .filter_map(|ext| {
            if let ServerExtension::SupportedVersions(vers) = ext {
                Some(vers)
            } else {
                None
            }
        })
        .next()
        .cloned()
}

pub fn get_client_tls_versions(shp: &ClientHelloPayload) -> Option<&Vec<ProtocolVersion>> {
    shp.extensions
        .iter()
        .filter_map(|ext| {
            if let ClientExtension::SupportedVersions(vers) = ext {
                Some(vers)
            } else {
                None
            }
        })
        .next()
}

pub trait TlsMessageExt {
    fn into_client_hello_payload(self) -> Option<ClientHelloPayload>;
    fn into_server_hello_payload(self) -> Option<ServerHelloPayload>;
}

impl TlsMessageExt for Message {
    fn into_client_hello_payload(self) -> Option<ClientHelloPayload> {
        if let MessagePayload::Handshake {
            parsed:
                HandshakeMessagePayload {
                    payload: HandshakePayload::ClientHello(chp),
                    ..
                },
            ..
        } = self.payload
        {
            Some(chp)
        } else {
            None
        }
    }

    fn into_server_hello_payload(self) -> Option<ServerHelloPayload> {
        if let MessagePayload::Handshake {
            parsed:
                HandshakeMessagePayload {
                    payload: HandshakePayload::ServerHello(shp),
                    ..
                },
            ..
        } = self.payload
        {
            Some(shp)
        } else {
            None
        }
    }
}

pub fn parse_tls_plain_message(buf: &[u8]) -> Result<Message, RustlsError> {
    OpaqueMessage::read(&mut Reader::init(buf))
        .map(|om| om.into_plain_message())
        .map_err(|e| {
            RustlsError::InvalidMessage(match e {
                MessageError::TooShortForHeader => InvalidMessage::MessageTooShort,
                MessageError::TooShortForLength => InvalidMessage::MessageTooShort,
                MessageError::InvalidEmptyPayload => InvalidMessage::InvalidEmptyPayload,
                MessageError::MessageTooLarge => InvalidMessage::MessageTooLarge,
                MessageError::InvalidContentType => InvalidMessage::InvalidContentType,
                MessageError::UnknownProtocolVersion => InvalidMessage::UnknownProtocolVersion,
            })
        }) // invalid header
        .and_then(Message::try_from)
}

pub struct ConcatenatingFormatter<'a, T: fmt::Display, const CHAR: char>(&'a [T]);

impl<'s, T: fmt::Display, const CHAR: char> fmt::Display for ConcatenatingFormatter<'s, T, CHAR> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut slice = self.0.iter().peekable();
        while let Some(part) = slice.next() {
            write!(f, "{}", part)?;
            if slice.peek().is_some() {
                write!(f, "{}", CHAR)?;
            }
        }
        Ok(())
    }
}

pub fn fmtconcat<T: fmt::Display, const CHAR: char>(
    slice: &'_ [T],
) -> ConcatenatingFormatter<'_, T, CHAR> {
    ConcatenatingFormatter(slice)
}

pub struct ConcatenatedParser<T: FromStr, const CHAR: char>(pub Vec<T>);

impl<T: FromStr, const CHAR: char> FromStr for ConcatenatedParser<T, CHAR> {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut v = vec![];
        for part in s.split(CHAR) {
            v.push(part.parse::<T>().map_err(|_e| "Not valid value")?);
        }
        Ok(Self(v))
    }
}

impl<T: FromStr, const CHAR: char> ConcatenatedParser<T, CHAR> {
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

// pub fn parseconcat<T: FromStr, const CHAR: char>() -> ConcatenatedParser<T, CHAR> {

// }

// Generate a random number within S..E.
pub fn rand_in<const S: usize, const E: usize>() -> usize {
    #[cfg(not(feature = "rand"))]
    {
        // https://users.rust-lang.org/t/random-number-without-using-the-external-crate/17260/11
        // https://www.reddit.com/r/rust/comments/c1az1t/comment/erbz4mg/
        use std::collections::hash_map::DefaultHasher;
        use std::hash::Hasher;
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let mut h = DefaultHasher::new();
        h.write_u32(nanos);
        (h.finish() as usize) % (E - S) + S
    }
    #[cfg(feature = "rand")]
    {
        use rand::{thread_rng, Rng};
        thread_rng().gen_range(S..E)
    }
}
