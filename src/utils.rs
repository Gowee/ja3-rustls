use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::handshake::{
    ClientExtension, ClientHelloPayload, HandshakeMessagePayload, HandshakePayload,
    ServerExtension, ServerHelloPayload,
};
use rustls::internal::msgs::message::{Message, MessageError, MessagePayload, OpaqueMessage};
use rustls::{Error as RustlsError, ProtocolVersion};

use std::fmt;

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
        .map_err(|_e| RustlsError::CorruptMessage) // invalid header
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