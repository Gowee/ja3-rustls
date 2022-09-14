// pub use rustls::Message;
use rustls::{
    internal::msgs::{
        enums::ExtensionType,
        handshake::{ClientExtension, ClientHelloPayload},
        message::{Message, MessageError, MessagePayload, OpaqueMessage},
    },
    ProtocolVersion,
};

use std::fmt;

mod utils;

pub use crate::utils::{fmtconcat, get_client_tls_versions, get_server_tls_version, TlsMessageExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja3 {
    pub version: u16,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub curves: Vec<u16>,
    pub point_formats: Vec<u8>,
}

pub trait Ja3Extractor {
    ///
    fn ja3(&self) -> Ja3;

    /// Almost same as `ja3`, except that the TLS version specified in extensions are preferred
    /// over the one in the message header.
    ///
    /// This appears to imcompliant to the JA3 standard.
    fn ja3_with_real_version(&self) -> Ja3;
}

impl Ja3Extractor for ClientHelloPayload {
    fn ja3(&self) -> Ja3 {
        get_ja3_from_chp(self, false)
    }

    fn ja3_with_real_version(&self) -> Ja3 {
        get_ja3_from_chp(self, true)
    }
}

fn get_ja3_from_chp(chp: &ClientHelloPayload, use_real_version: bool) -> Ja3 {
    // SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
    let mut version = chp.client_version;
    if use_real_version
        && get_client_tls_versions(chp)
            .map(|vers| vers.iter().any(|&ver| ver == ProtocolVersion::TLSv1_3))
            .unwrap_or(false)
    {
        // TODO: only TLS 1.3 is considered for now
        version = ProtocolVersion::TLSv1_3;
    }
    let ciphers = chp
        .cipher_suites
        .iter()
        .map(|cipher| cipher.get_u16())
        .collect();
    let extensions = chp
        .extensions
        .iter()
        .map(|extension| extension.get_type().get_u16())
        .collect();

    let mut curves = Vec::<u16>::new();
    for extension in chp.extensions.iter() {
        match extension {
            ClientExtension::NamedGroups(groups) => {
                curves = groups.iter().map(|curve| curve.get_u16()).collect()
            }
            _ => {}
        }
    }
    // if let Some(curves) = self.extensions.iter().filter(|extension| extension.get_type() == ExtensionType::EllipticCurves).next() {

    // }
    let mut point_formats = Vec::<u8>::new();
    for extension in chp.extensions.iter() {
        match extension {
            ClientExtension::ECPointFormats(formats) => {
                point_formats = formats.iter().map(|format| format.get_u8()).collect()
            }
            _ => {}
        }
    }
    Ja3 {
        version: version.get_u16(),
        ciphers,
        extensions,
        curves,
        point_formats,
    }
}

impl fmt::Display for Ja3 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Self {
            version,
            ciphers,
            extensions,
            curves,
            point_formats,
        } = self;
        write!(
            f,
            "{},{},{},{},{}",
            version,
            fmtconcat::<_, '-'>(ciphers),
            fmtconcat::<_, '-'>(extensions),
            fmtconcat::<_, '-'>(curves),
            fmtconcat::<_, '-'>(point_formats)
        )?;
        // ciphers.iter().intre
        // unimplemented!();
        Ok(())
    }
}

#[cfg(feature = "md5")]
impl Ja3 {
    /// Helper function to generate the MD5 format of JA3 string.
    pub fn to_md5(&self) -> [u8; 16] {
        use md5::{Digest, Md5};
        let mut h = Md5::new();
        h.update(self.to_string().as_bytes());
        // (&h.finalize()[..]).try_into().unwrap()
        dbg!(h.finalize()).as_slice().try_into().unwrap()
    }

    #[cfg(feature = "md5-string")]
    #[inline(always)]
    /// Helper function to generate the MD5 (hex string) format of JA3 string.
    pub fn to_md5_string(&self) -> String {
        hex::encode(self.to_md5())
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use rustls::internal::msgs::{
        codec::Reader,
        message::{Message, OpaqueMessage},
    };
    use rustls::Error as RustlsError;

    use crate::utils::{parse_tls_plain_message, TlsMessageExt};
    use crate::Ja3Extractor;
    #[test]
    fn ja3_from_client_hello_message() {
        let buf = hex!("16030100f5010000f10303ad8e0c8dfe3adbc045e51aee4cb9480c02d5da4a240f95e8282a1f51be34901a20681af80b44c4b359adb3f9543a966e07e6ba6bed551472a62cd4b107cbd40e830014130213011303c02cc02bcca9c030c02fcca800ff01000094002b00050403040303000b00020100000a00080006001d00170018000d00140012050304030807080608050804060105010401001700000005000501000000000000001800160000137777772e706574616c7365617263682e636f6d00120000003300260024001d0020086fffef5fa7f04fb7d788615bc425820eba366ddb5f75c7d8336a0a05722d38002d0002010100230000");
        let chp = parse_tls_plain_message(&buf)
            .ok()
            .and_then(|message| message.into_client_hello_payload())
            .expect("Message valid");
        dbg!(chp.ja3());
        assert_eq!(chp.ja3().to_string(), "771,4866-4865-4867-49196-49195-52393-49200-49199-52392-255,43-11-10-13-23-5-0-18-51-45-35,29-23-24,0");
        assert_eq!(chp.ja3_with_real_version().to_string(), "772,4866-4865-4867-49196-49195-52393-49200-49199-52392-255,43-11-10-13-23-5-0-18-51-45-35,29-23-24,0");
        #[cfg(feature = "md5-string")]
        {
            assert_eq!(
                chp.ja3().to_md5_string(),
                "a94fc11547bcef10847672ff518b3fb9"
            )
        }
        // println!("{}", chp.ja3_with_real_version());
    }
}

// pub fn add(left: usize, right: usize) -> usize {
//     left + right
// }

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn it_works() {
//         let result = add(2, 2);
//         assert_eq!(result, 4);
//     }
// }
