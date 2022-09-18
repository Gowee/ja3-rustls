//! JA3 with Rustls types
//!
//! # Example
//! Extract JA3 TLS fingerprint from a slice of bytes:
//! ```rust
//! use ja3_rustls::{parse_tls_plain_message, TlsMessageExt, Ja3Extractor};
//! use hex_literal::hex;
//!
//! let buf = hex!("16030100f5010000f10303ad8e0c8dfe3adbc045e51aee4cb9480c02d5da4a240f95e8282a1f51be34901a20681af80b44c4b359adb3f9543a966e07e6ba6bed551472a62cd4b107cbd40e830014130213011303c02cc02bcca9c030c02fcca800ff01000094002b00050403040303000b00020100000a00080006001d00170018000d00140012050304030807080608050804060105010401001700000005000501000000000000001800160000137777772e706574616c7365617263682e636f6d00120000003300260024001d0020086fffef5fa7f04fb7d788615bc425820eba366ddb5f75c7d8336a0a05722d38002d0002010100230000");
//! let chp = parse_tls_plain_message(&buf)
//!   .ok()
//!   .and_then(|message| message.into_client_hello_payload())
//!   .expect("Message valid");
//! println!("{:?}", chp.ja3());
//! println!("{}", chp.ja3());
//! println!("{}", chp.ja3_with_real_version());
//! assert_eq!(chp.ja3().to_string(), "771,4866-4865-4867-49196-49195-52393-49200-49199-52392-255,43-11-10-13-23-5-0-18-51-45-35,29-23-24,0");
//! ```
//!
//! To generate hex string of JA3, activating optional features via Cargo.toml:
//! ```toml
//! # in Cargo.toml
//! # under [dependencies]
//! ja3-rustls = { version = "0.0.0", features = ["md5-string"] } # or just md5
//! ```
//! , then
//! ```ignore
//! println!("{:x?}", chp.ja3().to_md5()); // requires feature: md5
//! println!("{}", chp.ja3().to_md5_string()); // requires feature: md5-string
//! ```
use rustls::{
    internal::msgs::{
        enums::{ECPointFormat, ExtensionType, NamedGroup},
        handshake::ClientExtension,
    },
    CipherSuite, ProtocolVersion,
};

pub use rustls::internal::msgs::{handshake::ClientHelloPayload, message::Message};

use std::{fmt, str::FromStr};

mod grease;
mod ja3nm;
mod utils;

pub use crate::utils::*;
// use crate::utils::{fmtconcat, get_client_tls_versions, ConcatenatedParser};

use crate::ja3nm::get_ja3_and_more_from_chp;
pub use crate::ja3nm::Ja3andMore;

pub use crate::grease::*;

#[derive(Debug, Clone, PartialEq, Eq)]
/// JA3, as explained in [https://github.com/salesforce/ja3]
pub struct Ja3 {
    /// SSLVersion
    pub version: u16,
    /// Cipher
    pub ciphers: Vec<u16>,
    /// SSLExtension
    pub extensions: Vec<u16>,
    /// EllipticCurve
    pub curves: Vec<u16>,
    /// EllipticCurvePointFormat
    pub point_formats: Vec<u8>,
}

pub trait Ja3Extractor {
    /// Get the JA3 of a [`ClientHelloPayload`]
    fn ja3(&self) -> Ja3;

    /// Almost same as `ja3`, except that the TLS version specified in extensions, if any, are
    /// preferred over the one indicated by the record header.
    ///
    /// This appears to be imcompliant to the JA3 standard.
    fn ja3_with_real_version(&self) -> Ja3;

    /// Check `ja3_with_real_version` and `ja3_with_grease` for more info.
    fn ja3_with_real_version_and_grease(&self) -> Ja3;

    /// Almost same `ja3`, except that all [RFC8701](https://www.rfc-editor.org/rfc/rfc8701.html)
    /// GREASE values are kept as is.
    ///
    /// This contradicts the JA3 standard.
    fn ja3_with_grease(&self) -> Ja3;

    /// Get the JA3 and more fields of a [`ClientHelloPayload`]
    ///
    /// Additional fields are not a part of the JA3 standard.
    fn ja3_and_more(&self) -> Ja3andMore;

    /// Almost same `ja3_and_more`, except that all [RFC8701](https://www.rfc-editor.org/rfc/rfc8701.html)
    /// GREASE values are kept as is.
    ///
    /// This contradicts the JA3 standard.
    fn ja3_and_more_with_grease(&self) -> Ja3andMore;
}

impl Ja3Extractor for ClientHelloPayload {
    fn ja3(&self) -> Ja3 {
        get_ja3_from_chp(self, false, true)
    }

    fn ja3_with_real_version(&self) -> Ja3 {
        get_ja3_from_chp(self, true, true)
    }

    fn ja3_with_real_version_and_grease(&self) -> Ja3 {
        get_ja3_from_chp(self, true, true)
    }

    fn ja3_with_grease(&self) -> Ja3 {
        get_ja3_from_chp(self, true, false)
    }

    fn ja3_and_more(&self) -> Ja3andMore {
        get_ja3_and_more_from_chp(self, true)
    }

    fn ja3_and_more_with_grease(&self) -> Ja3andMore {
        get_ja3_and_more_from_chp(self, false)
    }
}

fn get_ja3_from_chp(
    chp: &ClientHelloPayload,
    use_real_version: bool,
    ignore_rfc8701_grease: bool,
) -> Ja3 {
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
        .filter(|&ext| !ignore_rfc8701_grease || !is_grease_u16_be(ext))
        .collect();
    let extensions = chp
        .extensions
        .iter()
        .map(|extension| extension.get_type().get_u16())
        .filter(|&ext| !ignore_rfc8701_grease || !is_grease_u16_be(ext))
        .collect();

    let mut curves = Vec::<u16>::new();
    let mut point_formats = Vec::<u8>::new();
    for extension in chp.extensions.iter() {
        match extension {
            ClientExtension::NamedGroups(groups) => {
                curves = groups
                    .iter()
                    .map(|curve| curve.get_u16())
                    .filter(|&ext| !ignore_rfc8701_grease || !is_grease_u16_be(ext))
                    .collect()
            }
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

impl From<&ClientHelloPayload> for Ja3 {
    #[inline(always)]
    fn from(chp: &ClientHelloPayload) -> Ja3 {
        chp.ja3()
    }
}

impl Ja3 {
    pub fn into_ja3_and_more(
        self,
        alpn: Vec<Vec<u8>>,
        signature_algos: Vec<u16>,
        key_share: Vec<u16>,
        supported_versions: Vec<u16>,
    ) -> Ja3andMore {
        Ja3andMore {
            ja3: self,
            alpn,
            signature_algos,
            key_share,
            supported_versions,
        }
    }

    pub fn version_to_typed(&self) -> ProtocolVersion {
        ProtocolVersion::from(self.version)
    }

    pub fn ciphers_as_typed(&self) -> impl Iterator<Item = CipherSuite> + '_ {
        self.ciphers.iter().map(|&cipher| CipherSuite::from(cipher))
    }

    /// `ciphers_as_typed` with existing GREASE values rewritten as newly generated ones. It
    /// is based on an insecure RNG unless the `rand` crate feature is activated.
    pub fn ciphers_regreasing_as_typed(&self) -> impl Iterator<Item = CipherSuite> + '_ {
        self.ciphers
            .iter()
            .map(|&cipher| CipherSuite::from(try_regrease_u16_be(cipher)))
    }

    pub fn extensions_as_typed(&self) -> impl Iterator<Item = ExtensionType> + '_ {
        self.extensions
            .iter()
            .map(|&extension| ExtensionType::from(extension))
    }

    /// `extensions_as_typed` with existing GREASE values rewritten as newly generated ones. It
    /// is based on an insecure RNG unless the `rand` crate feature is activated.
    pub fn extensions_regreasing_as_typed(&self) -> impl Iterator<Item = ExtensionType> + '_ {
        self.extensions
            .iter()
            .map(|&extension| ExtensionType::from(try_regrease_u16_be(extension)))
    }

    pub fn curves_as_typed(&self) -> impl Iterator<Item = NamedGroup> + '_ {
        self.curves.iter().map(|&curve| NamedGroup::from(curve))
    }

    /// `curves_as_typed` with existing GREASE values rewritten as newly generated ones. It
    /// is based on an insecure RNG unless the `rand` crate feature is activated.
    pub fn curves_regreasing_as_typed(&self) -> impl Iterator<Item = NamedGroup> + '_ {
        self.curves
            .iter()
            .map(|&curve| NamedGroup::from(try_regrease_u16_be(curve)))
    }
    pub fn point_formats_as_typed(&self) -> impl Iterator<Item = ECPointFormat> + '_ {
        self.point_formats
            .iter()
            .map(|&format| ECPointFormat::from(format))
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
        Ok(())
    }
}

impl FromStr for Ja3 {
    type Err = &'static str; // TODO: typing

    fn from_str(s: &str) -> Result<Ja3, Self::Err> {
        let mut parts = s.split(',');
        let version = parts
            .next()
            .ok_or("Emtpy string")?
            .parse::<u16>()
            .map_err(|_e| "Version not integer")?;
        let ciphers = parts
            .next()
            .ok_or("No ciphers and following")?
            .parse::<ConcatenatedParser<_, '-'>>()?
            .into_inner();
        let extensions = parts
            .next()
            .ok_or("No extensiosn and following")?
            .parse::<ConcatenatedParser<_, '-'>>()?
            .into_inner();
        let curves = parts
            .next()
            .ok_or("No curves and following")?
            .parse::<ConcatenatedParser<_, '-'>>()?
            .into_inner();
        let point_formats = parts
            .next()
            .ok_or("No point formats")?
            .parse::<ConcatenatedParser<_, '-'>>()?
            .into_inner();
        if parts.next().is_some() {
            return Err("String redundant");
        }
        Ok(Ja3 {
            version,
            ciphers,
            extensions,
            curves,
            point_formats,
        })
    }
}

#[cfg(feature = "md5")]
impl Ja3 {
    /// Helper function to generate the MD5 format of JA3 string.
    pub fn to_md5(&self) -> [u8; 16] {
        use md5::{Digest, Md5};
        let mut h = Md5::new();
        h.update(self.to_string().as_bytes());
        h.finalize().as_slice().try_into().unwrap()
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

    use crate::utils::{parse_tls_plain_message, TlsMessageExt};
    use crate::{Ja3, Ja3Extractor};
    #[test]
    fn ja3_from_client_hello_message() {
        // rustls safe default client ja3
        let buf = hex!("16030100f5010000f10303ad8e0c8dfe3adbc045e51aee4cb9480c02d5da4a240f95e8282a1f51be34901a20681af80b44c4b359adb3f9543a966e07e6ba6bed551472a62cd4b107cbd40e830014130213011303c02cc02bcca9c030c02fcca800ff01000094002b00050403040303000b00020100000a00080006001d00170018000d00140012050304030807080608050804060105010401001700000005000501000000000000001800160000137777772e706574616c7365617263682e636f6d00120000003300260024001d0020086fffef5fa7f04fb7d788615bc425820eba366ddb5f75c7d8336a0a05722d38002d0002010100230000");
        let chp = parse_tls_plain_message(&buf)
            .ok()
            .and_then(|message| message.into_client_hello_payload())
            .expect("Message valid");
        println!("{:?}", chp.ja3());
        println!("{}", chp.ja3());
        println!("{}", chp.ja3_with_real_version());
        assert_eq!(chp.ja3().to_string(), "771,4866-4865-4867-49196-49195-52393-49200-49199-52392-255,43-11-10-13-23-5-0-18-51-45-35,29-23-24,0");
        assert_eq!(chp.ja3_with_real_version().to_string(), "772,4866-4865-4867-49196-49195-52393-49200-49199-52392-255,43-11-10-13-23-5-0-18-51-45-35,29-23-24,0");
        #[cfg(feature = "md5-string")]
        {
            assert_eq!(
                chp.ja3().to_md5_string(),
                "a94fc11547bcef10847672ff518b3fb9"
            )
        }
    }

    #[test]
    fn ja3_from_string() {
        let buf = hex!("16030100f5010000f10303ad8e0c8dfe3adbc045e51aee4cb9480c02d5da4a240f95e8282a1f51be34901a20681af80b44c4b359adb3f9543a966e07e6ba6bed551472a62cd4b107cbd40e830014130213011303c02cc02bcca9c030c02fcca800ff01000094002b00050403040303000b00020100000a00080006001d00170018000d00140012050304030807080608050804060105010401001700000005000501000000000000001800160000137777772e706574616c7365617263682e636f6d00120000003300260024001d0020086fffef5fa7f04fb7d788615bc425820eba366ddb5f75c7d8336a0a05722d38002d0002010100230000");
        let chp = parse_tls_plain_message(&buf)
            .ok()
            .and_then(|message| message.into_client_hello_payload())
            .expect("Message valid");
        let ja3 = "771,4866-4865-4867-49196-49195-52393-49200-49199-52392-255,43-11-10-13-23-5-0-18-51-45-35,29-23-24,0".parse().unwrap();
        println!("{:?}", ja3);
        assert_eq!(chp.ja3(), ja3);
        assert!("771,4866-4865-4867-49196-49195-52393-49200-49199-52392-255,43-11-10-13-23-5-0-18-51-45-35,29-23-24,0,".parse::<Ja3>().is_err());
        assert!("771,".parse::<Ja3>().is_err());
        assert!("a,4866-4865-4867-49196-49195-52393-49200-49199-52392-255,43-11-10-13-23-5-0-18-51-45-35,29-23-24,0".parse::<Ja3>().is_err());
    }

    #[test]
    fn regreasing() {
        let ja3:Ja3 = "771,2570-4866-4865-4867-49196-49195-52393-49200-49199-52392-255,2570-43-11-10-13-23-5-0-18-51-45-2570-35,2570-29-23-24,0".parse().unwrap();
        // failed chance: (1 - (1 - 15/16) ** 3) ~= 17.6%
        assert_ne!(
            ja3.ciphers_regreasing_as_typed().collect::<Vec<_>>(),
            ja3.ciphers_regreasing_as_typed().collect::<Vec<_>>()
        );
        assert_ne!(
            ja3.extensions_regreasing_as_typed().collect::<Vec<_>>(),
            ja3.extensions_regreasing_as_typed().collect::<Vec<_>>()
        );
        assert_ne!(
            ja3.curves_regreasing_as_typed().collect::<Vec<_>>(),
            ja3.curves_regreasing_as_typed().collect::<Vec<_>>()
        );
        assert_eq!(
            ja3.ciphers_as_typed().collect::<Vec<_>>(),
            ja3.ciphers_as_typed().collect::<Vec<_>>()
        );
        assert_eq!(
            ja3.extensions_as_typed().collect::<Vec<_>>(),
            ja3.extensions_as_typed().collect::<Vec<_>>()
        );
        assert_eq!(
            ja3.curves_as_typed().collect::<Vec<_>>(),
            ja3.curves_as_typed().collect::<Vec<_>>()
        );
    }
}
