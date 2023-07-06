use rustls::{
    internal::msgs::{
        enums::NamedGroup,
        handshake::{ClientExtension, ClientHelloPayload},
    },
    ProtocolVersion, SignatureScheme,
};

use crate::get_ja3_from_chp;
use crate::grease::*;
use crate::Ja3;

/// `Ja3` and more fields
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja3andMore {
    pub ja3: Ja3,
    pub alpn: Vec<Vec<u8>>,           // 0x0010
    pub signature_algos: Vec<u16>,    // 0x000d
    pub supported_versions: Vec<u16>, // 0x002b
    pub key_share: Vec<u16>,          // 0x0033
}

pub fn get_ja3_and_more_from_chp(
    chp: &ClientHelloPayload,
    ignore_rfc8701_grease: bool,
) -> Ja3andMore {
    use ClientExtension::*;
    let mut alpn = vec![];
    let mut signature_algos = vec![];
    let mut key_share = vec![];
    let mut supported_versions = vec![];

    let ja3 = get_ja3_from_chp(chp, false, ignore_rfc8701_grease);
    for extension in chp.extensions.iter() {
        match extension {
            Protocols(protos) => {
                alpn = protos
                    .iter()
                    .map(|pld| pld.clone().as_ref().to_vec())
                    .collect();
            }
            SignatureAlgorithms(algos) => {
                signature_algos = algos
                    .iter()
                    .map(|algo| algo.get_u16())
                    .filter(|&ext| !ignore_rfc8701_grease || !is_grease_u16_be(ext))
                    .collect()
            }
            KeyShare(ents) => {
                key_share = ents
                    .iter()
                    .map(|ent| ent.group.get_u16())
                    .filter(|&ext| !ignore_rfc8701_grease || !is_grease_u16_be(ext))
                    .collect()
            }
            SupportedVersions(vers) => {
                // TODO: GREASE in supported versions is not a part of RFC8701?
                supported_versions = vers
                    .iter()
                    .map(|ver| ver.get_u16())
                    .filter(|&ext| !ignore_rfc8701_grease || !is_grease_u16_be(ext))
                    .collect()
            }
            _ => {}
        }
    }
    Ja3andMore {
        ja3,
        alpn,
        signature_algos,
        key_share,
        supported_versions,
    }
}

impl Ja3andMore {
    pub fn into_ja3(self) -> Ja3 {
        self.ja3
    }

    pub fn signature_algos_as_typed(&self) -> impl Iterator<Item = SignatureScheme> + '_ {
        self.signature_algos.iter().map(|&algo| algo.into())
    }

    pub fn key_share_as_typed(&self) -> impl Iterator<Item = NamedGroup> + '_ {
        self.key_share.iter().map(|&curve| curve.into())
    }

    pub fn supported_verisons_as_typed(&self) -> impl Iterator<Item = ProtocolVersion> + '_ {
        self.supported_versions.iter().map(|&ver| ver.into())
    }

    /// `signature_algos_as_typed` with existing GREASE values rewritten as newly generated ones. It
    /// is based on an insecure RNG unless the `rand` crate feature is activated.
    pub fn signature_algos_regreasing_as_typed(
        &self,
    ) -> impl Iterator<Item = SignatureScheme> + '_ {
        self.signature_algos
            .iter()
            .map(|&algo| try_regrease_u16_be(algo).into())
    }

    /// `key_share_as_typed` with existing GREASE values rewritten as newly generated ones. It
    /// is based on an insecure RNG unless the `rand` crate feature is activated.
    pub fn key_share_regreasing_as_typed(&self) -> impl Iterator<Item = NamedGroup> + '_ {
        self.key_share
            .iter()
            .map(|&curve| try_regrease_u16_be(curve).into())
    }

    /// `supported_versions_as_typed` with existing GREASE values rewritten as newly generated ones.
    /// It is based on an insecure RNG unless the `rand` crate feature is activated.
    pub fn supported_verisons_regreasing_as_typed(
        &self,
    ) -> impl Iterator<Item = ProtocolVersion> + '_ {
        self.supported_versions
            .iter()
            .map(|&ver| try_regrease_u16_be(ver).into())
    }
}

// macro_rules! impl_as_typed {
//     ($field: ident, $type:ty) => {
//         fn $(field)_as_typed(&self) -> impl Iterator<Item = SignatureAlgorithms> + '_
//     }
// }
