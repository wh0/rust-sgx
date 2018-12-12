/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::Cow;
use std::mem;

use byteorder::{ByteOrder, LE};
use num_traits::FromPrimitive;

// ====================================================
// ================= TYPE DEFINITIONS =================
// ====================================================

pub struct Quote<'a> {
    header: QuoteHeader<'a>,
    report_body: Cow<'a, [u8]>,
    signature: Cow<'a, [u8]>,
}

pub enum QuoteHeader<'a> {
    V3 {
        attestation_key_type: Quote3AttestationKeyType,
        qe3_svn: u16,
        pce_svn: u16,
        qe3_vendor_id: Cow<'a, [u8]>,
        user_data: Cow<'a, [u8]>,
    },
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, FromPrimitive, ToPrimitive)]
pub enum Quote3AttestationKeyType {
    EcdsaP256 = 2,
    EcdsaP384 = 3,
}

pub const QE3_VENDOR_ID_INTEL: [u8; 16] = [
    0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
];

pub type QeId<'a> = Cow<'a, [u8]>;

pub struct Quote3SignatureEcdsaP256<'a> {
    signature: Cow<'a, [u8]>,
    attestation_public_key: Cow<'a, [u8]>,
    qe3_report: Cow<'a, [u8]>,
    qe3_signature: Cow<'a, [u8]>,
    authentication_data: Cow<'a, [u8]>,
    certification_data_type: CertificationDataType,
    certification_data: Cow<'a, [u8]>,
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, FromPrimitive, ToPrimitive)]
pub enum CertificationDataType {
    PpidCleartext = 1,
    PpidEncryptedRsa2048 = 2,
    PpidEncryptedRsa3072 = 3,
    PckCertificate = 4,
    PckCertificateChain = 5,
    EcdsaSignatureAuxiliaryData = 6,
    PlatformManifest = 7,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Qe3CertDataPpid<'a> {
    pub ppid: Cow<'a, [u8]>,
    pub cpusvn: Cow<'a, [u8]>,
    pub pcesvn: u16,
    pub pceid: u16,
}

pub type Result<T> = ::std::result::Result<T, ::failure::Error>;

// ===========================================
// ================= PARSING =================
// ===========================================

trait TrySplitAt {
    fn try_split_at(&self, mid: usize) -> Result<(&Self, &Self)>;

    fn try_split_at_map<'a, F: FnOnce(&'a Self) -> R, R: 'a>(
        &'a self,
        mid: usize,
        f: F,
    ) -> Result<(R, &'a Self)> {
        let (a, b) = self.try_split_at(mid)?;
        Ok((f(a), b))
    }
}

impl<T> TrySplitAt for [T] {
    fn try_split_at(&self, mid: usize) -> Result<(&Self, &Self)> {
        match (self.get(..mid), self.get(mid..)) {
            (Some(a), Some(b)) => Ok((a, b)),
            _ => bail!("Unexpected end of quote"),
        }
    }
}

pub trait Quote3Signature<'a>: Sized {
    fn parse(type_: Quote3AttestationKeyType, data: &'a [u8]) -> Result<Self>;
}

pub trait Qe3CertData<'a>: Sized {
    fn parse(type_: CertificationDataType, data: &'a [u8]) -> Result<Self>;
}

const ECDSA_P256_SIGNATURE_LEN: usize = 64;
const ECDSA_P256_PUBLIC_KEY_LEN: usize = 64;
const QE3_VENDOR_ID_LEN: usize = 16;
const QE3_USER_DATA_LEN: usize = 20;
const REPORT_BODY_LEN: usize = 384;
const CPUSVN_LEN: usize = 16;
const QUOTE_VERSION_3: u16 = 3;

impl<'a> Quote<'a> {
    pub fn parse(quote: &'a [u8]) -> Result<Quote<'a>> {
        let (version, rest) = quote.try_split_at_map(mem::size_of::<u16>(), LE::read_u16)?;
        if version != QUOTE_VERSION_3 {
            bail!("Unknown quote version: {}", version);
        }
        let (att_key_type, rest) = rest.try_split_at_map(mem::size_of::<u16>(), LE::read_u16)?;
        let attestation_key_type = Quote3AttestationKeyType::from_u16(att_key_type)
            .ok_or_else(|| format_err!("Unknown attestation key type: {}", att_key_type))?;
        let (reserved, rest) = rest.try_split_at_map(mem::size_of::<u32>(), LE::read_u32)?;
        if reserved != 0 {
            bail!("Data in reserved field: {:08x}", reserved);
        }
        let (qe3_svn, rest) = rest.try_split_at_map(mem::size_of::<u16>(), LE::read_u16)?;
        let (pce_svn, rest) = rest.try_split_at_map(mem::size_of::<u16>(), LE::read_u16)?;
        let (qe3_vendor_id, rest) = rest.try_split_at_map(QE3_VENDOR_ID_LEN, Cow::from)?;
        let (user_data, rest) = rest.try_split_at_map(QE3_USER_DATA_LEN, Cow::from)?;
        let (report_body, signature) = rest.try_split_at_map(REPORT_BODY_LEN, Cow::from)?;

        Ok(Quote {
            header: QuoteHeader::V3 {
                attestation_key_type,
                qe3_svn,
                pce_svn,
                qe3_vendor_id,
                user_data,
            },
            report_body,
            signature: signature.into(),
        })
    }
}

impl<'a> Quote3Signature<'a> for Quote3SignatureEcdsaP256<'a> {
    fn parse(type_: Quote3AttestationKeyType, data: &'a [u8]) -> Result<Self> {
        if type_ != Quote3AttestationKeyType::EcdsaP256 {
            bail!("Invalid attestation key type: {:?}", type_)
        }

        let (sig_len, rest) = data.try_split_at_map(mem::size_of::<u32>(), LE::read_u32)?;
        if sig_len as usize != rest.len() {
            bail!(
                "Invalid signature length. Got {}, expected {}",
                rest.len(),
                sig_len
            );
        }
        let (signature, rest) = rest.try_split_at_map(ECDSA_P256_SIGNATURE_LEN, Cow::from)?;
        let (attestation_public_key, rest) =
            rest.try_split_at_map(ECDSA_P256_PUBLIC_KEY_LEN, Cow::from)?;
        let (qe3_report, rest) = rest.try_split_at_map(REPORT_BODY_LEN, Cow::from)?;
        let (qe3_signature, rest) = rest.try_split_at_map(ECDSA_P256_SIGNATURE_LEN, Cow::from)?;
        let (authdata_len, rest) = rest.try_split_at_map(mem::size_of::<u16>(), LE::read_u16)?;
        let (authentication_data, rest) = rest.try_split_at_map(authdata_len as _, Cow::from)?;
        let (cd_type, rest) = rest.try_split_at_map(mem::size_of::<u16>(), LE::read_u16)?;
        let certification_data_type = CertificationDataType::from_u16(cd_type)
            .ok_or_else(|| format_err!("Unknown certification data type: {}", cd_type))?;
        let (certdata_len, certification_data) =
            rest.try_split_at_map(mem::size_of::<u32>(), LE::read_u32)?;
        if certdata_len as usize != certification_data.len() {
            bail!(
                "Invalid certification data length. Got {}, expected {}",
                certification_data.len(),
                certdata_len
            );
        }

        Ok(Quote3SignatureEcdsaP256 {
            signature: signature.into(),
            attestation_public_key: attestation_public_key.into(),
            qe3_report: qe3_report.into(),
            qe3_signature: qe3_signature.into(),
            authentication_data: authentication_data.into(),
            certification_data_type,
            certification_data: certification_data.into(),
        })
    }
}

impl<'a> Qe3CertData<'a> for Qe3CertDataPpid<'a> {
    fn parse(type_: CertificationDataType, data: &'a [u8]) -> Result<Self> {
        let ppid_len = match type_ {
            CertificationDataType::PpidCleartext => bail!(
                "PPID clear text not implemented. Data length = {}",
                data.len()
            ),
            CertificationDataType::PpidEncryptedRsa2048 => 256,
            CertificationDataType::PpidEncryptedRsa3072 => 384,
            _ => bail!("Invalid certification data type: {:?}", type_),
        };

        let (ppid, rest) = data.try_split_at_map(ppid_len, Cow::from)?;
        let (cpusvn, rest) = rest.try_split_at_map(CPUSVN_LEN, Cow::from)?;
        let (pcesvn, rest) = rest.try_split_at_map(mem::size_of::<u16>(), LE::read_u16)?;
        let (pceid, rest) = rest.try_split_at_map(mem::size_of::<u16>(), LE::read_u16)?;
        if !rest.is_empty() {
            bail!(
                "Invalid certification data length for type {:?}: {}",
                type_,
                data.len()
            );
        }

        Ok(Qe3CertDataPpid {
            ppid: ppid.into(),
            cpusvn: cpusvn.into(),
            pcesvn,
            pceid,
        })
    }
}

// =============================================
// ================= ACCESSORS =================
// =============================================

impl<'a> Quote<'a> {
    pub fn header(&self) -> &QuoteHeader<'a> {
        &self.header
    }

    pub fn report_body(&self) -> &[u8] {
        &self.report_body
    }

    pub fn signature<'b, T: Quote3Signature<'b>>(&'b self) -> Result<T> {
        let QuoteHeader::V3 {
            attestation_key_type,
            ..
        } = self.header;
        T::parse(attestation_key_type, &self.signature)
    }

    pub fn clone_owned(&self) -> Quote<'static> {
        Quote {
            header: self.header.clone_owned(),
            report_body: self.report_body.clone().into_owned().into(),
            signature: self.signature.clone().into_owned().into(),
        }
    }
}

impl<'a> QuoteHeader<'a> {
    pub fn clone_owned(&self) -> QuoteHeader<'static> {
        match *self {
            QuoteHeader::V3 {
                attestation_key_type,
                qe3_svn,
                pce_svn,
                ref qe3_vendor_id,
                ref user_data,
            } => QuoteHeader::V3 {
                attestation_key_type,
                qe3_svn,
                pce_svn,
                qe3_vendor_id: qe3_vendor_id.clone().into_owned().into(),
                user_data: user_data.clone().into_owned().into(),
            },
        }
    }
}

impl<'a> Quote3SignatureEcdsaP256<'a> {
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn attestation_public_key(&self) -> &[u8] {
        &self.attestation_public_key
    }

    pub fn qe3_report(&self) -> &[u8] {
        &self.qe3_report
    }

    pub fn qe3_signature(&self) -> &[u8] {
        &self.qe3_signature
    }

    pub fn authentication_data(&self) -> &[u8] {
        &self.authentication_data
    }

    pub fn certification_data_type(&self) -> CertificationDataType {
        self.certification_data_type
    }

    pub fn certification_data<'b, T: Qe3CertData<'b>>(&'b self) -> Result<T> {
        T::parse(self.certification_data_type, &self.certification_data)
    }

    pub fn clone_owned(&self) -> Quote3SignatureEcdsaP256<'static> {
        Quote3SignatureEcdsaP256 {
            signature: self.signature.clone().into_owned().into(),
            attestation_public_key: self.attestation_public_key.clone().into_owned().into(),
            qe3_report: self.qe3_report.clone().into_owned().into(),
            qe3_signature: self.qe3_signature.clone().into_owned().into(),
            authentication_data: self.authentication_data.clone().into_owned().into(),
            certification_data_type: self.certification_data_type,
            certification_data: self.certification_data.clone().into_owned().into(),
        }
    }
}

impl<'a> Qe3CertDataPpid<'a> {
    pub fn clone_owned(&self) -> Qe3CertDataPpid<'static> {
        Qe3CertDataPpid {
            ppid: self.ppid.clone().into_owned().into(),
            cpusvn: self.cpusvn.clone().into_owned().into(),
            pcesvn: self.pcesvn,
            pceid: self.pceid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_certdata() {
        const TEST_QUOTE: &[u8] = &*include_bytes!("../tests/quote_raw_tcb.bin");
        const QE_ID: [u8; 16] = [
            0x00, 0xfb, 0xe6, 0x73, 0x33, 0x36, 0xea, 0xf7, 0xa4, 0xe3, 0xd8, 0xb9, 0x66, 0xa8,
            0x2e, 0x64,
        ];

        const EXPECTED_PPID: &[u8; 384] = include_bytes!("../tests/encrypted_ppid.bin");
        const EXPECTED_CPUSVN: [u8; 16] = [
            0x05, 0x05, 0x02, 0x05, 0xff, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        const EXPECTED_PCESVN: u16 = 6;
        const EXPECTED_PCEID: u16 = 0;

        let quote = Quote::parse(TEST_QUOTE).unwrap();
        let &QuoteHeader::V3 {
            attestation_key_type,
            ref qe3_vendor_id,
            ref user_data,
            ..
        } = quote.header();

        assert_eq!(qe3_vendor_id, &&QE3_VENDOR_ID_INTEL[..]);
        let mut ud = QE_ID.to_vec();
        ud.resize(20usize, 0u8);
        assert_eq!(user_data, &ud);

        assert_eq!(attestation_key_type, Quote3AttestationKeyType::EcdsaP256);
        let sig = quote.signature::<Quote3SignatureEcdsaP256>().unwrap();

        assert_eq!(
            sig.certification_data_type(),
            CertificationDataType::PpidEncryptedRsa3072
        );
        let cd = sig.certification_data::<Qe3CertDataPpid>().unwrap();

        assert_eq!(cd.ppid, &EXPECTED_PPID[..]);
        assert_eq!(cd.cpusvn, &EXPECTED_CPUSVN[..]);
        assert_eq!(cd.pcesvn, EXPECTED_PCESVN);
        assert_eq!(cd.pceid, EXPECTED_PCEID);
    }
}
