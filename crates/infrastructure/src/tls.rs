//! The server's TLS identity: a self-signed certificate, generated once.
//!
//! There is no certificate authority on a home network, so apps do not
//! check this certificate against one: they pin its SHA-256 fingerprint,
//! which the server prints at start-up and the user confirms once per phone.

use larder_server_application::error::{ServerError, ServerResult};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, date_time_ymd};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use sha2::{Digest, Sha256};

use crate::security::hex;

fn internal(e: impl std::fmt::Display) -> ServerError {
    ServerError::Internal(e.to_string())
}

/// Certificate and private key, PEM encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsIdentity {
    pub cert_pem: String,
    pub key_pem: String,
}

impl TlsIdentity {
    /// A new ECDSA P-256 key and a self-signed certificate for it.
    ///
    /// Valid until 2075: a pinned certificate gains nothing from expiring,
    /// and replacing it means every phone has to confirm the new one.
    pub fn generate() -> ServerResult<Self> {
        let key = KeyPair::generate().map_err(internal)?;
        let mut params =
            CertificateParams::new(vec!["localhost".to_string(), "larder-server".to_string()])
                .map_err(internal)?;
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "Larder household server");
        params.distinguished_name = name;
        params.not_before = date_time_ymd(2025, 1, 1);
        params.not_after = date_time_ymd(2075, 1, 1);
        let cert = params.self_signed(&key).map_err(internal)?;
        Ok(Self {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        })
    }

    /// SHA-256 of the certificate, lowercase hex: what apps pin.
    pub fn fingerprint(&self) -> ServerResult<String> {
        let der = CertificateDer::from_pem_slice(self.cert_pem.as_bytes()).map_err(internal)?;
        Ok(hex(&Sha256::digest(der.as_ref())))
    }
}

/// A fingerprint in groups of four, easier to compare by eye.
pub fn display_fingerprint(hex: &str) -> String {
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identities_are_distinct_and_parse() {
        let a = TlsIdentity::generate().unwrap();
        let b = TlsIdentity::generate().unwrap();
        assert!(a.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(a.key_pem.contains("PRIVATE KEY"));
        let fa = a.fingerprint().unwrap();
        assert_eq!(fa.len(), 64);
        assert!(
            fa.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
        assert_ne!(fa, b.fingerprint().unwrap());
    }

    #[test]
    fn fingerprint_is_shown_in_groups_of_four() {
        assert_eq!(display_fingerprint("0123456789ab"), "0123 4567 89ab");
    }
}
