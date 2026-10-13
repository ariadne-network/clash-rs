//! The certificate authority of HTTPS decryption: a CA the user installs
//! and trusts, and the per-host certificates it signs on the fly.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::{
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    sign::CertifiedKey,
};

/// A new CA for the apps to keep (certificate and private key, PEM), named
/// `name`, valid ten years.
pub fn generate_ca(name: &str) -> Result<(String, String), rcgen::Error> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    dn.push(DnType::OrganizationName, name);
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(3650);
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// Signs host certificates with the CA. One key serves every host; the
/// certificates stay cached.
pub struct Authority {
    issuer: Issuer<'static, KeyPair>,
    leaf_key: KeyPair,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

/// Hosts certified at most at once; past that the cache starts over.
const CACHE_LIMIT: usize = 512;

impl Authority {
    pub fn new(ca_cert_pem: &str, ca_key_pem: &str) -> Result<Self, String> {
        let ca_key =
            KeyPair::from_pem(ca_key_pem).map_err(|e| format!("CA key: {e}"))?;
        let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, ca_key)
            .map_err(|e| format!("CA certificate: {e}"))?;
        let leaf_key = KeyPair::generate().map_err(|e| format!("host key: {e}"))?;
        Ok(Self {
            issuer,
            leaf_key,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// A certificate for `host` (a name or an address). Apple's rules for
    /// TLS server certificates: SAN, serverAuth, at most 825 days.
    pub fn certify(&self, host: &str) -> Result<Arc<CertifiedKey>, String> {
        if let Some(key) = self.cache.lock().unwrap().get(host) {
            return Ok(key.clone());
        }
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| e.to_string())?;
        params.subject_alt_names = vec![match host.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(
                host.to_owned()
                    .try_into()
                    .map_err(|e| format!("{host}: {e}"))?,
            ),
        }];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(397);
        let cert = params
            .signed_by(&self.leaf_key, &self.issuer)
            .map_err(|e| format!("{host}: {e}"))?;
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            self.leaf_key.serialize_der(),
        ));
        let provider = CryptoProvider::get_default()
            .cloned()
            .ok_or("no TLS crypto provider")?;
        let signing_key = provider
            .key_provider
            .load_private_key(key_der)
            .map_err(|e| e.to_string())?;
        let certified = Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(cert.der().to_vec())],
            signing_key,
        ));
        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= CACHE_LIMIT {
            cache.clear();
        }
        cache.insert(host.to_owned(), certified.clone());
        Ok(certified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_ca_signs_host_certificates() {
        crate::setup_default_crypto_provider();
        let (cert, key) = generate_ca("Test CA").unwrap();
        assert!(cert.starts_with("-----BEGIN CERTIFICATE-----"));
        let authority = Authority::new(&cert, &key).unwrap();
        let a = authority.certify("example.com").unwrap();
        let b = authority.certify("example.com").unwrap();
        assert!(Arc::ptr_eq(&a, &b), "cached");
        authority.certify("192.0.2.1").unwrap();
    }
}
