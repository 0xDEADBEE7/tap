//! The local interception CA, per-host leaf certificates, and the TLS client
//! configuration TAP uses for upstream connections.

use crate::paths;
use base64::Engine;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(test)]
mod tests;

const DAY: Duration = Duration::from_secs(86_400);
const CA_VALIDITY_DAYS: u32 = 3_652;
/// Apple rejects TLS server certificates valid for more than 398 days (1 day backdated + 397).
const LEAF_VALIDITY_DAYS: u32 = 397;
/// X.520 upper bound for a CommonName; longer hosts get a SAN-only certificate.
const MAX_COMMON_NAME: usize = 64;

pub struct Ca {
    cert_pem: String,
    /// The certificate exactly as stored in `ca.pem`, served after every leaf.
    cert_der: CertificateDer<'static>,
    /// Re-created from `ca.pem` + `ca.key`; supplies the issuer name and key identifier.
    issuer: rcgen::Certificate,
    issuer_key: KeyPair,
    /// One key for every leaf this instance issues.
    leaf_key: KeyPair,
    provider: Arc<CryptoProvider>,
    configs: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl Ca {
    /// Loads `dir/ca.pem` + `dir/ca.key`, or creates them (dir 0700, key 0600)
    /// if neither exists. Errors if only one of the two exists.
    pub fn load_or_create(dir: &Path) -> io::Result<Ca> {
        let cert_path = Self::cert_path(dir);
        let key_path = dir.join("ca.key");
        if !(exists(&cert_path)? && exists(&key_path)?) {
            create_once(dir, &cert_path, &key_path)?;
        }
        let cert_pem = read(&cert_path)?;
        let key_pem = read(&key_path)?;
        Ca::from_pem(cert_pem, &key_pem).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cannot load the TAP CA from {}: {error}; delete ca.pem and ca.key there to create a new CA",
                    dir.display()
                ),
            )
        })
    }

    /// `dir/ca.pem`, the file users point their clients at.
    pub fn cert_path(dir: &Path) -> PathBuf {
        dir.join("ca.pem")
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// A server config presenting a leaf certificate for `host` (DNS name or IP
    /// literal) signed by this CA, advertising ALPN `h2` and `http/1.1`.
    /// Generated on first use and cached per host.
    pub fn server_config(&self, host: &str) -> io::Result<Arc<ServerConfig>> {
        let host = normalize_host(host)?;
        if let Some(config) = self.lock_configs().get(&host) {
            return Ok(config.clone());
        }
        let leaf = self.issue_leaf(&host)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()));
        let mut config = ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|error| tls_error("configuring TLS", error))?
            .with_no_client_auth()
            .with_single_cert(vec![leaf, self.cert_der.clone()], key)
            .map_err(|error| tls_error(&format!("configuring TLS for {host}"), error))?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let config = Arc::new(config);
        Ok(self.lock_configs().entry(host).or_insert(config).clone())
    }

    fn from_pem(cert_pem: String, key_pem: &str) -> io::Result<Ca> {
        let provider = provider();
        let cert_der = CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .map_err(|error| invalid(format!("ca.pem holds no usable certificate ({error})")))?;
        let issuer_key = KeyPair::from_pem(key_pem)
            .map_err(|error| invalid(format!("ca.key holds no usable private key ({error})")))?;
        let issuer_key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(issuer_key.serialize_der()));
        CertifiedKey::from_der(vec![cert_der.clone()], issuer_key_der, &provider)
            .map_err(|error| invalid(format!("ca.key does not belong to ca.pem ({error})")))?;
        let issuer = CertificateParams::from_ca_cert_pem(&cert_pem)
            .and_then(|params| params.self_signed(&issuer_key))
            .map_err(|error| invalid(format!("ca.pem cannot be used as an issuer ({error})")))?;
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|error| tls_error("generating the leaf key", error))?;
        Ok(Ca {
            cert_pem,
            cert_der,
            issuer,
            issuer_key,
            leaf_key,
            provider,
            configs: Mutex::new(HashMap::new()),
        })
    }

    /// Issues a leaf for an already normalised host.
    fn issue_leaf(&self, host: &str) -> io::Result<CertificateDer<'static>> {
        let san = match host.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(host.try_into().map_err(|error| {
                invalid(format!(
                    "cannot issue a certificate for host {host:?} ({error})"
                ))
            })?),
        };
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![san];
        params.distinguished_name = DistinguishedName::new();
        if host.len() <= MAX_COMMON_NAME {
            params.distinguished_name.push(DnType::CommonName, host);
        }
        // Never empty: strict verifiers (OpenSSL X509_STRICT, Python 3.13+) reject an empty
        // subject unless the SAN is critical, and rcgen cannot mark it critical.
        params
            .distinguished_name
            .push(DnType::OrganizationName, "TAP");
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        set_validity(&mut params, LEAF_VALIDITY_DAYS);
        params.serial_number = Some(random_serial(&self.provider)?);
        let leaf = params
            .signed_by(&self.leaf_key, &self.issuer, &self.issuer_key)
            .map_err(|error| tls_error(&format!("issuing a certificate for {host}"), error))?;
        Ok(leaf.into())
    }

    fn lock_configs(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<ServerConfig>>> {
        self.configs.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Writes `dir/bundle.pem` = the platform's trusted roots followed by the TAP CA,
/// for clients that replace (rather than extend) their trust store via
/// `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE`. Returns its path.
pub fn write_trust_bundle(dir: &Path, ca: &Ca) -> io::Result<PathBuf> {
    let path = dir.join("bundle.pem");
    let native = rustls_native_certs::load_native_certs();
    if native.certs.is_empty() {
        let errors: Vec<String> = native.errors.iter().map(ToString::to_string).collect();
        eprintln!(
            "warning: no platform root certificates could be loaded{}; {} trusts only the TAP CA, \
             so clients using it can reach only intercepted hosts",
            if errors.is_empty() {
                String::new()
            } else {
                format!(" ({})", errors.join("; "))
            },
            path.display()
        );
    }
    let mut seen: HashSet<&[u8]> = HashSet::new();
    seen.insert(ca.cert_der.as_ref());
    let mut bundle = String::new();
    for cert in &native.certs {
        if seen.insert(cert.as_ref()) {
            bundle.push_str(&pem_certificate(cert));
        }
    }
    bundle.push_str(&pem_certificate(&ca.cert_der));
    paths::create_private_dir(dir)?;
    paths::write_private_file(&path, bundle.as_bytes())?;
    Ok(path)
}

/// TLS client config for upstream connections: platform roots plus, if given,
/// the certificates in `extra_ca` (a PEM file). ALPN is left unset (the hyper
/// connector sets it).
pub fn upstream_client_config(extra_ca: Option<&Path>) -> io::Result<rustls::ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    if let Some(path) = extra_ca {
        let certs = CertificateDer::pem_file_iter(path)
            .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
            .map_err(|error| pem_error(path, error))?;
        if certs.is_empty() {
            return Err(invalid(format!(
                "{}: no certificates found (expected PEM \"-----BEGIN CERTIFICATE-----\" blocks)",
                path.display()
            )));
        }
        for cert in certs {
            roots.add(cert).map_err(|error| {
                invalid(format!(
                    "{}: unusable CA certificate ({error})",
                    path.display()
                ))
            })?;
        }
    }
    if roots.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no trusted root certificates for upstream TLS: none could be loaded from the platform \
             store and no extra CA file was given",
        ));
    }
    Ok(ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| tls_error("configuring upstream TLS", error))?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// The process-default provider is never installed; every config names ring explicitly.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Creates the CA unless another process already did. The directory lock keeps
/// concurrent first runs from writing a ca.key and a ca.pem of different CAs.
fn create_once(dir: &Path, cert_path: &Path, key_path: &Path) -> io::Result<()> {
    paths::create_private_dir(dir)?;
    let _lock = lock_dir(dir)?;
    match (exists(cert_path)?, exists(key_path)?) {
        (true, true) => Ok(()),
        (false, false) => create(cert_path, key_path),
        (cert_exists, _) => {
            let (present, missing) = if cert_exists {
                (cert_path, key_path)
            } else {
                (key_path, cert_path)
            };
            Err(invalid(format!(
                "TAP CA is incomplete: {} exists but {} does not; delete {} to create a new CA \
                 (clients that trusted the old ca.pem must then trust the new one)",
                present.display(),
                missing.display(),
                present.display()
            )))
        }
    }
}

/// An exclusive `flock` on `dir`, released when the returned handle is dropped.
fn lock_dir(dir: &Path) -> io::Result<std::fs::File> {
    let handle = std::fs::File::open(dir).map_err(|error| {
        io::Error::new(error.kind(), format!("opening {}: {error}", dir.display()))
    })?;
    while unsafe { libc::flock(handle.as_raw_fd(), libc::LOCK_EX) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::new(
                error.kind(),
                format!("locking {}: {error}", dir.display()),
            ));
        }
    }
    Ok(handle)
}

fn create(cert_path: &Path, key_path: &Path) -> io::Result<()> {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|error| tls_error("generating the CA key", error))?;
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, ca_common_name());
    params
        .distinguished_name
        .push(DnType::OrganizationName, "TAP");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    set_validity(&mut params, CA_VALIDITY_DAYS);
    params.serial_number = Some(random_serial(&provider())?);
    let cert = params
        .self_signed(&key)
        .map_err(|error| tls_error("creating the CA certificate", error))?;
    paths::write_private_file(key_path, key.serialize_pem().as_bytes())?;
    paths::write_private_file(cert_path, cert.pem().as_bytes())
}

fn ca_common_name() -> String {
    match std::env::var("USER") {
        Ok(user) if !user.trim().is_empty() => format!("TAP Local CA ({})", user.trim()),
        _ => "TAP Local CA".to_string(),
    }
}

/// Lowercases, strips IPv6 brackets and a trailing dot, and canonicalises IP literals.
fn normalize_host(host: &str) -> io::Result<String> {
    let host = host.trim();
    let host = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if host.is_empty() {
        return Err(invalid(
            "cannot issue a certificate for an empty host".to_string(),
        ));
    }
    Ok(host)
}

/// Valid from a day ago (tolerates clock skew) until `days` from now, in whole seconds.
fn set_validity(params: &mut CertificateParams, days: u32) {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let now = rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs(since_epoch.as_secs());
    params.not_before = now - DAY;
    params.not_after = now + DAY * days;
}

/// 128 random bits, positive and without a leading zero byte.
fn random_serial(provider: &CryptoProvider) -> io::Result<SerialNumber> {
    let mut bytes = [0u8; 16];
    provider
        .secure_random
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("no secure random source for certificate serial numbers"))?;
    bytes[0] = (bytes[0] & 0x7f) | 0x40;
    Ok(SerialNumber::from_slice(&bytes))
}

fn pem_certificate(cert: &CertificateDer<'_>) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(cert.as_ref());
    let mut pem = String::with_capacity(encoded.len() + encoded.len() / 64 + 60);
    pem.push_str("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

fn exists(path: &Path) -> io::Result<bool> {
    path.try_exists().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("checking {}: {error}", path.display()),
        )
    })
}

fn read(path: &Path) -> io::Result<String> {
    std::fs::read_to_string(path).map_err(|error| {
        io::Error::new(error.kind(), format!("reading {}: {error}", path.display()))
    })
}

fn pem_error(path: &Path, error: pem::Error) -> io::Error {
    match error {
        pem::Error::Io(error) => {
            io::Error::new(error.kind(), format!("reading {}: {error}", path.display()))
        }
        error => invalid(format!("{}: invalid PEM ({error})", path.display())),
    }
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn tls_error(context: &str, error: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("{context}: {error}"))
}
