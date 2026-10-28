use super::*;
use rcgen::DnValue;
use rustls::pki_types::ServerName;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU32, Ordering};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "tap-tls-test-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        TempDir(path)
    }

    /// A not-yet-existing CA directory inside the temp dir.
    fn ca_dir(&self) -> PathBuf {
        self.0.join("ca")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn certs_in(pem: &[u8]) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(pem)
        .map(Result::unwrap)
        .collect()
}

fn client_trusting(pem: &[u8], alpn: &[&[u8]]) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    for cert in certs_in(pem) {
        roots.add(cert).unwrap();
    }
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    config
}

struct Negotiated {
    alpn: Option<Vec<u8>>,
    chain: Vec<CertificateDer<'static>>,
    version: Option<rustls::ProtocolVersion>,
}

/// A real TLS handshake over an in-memory pipe. Err carries the client's error.
async fn handshake(
    server: Arc<ServerConfig>,
    client: ClientConfig,
    server_name: &str,
) -> Result<Negotiated, String> {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let acceptor = tokio_rustls::TlsAcceptor::from(server);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let name = ServerName::try_from(server_name.to_string()).unwrap();
    let (server_result, client_result) = tokio::join!(
        acceptor.accept(server_io),
        connector.connect(name, client_io)
    );
    let client_stream = client_result.map_err(|error| error.to_string())?;
    server_result.map_err(|error| format!("server side failed: {error}"))?;
    let (_, connection) = client_stream.get_ref();
    Ok(Negotiated {
        alpn: connection.alpn_protocol().map(<[u8]>::to_vec),
        chain: connection.peer_certificates().unwrap_or_default().to_vec(),
        version: connection.protocol_version(),
    })
}

#[test]
fn ca_is_shareable_across_tasks() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Ca>();
}

#[test]
fn creates_private_files_and_reloads_the_same_ca() {
    let temp = TempDir::new("create");
    let dir = temp.ca_dir();
    let created = Ca::load_or_create(&dir).unwrap();
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join("ca.key")), 0o600);
    assert_eq!(mode(&Ca::cert_path(&dir)), 0o600);
    assert_eq!(
        fs::read_to_string(Ca::cert_path(&dir)).unwrap(),
        created.cert_pem()
    );
    assert!(created
        .cert_pem()
        .starts_with("-----BEGIN CERTIFICATE-----"));

    let reloaded = Ca::load_or_create(&dir).unwrap();
    assert_eq!(reloaded.cert_pem(), created.cert_pem());
    assert_eq!(reloaded.cert_der, created.cert_der);
}

#[test]
fn ca_certificate_has_the_expected_shape() {
    let temp = TempDir::new("shape");
    let ca = Ca::load_or_create(&temp.ca_dir()).unwrap();
    let params = CertificateParams::from_ca_cert_pem(ca.cert_pem()).unwrap();
    assert_eq!(params.is_ca, IsCa::Ca(BasicConstraints::Unconstrained));
    for usage in [
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ] {
        assert!(params.key_usages.contains(&usage), "missing {usage:?}");
    }
    match params.distinguished_name.get(&DnType::CommonName) {
        Some(DnValue::Utf8String(name)) => assert!(name.starts_with("TAP Local CA"), "{name}"),
        other => panic!("unexpected CN {other:?}"),
    }
    assert_eq!(
        params.distinguished_name.get(&DnType::OrganizationName),
        Some(&DnValue::Utf8String("TAP".into()))
    );
    let days = (params.not_after - params.not_before).whole_days();
    assert_eq!(days, i64::from(CA_VALIDITY_DAYS) + 1);
    let key = fs::read_to_string(temp.ca_dir().join("ca.key")).unwrap();
    assert_eq!(
        KeyPair::from_pem(&key).unwrap().algorithm(),
        &rcgen::PKCS_ECDSA_P256_SHA256
    );
}

#[test]
fn errors_when_only_one_file_exists() {
    let temp = TempDir::new("half");
    let dir = temp.ca_dir();
    drop(Ca::load_or_create(&dir).unwrap());
    let key = fs::read(dir.join("ca.key")).unwrap();

    fs::remove_file(dir.join("ca.key")).unwrap();
    let error = Ca::load_or_create(&dir).err().unwrap().to_string();
    assert!(
        error.contains("ca.pem exists but") && error.contains("ca.key does not"),
        "{error}"
    );
    assert!(error.contains("delete"), "{error}");

    fs::write(dir.join("ca.key"), key).unwrap();
    fs::remove_file(Ca::cert_path(&dir)).unwrap();
    let error = Ca::load_or_create(&dir).err().unwrap().to_string();
    assert!(
        error.contains("ca.key exists but") && error.contains("ca.pem does not"),
        "{error}"
    );
}

#[test]
fn errors_when_key_does_not_match_certificate() {
    let first = TempDir::new("mismatch-a");
    let second = TempDir::new("mismatch-b");
    drop(Ca::load_or_create(&first.ca_dir()).unwrap());
    drop(Ca::load_or_create(&second.ca_dir()).unwrap());
    fs::copy(
        second.ca_dir().join("ca.key"),
        first.ca_dir().join("ca.key"),
    )
    .unwrap();
    let error = Ca::load_or_create(&first.ca_dir())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("does not belong"), "{error}");
}

#[test]
fn issues_leaves_for_dns_names_and_ip_literals() {
    let temp = TempDir::new("leaves");
    let ca = Ca::load_or_create(&temp.ca_dir()).unwrap();
    let cases: [(&str, SanType, &str); 5] = [
        (
            "example.test",
            SanType::DnsName("example.test".try_into().unwrap()),
            "example.test",
        ),
        (
            "API.Example.TEST",
            SanType::DnsName("api.example.test".try_into().unwrap()),
            "api.example.test",
        ),
        (
            "127.0.0.1",
            SanType::IpAddress("127.0.0.1".parse().unwrap()),
            "127.0.0.1",
        ),
        ("::1", SanType::IpAddress("::1".parse().unwrap()), "::1"),
        ("[::1]", SanType::IpAddress("::1".parse().unwrap()), "::1"),
    ];
    for (host, san, common_name) in cases {
        let normalized = normalize_host(host).unwrap();
        let leaf = ca.issue_leaf(&normalized).unwrap();
        let params = CertificateParams::from_ca_cert_der(&leaf).unwrap();
        assert_eq!(params.subject_alt_names, vec![san], "{host}");
        assert_eq!(
            params.distinguished_name.get(&DnType::CommonName),
            Some(&DnValue::Utf8String(common_name.into())),
            "{host}"
        );
        assert_eq!(
            params.extended_key_usages,
            vec![ExtendedKeyUsagePurpose::ServerAuth]
        );
        assert_eq!(params.key_usages, vec![KeyUsagePurpose::DigitalSignature]);
        assert_eq!(params.is_ca, IsCa::ExplicitNoCa);
        assert_eq!((params.not_after - params.not_before).whole_days(), 398);
        ca.server_config(host).unwrap();
    }
    assert!(Arc::ptr_eq(
        &ca.server_config("::1").unwrap(),
        &ca.server_config("[::1]").unwrap()
    ));
    assert!(Arc::ptr_eq(
        &ca.server_config("example.test").unwrap(),
        &ca.server_config("EXAMPLE.test").unwrap()
    ));
    assert!(ca.server_config("").is_err());
}

#[test]
fn leaf_serials_are_random() {
    let temp = TempDir::new("serials");
    let ca = Ca::load_or_create(&temp.ca_dir()).unwrap();
    let serial = |host: &str| {
        let leaf = ca.issue_leaf(host).unwrap();
        CertificateParams::from_ca_cert_der(&leaf)
            .unwrap()
            .serial_number
            .unwrap()
    };
    let first = serial("a.test");
    assert_ne!(first, serial("b.test"));
    assert_ne!(first, serial("a.test"));
    assert_eq!(first.len(), 16);
}

#[tokio::test]
async fn handshake_succeeds_for_a_client_trusting_ca_pem() {
    let temp = TempDir::new("handshake");
    let ca = Ca::load_or_create(&temp.ca_dir()).unwrap();
    let ca_pem = fs::read(Ca::cert_path(&temp.ca_dir())).unwrap();

    for (host, server_name) in [
        ("example.test", "example.test"),
        ("127.0.0.1", "127.0.0.1"),
        ("::1", "::1"),
        ("[::1]", "::1"),
    ] {
        let client = client_trusting(&ca_pem, &[b"h2", b"http/1.1"]);
        let negotiated = handshake(ca.server_config(host).unwrap(), client, server_name)
            .await
            .unwrap_or_else(|error| panic!("{host}: {error}"));
        assert_eq!(negotiated.alpn.as_deref(), Some(&b"h2"[..]), "{host}");
        assert_eq!(negotiated.chain.len(), 2);
        assert_eq!(negotiated.chain[1], ca.cert_der);
    }

    let client = client_trusting(&ca_pem, &[b"http/1.1"]);
    let negotiated = handshake(
        ca.server_config("example.test").unwrap(),
        client,
        "example.test",
    )
    .await
    .unwrap();
    assert_eq!(negotiated.alpn.as_deref(), Some(&b"http/1.1"[..]));
}

#[tokio::test]
async fn handshake_fails_for_wrong_root_or_wrong_name() {
    let temp = TempDir::new("wrong-root");
    let other = TempDir::new("wrong-root-other");
    let ca = Ca::load_or_create(&temp.ca_dir()).unwrap();
    let other_ca = Ca::load_or_create(&other.ca_dir()).unwrap();

    let client = client_trusting(other_ca.cert_pem().as_bytes(), &[b"h2"]);
    let error = handshake(
        ca.server_config("example.test").unwrap(),
        client,
        "example.test",
    )
    .await
    .err()
    .unwrap();
    // Every TAP CA has the same subject, so the client finds a name match and rejects the signature.
    assert!(
        error.contains("invalid peer certificate: BadSignature"),
        "{error}"
    );

    let client = client_trusting(ca.cert_pem().as_bytes(), &[b"h2"]);
    let error = handshake(
        ca.server_config("example.test").unwrap(),
        client,
        "other.test",
    )
    .await
    .err()
    .unwrap();
    assert!(
        error.contains("not valid for name \"other.test\""),
        "{error}"
    );
}

#[tokio::test]
async fn reloaded_ca_issues_leaves_trusted_by_the_original_ca_pem() {
    let temp = TempDir::new("reload");
    let dir = temp.ca_dir();
    let original = Ca::load_or_create(&dir).unwrap();
    let original_pem = fs::read(Ca::cert_path(&dir)).unwrap();
    let original_der = original.cert_der.clone();
    drop(original);

    let reloaded = Ca::load_or_create(&dir).unwrap();
    let client = client_trusting(&original_pem, &[b"h2", b"http/1.1"]);
    let negotiated = handshake(
        reloaded.server_config("reload.test").unwrap(),
        client,
        "reload.test",
    )
    .await
    .unwrap();
    assert_eq!(negotiated.chain[1], original_der);
    assert_eq!(certs_in(&original_pem), vec![original_der]);
}

#[test]
fn trust_bundle_holds_platform_roots_then_the_ca() {
    let temp = TempDir::new("bundle");
    let ca = Ca::load_or_create(&temp.ca_dir()).unwrap();
    let path = write_trust_bundle(&temp.ca_dir(), &ca).unwrap();
    assert_eq!(path, temp.ca_dir().join("bundle.pem"));
    assert_eq!(mode(&path), 0o600);

    let text = fs::read_to_string(&path).unwrap();
    let certs = certs_in(text.as_bytes());
    assert_eq!(certs.last(), Some(&ca.cert_der));
    assert!(certs.len() > 1, "expected platform roots before the TAP CA");
    let unique: HashSet<&[u8]> = certs.iter().map(|cert| cert.as_ref()).collect();
    assert_eq!(unique.len(), certs.len(), "bundle has duplicates");
    assert!(text.ends_with(&pem_certificate(&ca.cert_der)));
    assert!(text.lines().all(|line| line.len() <= 64));
    assert!(text.contains(ca.cert_pem().trim()));
}

#[tokio::test]
async fn upstream_config_trusts_extra_ca_file() {
    let temp = TempDir::new("upstream");
    let upstream_ca = Ca::load_or_create(&temp.ca_dir()).unwrap();
    let extra = Ca::cert_path(&temp.ca_dir());
    let server = upstream_ca.server_config("upstream.test").unwrap();

    let client = upstream_client_config(Some(&extra)).unwrap();
    assert!(client.alpn_protocols.is_empty());
    let negotiated = handshake(server.clone(), client, "upstream.test")
        .await
        .unwrap();
    assert_eq!(negotiated.alpn, None);

    let client = upstream_client_config(None).unwrap();
    let error = handshake(server, client, "upstream.test")
        .await
        .err()
        .unwrap();
    assert!(error.contains("UnknownIssuer"), "{error}");
}

#[test]
fn upstream_config_rejects_unusable_extra_ca_files() {
    let temp = TempDir::new("upstream-bad");
    fs::create_dir_all(&temp.0).unwrap();
    let empty = temp.0.join("empty.pem");
    fs::write(&empty, "not a certificate\n").unwrap();
    let error = upstream_client_config(Some(&empty)).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(
        error.to_string().contains("no certificates found"),
        "{error}"
    );

    let missing = temp.0.join("missing.pem");
    let error = upstream_client_config(Some(&missing)).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert!(error.to_string().contains("missing.pem"), "{error}");
}

#[test]
fn concurrent_first_use_creates_one_ca() {
    let temp = TempDir::new("race");
    let dir = temp.ca_dir();
    let barrier = std::sync::Barrier::new(8);
    let results: Vec<io::Result<String>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    Ca::load_or_create(&dir).map(|ca| ca.cert_pem().to_string())
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    });
    let on_disk = fs::read_to_string(Ca::cert_path(&dir)).unwrap();
    for result in results {
        assert_eq!(result.unwrap(), on_disk);
    }
    Ca::load_or_create(&dir).unwrap();
}

#[test]
fn concurrent_server_configs_share_one_cached_config() {
    let temp = TempDir::new("cache-race");
    let ca = Ca::load_or_create(&temp.ca_dir()).unwrap();
    let barrier = std::sync::Barrier::new(8);
    let configs: Vec<Arc<ServerConfig>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    ca.server_config("race.test").unwrap()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    });
    assert!(configs
        .iter()
        .all(|config| Arc::ptr_eq(config, &configs[0])));
    assert!(Arc::ptr_eq(
        &configs[0],
        &ca.server_config("race.test").unwrap()
    ));
}

#[tokio::test]
async fn long_hosts_get_a_san_only_leaf_with_a_subject() {
    let temp = TempDir::new("long-host");
    let ca = Ca::load_or_create(&temp.ca_dir()).unwrap();
    let host = format!("{}.example.test", "a".repeat(60));
    let client = client_trusting(ca.cert_pem().as_bytes(), &[b"h2"]);
    let negotiated = handshake(ca.server_config(&host).unwrap(), client, &host)
        .await
        .unwrap();
    let params = CertificateParams::from_ca_cert_der(&negotiated.chain[0]).unwrap();
    assert_eq!(params.distinguished_name.get(&DnType::CommonName), None);
    // An empty subject with a non-critical SAN fails OpenSSL's X509_STRICT (Python 3.13+).
    assert_eq!(
        params.distinguished_name.get(&DnType::OrganizationName),
        Some(&DnValue::Utf8String("TAP".into()))
    );
}

#[tokio::test]
async fn handshake_succeeds_for_a_tls12_only_client() {
    let temp = TempDir::new("tls12");
    let ca = Ca::load_or_create(&temp.ca_dir()).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert_der.clone()).unwrap();
    let client = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let negotiated = handshake(ca.server_config("old.test").unwrap(), client, "old.test")
        .await
        .unwrap();
    assert_eq!(negotiated.version, Some(rustls::ProtocolVersion::TLSv1_2));
}

#[test]
fn corrupt_ca_files_error_without_being_replaced() {
    let temp = TempDir::new("corrupt");
    let dir = temp.ca_dir();
    drop(Ca::load_or_create(&dir).unwrap());
    let cert = fs::read(Ca::cert_path(&dir)).unwrap();

    fs::write(Ca::cert_path(&dir), "garbage\n").unwrap();
    let error = Ca::load_or_create(&dir).err().unwrap().to_string();
    assert!(
        error.contains("ca.pem holds no usable certificate"),
        "{error}"
    );
    assert!(error.contains("delete ca.pem and ca.key"), "{error}");
    assert_eq!(
        fs::read_to_string(Ca::cert_path(&dir)).unwrap(),
        "garbage\n"
    );

    fs::write(Ca::cert_path(&dir), cert).unwrap();
    fs::write(
        dir.join("ca.key"),
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();
    let error = Ca::load_or_create(&dir).err().unwrap().to_string();
    assert!(
        error.contains("ca.key holds no usable private key"),
        "{error}"
    );
}

#[test]
fn upstream_config_rejects_malformed_extra_ca_files() {
    let temp = TempDir::new("upstream-malformed");
    let ca_dir = temp.ca_dir();
    drop(Ca::load_or_create(&ca_dir).unwrap());
    let cases = [
        (
            "key-only.pem",
            fs::read_to_string(ca_dir.join("ca.key")).unwrap(),
            "no certificates found",
        ),
        (
            "bad-base64.pem",
            "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n".to_string(),
            "invalid PEM",
        ),
        (
            "not-der.pem",
            pem_certificate(&CertificateDer::from(b"not der".to_vec())),
            "unusable CA certificate",
        ),
    ];
    for (name, contents, expected) in cases {
        let path = temp.0.join(name);
        fs::write(&path, contents).unwrap();
        let error = upstream_client_config(Some(&path)).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{name}");
        assert!(
            error.to_string().contains(expected) && error.to_string().contains(name),
            "{error}"
        );
    }
}
