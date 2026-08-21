use std::io;
use std::path::PathBuf;

pub fn subject(host: &str) -> String {
    format!("/CN={host}")
}

pub struct Ca {
    pub directory: PathBuf,
}

impl Ca {
    pub fn from_home() -> io::Result<Self> {
        std::env::var_os("HOME")
            .map(|home| Self {
                directory: PathBuf::from(home).join(".tap"),
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))
    }
    pub fn path(&self) -> PathBuf {
        self.directory.join("ca.crt")
    }
    pub fn certificate(&self, host: &str) -> crate::tls::cert::Certificate {
        let certificate = crate::tls::cert::Certificate::new(host, self.path());
        let _ = (certificate.common_name(), certificate.file_path());
        certificate
    }
    pub fn init(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.directory)?;
        let key = self.directory.join("ca.key");
        let cert = self.path();
        let _leaf = self.certificate("TAP CA");
        if key.exists() || cert.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "TAP CA already exists",
            ));
        }
        let status = std::process::Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650", "-subj",
            ])
            .arg(subject("TAP CA"))
            .arg("-keyout")
            .arg(key)
            .arg("-out")
            .arg(&cert)
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "openssl failed"))
        }
    }
}
