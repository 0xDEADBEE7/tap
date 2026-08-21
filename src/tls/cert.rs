use std::path::PathBuf;

pub struct Certificate {
    pub host: String,
    pub path: PathBuf,
}

impl Certificate {
    pub fn new(host: &str, path: PathBuf) -> Self {
        Self {
            host: host.into(),
            path,
        }
    }

    pub fn common_name(&self) -> &str {
        &self.host
    }

    pub fn file_path(&self) -> &PathBuf {
        &self.path
    }
}
