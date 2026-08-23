pub fn request(method: &str, host: &str, path: &str) {
    println!(r#"{{"type":"request","method":"{method}","host":"{host}","path":"{path}"}}"#);
}

pub fn response(method: &str, host: &str, path: &str, status: u16) {
    println!(
        r#"{{"type":"response","method":"{method}","host":"{host}","path":"{path}","status":{status}}}"#
    );
}
