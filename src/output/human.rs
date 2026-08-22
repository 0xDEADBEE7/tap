pub fn request(method: &str, host: &str, path: &str) {
    println!("SEND {method} {host}{path}");
}

pub fn response(method: &str, host: &str, path: &str, status: u16) {
    println!("RECV {status} {host}{path} ({method})");
}
