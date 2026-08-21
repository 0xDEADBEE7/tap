pub fn response(method: &str, host: &str, path: &str, status: u16) {
    println!("← {status} {host}{path} ({method})");
}
