use std::io;
use std::net::TcpStream;

pub fn connect(host: &str, port: u16) -> io::Result<TcpStream> {
    TcpStream::connect((host, port))
}
pub fn tunnel(mut client: TcpStream, mut upstream: TcpStream) -> io::Result<()> {
    let mut copy = client.try_clone()?;
    let mut upstream_copy = upstream.try_clone()?;
    std::thread::spawn(move || {
        let _ = io::copy(&mut copy, &mut upstream_copy);
    });
    io::copy(&mut upstream, &mut client).map(|_| ())
}
