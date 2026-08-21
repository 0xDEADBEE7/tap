use crate::cli::Config;
use std::io;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

pub fn run(config: Config) -> io::Result<()> {
    let listener = TcpListener::bind(&config.listen)?;
    eprintln!("TAP listening on {}", config.listen);
    let config = Arc::new(config);
    accept_connections(listener, config)
}

fn accept_connections(listener: TcpListener, config: Arc<Config>) -> io::Result<()> {
    for connection in listener.incoming() {
        let config = Arc::clone(&config);
        thread::spawn(move || {
            if let Ok(client) = connection {
                let _ = super::connection::handle(client, &config);
            }
        });
    }
    Ok(())
}
