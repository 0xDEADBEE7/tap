mod cli;
mod http;
mod intercept;
mod output;
mod proxy;
mod session;
mod tls;

fn main() {
    if let Err(error) = cli::run() {
        eprintln!("tap: {error}");
        std::process::exit(1);
    }
}
