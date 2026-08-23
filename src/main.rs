fn main() {
    if let Err(error) = tap::cli::run() {
        eprintln!("tap: {error}");
        std::process::exit(1);
    }
}
