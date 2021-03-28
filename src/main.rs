fn main() {
    if let Err(e) = smcrypt::run() {
        eprintln!("{}", e);
    }
}
