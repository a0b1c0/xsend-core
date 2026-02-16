#[tokio::main]
async fn main() {
    if let Err(err) = xsend::daemon::run().await {
        eprintln!("fatal: {err:#}");
        std::process::exit(1);
    }
}
