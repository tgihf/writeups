use clap::Parser;

use horizontall::Args;

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if let Err(e) = args.validate() {
        eprintln!("[!] Error validating arguments: {}", e);
        std::process::exit(1);
    }
    if let Err(e) = horizontall::run(args).await {
        eprintln!("[!] {}", e);
        std::process::exit(1);
    }
}
