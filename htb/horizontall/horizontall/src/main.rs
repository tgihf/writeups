use clap::Parser;

use horizontall::Args;

// Example usage
// horizontall --target-ip $IP_ADDRESS --iface $INTERFACE --lport1 $443 --chisel-path $CHISEL_PATH
#[tokio::main]
async fn main() {
    let args = Args::parse();
    if let Err(e) = args.validate() {
        eprintln!("Error validating arguments: {}", e)
    }
    println!("{:?}", args);
    if let Err(e) = horizontall::run(args).await {
        eprintln!("[!] {}", e);
    }
}
