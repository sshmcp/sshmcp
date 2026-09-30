mod agent;
mod approval;
mod audit;
mod cli;
mod config;
mod daemon;
mod errors;
mod grant;
mod ipc;
mod mcp;
mod policy;
mod principal;
mod protocol;
mod redaction;
mod service;
mod session;
mod ssh;
mod storage;
mod target;
mod worker;

use clap::Parser;

#[tokio::main]
async fn main() {
    let cli = cli::Cli::parse();
    let result = cli::dispatch(cli).await;
    println!("{}", result.to_json());
    if result.ok {
        std::process::exit(0);
    }
    std::process::exit(1);
}
