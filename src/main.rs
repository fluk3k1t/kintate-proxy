//! Kintate Proxy - Sample Application
//!
//! This is a sample application that demonstrates how to use the kintate-proxy library
//! to create a MITM proxy with policy-based URL filtering.

use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use kintate_proxy::policy::{AccessSession, Action, Policy, RuleData};
use kintate_proxy::proxy::PolicyProxy;
use moka::sync::Cache;
use rcgen::Issuer;
use tracing_subscriber::EnvFilter;

/// Command-line arguments
#[derive(Parser)]
#[command(name = "kintate-proxy")]
#[command(about = "MITM proxy with policy-based URL filtering")]
struct Opt {
    /// Path to the SQLite database file (default: policy.db)
    #[arg(long, default_value = "policy.db")]
    database: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the proxy server
    Serve {
        /// Path to the CA certificate file
        #[arg(long, required = false)]
        cert: Option<PathBuf>,
        /// Path to the private key file
        #[arg(long, required = false)]
        private_key: Option<PathBuf>,
        /// Proxy listen address (default: 127.0.0.1:3003)
        #[arg(long, default_value = "127.0.0.1:3004")]
        listen: String,
        /// Enable interactive policy management while serving
        #[arg(long)]
        manage: bool,
    },
    /// Manage policies interactively
    Manage,
    /// List all policies
    List,
    /// Show access logs from the database
    Logs {
        /// Maximum number of records to show (default: 50)
        #[arg(long, default_value = "50")]
        limit: usize,
        /// Filter by specific device IP
        #[arg(long)]
        ip: Option<String>,
    },
}

/// Create a root issuer from existing certificate and key files
fn create_root_issuer_from_files(
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<Issuer<'static, rcgen::KeyPair>, Box<dyn std::error::Error>> {
    let signing_key = rcgen::KeyPair::from_pem(&std::fs::read_to_string(key_path)?)?;
    let issuer =
        rcgen::Issuer::from_ca_cert_pem(&std::fs::read_to_string(cert_path)?, signing_key)?;
    Ok(issuer)
}

/// Create a new self-signed root issuer
fn create_new_root_issuer() -> Issuer<'static, rcgen::KeyPair> {
    let mut params = rcgen::CertificateParams::default();

    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("<HTTP-MITM-PROXY CA>".to_string()),
    );
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let signing_key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&signing_key).unwrap();

    println!();
    println!("Trust this cert if you want to use HTTPS");
    println!();
    println!("{}", cert.pem());
    println!();

    println!("Private key");
    println!("{}", signing_key.serialize_pem());

    rcgen::Issuer::new(params, signing_key)
}

fn prompt(message: &str) -> String {
    print!("{}", message);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn prompt_opt(message: &str) -> Option<String> {
    let res = prompt(message);
    if res.is_empty() { None } else { Some(res) }
}

fn print_access_logs(logs: &[AccessSession]) {
    if logs.is_empty() {
        println!("No access logs found.");
        println!(
            "(Logs are written to DB after sessions expire. Use `--manage` and wait, or restart with Ctrl+C.)"
        );
        return;
    }

    let col_ip = 16;
    let col_domain = 32;
    let col_action = 7;
    let col_count = 7;
    let col_first = 20;
    let col_last = 20;

    println!();
    println!(
        "{:<col_ip$} | {:<col_domain$} | {:<col_action$} | {:<col_count$} | {:<col_first$} | {:<col_last$}",
        "Device IP",
        "Target Domain",
        "Action",
        "Reqs",
        "First Access",
        "Last Access",
        col_ip = col_ip,
        col_domain = col_domain,
        col_action = col_action,
        col_count = col_count,
        col_first = col_first,
        col_last = col_last,
    );
    println!(
        "{}",
        "-".repeat(col_ip + col_domain + col_action + col_count + col_first + col_last + 15)
    );

    for log in logs {
        let action_str = match log.action {
            Action::Allow => "Allow",
            Action::Block => "BLOCK",
        };
        let first = log.first_access.format("%Y-%m-%d %H:%M:%S").to_string();
        let last = log.last_access.format("%Y-%m-%d %H:%M:%S").to_string();
        println!(
            "{:<col_ip$} | {:<col_domain$} | {:<col_action$} | {:<col_count$} | {:<col_first$} | {:<col_last$}",
            log.device_ip,
            log.target_domain,
            action_str,
            log.request_count,
            first,
            last,
            col_ip = col_ip,
            col_domain = col_domain,
            col_action = col_action,
            col_count = col_count,
            col_first = col_first,
            col_last = col_last,
        );
    }
    println!();
}

/// Interactive policy management
fn interactive_manage(policy: &Policy) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        println!("\n=== Policy Management ===");
        println!("1. List Rules");
        println!("2. Add Rule");
        println!("3. Delete Rule");
        println!("4. View Access Logs");
        println!("5. Exit");

        let choice = prompt("Select: ");

        match choice.as_str() {
            "1" => {
                let rules = policy.get_all_rules();
                if rules.is_empty() {
                    println!("No rules found.");
                } else {
                    println!(
                        "\n{:<4} | {:<8} | {:<5} | {:<20} | {:<20} | {:<15} | {:<11}",
                        "ID", "Priority", "Action", "Domain", "Path", "Client IP", "Time Span"
                    );
                    println!("{:-<100}", "");
                    for rule in rules {
                        let data = &rule.data;
                        let time_str = match (&data.time_start, &data.time_end) {
                            (Some(s), Some(e)) => format!("{}-{}", s, e),
                            _ => "*".to_string(),
                        };
                        println!(
                            "{:<4} | {:<8} | {:<5} | {:<20} | {:<20} | {:<15} | {:<11}",
                            rule.id,
                            data.priority,
                            match data.action {
                                Action::Allow => "Allow",
                                Action::Block => "Block",
                            },
                            data.domain.as_deref().unwrap_or("*"),
                            data.path_pattern.as_deref().unwrap_or("*"),
                            data.client_ip.as_deref().unwrap_or("*"),
                            time_str
                        );
                    }
                }
            }
            "2" => {
                println!("\n--- Add New Rule ---");
                let prio_str = prompt("Priority (e.g. 10, lower number is checked first): ");
                let priority: i32 = prio_str.parse().unwrap_or(100);

                let action_str = prompt("Action (Allow/Block): ");
                let action = if action_str.eq_ignore_ascii_case("allow") {
                    Action::Allow
                } else {
                    Action::Block
                };

                let name = prompt_opt("Rule Name (optional): ");
                let domain = prompt_opt("Target Domain (optional, e.g. youtube.com): ");
                let path_pattern = prompt_opt("Path Regex (optional, e.g. ^/shorts/): ");
                let client_ip = prompt_opt("Client IP (optional, e.g. 192.168.1.5): ");

                let time_start = prompt_opt("Start Time (optional, HH:MM): ");
                let time_end = prompt_opt("End Time (optional, HH:MM): ");

                policy.insert_rule(RuleData {
                    priority,
                    action,
                    name,
                    domain,
                    path_pattern,
                    client_ip,
                    time_start,
                    time_end,
                })?;

                println!("Rule added successfully.");
            }
            "3" => {
                let rules = policy.get_all_rules();
                if rules.is_empty() {
                    println!("No rules to delete.");
                    continue;
                }
                let id_str = prompt("Enter Rule ID to delete: ");
                if let Ok(id) = id_str.parse::<i64>() {
                    policy.delete_rule(id)?;
                    println!("Rule deleted.");
                } else {
                    println!("Invalid ID.");
                }
            }
            "4" => {
                let limit_str = prompt("Show last N records (default: 50): ");
                let limit = limit_str.parse::<usize>().unwrap_or(50);
                let ip_str = prompt("Filter by IP (leave blank for all): ");
                let ip_filter = if ip_str.is_empty() { None } else { Some(ip_str.as_str()) };
                match policy.get_access_logs(limit, ip_filter) {
                    Ok(logs) => print_access_logs(&logs),
                    Err(e) => println!("Error fetching logs: {}", e),
                }
            }
            "5" => {
                return Ok(());
            }
            _ => {
                println!("Invalid choice.");
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Create policy database
    let policy = Policy::new(opt.database.to_str().unwrap())?;

    // Handle commands
    match opt.command {
        Some(Command::Serve {
            cert,
            private_key,
            listen,
            manage,
        }) => {
            // Create root issuer
            let root_issuer = if let (Some(cert_path), Some(key_path)) = (cert, private_key) {
                create_root_issuer_from_files(&cert_path, &key_path)?
            } else {
                create_new_root_issuer()
            };

            // Create MITM proxy
            let proxy = http_mitm_proxy::MitmProxy::new(Some(root_issuer), Some(Cache::new(128)));

            let policy_for_proxy = policy.clone();

            // Create policy proxy wrapper
            let policy_proxy = PolicyProxy::new(proxy, policy_for_proxy);

            // Parse listen address
            let addr: SocketAddr = listen.parse()?;

            // Shutdown oneshot channel: send () to stop the server gracefully
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            // Wrap in Arc<Mutex<Option<...>>> so both threads can take it
            let shutdown_tx = std::sync::Arc::new(std::sync::Mutex::new(Some(shutdown_tx)));

            // Spawn interactive manage thread if requested
            if manage {
                let policy_for_manage = policy.clone();
                let shutdown_tx = shutdown_tx.clone();
                tokio::task::spawn_blocking(move || {
                    println!("\nStarting interactive management...");
                    if let Err(e) = interactive_manage(&policy_for_manage) {
                        tracing::error!("Interactive management error: {}", e);
                    }
                    println!("\nExiting...");
                    // Signal server to stop
                    if let Ok(mut lock) = shutdown_tx.lock() {
                        if let Some(tx) = lock.take() {
                            let _ = tx.send(());
                        }
                    }
                });
            }

            // Ctrl+C also sends shutdown signal
            let shutdown_tx_ctrlc = shutdown_tx.clone();
            let policy_for_ctrlc = policy.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                tracing::info!("Ctrl+C received. Flushing access logs...");
                if let Err(e) = policy_for_ctrlc.sweep_sessions(-1) {
                    tracing::error!("Failed to flush: {}", e);
                } else {
                    tracing::info!("Access logs flushed.");
                }
                if let Ok(mut lock) = shutdown_tx_ctrlc.lock() {
                    if let Some(tx) = lock.take() {
                        let _ = tx.send(());
                    }
                }
            });

            // Start serving (blocks until shutdown signal)
            policy_proxy.serve(addr, shutdown_rx).await?;

            // Final flush on natural exit
            tracing::info!("Flushing remaining access logs...");
            let _ = policy.sweep_sessions(-1);
        }
        Some(Command::Manage) => {
            interactive_manage(&policy)?;
        }
        Some(Command::List) => {
            let rules = policy.get_all_rules();
            if rules.is_empty() {
                println!("No rules found.");
            } else {
                println!("All rules:");
                for rule in rules {
                    println!(
                        "ID {}: Priority {} [{:?}] -> Domain: {:?}",
                        rule.id, rule.data.priority, rule.data.action, rule.data.domain
                    );
                }
            }
        }
        Some(Command::Logs { limit, ip }) => {
            let logs = policy.get_access_logs(limit, ip.as_deref())?;
            print_access_logs(&logs);
        }
        None => {
            // No subcommand, show help
            println!("Use --help to see available commands.");
        }
    }

    Ok(())
}
