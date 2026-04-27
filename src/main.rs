//! Kintate Proxy - Sample Application
//!
//! This is a sample application that demonstrates how to use the kintate-proxy library
//! to create a MITM proxy with policy-based URL filtering.

use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use kintate_proxy::policy::{AccessSession, Action, DomainTag, Policy, RuleData};
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

use kintate_proxy::limit::{LimitManager, LimitRule};

// ... (skipping some unchanged code)

fn print_access_logs(logs: &[AccessSession]) {
    if logs.is_empty() {
        println!("No access logs found.");
        return;
    }

    let col_ip = 16;
    let col_domain = 28;
    let col_tag = 14;
    let col_action = 7;
    let col_count = 7;

    println!(
        "\n{:<col_ip$} | {:<col_domain$} | {:<col_tag$} | {:<col_action$} | {:<col_count$}",
        "Device IP",
        "Target",
        "Tag",
        "Action",
        "Reqs",
        col_ip = col_ip,
        col_domain = col_domain,
        col_tag = col_tag,
        col_action = col_action,
        col_count = col_count
    );
    println!(
        "{}",
        "-".repeat(col_ip + col_domain + col_tag + col_action + col_count + 12)
    );

    for log in logs {
        println!(
            "{:<col_ip$} | {:<col_domain$} | {:<col_tag$} | {:<col_action$} | {:<col_count$}",
            log.device_ip,
            log.target_domain,
            log.tag.as_deref().unwrap_or("-"),
            log.action.as_str(),
            log.request_count,
            col_ip = col_ip,
            col_domain = col_domain,
            col_tag = col_tag,
            col_action = col_action,
            col_count = col_count
        );
    }
}

fn print_domain_tags(tags: &[DomainTag]) {
    if tags.is_empty() {
        println!("No domain tags configured.");
        return;
    }
    println!("\n{:<6} | {:<20} | {:<20}", "ID", "SLD", "Tag");
    println!("{}", "-".repeat(53));
    for t in tags {
        println!("{:<6} | {:<20} | {:<20}", t.id, t.sld, t.tag);
    }
}

fn manage_domain_tags(policy: &Policy) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        println!("\n=== Domain Tag Management ===");
        println!("1. List Domain Tags");
        println!("2. Add Domain Tag");
        println!("3. Delete Domain Tag");
        println!("4. Back");

        let choice = prompt("Select: ");
        match choice.as_str() {
            "1" => match policy.get_all_domain_tags() {
                Ok(tags) => print_domain_tags(&tags),
                Err(e) => println!("Error: {}", e),
            },
            "2" => {
                let input = prompt("Domain: ").to_lowercase();
                if input.is_empty() {
                    continue;
                }
                let sld = kintate_proxy::policy::extract_sld(&input);
                let tag = prompt(&format!("Tag name for SLD '{}': ", sld));
                if tag.is_empty() {
                    continue;
                }
                policy.add_domain_tag(&sld, &tag)?;
                println!("Added: '{}' -> '{}'", sld, tag);
            }
            "3" => {
                let sld = prompt("Enter SLD to delete: ").to_lowercase();
                policy.delete_domain_tag(&sld)?;
                println!("Deleted.");
            }
            "4" => return Ok(()),
            _ => println!("Invalid choice."),
        }
    }
}

fn print_limit_rules(rules: &[LimitRule]) {
    if rules.is_empty() {
        println!("No limits configured.");
        return;
    }
    println!("\n{:<6} | {:<20} | {:<15}", "ID", "Tag", "Max Duration");
    println!("{}", "-".repeat(45));
    for r in rules {
        println!(
            "{:<6} | {:<20} | {:>4} min",
            r.id,
            r.tag,
            r.max_duration_secs / 60
        );
    }
    println!();
}

fn manage_limits(limit_manager: &LimitManager) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        println!("\n=== Usage Limit Management ===");
        println!("1. List Limits");
        println!("2. Set Limit");
        println!("3. Delete Limit");
        println!("4. Back");

        let choice = prompt("Select: ");
        match choice.as_str() {
            "1" => match limit_manager.get_all_limits() {
                Ok(rules) => print_limit_rules(&rules),
                Err(e) => println!("Error: {}", e),
            },
            "2" => {
                let tag = prompt("Tag to limit (e.g. Social): ");
                if tag.is_empty() {
                    continue;
                }
                let mins_str = prompt("Max minutes per day: ");
                if let Ok(mins) = mins_str.parse::<i64>() {
                    limit_manager.add_limit(&tag, mins * 60)?;
                    println!("Limit set: {} -> {} min/day", tag, mins);
                } else {
                    println!("Invalid duration.");
                }
            }
            "3" => {
                let tag = prompt("Enter tag to remove limit: ");
                limit_manager.delete_limit(&tag)?;
                println!("Limit removed.");
            }
            "4" => return Ok(()),
            _ => println!("Invalid choice."),
        }
    }
}

/// Interactive policy management
fn interactive_manage(
    policy: &Policy,
    limit_manager: &LimitManager,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        println!("\n=== Management Menu ===");
        println!("1. List Rules");
        println!("2. Add Rule");
        println!("3. Delete Rule");
        println!("4. View Access Logs");
        println!("5. Manage Domain Tags");
        println!("6. Manage Usage Limits");
        println!("7. Clear Access Logs");
        println!("8. Exit");

        let choice = prompt("Select: ");

        match choice.as_str() {
            "1" => {
                let rules = policy.get_all_rules();
                if rules.is_empty() {
                    println!("No rules found.");
                } else {
                    println!(
                        "\n{:<4} | {:<8} | {:<5} | {:<20} | {:<15} | {:<15} | {:<20}",
                        "ID", "Priority", "Action", "Domain", "Tag", "Client IP", "Name"
                    );
                    println!("{:-<100}", "");
                    for rule in rules {
                        let data = &rule.data;
                        println!(
                            "{:<4} | {:<8} | {:<5} | {:<20} | {:<15} | {:<15} | {:<20}",
                            rule.id,
                            data.priority,
                            match data.action {
                                Action::Allow => "Allow",
                                Action::Block => "Block",
                            },
                            data.domain.as_deref().unwrap_or("*"),
                            data.tag.as_deref().unwrap_or("*"),
                            data.client_ip.as_deref().unwrap_or("*"),
                            data.name.as_deref().unwrap_or("-")
                        );
                    }
                }
            }
            "2" => {
                println!("\n--- Add New Rule ---");
                let prio_str = prompt("Priority (e.g. 10): ");
                let priority: i32 = prio_str.parse().unwrap_or(100);

                let action_str = prompt("Action (Allow/Block): ");
                let action = if action_str.eq_ignore_ascii_case("allow") {
                    Action::Allow
                } else {
                    Action::Block
                };

                let name = prompt_opt("Rule Name (optional): ");
                let domain = prompt_opt("Target Domain (optional): ");
                let tag = prompt_opt("Target Tag (optional): ");
                let path_pattern = prompt_opt("Path Regex (optional): ");
                let client_ip = prompt_opt("Client IP (optional): ");

                policy.insert_rule(RuleData {
                    priority,
                    action,
                    name,
                    domain,
                    tag,
                    path_pattern,
                    client_ip,
                })?;

                println!("Rule added successfully.");
            }
            "3" => {
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
                let ip_filter = if ip_str.is_empty() {
                    None
                } else {
                    Some(ip_str.as_str())
                };
                match policy.get_access_logs(limit, ip_filter, None) {
                    Ok(logs) => print_access_logs(&logs),
                    Err(e) => println!("Error: {}", e),
                }
            }
            "5" => {
                manage_domain_tags(policy)?;
            }
            "6" => {
                manage_limits(limit_manager)?;
            }
            "7" => {
                let confirm = prompt("Clear all logs? (y/N): ");
                if confirm.to_lowercase() == "y" {
                    policy.clear_access_logs()?;
                }
            }
            "8" => return Ok(()),
            _ => println!("Invalid choice."),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let policy = Policy::new(opt.database.to_str().unwrap())?;
    let limit_manager = LimitManager::new(policy.clone())?;

    match opt.command {
        Some(Command::Serve {
            cert,
            private_key,
            listen,
            manage,
        }) => {
            let root_issuer = if let (Some(cert_path), Some(key_path)) = (cert, private_key) {
                create_root_issuer_from_files(&cert_path, &key_path)?
            } else {
                create_new_root_issuer()
            };

            let proxy = http_mitm_proxy::MitmProxy::new(Some(root_issuer), Some(Cache::new(128)));
            let policy_proxy = PolicyProxy::new(proxy, policy.clone());
            let addr: SocketAddr = listen.parse()?;

            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            let shutdown_tx = std::sync::Arc::new(std::sync::Mutex::new(Some(shutdown_tx)));

            if manage {
                let p = policy.clone();
                let l = limit_manager.clone();
                let s = shutdown_tx.clone();
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = interactive_manage(&p, &l) {
                        tracing::error!("Interactive Error: {}", e);
                    }
                    if let Ok(mut lock) = s.lock() {
                        if let Some(tx) = lock.take() {
                            let _ = tx.send(());
                        }
                    }
                });
            }

            // Limit Enforcement Task
            let policy_for_limits = policy.clone();
            let limit_manager_for_task = limit_manager.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    // First flush sessions to DB
                    if let Err(e) = policy_for_limits.sweep_sessions(0) {
                        tracing::error!("Failed to sweep: {}", e);
                    }
                    // Then enforce limits
                    if let Err(e) = limit_manager_for_task.enforce() {
                        tracing::error!("Limit enforcement error: {}", e);
                    }
                }
            });

            policy_proxy.serve(addr, shutdown_rx).await?;
        }
        Some(Command::Manage) => {
            interactive_manage(&policy, &limit_manager)?;
        }
        _ => {
            println!("See --help for usage.");
        }
    }

    Ok(())
}
