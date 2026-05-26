//! Kintate Proxy - Sample Application
//!
//! This is a sample application that demonstrates how to use the kintate-proxy library
//! to create a MITM proxy with policy-based URL filtering.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use common_access_token::{Algorithm, KeyId, RegisteredClaims, TokenBuilder, current_timestamp};
use kintate_proxy::TokenManager;
use kintate_proxy::api::serve_api;
use kintate_proxy::limit::LimitManager;
use kintate_proxy::policy::{AccessSession, Policy};
use kintate_proxy::proxy::PolicyProxy;
use kintate_proxy::tui_app::{App as TuiApp, TuiLogger};
use moka::sync::Cache;
use rcgen::Issuer;
use std::sync::{Arc, Mutex};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

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
        /// Idle timeout for session aggregation in seconds (default: 60)
        #[arg(long, default_value = "60")]
        session_timeout: i64,
        /// Address to listen on for the API server (e.g. 127.0.0.1:3005)
        #[arg(long)]
        api_listen: Option<String>,
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
    // Generate access token for API server
    GenerateToken {},
    VerifyToken {
        token: String,
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::parse();

    let error_logs = Arc::new(Mutex::new(Vec::new()));
    let tui_logger = TuiLogger::new(error_logs.clone());

    let is_tui = match &opt.command {
        Some(Command::Serve { manage, .. }) => *manage,
        Some(Command::Manage) => true,
        _ => false,
    };

    let fmt_layer = if is_tui {
        None
    } else {
        Some(tracing_subscriber::fmt::layer())
    };

    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt_layer)
        .with(tui_logger)
        .init();

    let policy = Policy::new(opt.database.to_str().unwrap())?;
    let limit_manager = LimitManager::new(policy.clone())?;
    let token_manager = TokenManager::new("token.db")?;

    match opt.command {
        Some(Command::Serve {
            cert,
            private_key,
            listen,
            manage,
            session_timeout,
            api_listen,
        }) => {
            let root_issuer = if let (Some(cert_path), Some(key_path)) = (cert, private_key) {
                create_root_issuer_from_files(&cert_path, &key_path)?
            } else {
                create_new_root_issuer()
            };

            let proxy = http_mitm_proxy::MitmProxy::new(Some(root_issuer), Some(Cache::new(128)));

            let search_history = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let ctx = kintate_proxy::handlers::HandlerContext {
                search_history: search_history.clone(),
            };
            let handlers = std::sync::Arc::new(kintate_proxy::handlers::DomainHandlers::new());

            let policy_proxy = PolicyProxy::new(proxy, policy.clone(), handlers, ctx);
            let addr: SocketAddr = listen.parse()?;

            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            let shutdown_tx = std::sync::Arc::new(std::sync::Mutex::new(Some(shutdown_tx)));

            if manage {
                let p = policy.clone();
                let l = limit_manager.clone();
                let s = shutdown_tx.clone();
                let e = error_logs.clone();
                let sh = search_history.clone();
                tokio::task::spawn_blocking(move || {
                    let mut app = TuiApp::new(p, l, e, sh);
                    if let Err(err) = app.run() {
                        tracing::error!("TUI Error: {}", err);
                    }
                    if let Ok(mut lock) = s.lock() {
                        if let Some(tx) = lock.take() {
                            let _ = tx.send(());
                        }
                    }
                });
            }

            if let Some(api_addr_str) = api_listen {
                let api_addr: SocketAddr = api_addr_str.parse()?;
                let policy_for_api = policy.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_api(policy_for_api, token_manager, api_addr).await {
                        tracing::error!("API server error: {}", e);
                    }
                });
            }

            // Limit Enforcement Task
            let policy_for_limits = policy.clone();
            let limit_manager_for_task = limit_manager.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    // First flush sessions to DB (using configured idle timeout)
                    if let Err(e) = policy_for_limits.sweep_sessions(session_timeout) {
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
            let search_history = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut app = TuiApp::new(policy, limit_manager, error_logs, search_history);
            app.run()?;
        }
        Some(Command::List) => {
            let rules = policy.get_all_rules();
            if rules.is_empty() {
                println!("No rules found.");
            } else {
                for rule in rules {
                    println!(
                        "ID {}: Priority {} [{:?}] -> Tag: {:?}",
                        rule.id, rule.data.priority, rule.data.action, rule.data.tag
                    );
                }
            }
        }
        Some(Command::Logs { limit, ip }) => {
            let logs = policy.get_access_logs(limit, ip.as_deref(), None)?;
            print_access_logs(&logs);
        }
        Some(Command::GenerateToken {}) => {
            // Create a key for signing and verification
            let mut token_manager =
                TokenManager::new("token.db").expect("Failed to create token manager");

            let generated = token_manager.generate().unwrap();

            println!("{}", generated);
        }
        Some(Command::VerifyToken { token }) => {
            let mut token_manager =
                TokenManager::new("token.db").expect("Failed to create token manager");

            println!("{:?}", token_manager.verify(&token));
        }
        None => {
            println!("Use --help to see available commands.");
        }
    }

    Ok(())
}
