//! Kintate Proxy - A MITM proxy with policy-based URL filtering
//!
//! # Example
//! ```ignore
//! use kintate_proxy::{PolicyProxy, Policy};
//! use http_mitm_proxy::MitmProxy;
//! use rcgen::Issuer;
//!
//! let policy = Policy::new(":memory:").unwrap();
//! policy.add_policy("work-filter", "example.com").unwrap();
//!
//! let proxy = MitmProxy::new(Some(issuer), None);
//! let wrapper = PolicyProxy::new(proxy, policy);
//! ```

pub mod api;
pub mod auth;
pub mod handlers;
pub mod limit;
pub mod policy;
pub mod proxy;
pub mod token;
pub mod tui_app;

pub use auth::*;
pub use limit::{LimitManager, LimitRule};
pub use policy::{AccessSession, Action, DomainTag, Policy, Rule, RuleData};
pub use proxy::PolicyProxy;
pub use token::TokenManager;
pub use tui_app::App as TuiApp;
