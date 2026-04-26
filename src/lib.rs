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

pub mod policy;
pub mod proxy;

pub use policy::{Policy, Rule, RuleData, Action};
pub use proxy::PolicyProxy;
