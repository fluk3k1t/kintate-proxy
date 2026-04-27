use kintate_proxy::policy::{Policy, RuleData, Action};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = Policy::new("policy.db")?;
    policy.insert_rule(RuleData {
        priority: 50,
        action: Action::Allow,
        name: Some("Test Rule".to_string()),
        domain: Some("example.com".to_string()),
        tag: None,
        path_pattern: None,
        client_ip: None,
    })?;
    
    let rules = policy.get_all_rules();
    println!("Total rules in DB: {}", rules.len());
    for r in rules {
        println!("- Rule {}: {:?}", r.id, r.data.domain);
    }
    
    Ok(())
}
