use std::sync::{Arc, Mutex};
use http::Uri;
use percent_encoding::percent_decode_str;

#[derive(Clone)]
pub struct HandlerContext {
    pub search_history: Arc<Mutex<Vec<String>>>,
}

pub trait RequestHandler: Send + Sync {
    fn handle(&self, domain: &str, uri: &Uri, ctx: &HandlerContext);
}

pub struct GoogleSearchHandler;

impl RequestHandler for GoogleSearchHandler {
    fn handle(&self, domain: &str, uri: &Uri, ctx: &HandlerContext) {
        if domain.contains("google.") && uri.path() == "/search" {
            if let Some(query) = uri.query() {
                for pair in query.split('&') {
                    if let Some((key, value)) = pair.split_once('=') {
                        if key == "q" {
                            let replaced = value.replace('+', " ");
                            let decoded = percent_decode_str(replaced.as_str())
                                .decode_utf8()
                                .unwrap_or_else(|_| value.into());
                            let mut history = ctx.search_history.lock().unwrap();
                            // prepend to keep newest at top
                            history.insert(0, decoded.into_owned());
                            if history.len() > 100 {
                                history.truncate(100);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
}

pub struct DomainHandlers {
    handlers: Vec<Box<dyn RequestHandler>>,
}

impl DomainHandlers {
    pub fn new() -> Self {
        Self {
            handlers: vec![Box::new(GoogleSearchHandler)],
        }
    }

    pub fn execute(&self, domain: &str, uri: &Uri, ctx: &HandlerContext) {
        for handler in &self.handlers {
            handler.handle(domain, uri, ctx);
        }
    }
}
