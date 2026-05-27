//! PolicyProxy - A MITM proxy wrapper with policy-based URL filtering

use crate::handlers::{DomainHandlers, HandlerContext};
use crate::log::AccessLogger;
use crate::policy::{Action, Policy, extract_domain, extract_path};
use http_body_util::BodyExt;
use http_mitm_proxy::{
    DefaultClient, MitmProxy, RemoteAddr,
    hyper::{Request, Response, body::Incoming, service::service_fn},
};
use std::sync::Arc;
use tracing::info;

pub struct PolicyProxy {
    inner: MitmProxy<rcgen::Issuer<'static, rcgen::KeyPair>>,
    policy: Policy,
    access_logger: AccessLogger,
    handlers: Arc<DomainHandlers>,
    ctx: HandlerContext,
}

impl PolicyProxy {
    pub fn new(
        proxy: MitmProxy<rcgen::Issuer<'static, rcgen::KeyPair>>,
        policy: Policy,
        access_logger: AccessLogger,
        handlers: Arc<DomainHandlers>,
        ctx: HandlerContext,
    ) -> Self {
        Self {
            inner: proxy,
            policy,
            access_logger,
            handlers,
            ctx,
        }
    }

    pub async fn serve(
        self,
        addr: impl tokio::net::ToSocketAddrs,
        mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let client = DefaultClient::new();
        let policy = self.policy;
        let access_logger = self.access_logger;
        let handlers = self.handlers;
        let ctx = self.ctx;

        let access_logger_for_gc = access_logger.clone();
        let server = self
            .inner
            .bind(
                addr,
                service_fn(move |req| {
                    let client = client.clone();
                    let policy = policy.clone();
                    let access_logger = access_logger.clone();
                    let handlers = handlers.clone();
                    let ctx = ctx.clone();
                    async move {
                        handle_request(req, client, policy, access_logger, handlers, ctx).await
                    }
                }),
            )
            .await?;

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                if let Err(e) = access_logger_for_gc.sweep_sessions(5 * 60) {
                    tracing::error!("Error sweeping access sessions: {}", e);
                }
            }
        });

        info!("HTTP Proxy is listening");

        tokio::select! {
            _ = server => {
                tracing::info!("Server exited naturally.");
            }
            _ = &mut shutdown_rx => {
                tracing::info!("Server received shutdown signal.");
            }
        }

        Ok(())
    }
}

async fn handle_request(
    req: Request<Incoming>,
    client: DefaultClient,
    policy: Policy,
    access_logger: AccessLogger,
    handlers: Arc<DomainHandlers>,
    ctx: HandlerContext,
) -> Result<
    Response<
        http_body_util::combinators::BoxBody<
            bytes::Bytes,
            Box<dyn std::error::Error + Send + Sync>,
        >,
    >,
    http_mitm_proxy::default_client::Error,
> {
    let uri = req.uri().clone();
    let url = uri.to_string();
    let remote_addr = req.extensions().get::<RemoteAddr>().map(|r| r.0);

    let domain = extract_domain(&url);
    let path = extract_path(&url);
    let client_ip = remote_addr.map(|addr| addr.ip().to_string());

    // Execute domain handlers
    handlers.execute(&domain, req.uri(), &ctx);

    let action = policy.evaluate(&domain, &path, client_ip.as_deref());

    if let Some(ip) = &client_ip {
        let ip_only = ip.split(':').next().unwrap_or(ip);
        let sld = crate::policy::extract_sld(&domain);
        let tag = policy.get_tag(&sld);
        access_logger.record_access(ip_only, &domain, &action, tag.as_deref());
    }

    //tracing::error!("[{}] {} - {:?}", domain, req.method(), action);

    match action {
        Action::Allow => {
            if let Some(addr) = remote_addr {
                info!("[{}] {} {} - ALLOWED", addr, req.method(), url);
            }
            let (res, _upgrade) = client.send_request(req).await?;
            if let Some(addr) = remote_addr {
                info!("[{}] {} -> {}", addr, url, res.status());
            }
            Ok(res.map(|b| b.boxed().map_err(|e| unreachable!("{}", e)).boxed()))
        }
        Action::Block => {
            if let Some(addr) = remote_addr {
                info!("[{}] {} {} - BLOCKED", addr, req.method(), url);
            }

            let html_template = include_str!("block.html");
            let html_body = html_template.replace("{url}", &url);

            Ok(Response::builder()
                .status(http::StatusCode::FORBIDDEN)
                .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
                .body(
                    http_body_util::Full::new(bytes::Bytes::from(html_body))
                        .map_err(|e| unreachable!("{}", e))
                        .boxed(),
                )
                .unwrap())
        }
    }
}
