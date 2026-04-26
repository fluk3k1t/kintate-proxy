//! PolicyProxy - A MITM proxy wrapper with policy-based URL filtering

use crate::policy::{Action, Policy, extract_domain, extract_path};
use http_body_util::BodyExt;
use http_mitm_proxy::{
    DefaultClient, MitmProxy, RemoteAddr,
    hyper::{Request, Response, body::Incoming, service::service_fn},
};
use tracing::info;

pub struct PolicyProxy {
    inner: MitmProxy<rcgen::Issuer<'static, rcgen::KeyPair>>,
    policy: Policy,
}

impl PolicyProxy {
    pub fn new(proxy: MitmProxy<rcgen::Issuer<'static, rcgen::KeyPair>>, policy: Policy) -> Self {
        Self {
            inner: proxy,
            policy,
        }
    }

    pub async fn serve(
        self,
        addr: impl tokio::net::ToSocketAddrs,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let client = DefaultClient::new();
        let policy = self.policy;

        let server = self
            .inner
            .bind(
                addr,
                service_fn(move |req| {
                    let client = client.clone();
                    let policy = policy.clone();
                    async move { handle_request(req, client, policy).await }
                }),
            )
            .await?;

        info!("HTTP Proxy is listening");
        server.await;

        Ok(())
    }
}

async fn handle_request(
    req: Request<Incoming>,
    client: DefaultClient,
    policy: Policy,
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

    let action = policy.evaluate(&domain, &path, client_ip.as_deref());

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
