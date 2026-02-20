use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use axum::{
    extract::{MatchedPath, Request},
    response::Response,
};
use tower::{Service, util::BoxCloneSyncService};

use crate::{Metric, MetricAccess, MetricLabels};

#[derive(Debug, Clone, MetricLabels)]
pub struct HttpLabels {
    pub method: String,
    pub path: String,
    pub status: String,
}

#[derive(Metric)]
#[counter(labels = HttpLabels, name = "http_request_total")]
pub struct HttpRequestTotalMetric;

#[derive(Metric)]
#[histogram(labels = HttpLabels, name = "http_request_duration_seconds")]
pub struct HttpRequestDurationMetric;

#[derive(Clone, Default)]
pub struct HttpMetricsMiddleware;

impl<S> tower::Layer<S> for HttpMetricsMiddleware
where
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + Sync + 'static,
    S::Future: Send + 'static,
{
    type Service = HttpMetricsService;

    fn layer(&self, inner: S) -> Self::Service {
        HttpMetricsService {
            inner: BoxCloneSyncService::new(inner),
        }
    }
}

#[derive(Clone)]
pub struct HttpMetricsService {
    inner: BoxCloneSyncService<Request, Response, Infallible>,
}

impl Service<Request> for HttpMetricsService {
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    /// Delegates readiness polling to the wrapped inner service.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let start = Instant::now();
            let path = if let Some(matched_path) = req.extensions().get::<MatchedPath>() {
                matched_path.as_str().to_owned()
            } else {
                req.uri().path().to_owned()
            };
            let method = req.method().clone();

            let response = inner.call(req).await;

            let latency = start.elapsed().as_secs_f64();
            let status = response
                .as_ref()
                .map(|res| res.status().as_u16().to_string())
                .unwrap_or_else(|_| "error".to_string());

            let labels = HttpLabels {
                method: method.to_string(),
                path,
                status,
            };

            HttpRequestTotalMetric::get(&labels).increment(1);
            HttpRequestDurationMetric::get(&labels).record(latency);

            response
        })
    }
}
