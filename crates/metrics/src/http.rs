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
#[counter(labels = HttpLabels, name = "http_requests_total")]
pub struct HttpRequestsTotalMetric;

#[derive(Metric)]
#[histogram(labels = HttpLabels, name = "http_requests_duration_seconds")]
pub struct HttpRequestsDurationMetric;

#[derive(Clone)]
pub struct MeasureHttpMiddleware;

impl<S> tower::Layer<S> for MeasureHttpMiddleware
where
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + Sync + 'static,
    S::Future: Send + 'static,
{
    type Service = MeasureHttpService;

    fn layer(&self, inner: S) -> Self::Service {
        MeasureHttpService {
            inner: BoxCloneSyncService::new(inner),
        }
    }
}

#[derive(Clone)]
pub struct MeasureHttpService {
    inner: BoxCloneSyncService<Request, Response, Infallible>,
}

impl Service<Request> for MeasureHttpService {
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

            HttpRequestsTotalMetric::get(&labels).increment(1);
            HttpRequestsDurationMetric::get(&labels).record(latency);

            response
        })
    }
}
