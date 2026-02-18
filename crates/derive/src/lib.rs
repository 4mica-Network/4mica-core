use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

mod labels;
mod metric;
mod util;

/// Derives `Metric` for a unit struct using a kind attribute (`counter`, `histogram`, or `gauge`).
///
/// ```rust,ignore
/// #[derive(Metric)]
/// #[counter(labels = HttpLabels, name = "http_requests_total")]
/// pub struct HttpRequestsTotalMetric;
///
/// #[derive(Metric)]
/// #[histogram(labels = HttpLabels, name = "http_requests_duration_millis")]
/// pub struct HttpRequestsDurationMetric;
///
/// #[derive(Metric)]
/// #[gauge(labels = (), name = "active_connections")]
/// pub struct ActiveConnectionsMetric;
/// ```
#[proc_macro_derive(Metric, attributes(counter, histogram, gauge))]
pub fn derive_metric(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match metric::expand_metric(input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Derives `MetricLabels` for a named struct whose fields all implement `ToString`.
/// Each field name becomes a label key and its value is produced via `.to_string()`.
///
/// ```rust,ignore
/// #[derive(MetricLabels)]
/// pub struct HttpLabels {
///     pub method: String,
///     pub path: String,
///     pub status: u16,
/// }
/// ```
#[proc_macro_derive(MetricLabels, attributes(metric_labels))]
pub fn derive_metric_labels(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match labels::expand_metric_labels(input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}
