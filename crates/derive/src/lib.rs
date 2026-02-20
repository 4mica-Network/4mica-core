use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

mod labels;
mod measure;
mod metric;

/// Derives `Metric` for a unit struct using a kind attribute (`counter`, `histogram`, or `gauge`).
///
/// ```rust,ignore
/// #[derive(MetricLabels)]
/// pub struct HttpLabels {
///     pub method: String,
///     pub path: String,
///     pub status: u16,
/// }
///
/// #[derive(Metric)]
/// #[counter(labels = HttpLabels, name = "http_requests_total")]
/// pub struct HttpRequestsTotalMetric;
///
/// #[derive(Metric)]
/// #[histogram(labels = (&'static str, String), name = "http_requests_duration_millis")]
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

/// Wraps a function to measure its execution time and report it via a user-supplied function.
///
/// The report function must have the signature `fn(&'static str, std::time::Duration)`.
/// It is called with the function name and elapsed time when the function returns (including
/// early returns and panics).
///
/// Use `name = "custom_name"` to override the default (the function name).
///
/// ```rust,ignore
/// fn record(name: &'static str, duration: std::time::Duration) {
///     println!("{name} took {:?}", duration);
/// }
///
/// #[measure(record)]
/// fn do_work() { /* ... */ }
///
/// #[measure(my_module::record)]
/// async fn fetch_data() -> Result<(), Error> { /* ... */ }
///
/// #[measure(record, name = "custom_metric")]
/// fn internal_helper() { /* ... */ }
/// ```
#[proc_macro_attribute]
pub fn measure(args: TokenStream, input: TokenStream) -> TokenStream {
    match measure::expand_measure(args.into(), input.into()) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}
