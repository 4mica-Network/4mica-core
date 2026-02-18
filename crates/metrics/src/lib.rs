use metrics::Counter;

pub use derive_4mica::{Metric, MetricLabels};

pub mod http;

pub trait MetricLabels {
    /// Returns a vector of (name, value) pairs.
    fn labels(&self) -> Vec<(&'static str, String)>;
}

impl MetricLabels for () {
    fn labels(&self) -> Vec<(&'static str, String)> {
        vec![]
    }
}

pub trait MetricName {
    fn name() -> &'static str;
}

pub trait MetricAccess<M, L: MetricLabels> {
    fn access(labels: &L) -> M;
}

pub trait Metric {
    type MetricType;
    type Labels: MetricLabels;

    const NAME: &'static str;
}

impl<T> MetricAccess<T::MetricType, T::Labels> for T
where
    T: Metric<MetricType = Counter> + MetricName,
{
    fn access(labels: &T::Labels) -> T::MetricType {
        metrics::counter!(T::name(), &labels.labels())
    }
}
