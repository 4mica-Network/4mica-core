use metrics::{Counter, Gauge, Histogram};

pub use derive_4mica::{Metric, MetricLabels, measure};

pub mod http;

pub trait MetricLabels {
    /// Returns a vector of (name, value) pairs.
    fn labels(&self) -> impl AsRef<[(&'static str, String)]>;
}

impl MetricLabels for () {
    fn labels(&self) -> impl AsRef<[(&'static str, String)]> {
        vec![]
    }
}

impl MetricLabels for (&'static str, String) {
    fn labels(&self) -> impl AsRef<[(&'static str, String)]> {
        vec![self.clone()]
    }
}

impl MetricLabels for &[(&'static str, String)] {
    fn labels(&self) -> impl AsRef<[(&'static str, String)]> {
        self
    }
}

impl MetricLabels for Vec<(&'static str, String)> {
    fn labels(&self) -> impl AsRef<[(&'static str, String)]> {
        self
    }
}

pub trait MetricAccess<M, L: MetricLabels> {
    fn get(labels: &L) -> M;
}

pub trait Metric<M> {
    type Labels: MetricLabels;

    const NAME: &'static str;
}

impl<T> MetricAccess<Counter, T::Labels> for T
where
    T: Metric<Counter>,
{
    fn get(labels: &T::Labels) -> Counter {
        metrics::counter!(T::NAME, labels.labels().as_ref())
    }
}

impl<T> MetricAccess<Gauge, T::Labels> for T
where
    T: Metric<Gauge>,
{
    fn get(labels: &T::Labels) -> Gauge {
        metrics::gauge!(T::NAME, labels.labels().as_ref())
    }
}

impl<T> MetricAccess<Histogram, T::Labels> for T
where
    T: Metric<Histogram>,
{
    fn get(labels: &T::Labels) -> Histogram {
        metrics::histogram!(T::NAME, labels.labels().as_ref())
    }
}
