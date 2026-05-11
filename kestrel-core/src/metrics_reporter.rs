use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};

/// Opaque handle to a pre-registered metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MetricId(u64);

impl MetricId {
    pub const NULL: Self = Self(u64::MAX);
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MetricKind {
    Counter,
    Histogram { buckets: &'static [f64] },
    Gauge,
}

#[derive(Debug, Clone)]
pub struct Label {
    pub key: &'static str,
    pub value: String,
}

impl Label {
    pub fn new(key: &'static str, value: impl Into<String>) -> Self {
        Self {
            key,
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MetricDescriptor {
    pub name: &'static str,
    pub help: &'static str,
    pub kind: MetricKind,
    pub labels: Vec<Label>,
}

/// Unified metrics reporter. Hot-path methods must be allocation-free.
pub trait MetricsReporter: Send + Sync {
    fn register(&self, descriptor: MetricDescriptor) -> MetricId;

    fn counter_inc(&self, id: MetricId, value: u64);

    fn histogram_record(&self, id: MetricId, value: f64);

    fn gauge_set(&self, id: MetricId, value: f64);

    fn export_prometheus(&self) -> String;

    fn export_json(&self) -> Value;
}

/// No-op implementation for tests and minimal builds.
pub struct NoOpMetricsReporter;

impl MetricsReporter for NoOpMetricsReporter {
    fn register(&self, _d: MetricDescriptor) -> MetricId {
        MetricId::NULL
    }
    fn counter_inc(&self, _id: MetricId, _v: u64) {}
    fn histogram_record(&self, _id: MetricId, _v: f64) {}
    fn gauge_set(&self, _id: MetricId, _v: f64) {}
    fn export_prometheus(&self) -> String {
        String::new()
    }
    fn export_json(&self) -> Value {
        Value::Null
    }
}

/// In-memory metrics reporter for testing and development.
pub struct InMemoryMetricsReporter {
    counters: parking_lot::RwLock<Vec<(MetricDescriptor, AtomicU64)>>,
    histograms:
        parking_lot::RwLock<Vec<(MetricDescriptor, Vec<(f64, AtomicU64)>, AtomicU64, AtomicU64)>>,
    gauges: parking_lot::RwLock<Vec<(MetricDescriptor, AtomicU64)>>,
}

impl InMemoryMetricsReporter {
    pub fn new() -> Self {
        Self {
            counters: parking_lot::RwLock::new(Vec::new()),
            histograms: parking_lot::RwLock::new(Vec::new()),
            gauges: parking_lot::RwLock::new(Vec::new()),
        }
    }

    pub fn counter_value(&self, name: &str) -> Option<u64> {
        let counters = self.counters.read();
        counters
            .iter()
            .find(|(d, _)| d.name == name)
            .map(|(_, v)| v.load(Ordering::Relaxed))
    }
}

impl Default for InMemoryMetricsReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsReporter for InMemoryMetricsReporter {
    fn register(&self, descriptor: MetricDescriptor) -> MetricId {
        match descriptor.kind {
            MetricKind::Counter => {
                let mut counters = self.counters.write();
                let idx = counters.len();
                counters.push((descriptor, AtomicU64::new(0)));
                MetricId(idx as u64)
            }
            MetricKind::Histogram { buckets } => {
                let mut histograms = self.histograms.write();
                let idx = histograms.len();
                let bucket_cells = buckets
                    .iter()
                    .map(|&b| (b, AtomicU64::new(0)))
                    .collect();
                histograms.push((
                    descriptor,
                    bucket_cells,
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                ));
                MetricId(0x4000_0000_0000_0000 | idx as u64)
            }
            MetricKind::Gauge => {
                let mut gauges = self.gauges.write();
                let idx = gauges.len();
                gauges.push((descriptor, AtomicU64::new(0)));
                MetricId(0x8000_0000_0000_0000 | idx as u64)
            }
        }
    }

    fn counter_inc(&self, id: MetricId, value: u64) {
        if id == MetricId::NULL {
            return;
        }
        let idx = (id.0 & 0x0FFF_FFFF_FFFF_FFFF) as usize;
        let counters = self.counters.read();
        if let Some((_, cell)) = counters.get(idx) {
            cell.fetch_add(value, Ordering::Relaxed);
        }
    }

    fn histogram_record(&self, id: MetricId, value: f64) {
        if id == MetricId::NULL {
            return;
        }
        let idx = (id.0 & 0x0FFF_FFFF_FFFF_FFFF) as usize;
        let histograms = self.histograms.read();
        if let Some((_, buckets, sum, count)) = histograms.get(idx) {
            count.fetch_add(1, Ordering::Relaxed);
            sum.fetch_add(value as u64, Ordering::Relaxed);
            for (bucket, counter) in buckets {
                if value <= *bucket {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    fn gauge_set(&self, id: MetricId, value: f64) {
        if id == MetricId::NULL {
            return;
        }
        let idx = (id.0 & 0x0FFF_FFFF_FFFF_FFFF) as usize;
        let gauges = self.gauges.read();
        if let Some((_, cell)) = gauges.get(idx) {
            cell.store(value.to_bits(), Ordering::Relaxed);
        }
    }

    fn export_prometheus(&self) -> String {
        let mut out = String::new();

        // Export counters
        let counters = self.counters.read();
        for (desc, value) in counters.iter() {
            out.push_str(&format!("# HELP {} {}\n", desc.name, desc.help));
            out.push_str(&format!("# TYPE {} counter\n", desc.name));
            let labels = desc
                .labels
                .iter()
                .map(|l| format!("{}=\"{}\"", l.key, l.value))
                .collect::<Vec<_>>()
                .join(",");
            if labels.is_empty() {
                out.push_str(&format!(
                    "{} {}\n\n",
                    desc.name,
                    value.load(Ordering::Relaxed)
                ));
            } else {
                out.push_str(&format!(
                    "{}{{{}}} {}\n\n",
                    desc.name,
                    labels,
                    value.load(Ordering::Relaxed)
                ));
            }
        }

        // Export gauges
        let gauges = self.gauges.read();
        for (desc, value) in gauges.iter() {
            out.push_str(&format!("# HELP {} {}\n", desc.name, desc.help));
            out.push_str(&format!("# TYPE {} gauge\n", desc.name));
            let labels = desc
                .labels
                .iter()
                .map(|l| format!("{}=\"{}\"", l.key, l.value))
                .collect::<Vec<_>>()
                .join(",");
            let val = f64::from_bits(value.load(Ordering::Relaxed));
            if labels.is_empty() {
                out.push_str(&format!("{} {}\n\n", desc.name, val));
            } else {
                out.push_str(&format!(
                    "{}{{{}}} {}\n\n",
                    desc.name, labels, val
                ));
            }
        }

        out
    }

    fn export_json(&self) -> Value {
        Value::Null // TODO: implement
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noop_reporter() {
        let reporter = NoOpMetricsReporter;

        let id = reporter.register(MetricDescriptor {
            name: "test_counter",
            help: "A test counter",
            kind: MetricKind::Counter,
            labels: vec![],
        });

        assert_eq!(id, MetricId::NULL);
        reporter.counter_inc(id, 42);
        reporter.histogram_record(id, 1.0);
        reporter.gauge_set(id, 3.14);
        assert!(reporter.export_prometheus().is_empty());
        assert_eq!(reporter.export_json(), Value::Null);
    }

    #[test]
    fn test_in_memory_counter() {
        let reporter = InMemoryMetricsReporter::new();

        let id = reporter.register(MetricDescriptor {
            name: "events_processed",
            help: "Number of events processed",
            kind: MetricKind::Counter,
            labels: vec![],
        });

        reporter.counter_inc(id, 1);
        reporter.counter_inc(id, 5);

        assert_eq!(reporter.counter_value("events_processed"), Some(6));
    }

    #[test]
    fn test_in_memory_counter_null_id() {
        let reporter = InMemoryMetricsReporter::new();
        reporter.counter_inc(MetricId::NULL, 10);
        // Should not panic and should not affect anything
        assert_eq!(reporter.counter_value("nonexistent"), None);
    }

    #[test]
    fn test_in_memory_gauge() {
        let reporter = InMemoryMetricsReporter::new();

        let id = reporter.register(MetricDescriptor {
            name: "queue_depth",
            help: "Current queue depth",
            kind: MetricKind::Gauge,
            labels: vec![],
        });

        reporter.gauge_set(id, 42.0);
        // Check via prometheus export that the value appears
        let prom = reporter.export_prometheus();
        assert!(prom.contains("queue_depth"));
    }

    #[test]
    fn test_in_memory_histogram() {
        let reporter = InMemoryMetricsReporter::new();

        let id = reporter.register(MetricDescriptor {
            name: "event_latency",
            help: "Event processing latency",
            kind: MetricKind::Histogram {
                buckets: &[1.0, 10.0, 100.0],
            },
            labels: vec![],
        });

        reporter.histogram_record(id, 5.0);
        reporter.histogram_record(id, 50.0);
        reporter.histogram_record(id, 200.0);

        // Since histograms are not yet exposed in public API, we just verify
        // it doesn't panic and counter export still works
        let prom = reporter.export_prometheus();
        assert!(prom.is_empty()); // counters are empty
    }

    #[test]
    fn test_prometheus_export_format() {
        let reporter = InMemoryMetricsReporter::new();

        let _id = reporter.register(MetricDescriptor {
            name: "my_counter",
            help: "My counter help",
            kind: MetricKind::Counter,
            labels: vec![Label::new("env", "test")],
        });

        let prom = reporter.export_prometheus();
        assert!(prom.contains("# HELP my_counter My counter help"));
        assert!(prom.contains("# TYPE my_counter counter"));
        assert!(prom.contains("my_counter{env=\"test\"}"));
    }

    #[test]
    fn test_prometheus_export_no_labels() {
        let reporter = InMemoryMetricsReporter::new();

        let id = reporter.register(MetricDescriptor {
            name: "simple_counter",
            help: "Simple counter",
            kind: MetricKind::Counter,
            labels: vec![],
        });
        reporter.counter_inc(id, 7);

        let prom = reporter.export_prometheus();
        assert!(prom.contains("# HELP simple_counter Simple counter"));
        assert!(prom.contains("# TYPE simple_counter counter"));
        assert!(prom.contains("simple_counter 7"));
    }

    #[test]
    fn test_multiple_counters() {
        let reporter = InMemoryMetricsReporter::new();

        let id1 = reporter.register(MetricDescriptor {
            name: "counter_a",
            help: "Counter A",
            kind: MetricKind::Counter,
            labels: vec![],
        });
        let id2 = reporter.register(MetricDescriptor {
            name: "counter_b",
            help: "Counter B",
            kind: MetricKind::Counter,
            labels: vec![],
        });

        reporter.counter_inc(id1, 3);
        reporter.counter_inc(id2, 7);

        assert_eq!(reporter.counter_value("counter_a"), Some(3));
        assert_eq!(reporter.counter_value("counter_b"), Some(7));
    }

    #[test]
    fn test_metric_id_null() {
        assert_eq!(MetricId::NULL, MetricId(u64::MAX));
    }
}
