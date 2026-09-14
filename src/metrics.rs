use prometheus::{Counter, Gauge, Histogram, register_counter, register_gauge, register_histogram};

#[derive(Clone)]
pub struct AppMetrics {
    pub requests_total: Counter,
    pub successful_requests_total: Counter,
    pub decryption_errors_total: Counter,
    pub encryption_errors_total: Counter,
    pub backend_errors_total: Counter,
    pub key_requests_total: Counter,
    pub request_duration: Histogram,
    pub active_connections: Gauge,
}

impl Default for AppMetrics {
    fn default() -> Self {
        AppMetrics::new()
    }
}

impl AppMetrics {
    fn new() -> Self {
        Self {
            requests_total: register_counter!(
                "ohttp_requests_total",
                "Total number of OHTTP requests"
            )
            .unwrap_or_else(|_| {
                Counter::with_opts(prometheus::Opts::new(
                    "ohttp_requests_total",
                    "Total number of OHTTP requests",
                ))
                .unwrap()
            }),
            successful_requests_total: register_counter!(
                "ohttp_successful_requests_total",
                "Total number of successful OHTTP requests"
            )
            .unwrap_or_else(|_| {
                Counter::with_opts(prometheus::Opts::new(
                    "ohttp_successful_requests_total",
                    "Total number of successful OHTTP requests",
                ))
                .unwrap()
            }),
            decryption_errors_total: register_counter!(
                "ohttp_decryption_errors_total",
                "Total number of decryption errors"
            )
            .unwrap_or_else(|_| {
                Counter::with_opts(prometheus::Opts::new(
                    "ohttp_decryption_errors_total",
                    "Total number of decryption errors",
                ))
                .unwrap()
            }),
            encryption_errors_total: register_counter!(
                "ohttp_encryption_errors_total",
                "Total number of encryption errors"
            )
            .unwrap_or_else(|_| {
                Counter::with_opts(prometheus::Opts::new(
                    "ohttp_encryption_errors_total",
                    "Total number of encryption errors",
                ))
                .unwrap()
            }),
            backend_errors_total: register_counter!(
                "ohttp_backend_errors_total",
                "Total number of backend errors"
            )
            .unwrap_or_else(|_| {
                Counter::with_opts(prometheus::Opts::new(
                    "ohttp_backend_errors_total",
                    "Total number of backend errors",
                ))
                .unwrap()
            }),
            key_requests_total: register_counter!(
                "ohttp_key_requests_total",
                "Total number of key configuration requests"
            )
            .unwrap_or_else(|_| {
                Counter::with_opts(prometheus::Opts::new(
                    "ohttp_key_requests_total",
                    "Total number of key configuration requests",
                ))
                .unwrap()
            }),
            request_duration: register_histogram!(
                "ohttp_request_duration_seconds",
                "Duration of OHTTP request processing"
            )
            .unwrap_or_else(|_| {
                Histogram::with_opts(prometheus::HistogramOpts::new(
                    "ohttp_request_duration_seconds",
                    "Duration of OHTTP request processing",
                ))
                .unwrap()
            }),
            active_connections: register_gauge!(
                "ohttp_active_connections",
                "Number of active connections"
            )
            .unwrap_or_else(|_| {
                Gauge::with_opts(prometheus::Opts::new(
                    "ohttp_active_connections",
                    "Number of active connections",
                ))
                .unwrap()
            }),
        }
    }
}
