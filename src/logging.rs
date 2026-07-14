//! Tracing/logging setup shared by both binaries (Section 8.6).

use crate::settings::Settings;
use tracing_subscriber::prelude::*;

/// Initialise the console logger (and, unless disabled, a plain-text debug log
/// file under this run's output directory). Returns the appender guard, which
/// must be kept alive for the lifetime of the program.
pub fn init(settings: &Settings) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_subscriber::fmt;
    use tracing_subscriber::fmt::time::UtcTime;
    use tracing_subscriber::EnvFilter;

    let console_filter = EnvFilter::try_new(settings.log_level.to_lowercase())
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let console_layer = fmt::layer()
        .with_timer(UtcTime::rfc_3339())
        .with_writer(std::io::stdout)
        .with_filter(console_filter);

    // Optional plain-text debug log file (Section 8.6).
    let (file_layer, guard) = if settings.store_debug_log && !settings.dry_run {
        let path = settings.output_path("debug_log.txt");
        match std::fs::File::create(&path) {
            Ok(file) => {
                let (nb, guard) = tracing_appender::non_blocking(file);
                let layer = fmt::layer()
                    .with_ansi(false)
                    .with_timer(UtcTime::rfc_3339())
                    .with_writer(nb)
                    .with_filter(EnvFilter::new("debug"));
                (Some(layer), Some(guard))
            }
            Err(e) => {
                eprintln!("warning: cannot create debug log: {e}");
                (None, None)
            }
        }
    } else {
        (None, None)
    };

    tracing_subscriber::registry()
        .with(console_layer)
        .with(file_layer)
        .init();

    guard
}
