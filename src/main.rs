//! Bitcoin mainnet P2P network crawler (see SPECIFICATION_v2.md).

mod addrlog;
mod address;
mod crawler;
mod dns;
mod output;
mod preflight;
mod protocol;
mod settings;
mod store;
mod transport;

use crate::addrlog::AddrLog;
use crate::address::classify;
use crate::crawler::Crawler;
use crate::output::SeedResult;
use crate::settings::Settings;
use crate::store::{AddrKey, NodeStore};
use clap::Parser;
use std::process::ExitCode;
use std::sync::Arc;
use tracing_subscriber::prelude::*;

/// Exit code used for a configuration error (Section 2.4 step 4).
const EXIT_CONFIG_ERROR: u8 = 2;

fn main() -> ExitCode {
    let cli = settings::Cli::parse();
    let settings = match cli.into_settings() {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("configuration error: {e}");
            return ExitCode::from(EXIT_CONFIG_ERROR);
        }
    };

    // Sanity-check: create the results directory if missing (Section 2.4 step 1).
    if !settings.dry_run {
        if let Err(e) = std::fs::create_dir_all(&settings.result_settings.path) {
            eprintln!(
                "cannot create results directory {}: {e}",
                settings.result_settings.path
            );
            return ExitCode::from(EXIT_CONFIG_ERROR);
        }
    }

    // Init logging (UTC timestamps; console at chosen level, optional debug file).
    let _guard = init_logging(&settings);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    runtime.block_on(async_main(settings))
}

fn init_logging(settings: &Settings) -> Option<tracing_appender::non_blocking::WorkerGuard> {
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
        let filename = format!("{}_debug_log.txt", settings.prefix());
        let path = std::path::Path::new(&settings.result_settings.path).join(filename);
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

async fn async_main(settings: Arc<Settings>) -> ExitCode {
    // Optional startup delay for local Tor/I2P warm-up (Section 2.4 step 3).
    if settings.delay_start > 0 {
        tracing::info!("delaying start by {}s", settings.delay_start);
        tokio::time::sleep(std::time::Duration::from_secs(settings.delay_start)).await;
    }

    // Network preflight (Section 2.5).
    let rows = preflight::run_preflight(&settings).await;

    if settings.dry_run {
        let all_ok = preflight::print_table(&rows);
        return if all_ok {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(EXIT_CONFIG_ERROR)
        };
    }

    let failures = preflight::any_enabled_failed(&rows);
    if !failures.is_empty() {
        if settings.strict_networks {
            for f in &failures {
                tracing::error!("preflight failed (strict): {f}");
            }
            return ExitCode::from(EXIT_CONFIG_ERROR);
        }
        for f in &failures {
            tracing::warn!("preflight failed (continuing): {f}");
        }
    }

    // Build the store and (optional) addr-response log.
    let store = Arc::new(NodeStore::new());
    let addr_log = if settings.record_addr_responses {
        let filename = format!(
            "{}_{}",
            settings.prefix(),
            settings.result_settings.addr_responses
        );
        let path = std::path::Path::new(&settings.result_settings.path).join(filename);
        match AddrLog::create(&path) {
            Ok(log) => Some(Arc::new(log)),
            Err(e) => {
                tracing::warn!("cannot create addr-response log: {e}");
                None
            }
        }
    } else {
        None
    };

    let crawler = Arc::new(Crawler::new(
        Arc::clone(&store),
        Arc::clone(&settings),
        addr_log.clone(),
    ));

    // Resolve DNS seeds into the initial Queued entries (Section 3.1).
    let seed_results = seed_from_dns(&crawler, &settings).await;

    let total_seeded: usize = seed_results.iter().map(|s| s.addrs.len()).sum();
    tracing::info!(
        "resolved {} seed(s) into {} initial addresses",
        seed_results.len(),
        total_seeded
    );

    // Run the crawl (Sections 3.5–3.6).
    Arc::clone(&crawler).run().await;

    let runtime_seconds = crawler.start_clock.elapsed().as_secs() as i64;
    let num_processed = crawler.num_processed();

    // Final summary (Section 7.3).
    let reachable = store.count_state(store::NodeState::Reachable);
    let handshake_failed = store.count_state(store::NodeState::HandshakeFailed);
    let unreachable = store.count_state(store::NodeState::Unreachable);
    tracing::info!(
        "crawl complete: processed={num_processed} reachable={reachable} handshake_failed={handshake_failed} unreachable={unreachable} runtime={runtime_seconds}s"
    );

    if let Some(log) = &addr_log {
        log.flush().await;
    }

    // Persist output files (Section 8).
    if let Err(e) =
        output::write_all(&store, &settings, &seed_results, runtime_seconds, num_processed)
    {
        tracing::error!("failed to write output: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

/// Resolve every DNS seed and enqueue the enabled-network initial addresses.
async fn seed_from_dns(crawler: &Arc<Crawler>, settings: &Settings) -> Vec<SeedResult> {
    let now = crawler::now_epoch();
    let mut results = Vec::new();

    for seed in dns::SEEDS {
        let ips = dns::resolve_seed(seed).await;
        let mut addrs = Vec::new();
        for ip in ips {
            let host = dns::ip_to_host(ip);
            let net = classify(&host);
            if !settings.is_enabled(net) {
                continue;
            }
            let key = AddrKey::new(host, dns::MAINNET_PORT);
            let outcome = crawler.store.observe_seed(key.clone(), now);
            if outcome.newly_queued {
                crawler.enqueue_seed(key.clone());
            }
            addrs.push((key, net));
        }
        results.push(SeedResult {
            seed: seed.to_string(),
            addrs,
        });
    }
    results
}
