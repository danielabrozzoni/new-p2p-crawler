//! Bitcoin mainnet P2P network crawler (see SPECIFICATION_v2.md).

use clap::Parser;
use new_p2p_crawler::addrlog::AddrLog;
use new_p2p_crawler::address::classify;
use new_p2p_crawler::crawler::{self, Crawler};
use new_p2p_crawler::output::SeedResult;
use new_p2p_crawler::settings::{self, Settings};
use new_p2p_crawler::store::{self, AddrKey, NodeStore};
use new_p2p_crawler::{dns, logging, output, preflight};
use std::process::ExitCode;
use std::sync::Arc;

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

    // Sanity-check: create this run's results directory if missing (Section 2.4 step 1).
    if !settings.dry_run {
        let run_dir = settings.run_dir();
        if let Err(e) = std::fs::create_dir_all(&run_dir) {
            eprintln!("cannot create results directory {}: {e}", run_dir.display());
            return ExitCode::from(EXIT_CONFIG_ERROR);
        }
    }

    // Init logging (UTC timestamps; console at chosen level, optional debug file).
    let _guard = logging::init(&settings);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    runtime.block_on(async_main(settings))
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
        let path = settings.output_path(&settings.result_settings.addr_responses);
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
    let seed_results = Arc::new(seed_from_dns(&crawler, &settings).await);

    let total_seeded: usize = seed_results.iter().map(|s| s.addrs.len()).sum();
    tracing::info!(
        "resolved {} seed(s) into {} initial addresses",
        seed_results.len(),
        total_seeded
    );

    // Periodically checkpoint the snapshot result files so a hard kill or crash
    // still leaves recent output. Ctrl+C is handled inside `run()` and writes a
    // final, consistent snapshot below.
    let checkpoint = spawn_checkpoint(&crawler, &store, &settings, &seed_results);

    // Run the crawl (Sections 3.5–3.6).
    Arc::clone(&crawler).run().await;

    // Stop checkpointing before the final write so they can't overlap.
    if let Some(task) = checkpoint {
        task.abort();
        let _ = task.await;
    }

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

/// Spawn a background task that re-writes the snapshot result files every
/// `checkpoint_interval` seconds (disabled when 0). Guards against a hard kill
/// or crash where the final write never runs.
fn spawn_checkpoint(
    crawler: &Arc<Crawler>,
    store: &Arc<NodeStore>,
    settings: &Arc<Settings>,
    seeds: &Arc<Vec<SeedResult>>,
) -> Option<tokio::task::JoinHandle<()>> {
    if settings.checkpoint_interval <= 0 {
        return None;
    }
    let interval = std::time::Duration::from_secs(settings.checkpoint_interval as u64);
    let crawler = Arc::clone(crawler);
    let store = Arc::clone(store);
    let settings = Arc::clone(settings);
    let seeds = Arc::clone(seeds);
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // first tick is immediate; skip so the first write is one interval in
        loop {
            ticker.tick().await;
            let runtime = crawler.start_clock.elapsed().as_secs() as i64;
            let processed = crawler.num_processed();
            match output::write_all(&store, &settings, &seeds, runtime, processed) {
                Ok(()) => tracing::info!("checkpoint: result files written ({processed} processed)"),
                Err(e) => tracing::warn!("checkpoint write failed: {e}"),
            }
        }
    }))
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
