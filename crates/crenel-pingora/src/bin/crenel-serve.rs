//! crenel-serve — minimal standalone static file server on Pingora.
//!
//! The standalone consumer proof for the crenel crates, and the e2e test vehicle.
//!
//! Usage:
//!   crenel-serve --bind 127.0.0.1:8080 \
//!       --mount /=/srv/site,index,fallthrough \
//!       --mount /assets=/srv/site/assets,cache-control=public%2Cmax-age=31536000
//!
//! Mount options (comma-separated after the directory): `index`, `fallthrough`,
//! `dotfiles`, `symlinks-within-root`, `no-sidecars`, `cache-control=VALUE`
//! (percent-encode commas inside VALUE as %2C).

#[cfg(target_os = "linux")]
fn main() {
    real::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("crenel-serve is Linux-only (openat2-based resolver)");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod real {
    use std::time::Duration;

    use crenel_pingora::{Limits, MountSpec, StaticApp, StaticServer, StaticServerConfig};
    use pingora::server::configuration::Opt;
    use pingora::server::Server;
    use pingora::services::listening::Service;

    pub fn main() {
        let (bind, config) = match parse_args(std::env::args().skip(1).collect()) {
            Ok(parsed) => parsed,
            Err(message) => {
                eprintln!("crenel-serve: {message}");
                std::process::exit(2);
            }
        };
        let server = match StaticServer::new(config) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("crenel-serve: boot failed (fail-closed): {e}");
                std::process::exit(1);
            }
        };

        let mut pingora_server = Server::new(None::<Opt>).expect("pingora server");
        pingora_server.bootstrap();
        let mut service = Service::new("crenel-serve".to_string(), StaticApp { server });
        service.add_tcp(&bind);
        pingora_server.add_service(service);
        eprintln!("crenel-serve: listening on {bind}");
        pingora_server.run_forever();
    }

    fn parse_args(args: Vec<String>) -> Result<(String, StaticServerConfig), String> {
        let mut bind: Option<String> = None;
        let mut mounts: Vec<MountSpec> = Vec::new();
        let mut limits = Limits::default();

        let mut iter = args.into_iter();
        while let Some(flag) = iter.next() {
            let mut value = |name: &str| {
                iter.next()
                    .ok_or_else(|| format!("{name} requires a value"))
            };
            match flag.as_str() {
                "--bind" => bind = Some(value("--bind")?),
                "--mount" => mounts.push(MountSpec::parse(&value("--mount")?)?),
                "--inline-threshold" => {
                    limits.inline_threshold = parse_u64(&value("--inline-threshold")?)?;
                }
                "--min-throughput" => {
                    limits.min_throughput_bytes_per_sec = parse_u64(&value("--min-throughput")?)?;
                }
                "--deadline-floor-secs" => {
                    limits.deadline_floor =
                        Duration::from_secs(parse_u64(&value("--deadline-floor-secs")?)?);
                }
                "--write-timeout-secs" => {
                    limits.write_timeout =
                        Duration::from_secs(parse_u64(&value("--write-timeout-secs")?)?);
                }
                "--io-permits" => {
                    limits.io_permits = parse_u64(&value("--io-permits")?)? as usize;
                }
                other => return Err(format!("unknown flag {other:?}")),
            }
        }

        let bind = bind.ok_or("--bind is required")?;
        if mounts.is_empty() {
            return Err("at least one --mount PREFIX=DIR is required".to_string());
        }
        Ok((bind, StaticServerConfig { mounts, limits }))
    }

    fn parse_u64(digits: &str) -> Result<u64, String> {
        digits
            .parse()
            .map_err(|_| format!("expected a number, got {digits:?}"))
    }
}
