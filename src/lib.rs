mod cli;
mod config;
mod config_watcher;
mod constants;
mod helper;
mod multi_map;
mod protocol;
mod transport;

pub use cli::Cli;
use cli::KeypairType;
pub use config::{
    ClientConfig, ClientServiceConfig, Config, MaskedString, ServerConfig, ServerServiceConfig,
    ServiceType, TransportConfig, TransportType,
};
pub use config_watcher::{ClientServiceChange, ConfigChange, ServerServiceChange};
pub use constants::UDP_BUFFER_SIZE;

use anyhow::{Context, Result};
use std::future::Future;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, info};

#[cfg(feature = "client")]
mod client;
#[cfg(feature = "client")]
use client::run_client;

#[cfg(feature = "server")]
mod server;
#[cfg(feature = "server")]
use server::run_server;

use crate::config_watcher::ConfigWatcherHandle;

const DEFAULT_CURVE: KeypairType = KeypairType::X25519;

fn get_str_from_keypair_type(curve: KeypairType) -> &'static str {
    match curve {
        KeypairType::X25519 => "25519",
        KeypairType::X448 => "448",
    }
}

#[cfg(feature = "noise")]
fn genkey(curve: Option<KeypairType>) -> Result<()> {
    let curve = curve.unwrap_or(DEFAULT_CURVE);
    let builder = snowstorm::Builder::new(
        format!(
            "Noise_KK_{}_ChaChaPoly_BLAKE2s",
            get_str_from_keypair_type(curve)
        )
        .parse()?,
    );
    let keypair = builder.generate_keypair()?;

    println!("Private Key:\n{}\n", base64::encode(keypair.private));
    println!("Public Key:\n{}", base64::encode(keypair.public));
    Ok(())
}

#[cfg(not(feature = "noise"))]
fn genkey(curve: Option<KeypairType>) -> Result<()> {
    crate::helper::feature_not_compile("nosie")
}

pub async fn run(args: Cli, shutdown_rx: broadcast::Receiver<bool>) -> Result<()> {
    if args.genkey.is_some() {
        return genkey(args.genkey.unwrap());
    }

    // Raise `nofile` limit on linux and mac
    fdlimit::raise_fd_limit();

    // Spawn a config watcher. The watcher will send a initial signal to start the instance with a config
    let config_path = args.config_path.as_ref().unwrap();
    let mut cfg_watcher = ConfigWatcherHandle::new(config_path, shutdown_rx).await?;

    // shutdown_tx owns the instance
    let (shutdown_tx, _) = broadcast::channel(1);

    // (The join handle of the last instance, The service update channel sender)
    let mut last_instance: Option<(tokio::task::JoinHandle<_>, mpsc::Sender<ConfigChange>)> = None;

    while let Some(e) = cfg_watcher.event_rx.recv().await {
        match e {
            ConfigChange::General(config) => {
                if let Some((i, _)) = last_instance {
                    info!("General configuration change detected. Restarting...");
                    shutdown_tx.send(true)?;
                    i.await??;
                }

                debug!("{:?}", config);

                let (service_update_tx, service_update_rx) = mpsc::channel(1024);

                last_instance = Some((
                    tokio::spawn(run_instance(
                        *config,
                        args.clone(),
                        shutdown_tx.subscribe(),
                        service_update_rx,
                    )),
                    service_update_tx,
                ));
            }
            ev => {
                info!("Service change detected. {:?}", ev);
                if let Some((_, service_update_tx)) = &last_instance {
                    let _ = service_update_tx.send(ev).await;
                }
            }
        }
    }

    let _ = shutdown_tx.send(true);

    Ok(())
}

async fn run_instance(
    config: Config,
    args: Cli,
    shutdown_rx: broadcast::Receiver<bool>,
    service_update: mpsc::Receiver<ConfigChange>,
) -> Result<()> {
    match determine_run_mode(&config, &args) {
        RunMode::Undetermine => panic!("Cannot determine running as a server or a client"),
        RunMode::Client => {
            #[cfg(not(feature = "client"))]
            crate::helper::feature_not_compile("client");
            #[cfg(feature = "client")]
            run_client(config, shutdown_rx, service_update).await
        }
        RunMode::Server => {
            #[cfg(not(feature = "server"))]
            crate::helper::feature_not_compile("server");
            #[cfg(feature = "server")]
            run_server(config, shutdown_rx, service_update).await
        }
    }
}

/// Internal helper that keeps the join handle and live channels for an embedded instance.
struct EmbeddedHandle {
    join: JoinHandle<Result<()>>,
    shutdown_tx: broadcast::Sender<bool>,
    update_tx: mpsc::Sender<ConfigChange>,
}

impl EmbeddedHandle {
    fn spawn<F, Fut>(builder: F) -> EmbeddedHandle
    where
        F: FnOnce(broadcast::Receiver<bool>, mpsc::Receiver<ConfigChange>) -> Fut,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let (update_tx, update_rx) = mpsc::channel(1024);
        let join = tokio::spawn(builder(shutdown_rx, update_rx));

        EmbeddedHandle {
            join,
            shutdown_tx,
            update_tx,
        }
    }

    fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    fn shutdown_signal(&self) -> broadcast::Sender<bool> {
        self.shutdown_tx.clone()
    }

    fn raw_update_sender(&self) -> mpsc::Sender<ConfigChange> {
        self.update_tx.clone()
    }

    async fn send_update(&self, change: ConfigChange) -> Result<()> {
        self.update_tx
            .send(change)
            .await
            .context("Failed to deliver configuration update to embedded instance")
    }

    async fn wait(self) -> Result<()> {
        self.join
            .await
            .context("Embedded instance task panicked or was cancelled")?
    }

    async fn stop(self) -> Result<()> {
        self.shutdown();
        self.wait().await
    }
}

/// Handle for running a rathole client inside an existing Tokio runtime without relying on
/// filesystem-backed configuration.
#[cfg(feature = "client")]
pub struct EmbeddedClient {
    handle: EmbeddedHandle,
}

#[cfg(feature = "client")]
impl EmbeddedClient {
    /// Start a client instance using the provided in-memory configuration.
    ///
    /// The returned handle keeps background tasks alive until [`EmbeddedClient::stop`] or
    /// [`EmbeddedClient::wait`] is called, or until it is dropped and the task completes on its own.
    pub fn spawn(config: ClientConfig) -> Result<EmbeddedClient> {
        let config = Config::from_client_config(config)?;
        Ok(EmbeddedClient {
            handle: EmbeddedHandle::spawn(move |shutdown_rx, update_rx| {
                run_client(config, shutdown_rx, update_rx)
            }),
        })
    }

    /// Dynamically add a service definition to the running client.
    pub async fn add_service(&self, service: ClientServiceConfig) -> Result<()> {
        self.handle
            .send_update(ConfigChange::ClientChange(ClientServiceChange::Add(
                service,
            )))
            .await
    }

    /// Remove a service from the running client by name.
    pub async fn remove_service(&self, name: impl Into<String>) -> Result<()> {
        self.handle
            .send_update(ConfigChange::ClientChange(ClientServiceChange::Delete(
                name.into(),
            )))
            .await
    }

    /// Forward a preconstructed client change message to the embedded instance.
    pub async fn send_change(&self, change: ClientServiceChange) -> Result<()> {
        self.handle
            .send_update(ConfigChange::ClientChange(change))
            .await
    }

    /// Request a graceful shutdown. The background task stops shortly afterwards.
    pub fn shutdown(&self) {
        self.handle.shutdown();
    }

    /// Obtain a broadcast sender that can be cloned to subscribe to the shutdown signal used by
    /// the embedded instance.
    pub fn shutdown_signal(&self) -> broadcast::Sender<bool> {
        self.handle.shutdown_signal()
    }

    /// Access the underlying configuration update channel for advanced workflows.
    pub fn raw_update_sender(&self) -> mpsc::Sender<ConfigChange> {
        self.handle.raw_update_sender()
    }

    /// Wait for the background task to finish without issuing an additional shutdown signal.
    pub async fn wait(self) -> Result<()> {
        self.handle.wait().await
    }

    /// Send a shutdown signal and wait for the background task to exit.
    pub async fn stop(self) -> Result<()> {
        self.handle.stop().await
    }
}

/// Handle for running a rathole server inside an existing Tokio runtime without relying on
/// filesystem-backed configuration.
#[cfg(feature = "server")]
pub struct EmbeddedServer {
    handle: EmbeddedHandle,
}

#[cfg(feature = "server")]
impl EmbeddedServer {
    /// Start a server instance using the provided in-memory configuration.
    pub fn spawn(config: ServerConfig) -> Result<EmbeddedServer> {
        let config = Config::from_server_config(config)?;
        Ok(EmbeddedServer {
            handle: EmbeddedHandle::spawn(move |shutdown_rx, update_rx| {
                run_server(config, shutdown_rx, update_rx)
            }),
        })
    }

    /// Dynamically add a service definition to the running server.
    pub async fn add_service(&self, service: ServerServiceConfig) -> Result<()> {
        self.handle
            .send_update(ConfigChange::ServerChange(ServerServiceChange::Add(
                service,
            )))
            .await
    }

    /// Remove a service from the running server by name.
    pub async fn remove_service(&self, name: impl Into<String>) -> Result<()> {
        self.handle
            .send_update(ConfigChange::ServerChange(ServerServiceChange::Delete(
                name.into(),
            )))
            .await
    }

    /// Forward a preconstructed server change message to the embedded instance.
    pub async fn send_change(&self, change: ServerServiceChange) -> Result<()> {
        self.handle
            .send_update(ConfigChange::ServerChange(change))
            .await
    }

    /// Request a graceful shutdown. The background task stops shortly afterwards.
    pub fn shutdown(&self) {
        self.handle.shutdown();
    }

    /// Obtain a broadcast sender that can be cloned to subscribe to the shutdown signal used by
    /// the embedded instance.
    pub fn shutdown_signal(&self) -> broadcast::Sender<bool> {
        self.handle.shutdown_signal()
    }

    /// Access the underlying configuration update channel for advanced workflows.
    pub fn raw_update_sender(&self) -> mpsc::Sender<ConfigChange> {
        self.handle.raw_update_sender()
    }

    /// Wait for the background task to finish without issuing an additional shutdown signal.
    pub async fn wait(self) -> Result<()> {
        self.handle.wait().await
    }

    /// Send a shutdown signal and wait for the background task to exit.
    pub async fn stop(self) -> Result<()> {
        self.handle.stop().await
    }
}

#[derive(PartialEq, Eq, Debug)]
enum RunMode {
    Server,
    Client,
    Undetermine,
}

fn determine_run_mode(config: &Config, args: &Cli) -> RunMode {
    use RunMode::*;
    if args.client && args.server {
        Undetermine
    } else if args.client {
        Client
    } else if args.server {
        Server
    } else if config.client.is_some() && config.server.is_none() {
        Client
    } else if config.server.is_some() && config.client.is_none() {
        Server
    } else {
        Undetermine
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_run_mode() {
        use config::*;
        use RunMode::*;

        struct T {
            cfg_s: bool,
            cfg_c: bool,
            arg_s: bool,
            arg_c: bool,
            run_mode: RunMode,
        }

        let tests = [
            T {
                cfg_s: false,
                cfg_c: false,
                arg_s: false,
                arg_c: false,
                run_mode: Undetermine,
            },
            T {
                cfg_s: true,
                cfg_c: false,
                arg_s: false,
                arg_c: false,
                run_mode: Server,
            },
            T {
                cfg_s: false,
                cfg_c: true,
                arg_s: false,
                arg_c: false,
                run_mode: Client,
            },
            T {
                cfg_s: true,
                cfg_c: true,
                arg_s: false,
                arg_c: false,
                run_mode: Undetermine,
            },
            T {
                cfg_s: true,
                cfg_c: true,
                arg_s: true,
                arg_c: false,
                run_mode: Server,
            },
            T {
                cfg_s: true,
                cfg_c: true,
                arg_s: false,
                arg_c: true,
                run_mode: Client,
            },
            T {
                cfg_s: true,
                cfg_c: true,
                arg_s: true,
                arg_c: true,
                run_mode: Undetermine,
            },
        ];

        for t in tests {
            let config = Config {
                server: match t.cfg_s {
                    true => Some(ServerConfig::default()),
                    false => None,
                },
                client: match t.cfg_c {
                    true => Some(ClientConfig::default()),
                    false => None,
                },
            };

            let args = Cli {
                config_path: Some(std::path::PathBuf::new()),
                server: t.arg_s,
                client: t.arg_c,
                ..Default::default()
            };

            assert_eq!(determine_run_mode(&config, &args), t.run_mode);
        }
    }
}
