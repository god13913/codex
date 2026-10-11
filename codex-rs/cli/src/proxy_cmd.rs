use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub struct ProxyCommand {
    #[command(subcommand)]
    command: ProxySubcommand,
}

#[derive(Debug, Subcommand)]
enum ProxySubcommand {
    /// Internal administrator forwarding process; the normal CLI starts it automatically.
    #[command(hide = true)]
    Bridge {
        #[arg(long)]
        request: std::path::PathBuf,
    },
    /// Internal detached desktop authorization coordinator.
    #[command(hide = true)]
    BridgeSession {
        #[arg(long)]
        request: std::path::PathBuf,
    },
    /// Internal forwarding worker started by an already authorized session helper.
    #[command(hide = true)]
    BridgeWorker {
        #[arg(long)]
        request: std::path::PathBuf,
    },
    /// Configure one HTTPS subscription URL in plain JSON and fetch its single node; enables the proxy.
    Configure {
        #[arg(long)]
        stdin: bool,
    },
    /// Backward-compatible alias for `configure`.
    Import {
        #[arg(long)]
        stdin: bool,
    },
    /// Import the protected VPS VLESS-WebSocket profile through hidden input or stdin; enables the proxy.
    VpsImport {
        #[arg(long)]
        stdin: bool,
    },
    /// Show redacted dedicated-proxy state.
    Status,
    /// Refresh node cache for subsequent service starts.
    Refresh,
    /// Enable the cached subscription for subsequent service starts.
    Enable,
    /// Disable the dedicated proxy for subsequent service starts.
    Disable,
}

pub async fn run(command: ProxyCommand) -> anyhow::Result<()> {
    let home = codex_core::config::find_codex_home()?;
    let (action, stdin) = match command.command {
        ProxySubcommand::Bridge { request } => {
            return codex_dedicated_proxy::run_desktop_bridge(&request);
        }
        ProxySubcommand::BridgeSession { request } => {
            return codex_dedicated_proxy::run_desktop_bridge_session(&request);
        }
        ProxySubcommand::BridgeWorker { request } => {
            return codex_dedicated_proxy::run_desktop_bridge_worker(&request);
        }
        ProxySubcommand::Configure { stdin } => ("configure", stdin),
        ProxySubcommand::Import { stdin } => ("import", stdin),
        ProxySubcommand::VpsImport { stdin } => ("vps-import", stdin),
        ProxySubcommand::Status => ("status", false),
        ProxySubcommand::Refresh => ("refresh", false),
        ProxySubcommand::Enable => ("enable", false),
        ProxySubcommand::Disable => ("disable", false),
    };
    println!(
        "{}",
        codex_dedicated_proxy::manage(&home, action, stdin).await?
    );
    Ok(())
}
