//! Small diagnostic/import entrypoint, also used before building the full Codex workspace.
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let home = std::env::var_os("CODEX_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE").map(|p| std::path::PathBuf::from(p).join(".codex"))
        })
        .ok_or_else(|| anyhow::anyhow!("CODEX_HOME is unavailable"))?;
    let action = std::env::args().nth(1).unwrap_or_else(|| "status".into());
    if action == "hold" {
        let guard = codex_dedicated_proxy::start_if_enabled(&home)
            .await?
            .ok_or_else(|| anyhow::anyhow!("dedicated proxy is disabled"))?;
        let (pid, proxy_port, control_port) = guard.local_process()?;
        println!(
            "{}",
            serde_json::json!({"kernel_ready": true, "kernel_pid": pid, "proxy_port": proxy_port, "control_port": control_port})
        );
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    } else if action == "probe" {
        let _guard = codex_dedicated_proxy::start_if_enabled(&home)
            .await?
            .ok_or_else(|| anyhow::anyhow!("dedicated proxy is disabled"))?;
        let endpoint = codex_dedicated_proxy::active_proxy_url()
            .ok_or_else(|| anyhow::anyhow!("proxy unavailable"))?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .proxy(reqwest::Proxy::all(&endpoint)?)
            .timeout(std::time::Duration::from_secs(20))
            .build()?;
        let response = client
            .get("https://chatgpt.com/backend-api/models")
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("proxied HTTPS probe failed"))?;
        println!(
            "{}",
            serde_json::json!({"kernel_started": true, "https_status": response.status().as_u16(), "model_call_verified": false})
        );
    } else {
        println!(
            "{}",
            codex_dedicated_proxy::manage(&home, &action, true).await?
        );
    }
    Ok(())
}
