mod bootstrap;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bootstrap::bootstrap().await?;
    Ok(())
}
