use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

pub fn init() {
    tracing_subscriber::fmt::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
}
