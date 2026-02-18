use crate::config::ControlConfig;
use crate::error::AppError;
use crate::management::handlers::control::control_monitor;
use crate::management::monitoring::monitor::Monitors;
use axum::Router;
use axum::routing::get;
use tower_http::services::ServeDir;
use tracing::info;
pub mod forms;
pub mod handlers;
pub mod monitoring;
pub mod templates;
pub mod utils;

pub async fn init_control(
    config: ControlConfig,
    monitors: Monitors,
    static_path: &str,
) -> Result<(), AppError> {
    let app = Router::new()
        .nest_service("/static", ServeDir::new(static_path))
        .route("/control/{name}", get(control_monitor))
        .with_state(monitors);

    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    info!("listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}
