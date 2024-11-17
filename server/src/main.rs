use crate::cfg::Config;
use crate::db::{run_migrations, seed_db};
use crate::state::State;
use anyhow::Result;
use axum::body::Body;
use axum::http::header::AUTHORIZATION;
use axum::http::Request;
use axum::routing::{delete, get, patch, post, put};
use axum::Router;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::AsyncPgConnection;
use jsonwebtoken::{DecodingKey, EncodingKey};
use std::fs;
use std::iter::once;
use std::time::Duration;
use tower::ServiceBuilder;
use tower_http::request_id::MakeRequestUuid;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tower_http::validate_request::ValidateRequestHeaderLayer;
use tower_http::ServiceBuilderExt;
use tracing::{info, span, Level};

//--------------------------------------------------------------------------------------------------

mod cfg;
mod client_admin_role;
mod db;
mod db_models;
mod handler_proxy;
mod handlers;
mod queries;
mod response;
mod schema;
mod state;
mod token;
mod types;

//--------------------------------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    // Load config
    let cfg: Config = config::Config::builder()
        .add_source(config::File::with_name("config").required(false))
        .add_source(config::File::with_name("config.local").required(false))
        .add_source(config::Environment::with_prefix("RSAUTH").separator("__"))
        .build()?
        .try_deserialize()?;

    // Initialize tracing
    let mut fmt_sub = tracing_subscriber::fmt();
    if cfg.debug {
        fmt_sub = fmt_sub.with_max_level(Level::DEBUG);
    } else {
        fmt_sub = fmt_sub.with_max_level(Level::INFO);
    }
    fmt_sub.init();

    // Read key files
    let private_key = fs::read(cfg.private_key_path)?;
    let public_key = fs::read(cfg.public_key_path)?;

    // Run the migrations
    run_migrations(cfg.postgres_connection_string.clone()).await?;

    // Open the database pool
    let db_cfg =
        AsyncDieselConnectionManager::<AsyncPgConnection>::new(cfg.postgres_connection_string);
    let pool = Pool::builder().build(db_cfg).await?;

    // Seed the DB
    seed_db(&pool).await?;

    // Create state
    let encoding_key = EncodingKey::from_ec_pem(&private_key)?;
    let decoding_key = DecodingKey::from_ec_pem(&public_key)?;
    let state = State::new(pool, encoding_key, decoding_key);

    // Setup the API
    let app = Router::new()
        .route("/authorise", post(handler_proxy::authorise))
        .route("/management/clients", get(handler_proxy::get_clients))
        .route("/management/clients", post(handler_proxy::new_client))
        .route(
            "/management/clients/:client_id",
            get(handler_proxy::get_client),
        )
        .route(
            "/management/clients/:client_id",
            patch(handler_proxy::update_client),
        )
        .route("/management/roles", get(handler_proxy::get_roles))
        .route("/management/roles", post(handler_proxy::new_role))
        .route("/management/roles/:role_id", get(handler_proxy::get_role))
        .route(
            "/management/roles/:role_id",
            patch(handler_proxy::update_role),
        )
        .route(
            "/management/clients/:client_id/roles",
            get(handler_proxy::get_client_roles_for_client),
        )
        .route(
            "/management/clients/:client_id/roles/:role_id",
            get(handler_proxy::get_client_role),
        )
        .route(
            "/management/clients/:client_id/roles/:role_id",
            put(handler_proxy::put_client_role),
        )
        .route(
            "/management/clients/:client_id/roles/:role_id",
            delete(handler_proxy::delete_client_role),
        )
        .with_state(state.into())
        .layer(
            ServiceBuilder::new()
                .sensitive_headers(once(AUTHORIZATION))
                .set_x_request_id(MakeRequestUuid)
                .decompression()
                .compression()
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(|request: &Request<Body>| {
                            let request_id = request
                                .headers()
                                .get("x-request-id")
                                .and_then(|hv| hv.to_str().ok())
                                .unwrap_or("unknown");
                            span!(
                                Level::INFO,
                                "http_request",
                                request_id,
                                http_request.request_method = request.method().as_str(),
                                http_request.request_url = request.uri().path()
                            )
                        })
                        .on_request(DefaultOnRequest::new().level(Level::INFO))
                        .on_response(DefaultOnResponse::new().level(Level::INFO)),
                )
                .propagate_x_request_id()
                .layer(TimeoutLayer::new(Duration::from_secs(10)))
                .layer(ValidateRequestHeaderLayer::accept("application/json")),
        );

    // Run the API
    let bind_addr = format!("0.0.0.0:{}", cfg.http_port.unwrap_or(3001));
    info!("Listening on {}", bind_addr);
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

//--------------------------------------------------------------------------------------------------
