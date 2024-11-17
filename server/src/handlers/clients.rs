use crate::db_models::Client;
use crate::queries;
use crate::queries::{create_client, get_all_clients, get_client_by_id, UpdateClientChangeset};
use crate::response::{JsonResponse, RSAuthError};
use crate::state::StateRef;
use crate::types::{ClientId, ClientSecret, ClientSecretHash};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::{error, info, warn};

//--------------------------------------------------------------------------------------------------
// Requests
//--------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateClientRequest {
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
    pub disabled: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateClientRequest {
    #[serde(default)]
    pub client_secret: Option<ClientSecret>,
    #[serde(default)]
    pub disabled: Option<bool>,
}

//--------------------------------------------------------------------------------------------------
// Responses
//--------------------------------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientResponse {
    pub client_id: ClientId,
    pub disabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<Client> for ClientResponse {
    fn from(client: Client) -> Self {
        Self {
            client_id: client.client_id,
            disabled: client.disabled,
            created_at: client.created_at,
            updated_at: client.updated_at,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientListResponse {
    pub clients: Vec<ClientResponse>,
}

pub enum ClientError {
    ClientAlreadyExists,
    ClientNotFound,
    DatabaseError,
    CryptoError,
}

impl RSAuthError for ClientError {
    fn response_data(&self) -> (StatusCode, &'static str, String) {
        match self {
            ClientError::ClientAlreadyExists => (
                StatusCode::CONFLICT,
                "client_already_exists",
                "Client already exists".to_string(),
            ),
            ClientError::ClientNotFound => (
                StatusCode::NOT_FOUND,
                "client_not_found",
                "Client not found".to_string(),
            ),
            ClientError::DatabaseError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database error".to_string(),
            ),
            ClientError::CryptoError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "crypto_error",
                "Crypto error".to_string(),
            ),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Handlers
//--------------------------------------------------------------------------------------------------

pub async fn get_clients(
    State(state): State<StateRef>,
) -> JsonResponse<ClientListResponse, ClientError> {
    let clients = match get_all_clients(state.db_connection()).await {
        Ok(clients) => clients,
        Err(err) => {
            error!("Failed to get clients: {:?}", err);
            return Err(ClientError::DatabaseError).into();
        }
    };

    info!("Returning {} clients", clients.len());

    Ok(ClientListResponse {
        clients: clients.into_iter().map(ClientResponse::from).collect(),
    })
    .into()
}

pub async fn get_client(
    State(state): State<StateRef>,
    Path(client_id): Path<ClientId>,
) -> JsonResponse<ClientResponse, ClientError> {
    let client = match get_client_by_id(&client_id, state.db_connection()).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            warn!("Client not found: {:?}", client_id);
            return Err(ClientError::ClientNotFound).into();
        }
        Err(err) => {
            error!("Failed to get client {:?}: {}", client_id, err);
            return Err(ClientError::DatabaseError).into();
        }
    };

    info!("Returning client {:?}", client_id);

    Ok(ClientResponse::from(client)).into()
}

pub async fn new_client(
    State(state): State<StateRef>,
    Json(request): Json<CreateClientRequest>,
) -> JsonResponse<ClientResponse, ClientError> {
    // Ensure client does not already exist
    match get_client_by_id(&request.client_id, state.db_connection()).await {
        Ok(Some(_)) => {
            warn!("Client already exists: {:?}", request.client_id);
            return Err(ClientError::ClientAlreadyExists).into();
        }
        Ok(None) => (),
        Err(err) => {
            error!(
                "Failed to check for client {:?}: {}",
                request.client_id, err
            );
            return Err(ClientError::DatabaseError).into();
        }
    };

    // Hash the secret
    let secret_hash = match ClientSecretHash::from_secret(request.client_secret) {
        Ok(hash) => hash,
        Err(err) => {
            error!(
                "Failed to hash secret for client {:?}: {}",
                request.client_id, err
            );
            return Err(ClientError::CryptoError).into();
        }
    };

    // Create the client
    let new_client_res = create_client(
        &request.client_id,
        &secret_hash,
        request.disabled,
        state.db_connection(),
    )
    .await;

    let new_client = match new_client_res {
        Ok(client) => client,
        Err(err) => {
            error!("Failed to create client {:?}: {}", request.client_id, err);
            return Err(ClientError::DatabaseError).into();
        }
    };

    info!("Created client {:?}", request.client_id);

    Ok(ClientResponse::from(new_client)).into()
}

pub async fn update_client(
    State(state): State<StateRef>,
    Path(client_id): Path<ClientId>,
    Json(request): Json<UpdateClientRequest>,
) -> JsonResponse<ClientResponse, ClientError> {
    // Ensure client exists
    let client = match get_client_by_id(&client_id, state.db_connection()).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            warn!("Client not found to update: {:?}", client_id);
            return Err(ClientError::ClientNotFound).into();
        }
        Err(err) => {
            error!("Failed to check for client {:?}: {}", client_id, err);
            return Err(ClientError::DatabaseError).into();
        }
    };

    if request.client_secret.is_none() && request.disabled.is_none() {
        warn!("No changes requested for client {:?}", client_id);
        return Ok(ClientResponse::from(client)).into();
    }

    // If the secret is being updated, hash it
    let secret_hash = match request.client_secret {
        Some(secret) => match ClientSecretHash::from_secret(secret) {
            Ok(hash) => Some(hash),
            Err(err) => {
                error!(
                    "Failed to hash new secret for client {:?}: {}",
                    client_id, err
                );
                return Err(ClientError::CryptoError).into();
            }
        },
        None => None,
    };
    let secret_changed = secret_hash.is_some();

    // Update the client
    let changeset = UpdateClientChangeset {
        client_secret_hash: secret_hash,
        disabled: request.disabled,
    };
    let updated_client_res =
        queries::update_client(&client, &changeset, state.db_connection()).await;

    let updated_client = match updated_client_res {
        Ok(client) => client,
        Err(err) => {
            error!("Failed to update client {:?}: {}", client_id, err);
            return Err(ClientError::DatabaseError).into();
        }
    };

    info!(
        "Updated client {:?} (secret updated: {}, disabled updated: {})",
        client_id,
        secret_changed,
        request.disabled.is_some()
    );

    Ok(ClientResponse::from(updated_client)).into()
}

//--------------------------------------------------------------------------------------------------
