use crate::db_models::{Client, ClientRole};
use crate::queries;
use crate::queries::get_client_by_id;
use crate::response::{JsonResponse, NoContentResponse, RSAuthError};
use crate::state::StateRef;
use crate::types::{ClientId, RoleId};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Serialize;
use time::OffsetDateTime;
use tracing::{error, info, warn};

//--------------------------------------------------------------------------------------------------
// Responses
//--------------------------------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientRoleResponse {
    pub client_id: ClientId,
    pub role_id: RoleId,
    #[serde(with = "time::serde::rfc3339")]
    pub added_at: OffsetDateTime,
}

impl From<ClientRole> for ClientRoleResponse {
    fn from(client_role: ClientRole) -> Self {
        Self {
            client_id: client_role.client_id,
            role_id: client_role.role_id,
            added_at: client_role.added_at,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientRoleListResponse {
    pub client_roles: Vec<ClientRoleResponse>,
}

pub enum ClientRoleError {
    ClientNotFound,
    RoleNotFound,
    ClientRoleNotFound,
    DatabaseError,
}

impl RSAuthError for ClientRoleError {
    fn response_data(&self) -> (StatusCode, &'static str, String) {
        match self {
            ClientRoleError::ClientNotFound => (
                StatusCode::NOT_FOUND,
                "client_not_found",
                "Client not found".to_string(),
            ),
            ClientRoleError::RoleNotFound => (
                StatusCode::NOT_FOUND,
                "role_not_found",
                "Role not found".to_string(),
            ),
            ClientRoleError::ClientRoleNotFound => (
                StatusCode::NOT_FOUND,
                "client_role_not_found",
                "Client role not found".to_string(),
            ),
            ClientRoleError::DatabaseError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database error".to_string(),
            ),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Helpers
//--------------------------------------------------------------------------------------------------

async fn ensure_client_exists(
    state: &StateRef,
    client_id: &ClientId,
) -> Result<Client, ClientRoleError> {
    match get_client_by_id(client_id, state.db_connection()).await {
        Ok(Some(client)) => Ok(client),
        Ok(None) => {
            warn!("Client {:?} not found", client_id);
            Err(ClientRoleError::ClientNotFound)
        }
        Err(err) => {
            error!("Failed to check for client {:?}: {}", client_id, err);
            Err(ClientRoleError::DatabaseError)
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Handlers
//--------------------------------------------------------------------------------------------------

pub async fn get_client_roles_for_client(
    State(state): State<StateRef>,
    Path(client_id): Path<ClientId>,
) -> JsonResponse<ClientRoleListResponse, ClientRoleError> {
    // Ensure client exists
    let client = match ensure_client_exists(&state, &client_id).await {
        Ok(client) => client,
        Err(err) => return Err(err).into(),
    };

    // Get the client's roles
    let client_roles_result =
        queries::get_client_roles_for_client(&client, state.db_connection()).await;
    let client_roles = match client_roles_result {
        Ok(client_roles) => client_roles,
        Err(err) => {
            error!(
                "Failed to get client roles for client {:?}: {}",
                client_id, err
            );
            return Err(ClientRoleError::DatabaseError).into();
        }
    };

    info!(
        "Returning {} roles for client {:?}",
        client_roles.len(),
        client_id
    );

    Ok(ClientRoleListResponse {
        client_roles: client_roles
            .into_iter()
            .map(ClientRoleResponse::from)
            .collect(),
    })
    .into()
}

pub async fn get_client_role(
    State(state): State<StateRef>,
    Path((client_id, role_id)): Path<(ClientId, RoleId)>,
) -> JsonResponse<ClientRoleResponse, ClientRoleError> {
    // Get the client role
    let client_role_result =
        queries::get_client_role(&client_id, &role_id, state.db_connection()).await;
    let client_role = match client_role_result {
        Ok(Some(client_role)) => client_role,
        Ok(None) => {
            warn!("Client role {:?} not found", (client_id, role_id));
            return Err(ClientRoleError::ClientRoleNotFound).into();
        }
        Err(err) => {
            error!(
                "Failed to get client role {:?}: {}",
                (client_id, role_id),
                err
            );
            return Err(ClientRoleError::DatabaseError).into();
        }
    };

    info!("Found client role {:?}", (client_id, role_id));

    Ok(ClientRoleResponse::from(client_role)).into()
}

pub async fn put_client_role(
    State(state): State<StateRef>,
    Path((client_id, role_id)): Path<(ClientId, RoleId)>,
) -> JsonResponse<ClientRoleResponse, ClientRoleError> {
    // If the client-role exists, no-op, return it. Otherwise, create it.

    // Ensure client exists
    match ensure_client_exists(&state, &client_id).await {
        Ok(_) => (),
        Err(err) => return Err(err).into(),
    };

    // Ensure role exists
    match queries::get_role_by_id(&role_id, state.db_connection()).await {
        Ok(Some(_)) => (),
        Ok(None) => {
            warn!("Role {:?} not found", role_id);
            return Err(ClientRoleError::RoleNotFound).into();
        }
        Err(err) => {
            error!("Failed to check for role {:?}: {}", role_id, err);
            return Err(ClientRoleError::DatabaseError).into();
        }
    };

    // Check if the client-role exists
    let client_role_result =
        queries::get_client_role(&client_id, &role_id, state.db_connection()).await;
    match client_role_result {
        Ok(Some(client_role)) => {
            info!("Client role {:?} already exists", (client_id, role_id));
            return Ok(ClientRoleResponse::from(client_role)).into();
        }
        Ok(None) => (),
        Err(err) => {
            error!(
                "Failed to check for client role {:?}: {}",
                (client_id, role_id),
                err
            );
            return Err(ClientRoleError::DatabaseError).into();
        }
    };

    // Create the client-role
    let new_client_role_res =
        queries::add_client_role(&client_id, &role_id, state.db_connection()).await;
    let new_client_role = match new_client_role_res {
        Ok(client_role) => client_role,
        Err(err) => {
            error!(
                "Failed to create client role {:?}: {}",
                (client_id, role_id),
                err
            );
            return Err(ClientRoleError::DatabaseError).into();
        }
    };

    info!("Created client role {:?}", (client_id, role_id));

    Ok(ClientRoleResponse::from(new_client_role)).into()
}

pub async fn delete_client_role(
    State(state): State<StateRef>,
    Path((client_id, role_id)): Path<(ClientId, RoleId)>,
) -> NoContentResponse<ClientRoleError> {
    // Check if the client-role exists
    let client_role_result =
        queries::get_client_role(&client_id, &role_id, state.db_connection()).await;
    match client_role_result {
        Ok(Some(_)) => (),
        Ok(None) => {
            warn!("Client role {:?} not found", (client_id, role_id));
            return ClientRoleError::ClientRoleNotFound.into();
        }
        Err(err) => {
            error!(
                "Failed to check for client role {:?}: {}",
                (client_id, role_id),
                err
            );
            return ClientRoleError::DatabaseError.into();
        }
    };

    // Delete the client-role
    let delete_client_role_res =
        queries::delete_client_role(&client_id, &role_id, state.db_connection()).await;
    match delete_client_role_res {
        Ok(_) => {
            info!("Deleted client role {:?}", (client_id, role_id));
            Ok(()).into()
        }
        Err(err) => {
            error!(
                "Failed to delete client role {:?}: {}",
                (client_id, role_id),
                err
            );
            ClientRoleError::DatabaseError.into()
        }
    }
}

//--------------------------------------------------------------------------------------------------
