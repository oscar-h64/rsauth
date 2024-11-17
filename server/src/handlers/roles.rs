use crate::db_models::Role;
use crate::queries;
use crate::queries::{create_role, get_all_roles, get_role_by_id};
use crate::response::{JsonResponse, RSAuthError};
use crate::state::StateRef;
use crate::types::{RoleDescription, RoleId};
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
pub struct CreateRoleRequest {
    pub role_id: RoleId,
    #[serde(default)]
    pub description: Option<RoleDescription>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRoleRequest {
    pub description: Option<RoleDescription>,
}

//--------------------------------------------------------------------------------------------------
// Responses
//--------------------------------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleResponse {
    pub role_id: RoleId,
    pub description: Option<RoleDescription>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<Role> for RoleResponse {
    fn from(role: Role) -> Self {
        Self {
            role_id: role.role_id,
            description: role.description,
            created_at: role.created_at,
            updated_at: role.updated_at,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleListResponse {
    pub roles: Vec<RoleResponse>,
}

pub enum RoleError {
    RoleAlreadyExists,
    RoleNotFound,
    DatabaseError,
}

impl RSAuthError for RoleError {
    fn response_data(&self) -> (StatusCode, &'static str, String) {
        match self {
            RoleError::RoleAlreadyExists => (
                StatusCode::BAD_REQUEST,
                "role_already_exists",
                "Role already exists".to_string(),
            ),
            RoleError::RoleNotFound => (
                StatusCode::NOT_FOUND,
                "role_not_found",
                "Role not found".to_string(),
            ),
            RoleError::DatabaseError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database error".to_string(),
            ),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Handlers
//--------------------------------------------------------------------------------------------------

pub async fn get_roles(State(state): State<StateRef>) -> JsonResponse<RoleListResponse, RoleError> {
    let roles = match get_all_roles(state.db_connection()).await {
        Ok(roles) => roles,
        Err(err) => {
            error!("Failed to get roles: {:?}", err);
            return Err(RoleError::DatabaseError).into();
        }
    };

    info!("Returning {} roles", roles.len());

    Ok(RoleListResponse {
        roles: roles.into_iter().map(RoleResponse::from).collect(),
    })
    .into()
}

pub async fn get_role(
    State(state): State<StateRef>,
    Path(role_id): Path<RoleId>,
) -> JsonResponse<RoleResponse, RoleError> {
    let role = match get_role_by_id(&role_id, state.db_connection()).await {
        Ok(Some(role)) => role,
        Ok(None) => {
            warn!("role not found: {:?}", role_id);
            return Err(RoleError::RoleNotFound).into();
        }
        Err(err) => {
            error!("Failed to get role {:?}: {}", role_id, err);
            return Err(RoleError::DatabaseError).into();
        }
    };

    info!("Returning role {:?}", role_id);

    Ok(RoleResponse::from(role)).into()
}

pub async fn new_role(
    State(state): State<StateRef>,
    Json(request): Json<CreateRoleRequest>,
) -> JsonResponse<RoleResponse, RoleError> {
    // Ensure role does not already exist
    match get_role_by_id(&request.role_id, state.db_connection()).await {
        Ok(Some(_)) => {
            warn!("role already exists: {:?}", request.role_id);
            return Err(RoleError::RoleAlreadyExists).into();
        }
        Ok(None) => (),
        Err(err) => {
            error!("Failed to check for role {:?}: {}", request.role_id, err);
            return Err(RoleError::DatabaseError).into();
        }
    };

    // Create the role
    let new_role_res = create_role(
        &request.role_id,
        &request.description,
        state.db_connection(),
    )
    .await;

    let new_role = match new_role_res {
        Ok(role) => role,
        Err(err) => {
            error!("Failed to create role {:?}: {}", request.role_id, err);
            return Err(RoleError::DatabaseError).into();
        }
    };

    info!("Created role {:?}", request.role_id);

    Ok(RoleResponse::from(new_role)).into()
}

pub async fn update_role(
    State(state): State<StateRef>,
    Path(role_id): Path<RoleId>,
    Json(request): Json<UpdateRoleRequest>,
) -> JsonResponse<RoleResponse, RoleError> {
    // Ensure role exists
    let role = match get_role_by_id(&role_id, state.db_connection()).await {
        Ok(Some(role)) => role,
        Ok(None) => {
            warn!("role not found to update: {:?}", role_id);
            return Err(RoleError::RoleNotFound).into();
        }
        Err(err) => {
            error!("Failed to check for role {:?}: {}", role_id, err);
            return Err(RoleError::DatabaseError).into();
        }
    };

    // Update the role
    let updated_role_res =
        queries::update_role(&role, &request.description, state.db_connection()).await;

    let updated_role = match updated_role_res {
        Ok(role) => role,
        Err(err) => {
            error!("Failed to update role {:?}: {}", role_id, err);
            return Err(RoleError::DatabaseError).into();
        }
    };

    info!("Updated role {:?}", role_id);

    Ok(RoleResponse::from(updated_role)).into()
}

//--------------------------------------------------------------------------------------------------
