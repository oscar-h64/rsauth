use crate::client_admin_role::ClientAdminRole;
use crate::handlers::authorise::{AuthoriseError, Request, Response};
use crate::handlers::client_roles::{ClientRoleError, ClientRoleListResponse, ClientRoleResponse};
use crate::handlers::clients::{
    ClientError, ClientListResponse, ClientResponse, CreateClientRequest, UpdateClientRequest,
};
use crate::handlers::roles::{
    CreateRoleRequest, RoleError, RoleListResponse, RoleResponse, UpdateRoleRequest,
};
use crate::handlers::{authorise, client_roles, clients, roles};
use crate::response::{JsonResponse, NoContentResponse};
use crate::state::StateRef;
use crate::types::{ClientId, RoleId};
use axum::extract::{Path, State};
use axum::{Form, Json};
use axum_extra::headers::authorization::Basic;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use rsauth::extract;
//--------------------------------------------------------------------------------------------------
// Types to represent permissions for the handlers
//--------------------------------------------------------------------------------------------------

// TODO: should we add any more permissions

#[allow(dead_code)]
pub struct PrivateKeyAccess(bool);

//--------------------------------------------------------------------------------------------------
// Re-export handlers, but grant handler access where applicable
//--------------------------------------------------------------------------------------------------

// authorise needs to be able to issue JWTs, so needs access to the private key
pub async fn authorise(
    state: State<StateRef>,
    auth_header: Option<TypedHeader<Authorization<Basic>>>,
    request: Form<Request>,
) -> JsonResponse<Response, AuthoriseError> {
    authorise::handler(PrivateKeyAccess(true), state, auth_header, request).await
}

//--------------------------------------------------------------------------------------------------

pub async fn get_clients(
    state: State<StateRef>,
    _: extract::RequireRole<ClientAdminRole>,
) -> JsonResponse<ClientListResponse, ClientError> {
    clients::get_clients(state).await
}

pub async fn get_client(
    state: State<StateRef>,
    _: extract::RequireRole<ClientAdminRole>,
    client_id: Path<ClientId>,
) -> JsonResponse<ClientResponse, ClientError> {
    clients::get_client(state, client_id).await
}

pub async fn new_client(
    state: State<StateRef>,
    _: extract::RequireRole<ClientAdminRole>,
    request: Json<CreateClientRequest>,
) -> JsonResponse<ClientResponse, ClientError> {
    clients::new_client(state, request).await
}

pub async fn update_client(
    state: State<StateRef>,
    _: extract::RequireRole<ClientAdminRole>,
    client_id: Path<ClientId>,
    request: Json<UpdateClientRequest>,
) -> JsonResponse<ClientResponse, ClientError> {
    clients::update_client(state, client_id, request).await
}

//--------------------------------------------------------------------------------------------------

pub async fn get_roles(
    state: State<StateRef>,
    _: extract::RequireRole<ClientAdminRole>,
) -> JsonResponse<RoleListResponse, RoleError> {
    roles::get_roles(state).await
}

pub async fn get_role(
    state: State<StateRef>,
    _: extract::RequireRole<ClientAdminRole>,
    role_id: Path<RoleId>,
) -> JsonResponse<RoleResponse, RoleError> {
    roles::get_role(state, role_id).await
}

pub async fn new_role(
    state: State<StateRef>,
    _: extract::RequireRole<ClientAdminRole>,
    request: Json<CreateRoleRequest>,
) -> JsonResponse<RoleResponse, RoleError> {
    roles::new_role(state, request).await
}

pub async fn update_role(
    state: State<StateRef>,
    _: extract::RequireRole<ClientAdminRole>,
    role_id: Path<RoleId>,
    request: Json<UpdateRoleRequest>,
) -> JsonResponse<RoleResponse, RoleError> {
    roles::update_role(state, role_id, request).await
}

//--------------------------------------------------------------------------------------------------

pub async fn get_client_roles_for_client(
    state: State<StateRef>,
    _: extract::RequireRole<ClientAdminRole>,
    client_id: Path<ClientId>,
) -> JsonResponse<ClientRoleListResponse, ClientRoleError> {
    client_roles::get_client_roles_for_client(state, client_id).await
}

pub async fn get_client_role(
    state: State<StateRef>,
    _: extract::RequireRole<ClientAdminRole>,
    path: Path<(ClientId, RoleId)>,
) -> JsonResponse<ClientRoleResponse, ClientRoleError> {
    client_roles::get_client_role(state, path).await
}

pub async fn put_client_role(
    state: State<StateRef>,
    _: extract::RequireRole<ClientAdminRole>,
    path: Path<(ClientId, RoleId)>,
) -> JsonResponse<ClientRoleResponse, ClientRoleError> {
    client_roles::put_client_role(state, path).await
}

pub async fn delete_client_role(
    state: State<StateRef>,
    _: extract::RequireRole<ClientAdminRole>,
    path: Path<(ClientId, RoleId)>,
) -> NoContentResponse<ClientRoleError> {
    client_roles::delete_client_role(state, path).await
}

//--------------------------------------------------------------------------------------------------
