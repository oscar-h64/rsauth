use crate::internal::claims::Claims;
use crate::{ClientId, Role, RoleId};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{async_trait, Json};
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, Algorithm, DecodingKey};
use serde::Serialize;
use std::marker::PhantomData;
use std::ops::{Add, Deref, Sub};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tracing::{debug, error, warn};

//--------------------------------------------------------------------------------------------------
// Trait for Axum states to comply with to provide the public key
//--------------------------------------------------------------------------------------------------

pub trait PublicKeyProvider {
    fn public_key(&self) -> &DecodingKey;
}

impl<T: PublicKeyProvider> PublicKeyProvider for Arc<T> {
    fn public_key(&self) -> &DecodingKey {
        self.deref().public_key()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait for extracting a list of roles from a type
//--------------------------------------------------------------------------------------------------

trait RoleSet {
    fn roles() -> Vec<&'static str>;
}

impl<T: Role> RoleSet for T {
    fn roles() -> Vec<&'static str> {
        vec![T::role_id()]
    }
}

#[allow(private_bounds)]
pub struct Or<T, U>(PhantomData<T>, PhantomData<U>)
where
    T: RoleSet,
    U: RoleSet;

impl<T, U> RoleSet for Or<T, U>
where
    T: RoleSet,
    U: RoleSet,
{
    fn roles() -> Vec<&'static str> {
        let mut roles = T::roles();
        roles.extend(U::roles());
        roles
    }
}

#[allow(private_bounds)]
pub struct Or3<T, U, V>(PhantomData<T>, PhantomData<U>, PhantomData<V>)
where
    T: RoleSet,
    U: RoleSet,
    V: RoleSet;

impl<T, U, V> RoleSet for Or3<T, U, V>
where
    T: RoleSet,
    U: RoleSet,
    V: RoleSet,
{
    fn roles() -> Vec<&'static str> {
        let mut roles = T::roles();
        roles.extend(U::roles());
        roles.extend(V::roles());
        roles
    }
}

#[allow(private_bounds)]
pub struct Or4<T, U, V, W>(
    PhantomData<T>,
    PhantomData<U>,
    PhantomData<V>,
    PhantomData<W>,
)
where
    T: RoleSet,
    U: RoleSet,
    V: RoleSet,
    W: RoleSet;

impl<T, U, V, W> RoleSet for Or4<T, U, V, W>
where
    T: RoleSet,
    U: RoleSet,
    V: RoleSet,
    W: RoleSet,
{
    fn roles() -> Vec<&'static str> {
        let mut roles = T::roles();
        roles.extend(U::roles());
        roles.extend(V::roles());
        roles.extend(W::roles());
        roles
    }
}

//--------------------------------------------------------------------------------------------------
// Extract Error
//--------------------------------------------------------------------------------------------------

pub enum ExtractError {
    NoAuthorizationHeader,
    InvalidAuthorizationHeader,
    BadToken,
    TokenWithSuspiciousTimes,
    NoRolesAcceptable,
    UserDoesNotHaveAcceptableRole,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorResponse {
    code: &'static str,
    message: String,
}

fn error_response_unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse {
            code: "unauthorized",
            message: "Unauthorized".to_string(),
        }),
    )
        .into_response()
}

fn error_response_forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            code: "forbidden",
            message: "Forbidden".to_string(),
        }),
    )
        .into_response()
}

impl IntoResponse for ExtractError {
    fn into_response(self) -> Response {
        match self {
            ExtractError::NoAuthorizationHeader => error_response_unauthorized(),
            ExtractError::InvalidAuthorizationHeader => error_response_unauthorized(),
            ExtractError::BadToken => error_response_unauthorized(),
            ExtractError::TokenWithSuspiciousTimes => error_response_unauthorized(),
            ExtractError::NoRolesAcceptable => error_response_forbidden(),
            ExtractError::UserDoesNotHaveAcceptableRole => error_response_forbidden(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Decoding and validation function
//--------------------------------------------------------------------------------------------------

#[derive(Clone)]
struct DecodedUser {
    client_id: ClientId,
    roles: Vec<RoleId>,
}

const AUTHORIZATION_HEADER: &str = "Authorization";
const AUTHORIZATION_BEARER_PREFIX: &str = "Bearer ";

fn validate_request<S>(parts: &mut Parts, state: &S) -> Result<DecodedUser, ExtractError>
where
    S: PublicKeyProvider + Send + Sync,
{
    // Check to see if we already validated and extracted the token
    if let Some(decoded_user) = parts.extensions.get::<DecodedUser>() {
        debug!("Token already validated for {:?}", decoded_user.client_id);
        return Ok(decoded_user.clone());
    }

    // Extract the token
    let Some(auth_header) = parts.headers.get(AUTHORIZATION_HEADER) else {
        warn!("Request made with no Authorization header");
        return Err(ExtractError::NoAuthorizationHeader);
    };

    let Ok(auth_header_str) = auth_header.to_str() else {
        warn!("Request made with Authorization header with more than visible ASCII characters");
        return Err(ExtractError::InvalidAuthorizationHeader);
    };

    let Some(auth_token) = auth_header_str.strip_prefix(AUTHORIZATION_BEARER_PREFIX) else {
        warn!("Request made with Authorization header without Bearer prefix");
        return Err(ExtractError::InvalidAuthorizationHeader);
    };

    // Decode the token, validate signatures and that we're within the time constraints
    let mut decoding_options = jsonwebtoken::Validation::default();
    decoding_options.algorithms = vec![Algorithm::ES256];
    decoding_options.validate_exp = true;
    decoding_options.validate_nbf = true;
    let token_res = decode::<Claims>(auth_token, state.public_key(), &decoding_options);
    let claims = match token_res {
        Ok(token) => token.claims,
        Err(err) => {
            return if *err.kind() == ErrorKind::InvalidToken {
                warn!("Request made with token that wasn't a JWT: {:?}", err);
                Err(ExtractError::InvalidAuthorizationHeader)
            } else {
                warn!("Request made with token that failed validation: {:?}", err);
                Err(ExtractError::BadToken)
            }
        }
    };

    // Validate that the times are sensible
    let minimum_issue_time = OffsetDateTime::now_utc().sub(Duration::hours(2));
    let maximum_expiry_time = OffsetDateTime::now_utc().add(Duration::hours(2));

    if OffsetDateTime::from(claims.iat()) < minimum_issue_time {
        warn!("Request made with token issued too far in the past");
        return Err(ExtractError::TokenWithSuspiciousTimes);
    }
    if OffsetDateTime::from(claims.nbf()) < minimum_issue_time {
        warn!("Request made with 'not before' time too far in the past");
        return Err(ExtractError::TokenWithSuspiciousTimes);
    }
    if OffsetDateTime::from(claims.exp()) > maximum_expiry_time {
        warn!("Request made with token expiring too far in the future");
        return Err(ExtractError::TokenWithSuspiciousTimes);
    }

    // Everything was successful, return the client ID and roles, and save the data for future
    // extractors

    let decoded_user = DecodedUser {
        client_id: claims.sub().clone(),
        roles: claims.roles().clone(),
    };

    parts.extensions.insert(decoded_user.clone());

    debug!("Token validated for {:?}", claims.sub());

    Ok(decoded_user)
}

//--------------------------------------------------------------------------------------------------
// Axum extractor to enforce role
//--------------------------------------------------------------------------------------------------

#[allow(private_bounds)]
pub struct RequireRole<T>(PhantomData<T>)
where
    T: RoleSet;

#[async_trait]
impl<S, T> FromRequestParts<S> for RequireRole<T>
where
    S: PublicKeyProvider + Send + Sync,
    T: RoleSet + Send + Sync,
{
    type Rejection = ExtractError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let decoded_user = validate_request(parts, state)?;

        let acceptable_roles = T::roles();

        // Check the roles isn't empty - that isn't allowed
        if acceptable_roles.is_empty() {
            error!("No acceptable roles provided for RequireRole");
            return Err(ExtractError::NoRolesAcceptable);
        }

        // Check the user has at least one of the acceptable roles
        if decoded_user
            .roles
            .iter()
            .any(|role| role.in_role_set(&acceptable_roles))
        {
            debug!("User {:?} has acceptable role", decoded_user.client_id);
            Ok(RequireRole(PhantomData))
        } else {
            warn!(
                "User {:?} does not have acceptable role",
                decoded_user.client_id
            );
            Err(ExtractError::UserDoesNotHaveAcceptableRole)
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Axum extractor to get client ID
//--------------------------------------------------------------------------------------------------

pub struct Client(pub ClientId);

#[async_trait]
impl<S> FromRequestParts<S> for Client
where
    S: PublicKeyProvider + Send + Sync,
{
    type Rejection = ExtractError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let decoded_user = validate_request(parts, state)?;

        // Everything was successful, return the client ID
        Ok(Client(decoded_user.client_id))
    }
}

//--------------------------------------------------------------------------------------------------
