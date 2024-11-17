use crate::handler_proxy::PrivateKeyAccess;
use crate::queries::{get_client_by_id, get_role_ids_for_client};
use crate::response::{JsonResponse, RSAuthError, StandaloneError};
use crate::state::StateRef;
use crate::token::AccessToken;
use crate::types::{Claims, ClientId, ClientSecret};
use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::{async_trait, Form, RequestPartsExt};
use axum_extra::headers::authorization::Basic;
use axum_extra::headers::{Authorization, ContentType};
use axum_extra::typed_header::TypedHeaderRejectionReason;
use axum_extra::TypedHeader;
use rsauth::internal::unixtime::{Seconds, ONE_HOUR};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

//--------------------------------------------------------------------------------------------------
// Types for the constant strings in the request/response
//--------------------------------------------------------------------------------------------------

pub struct GrantTypeClientCredentials;

impl<'a> Deserialize<'a> for GrantTypeClientCredentials {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        const VALID_GRANT_TYPE: &str = "client_credentials";

        let s: String = Deserialize::deserialize(deserializer)?;

        if s == VALID_GRANT_TYPE {
            Ok(GrantTypeClientCredentials)
        } else {
            Err(serde::de::Error::custom(
                "invalid or unsupported grant type",
            ))
        }
    }
}

pub struct TokenTypeBearer;

impl Serialize for TokenTypeBearer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        const TOKEN_TYPE: &str = "Bearer";
        TOKEN_TYPE.serialize(serializer)
    }
}

//--------------------------------------------------------------------------------------------------
// Request and response types
//--------------------------------------------------------------------------------------------------

// OAuth uses snake_case, no renaming needed

#[derive(Deserialize)]
pub struct Request {
    #[serde(rename = "grant_type")]
    _grant_type: GrantTypeClientCredentials,
    #[serde(default)]
    pub client_id: Option<ClientId>,
    #[serde(default)]
    pub client_secret: Option<ClientSecret>,
}

#[derive(Serialize)]
pub struct Response {
    access_token: AccessToken,
    token_type: TokenTypeBearer,
    expires_in: Seconds,
}

pub enum AuthoriseError {
    ClientIdMustBeInBodyIfSecretIs,
    ClientSecretMustBeInBodyIfIdIs,
    CredentialsProvidedInBothHeaderAndBody,
    NoCredentialsProvided,
    InvalidCredentials,
    TokenGenerationError,
    DatabaseError,
    CryptoError,
}

impl RSAuthError for AuthoriseError {
    fn response_data(&self) -> (StatusCode, &'static str, String) {
        match self {
            AuthoriseError::ClientIdMustBeInBodyIfSecretIs => (
                StatusCode::BAD_REQUEST,
                "client_id_missing",
                "Client ID must be in request body if client secret is".to_string(),
            ),
            AuthoriseError::ClientSecretMustBeInBodyIfIdIs => (
                StatusCode::BAD_REQUEST,
                "client_secret_missing",
                "Client secret must be in request body if client ID is".to_string(),
            ),
            AuthoriseError::CredentialsProvidedInBothHeaderAndBody => (
                StatusCode::BAD_REQUEST,
                "credentials_in_both_header_and_body",
                "Credentials provided in both header and body".to_string(),
            ),
            AuthoriseError::NoCredentialsProvided => (
                StatusCode::BAD_REQUEST,
                "no_credentials_provided",
                "No credentials provided".to_string(),
            ),
            AuthoriseError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "Invalid credentials".to_string(),
            ),
            AuthoriseError::TokenGenerationError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "token_generation_error",
                "Error generating token".to_string(),
            ),
            AuthoriseError::DatabaseError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Error accessing database".to_string(),
            ),
            AuthoriseError::CryptoError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "crypto_error",
                "Error with cryptographic operations".to_string(),
            ),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Extractor to filter by content type
//--------------------------------------------------------------------------------------------------

pub enum ContentTypeRejection {
    NoContentType,
    WrongContentType,
    InvalidHeader,
}

impl RSAuthError for ContentTypeRejection {
    fn response_data(&self) -> (StatusCode, &'static str, String) {
        match self {
            ContentTypeRejection::NoContentType => (
                StatusCode::BAD_REQUEST,
                "missing_content_type",
                "Content-Type header missing".to_string(),
            ),
            ContentTypeRejection::WrongContentType => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "wrong_content_type",
                "Content-Type header incorrect".to_string(),
            ),
            ContentTypeRejection::InvalidHeader => (
                StatusCode::BAD_REQUEST,
                "invalid_header",
                "Invalid header".to_string(),
            ),
        }
    }
}

async fn extract_content_type(
    parts: &mut Parts,
) -> Result<ContentType, StandaloneError<ContentTypeRejection>> {
    parts
        .extract::<TypedHeader<ContentType>>()
        .await
        .map_err(|t| match t.reason() {
            TypedHeaderRejectionReason::Missing => {
                StandaloneError::from(ContentTypeRejection::NoContentType)
            }
            _ => StandaloneError::from(ContentTypeRejection::InvalidHeader),
        })
        .map(|TypedHeader(header)| header)
}

pub struct ContentTypeJson;

#[async_trait]
impl<S> FromRequestParts<S> for ContentTypeJson
where
    S: Send + Sync,
{
    type Rejection = StandaloneError<ContentTypeRejection>;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let content_type = extract_content_type(parts).await?;

        if content_type != ContentType::json() {
            return Err(ContentTypeRejection::WrongContentType.into());
        }

        Ok(ContentTypeJson)
    }
}

pub struct ContentTypeFormUrlEncoded;

#[async_trait]
impl<S> FromRequestParts<S> for ContentTypeFormUrlEncoded
where
    S: Send + Sync,
{
    type Rejection = StandaloneError<ContentTypeRejection>;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let content_type = extract_content_type(parts).await?;

        if content_type != ContentType::form_url_encoded() {
            return Err(ContentTypeRejection::WrongContentType.into());
        }

        Ok(ContentTypeFormUrlEncoded)
    }
}

//--------------------------------------------------------------------------------------------------
// Handler
//--------------------------------------------------------------------------------------------------

pub async fn handler(
    private_key_access: PrivateKeyAccess,
    State(state): State<StateRef>,
    auth_header: Option<TypedHeader<Authorization<Basic>>>,
    Form(request): Form<Request>,
) -> JsonResponse<Response, AuthoriseError> {
    // Ensure we have a client ID and secret
    if request.client_id.is_some() && auth_header.is_some() {
        warn!("Credentials provided in both header and body");
        return Err(AuthoriseError::CredentialsProvidedInBothHeaderAndBody).into();
    }

    let (client_id, client_secret) = match (request.client_id, request.client_secret) {
        (Some(client_id), Some(client_secret)) => (client_id, client_secret),
        (Some(_), None) => {
            warn!("Client secret missing from body when client ID provided");
            return Err(AuthoriseError::ClientSecretMustBeInBodyIfIdIs).into();
        }
        (None, Some(_)) => {
            warn!("Client ID missing from body when client secret provided");
            return Err(AuthoriseError::ClientIdMustBeInBodyIfSecretIs).into();
        }
        (None, None) => match auth_header {
            Some(TypedHeader(Authorization(basic))) => {
                (ClientId::from(&basic), ClientSecret::from(&basic))
            }
            None => {
                warn!("No credentials provided in either header or body");
                return Err(AuthoriseError::NoCredentialsProvided).into();
            }
        },
    };

    // Get the client from the ID - if it doesn't exist return generic invalid credentials
    let client = match get_client_by_id(&client_id, state.db_connection()).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            warn!("Client ID {:?} not found", client_id);
            return Err(AuthoriseError::InvalidCredentials).into();
        }
        Err(err) => {
            error!("Error accessing database to get client: {}", err);
            return Err(AuthoriseError::DatabaseError).into();
        }
    };

    // Ensure the client isn't disabled
    if client.disabled {
        warn!("Client ID {:?} is disabled", client_id);
        return Err(AuthoriseError::InvalidCredentials).into();
    }

    // Validate the client secret with the hash
    let secret_passes = match client.client_secret_hash.validate(client_secret) {
        Ok(secret_passes) => secret_passes,
        Err(err) => {
            error!("Error validating client secret: {}", err);
            return Err(AuthoriseError::CryptoError).into();
        }
    };

    if !secret_passes {
        warn!("Invalid client secret for client ID {:?}", client_id);
        return Err(AuthoriseError::InvalidCredentials).into();
    }

    // WE HAVE VALIDATED THE CLIENT

    // Get the roles for the client
    let roles = match get_role_ids_for_client(&client, state.db_connection()).await {
        Ok(roles) => roles,
        Err(err) => {
            error!("Error accessing database for roles: {}", err);
            return Err(AuthoriseError::DatabaseError).into();
        }
    };

    // Generate an access token
    let claims = Claims::new(client.client_id, roles);

    let private_key = state.private_key(private_key_access);
    let token = match AccessToken::encode_new(claims, private_key) {
        Ok(token) => token,
        Err(err) => {
            error!("Error generating token: {}", err);
            return Err(AuthoriseError::TokenGenerationError).into();
        }
    };

    info!("Client ID {:?} authorised - token issued", client_id);

    Ok(Response {
        access_token: token,
        token_type: TokenTypeBearer,
        expires_in: ONE_HOUR,
    })
    .into()
}

//--------------------------------------------------------------------------------------------------
