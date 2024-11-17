use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

//--------------------------------------------------------------------------------------------------
// Error handling
//--------------------------------------------------------------------------------------------------

// Any errors returned by a handler should confirm to this
pub trait RSAuthError: Sized {
    fn response_data(&self) -> (StatusCode, &'static str, String);
}

// Useful for eg Rejection in a FromRequestParts implementation
pub struct StandaloneError<E>(E)
where
    E: RSAuthError;

impl<T> From<T> for StandaloneError<T>
where
    T: RSAuthError,
{
    fn from(err: T) -> Self {
        StandaloneError(err)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorResponse {
    code: &'static str,
    message: String,
}

//--------------------------------------------------------------------------------------------------
// Response JSON handling
//--------------------------------------------------------------------------------------------------

pub struct JsonResponse<T: Serialize, E: RSAuthError>(Result<T, E>);

impl<T: Serialize, E: RSAuthError> From<Result<T, E>> for JsonResponse<T, E> {
    fn from(r: Result<T, E>) -> Self {
        JsonResponse(r)
    }
}

impl<T: Serialize, E: RSAuthError> From<T> for JsonResponse<T, E> {
    fn from(resp: T) -> Self {
        JsonResponse(Ok(resp))
    }
}

//--------------------------------------------------------------------------------------------------
// HTTP 204 handling
//--------------------------------------------------------------------------------------------------

pub struct NoContentResponse<E: RSAuthError>(Result<(), E>);

impl<E: RSAuthError> From<Result<(), E>> for NoContentResponse<E> {
    fn from(r: Result<(), E>) -> Self {
        NoContentResponse(r)
    }
}

impl<E: RSAuthError> From<E> for NoContentResponse<E> {
    fn from(err: E) -> Self {
        NoContentResponse(Err(err))
    }
}

//--------------------------------------------------------------------------------------------------
// IntoResponse handling
//--------------------------------------------------------------------------------------------------

impl<T: Serialize, E: RSAuthError> IntoResponse for JsonResponse<T, E> {
    fn into_response(self) -> Response {
        match self.0 {
            Ok(resp) => Json(resp).into_response(),
            Err(err) => StandaloneError(err).into_response(),
        }
    }
}

impl<E: RSAuthError> IntoResponse for NoContentResponse<E> {
    fn into_response(self) -> Response {
        match self.0 {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(err) => StandaloneError(err).into_response(),
        }
    }
}

impl<E: RSAuthError> IntoResponse for StandaloneError<E> {
    fn into_response(self) -> Response {
        let (status_code, code, message) = self.0.response_data();
        let body = ErrorResponse { code, message };
        (status_code, Json(body)).into_response()
    }
}

//--------------------------------------------------------------------------------------------------
