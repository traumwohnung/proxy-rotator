//! API endpoint handlers and OpenAPI spec generation.
//!
//! Each public handler function is annotated with `#[utoipa::path]` to generate
//! the OpenAPI documentation. These are the real handlers called from `proxy.rs`.

use crate::rotator::{ApiError, Rotator, SessionInfo};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{Response, StatusCode};

// ---------------------------------------------------------------------------
// Handlers — called from proxy::handle_api_request
// ---------------------------------------------------------------------------

/// List all active sessions
///
/// Returns all currently active sticky sessions across all proxy sets.
/// Sessions with 0 minutes (no affinity) are not tracked and won't appear here.
#[utoipa::path(
    get,
    path = "/api/sessions",
    responses(
        (status = 200, description = "List of active sessions", body = Vec<SessionInfo>),
        (status = 401, description = "Invalid or missing API key", body = ApiError),
    ),
    security(
        ("bearer" = [])
    )
)]
pub fn list_sessions(rotator: &Rotator) -> Response<BoxBody<Bytes, hyper::Error>> {
    let sessions = rotator.list_sessions();
    let json = serde_json::to_string(&sessions).unwrap_or_else(|_| "[]".to_string());
    json_response(StatusCode::OK, &json)
}

/// Get session by username
///
/// Returns details of a specific active session identified by its full username
/// in the format `<proxyset>-<minutes>-<sessionkey>`.
#[utoipa::path(
    get,
    path = "/api/sessions/{username}",
    params(
        ("username" = String, Path, description = "Full username in format <proxyset>-<minutes>-<sessionkey>", example = "residential-5-abc123"),
    ),
    responses(
        (status = 200, description = "Session found", body = SessionInfo),
        (status = 401, description = "Invalid or missing API key", body = ApiError),
        (status = 404, description = "No active session for this username", body = ApiError),
    ),
    security(
        ("bearer" = [])
    )
)]
pub fn get_session(rotator: &Rotator, username: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    if username.is_empty() {
        return json_response(
            StatusCode::BAD_REQUEST,
            r#"{"error":"Username is required"}"#,
        );
    }
    match rotator.get_session(username) {
        Some(info) => {
            let json = serde_json::to_string(&info).unwrap_or_else(|_| "{}".to_string());
            json_response(StatusCode::OK, &json)
        }
        None => json_response(
            StatusCode::NOT_FOUND,
            &format!(r#"{{"error":"No active session for '{}'"}}"#, username),
        ),
    }
}

/// Get the OpenAPI spec
///
/// Returns the OpenAPI 3.1 JSON specification for this API.
/// This endpoint is publicly accessible (no authentication required).
pub fn openapi_spec() -> Response<BoxBody<Bytes, hyper::Error>> {
    json_response(StatusCode::OK, &openapi_json())
}

// ---------------------------------------------------------------------------
// OpenAPI spec generation
// ---------------------------------------------------------------------------

#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "Proxy Rotator API",
        version = "0.4.0",
        description = "API for inspecting active proxy sessions in proxy-rotator.\n\nAuthenticate with `Authorization: Bearer <api_key>` where `api_key` is set via the `API_KEY` environment variable.",
    ),
    paths(
        list_sessions,
        get_session,
    ),
    components(
        schemas(SessionInfo, ApiError),
    ),
    modifiers(&SecurityAddon),
)]
pub struct ApiDoc;

/// Generate the OpenAPI JSON spec as a pretty-printed string.
pub fn openapi_json() -> String {
    use utoipa::OpenApi;
    ApiDoc::openapi()
        .to_pretty_json()
        .unwrap_or_else(|e| panic!("Failed to serialize OpenAPI spec: {e}"))
}

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::HttpBuilder::new()
                        .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                        .bearer_format("API Key")
                        .description(Some(
                            "API key set via the API_KEY environment variable. Pass as: Authorization: Bearer <api_key>",
                        ))
                        .build(),
                ),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn json_response(
    status: StatusCode,
    body: &str,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(
            Full::new(Bytes::from(body.to_string()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

pub fn unauthorized_response() -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("Content-Type", "application/json")
        .header("WWW-Authenticate", "Bearer")
        .body(
            Full::new(Bytes::from(r#"{"error":"Invalid or missing API key"}"#))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_spec_is_valid_json() {
        let json = openapi_json();
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("OpenAPI spec should be valid JSON");

        assert!(parsed["openapi"].as_str().unwrap().starts_with("3.1"));
        assert_eq!(
            parsed["info"]["title"].as_str().unwrap(),
            "Proxy Rotator API"
        );
        assert!(parsed["paths"]["/api/sessions"].is_object());
        assert!(parsed["paths"]["/api/sessions/{username}"].is_object());
        assert!(parsed["components"]["schemas"]["SessionInfo"].is_object());
        assert!(parsed["components"]["schemas"]["ApiError"].is_object());
    }
}
