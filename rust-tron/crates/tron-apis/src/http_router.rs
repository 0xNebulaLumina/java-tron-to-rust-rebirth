use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::{Duration, Instant}};

use axum::{Router, body::Body, extract::State, http::{Method, Request}, response::Response, routing::{get, post}};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use prost::Message;
use serde_json::Value;
use tron_crypto::{CryptoEngine, decode_base58check};

use crate::{
    ApiRateLimiter, RpcApiServices,
    http_filters::{HttpControls, collect_limited_body, json_response, payload_too_large, process_error, rate_limit_response},
    http_json::{ProtobufJson, decode_broadcast_hex, parse_post_body, with_get_int64_as_string},
    http_routes::{HTTP_ROUTES, HttpRouteSpec},
};

#[derive(Clone)]
pub struct HttpRouteState {
    services: RpcApiServices,
    json: ProtobufJson,
    controls: HttpControls,
    rate_limiter: Arc<ApiRateLimiter>,
    request_deadline: Duration,
    lite_node: bool,
}

impl HttpRouteState {
    #[must_use]
    pub fn new(
        services: RpcApiServices,
        controls: HttpControls,
        rate_limiter: Arc<ApiRateLimiter>,
        request_deadline: Duration,
        lite_node: bool,
    ) -> Self {
        assert!(!request_deadline.is_zero() && Instant::now().checked_add(request_deadline).is_some(), "HTTP request deadline must be finite and positive");
        Self { services, json: ProtobufJson::default(), controls, rate_limiter, request_deadline, lite_node }
    }
}

/// Builds one servlet-derived HTTP surface. Paths are deduplicated only within the selected
/// server surface, so Java's Full and Solidity `/wallet/getnodeinfo` handlers can coexist.
#[must_use]
pub fn http_router(state: HttpRouteState, surface: crate::http_routes::HttpSurface) -> Router {
    let mut router = Router::new();
    let mut registered_paths = HashSet::new();
    for route in HTTP_ROUTES.iter().filter(|route| route.surface == surface) {
        if !registered_paths.insert(route.path) { continue; }
        let spec = route;
        let mut method_router = axum::routing::MethodRouter::new();
        if spec.get { method_router = method_router.merge(get(move |state, request| execute(state, request, spec))); }
        if spec.post { method_router = method_router.merge(post(move |state, request| execute(state, request, spec))); }
        router = router.route(spec.path, method_router);
    }
    router.with_state(state)
}

async fn execute(State(state): State<HttpRouteState>, request: Request<Body>, route: &'static HttpRouteSpec) -> Response<Body> {
    if state.controls.is_disabled(route.path) { return state.controls.disabled_response().expect("disabled response"); }
    if state.lite_node && state.controls.is_lite_history_path(route.path) { return state.controls.lite_response(); }
    let method = request.method().clone();
    let content_type = request.headers().get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(str::to_owned);
    let chunked = request.headers().get(axum::http::header::TRANSFER_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|coding| coding.trim().eq_ignore_ascii_case("chunked")));
    let body_limit = if content_type.as_deref().is_some_and(is_form_content_type) {
        state.controls.max_body_bytes.min(state.controls.max_form_bytes)
    } else {
        state.controls.max_body_bytes
    };
    if method != Method::GET
        && request.headers().get(axum::http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > body_limit as u64)
    {
        return payload_too_large();
    }
    let query = request.uri().query().unwrap_or_default().as_bytes().to_vec();
    let remote_ip = request.extensions().get::<SocketAddr>().map(|address| address.ip().to_string());
    let deadline = Some(Instant::now().checked_add(state.request_deadline).expect("validated HTTP request deadline"));
    let permit = match state.rate_limiter.acquire(&rate_limit_method(route), remote_ip.as_deref(), deadline).await {
        Ok(permit) => permit,
        Err(status) => return rate_limit_response(&status),
    };
    let body = if method == Method::GET { query.into() } else {
        match collect_limited_body(request.into_body(), body_limit).await {
            Ok(body) => body,
            Err(_) if chunked => return process_error("org.eclipse.jetty.http.BadMessageException", "request body exceeds configured limit"),
            Err(response) => return response,
        }
    };
    let parsed = if method == Method::GET {
        parse_post_body(&body, Some("application/x-www-form-urlencoded"))
    } else {
        parse_post_body(&body, content_type.as_deref())
    };
    let (json, visible) = match parsed { Ok(value) => value, Err(error) => return process_error("org.tron.core.services.http.JsonFormat$ParseException", &error.to_string()) };
    if route.path == "/wallet/validateaddress" {
        let input = serde_json::from_str::<Value>(&json).ok().and_then(|value| value.get("address").and_then(Value::as_str).map(str::to_owned));
        return match input {
            Some(address) => json_response(axum::http::StatusCode::OK, validate_address_json(&address)),
            None if method == Method::POST => json_response(axum::http::StatusCode::OK, String::new()),
            None => process_error("java.lang.NullPointerException", "Cannot invoke String.length() because input is null"),
        };
    }
    let broadcast_hex = route.path == "/wallet/broadcasthex";
    let broadcast_bytes = if broadcast_hex {
        match decode_broadcast_hex(&json) { Ok(bytes) => Some(bytes), Err(error) => return process_error("org.tron.core.services.http.JsonFormat$ParseException", &error.to_string()) }
    } else { None };
    let request_message = if let Some(bytes) = broadcast_bytes {
        match state.json.decode("protocol.Transaction", &bytes) { Ok(message) => message, Err(error) => return process_error("org.tron.core.services.http.JsonFormat$ParseException", &error.to_string()) }
    } else if route.request_type == "protocol.Transaction" {
        match state.json.parse_transaction(&json, visible) { Ok(message) => message, Err(error) => return process_error("org.tron.core.services.http.JsonFormat$ParseException", &error.to_string()) }
    } else {
        match state.json.parse(route.request_type, &json, visible) { Ok(message) => message, Err(error) => return process_error("org.tron.core.services.http.JsonFormat$ParseException", &error.to_string()) }
    };
    let encoded = request_message.encode_to_vec();
    let response = match state.services.execute_http_route(route, &encoded).await {
        Ok(bytes) => match state.json.decode(route.response_type, &bytes).and_then(|message| with_get_int64_as_string(method.as_str(), route.get_int64_as_string, || state.json.print(&message, visible))) {
            Ok(body) => json_response(axum::http::StatusCode::from_u16(route.success_status).expect("inventory status"), body),
            Err(error) => process_error("org.tron.core.services.http.JsonFormat$PrintException", &error.to_string()),
        },
        Err(status) => process_error("io.grpc.StatusRuntimeException", &status.to_string()),
    };
    drop(permit);
    response
}

fn rate_limit_method(route: &HttpRouteSpec) -> String {
    let mut method = String::with_capacity(route.rpc_method.len());
    let mut uppercase = true;
    for character in route.rpc_method.chars() {
        if character == '_' { uppercase = true; }
        else if uppercase { method.extend(character.to_uppercase()); uppercase = false; }
        else { method.push(character); }
    }
    format!("protocol.{}/{method}", route.rpc_api)
}

fn is_form_content_type(value: &str) -> bool {
    value.split(';').next().is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/x-www-form-urlencoded"))
}

/// Exact JSON body produced by Java's `ValidateAddressServlet` for a supplied address string.
#[must_use]
pub fn validate_address_json(input: &str) -> String {
    let (result, message) = if input.len() == 42 {
        match decode_hex(input) {
            Ok(address) if valid_address_bytes(&address) => (true, "Hex string format".to_owned()),
            Ok(_) => (false, "Invalid address".to_owned()),
            Err(message) => (false, message),
        }
    } else if input.len() == 34 {
        match decode_base58check(CryptoEngine::Secp256k1, input) {
            Ok(address) if valid_address_bytes(&address) => (true, "Base58check format".to_owned()),
            Ok(_) => (false, "Invalid address".to_owned()),
            Err(error) => (false, error.to_string()),
        }
    } else if input.len() == 28 {
        match STANDARD.decode(input) {
            Ok(address) if valid_address_bytes(&address) => (true, "Base64 format".to_owned()),
            Ok(_) => (false, "Invalid address".to_owned()),
            Err(error) => (false, error.to_string()),
        }
    } else {
        (false, "Length error".to_owned())
    };
    format!("{{\"result\":{result},\"message\":{}}}", serde_json::to_string(&message).expect("string JSON"))
}

fn valid_address_bytes(address: &[u8]) -> bool { address.len() == 21 && address[0] == 0x41 }

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 { return Err("invalidate hex String".into()); }
    (0..input.len()).step_by(2).map(|offset| u8::from_str_radix(&input[offset..offset + 2], 16).map_err(|error| error.to_string())).collect()
}
