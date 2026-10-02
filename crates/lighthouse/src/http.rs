//! HTTP carrier: a few axum routes over the shared handler.

use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{Method, StatusCode, header};
use axum::routing::{get, post};
use iroh::EndpointId;
use iroh_lighthouse_protocol::{
    Announce, ErrorCode, HTTP_ANNOUNCE, HTTP_HEALTH, HTTP_INFO, HTTP_LOOKUP, HTTP_RESOLVE, Lookup,
    MAX_MESSAGE_SIZE, Request, Response,
};

use tower_http::cors::{Any, CorsLayer};

use crate::handler::{Ctx, handle};

type Reply = (StatusCode, Json<Response>);

/// The complete HTTP API.
///
/// CORS is open to any origin so a static page can talk to the lighthouse
/// directly. That is safe here: requests carry no cookies or credentials, and
/// every write is authenticated by signatures inside the body.
pub fn router(ctx: Arc<Ctx>) -> axum::Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE]);
    axum::Router::new()
        .route(HTTP_ANNOUNCE, post(announce))
        .route(HTTP_LOOKUP, post(lookup))
        .route(&format!("{HTTP_RESOLVE}/{{id}}"), get(resolve))
        .route(HTTP_INFO, get(info))
        .route(HTTP_HEALTH, get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(MAX_MESSAGE_SIZE))
        .layer(cors)
        .with_state(ctx)
}

fn reply(response: Response) -> Reply {
    let status = match &response {
        Response::Error(err) => StatusCode::from_u16(err.code.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        _ => StatusCode::OK,
    };
    (status, Json(response))
}

fn rejected(rejection: JsonRejection) -> Reply {
    let code = if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ErrorCode::PayloadTooLarge
    } else {
        ErrorCode::Malformed
    };
    reply(Response::error(code, rejection.body_text()))
}

async fn announce(
    State(ctx): State<Arc<Ctx>>,
    body: Result<Json<Announce>, JsonRejection>,
) -> Reply {
    match body {
        Ok(Json(announce)) => reply(handle(&ctx, Request::Announce(announce))),
        Err(rejection) => rejected(rejection),
    }
}

async fn lookup(State(ctx): State<Arc<Ctx>>, body: Result<Json<Lookup>, JsonRejection>) -> Reply {
    match body {
        Ok(Json(lookup)) => reply(handle(&ctx, Request::Lookup(lookup))),
        Err(rejection) => rejected(rejection),
    }
}

async fn resolve(State(ctx): State<Arc<Ctx>>, Path(id): Path<String>) -> Reply {
    match id.parse::<EndpointId>() {
        Ok(id) => reply(handle(&ctx, Request::Resolve { id })),
        Err(err) => reply(Response::error(
            ErrorCode::Malformed,
            format!("invalid endpoint id: {err}"),
        )),
    }
}

async fn info(State(ctx): State<Arc<Ctx>>) -> Reply {
    reply(handle(&ctx, Request::Info))
}
