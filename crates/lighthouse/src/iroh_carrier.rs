//! iroh carrier: one JSON request per bidirectional stream.

use std::sync::Arc;

use iroh::endpoint::{Connection, ReadToEndError, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh_lighthouse_protocol::{ErrorCode, MAX_MESSAGE_SIZE, Request, Response};
use tracing::debug;

use crate::handler::{Ctx, handle};

/// Accepts lighthouse connections and serves every stream on them.
#[derive(Debug, Clone)]
pub struct LighthouseProtocol {
    ctx: Arc<Ctx>,
}

impl LighthouseProtocol {
    pub fn new(ctx: Arc<Ctx>) -> Self {
        Self { ctx }
    }
}

impl ProtocolHandler for LighthouseProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = conn.remote_id();
        loop {
            let (send, recv) = match conn.accept_bi().await {
                Ok(streams) => streams,
                Err(err) => {
                    debug!(%remote, %err, "lighthouse connection closed");
                    return Ok(());
                }
            };
            let ctx = self.ctx.clone();
            tokio::spawn(async move {
                if let Err(err) = serve_stream(&ctx, send, recv).await {
                    debug!(%remote, %err, "lighthouse stream failed");
                }
            });
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum StreamError {
    #[error("read: {0}")]
    Read(#[from] ReadToEndError),
    #[error("write: {0}")]
    Write(#[from] iroh::endpoint::WriteError),
    #[error("finish: {0}")]
    Finish(#[from] iroh::endpoint::ClosedStream),
    #[error("encode: {0}")]
    Encode(#[from] serde_json::Error),
}

async fn serve_stream(
    ctx: &Ctx,
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<(), StreamError> {
    let response = match recv.read_to_end(MAX_MESSAGE_SIZE).await {
        Ok(bytes) => match serde_json::from_slice::<Request>(&bytes) {
            Ok(request) => handle(ctx, request),
            Err(err) => Response::error(ErrorCode::Malformed, err.to_string()),
        },
        Err(ReadToEndError::TooLong) => Response::error(
            ErrorCode::PayloadTooLarge,
            format!("request exceeds {MAX_MESSAGE_SIZE} bytes"),
        ),
        Err(err) => return Err(err.into()),
    };
    let bytes = serde_json::to_vec(&response)?;
    send.write_all(&bytes).await?;
    send.finish()?;
    // Resolves once the peer has read everything (or stopped us), so the data
    // is delivered before the stream is dropped.
    let _ = send.stopped().await;
    Ok(())
}
