//! Typed ComponentSession named-stream handles.

use crate::{
    ComponentSessionDriver, Result, SessionDriverHandle, SessionError, StreamEvent, StreamId,
    contract::SessionErrorCode,
};

/// A single-owner handle for one authenticated ComponentSession named stream.
///
/// The handle exposes only bounded stream operations. It carries no resource
/// claims, target identity, or generic RPC method catalogue.
pub struct ComponentSessionStream {
    driver: SessionDriverHandle,
    stream: StreamId,
    generation: u64,
}

impl ComponentSessionStream {
    pub(crate) async fn open(
        driver: SessionDriverHandle,
        stream: StreamId,
        send_credit: u32,
        receive_credit: u32,
    ) -> Result<Self> {
        driver
            .open_named_stream(stream, send_credit, receive_credit)
            .await?;
        let generation = ComponentSessionDriver::generation(&driver);
        Ok(Self {
            driver,
            stream,
            generation,
        })
    }

    fn ensure_current(&self) -> Result<()> {
        if ComponentSessionDriver::generation(&self.driver) != self.generation {
            Err(SessionError::new(SessionErrorCode::GenerationMismatch))
        } else {
            Ok(())
        }
    }

    /// Return the stream's opaque channel identifier.
    pub const fn stream_id(&self) -> StreamId {
        self.stream
    }

    /// Return the reconnect generation that opened this stream.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Send one bounded logical stream message.
    pub async fn send(&self, bytes: Vec<u8>) -> Result<()> {
        self.ensure_current()?;
        self.driver.send_named_stream(self.stream, bytes).await
    }

    /// Receive the next authenticated named-stream event.
    pub async fn receive(&self) -> Result<StreamEvent> {
        self.ensure_current()?;
        self.driver.receive_named_stream_for(self.stream).await
    }

    /// Return logical receive credit after consuming stream data.
    pub async fn grant_credit(&self, bytes: u32) -> Result<()> {
        self.ensure_current()?;
        self.driver
            .grant_named_stream_credit(self.stream, bytes)
            .await
    }

    /// Close this named stream.
    pub async fn close(&self) -> Result<()> {
        self.ensure_current()?;
        self.driver.close_named_stream(self.stream).await
    }

    /// Reset this named stream.
    pub async fn reset(&self) -> Result<()> {
        self.ensure_current()?;
        self.driver.reset_named_stream(self.stream).await
    }
}

impl std::fmt::Debug for ComponentSessionStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ComponentSessionStream")
            .field("stream", &"<redacted>")
            .field("generation", &self.generation)
            .finish()
    }
}
