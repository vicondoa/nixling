use std::{collections::BTreeMap, fmt};

use d2b_contracts_zone_session::v3::component_session::{
    ChannelId, LimitProfile, SessionErrorCode,
};

use crate::{Result, SessionError};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(ChannelId);

impl StreamId {
    pub fn new(value: u16) -> Result<Self> {
        Ok(Self(ChannelId::named(value)?))
    }

    pub fn channel(self) -> ChannelId {
        self.0
    }
}

impl fmt::Debug for StreamId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StreamId(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamPhase {
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
    Reset,
}

pub enum StreamEvent {
    Data { stream: StreamId, bytes: Vec<u8> },
    RemoteClosed { stream: StreamId },
    Reset { stream: StreamId },
}

impl StreamEvent {
    pub const fn stream(&self) -> StreamId {
        match self {
            Self::Data { stream, .. } | Self::RemoteClosed { stream } | Self::Reset { stream } => {
                *stream
            }
        }
    }
}

impl fmt::Debug for StreamEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data { bytes, .. } => formatter
                .debug_struct("StreamEvent::Data")
                .field("stream", &"<redacted>")
                .field("bytes", &"<redacted>")
                .field("len", &bytes.len())
                .finish(),
            Self::RemoteClosed { .. } => {
                formatter.write_str("StreamEvent::RemoteClosed(<redacted>)")
            }
            Self::Reset { .. } => formatter.write_str("StreamEvent::Reset(<redacted>)"),
        }
    }
}

struct StreamState {
    phase: StreamPhase,
    send_credit: u32,
    receive_credit: u32,
    receive_reserved: u32,
}

pub struct NamedStreamMux {
    limits: LimitProfile,
    streams: BTreeMap<StreamId, StreamState>,
    aggregate_receive_reserved: u32,
}

impl NamedStreamMux {
    pub fn new(limits: LimitProfile) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            limits,
            streams: BTreeMap::new(),
            aggregate_receive_reserved: 0,
        })
    }

    pub fn open(&mut self, stream: StreamId, send_credit: u32, receive_credit: u32) -> Result<()> {
        if self.streams.len() >= self.limits.active_named_streams as usize
            || send_credit > self.limits.named_stream_queue_bytes
            || receive_credit > self.limits.named_stream_queue_bytes
            || self.streams.contains_key(&stream)
        {
            return Err(SessionError::new(SessionErrorCode::QueueBackpressure));
        }
        self.streams.insert(
            stream,
            StreamState {
                phase: StreamPhase::Open,
                send_credit,
                receive_credit,
                receive_reserved: 0,
            },
        );
        Ok(())
    }

    pub fn phase(&self, stream: StreamId) -> Option<StreamPhase> {
        self.streams.get(&stream).map(|state| state.phase)
    }

    pub fn send_credit(&self, stream: StreamId) -> Option<u32> {
        self.streams.get(&stream).map(|state| state.send_credit)
    }

    pub(crate) fn ensure_send_open(&mut self, stream: StreamId) -> Result<()> {
        let state = self.stream_mut(stream)?;
        if matches!(
            state.phase,
            StreamPhase::Open | StreamPhase::HalfClosedRemote
        ) {
            Ok(())
        } else {
            Err(SessionError::new(SessionErrorCode::QueueBackpressure))
        }
    }

    pub fn reserve_send(&mut self, stream: StreamId, bytes: usize) -> Result<()> {
        let bytes = checked_message_len(bytes, self.limits.logical_named_stream_bytes)?;
        let state = self.stream_mut(stream)?;
        if !matches!(
            state.phase,
            StreamPhase::Open | StreamPhase::HalfClosedRemote
        ) || state.send_credit < bytes
        {
            return Err(SessionError::new(SessionErrorCode::QueueBackpressure));
        }
        state.send_credit -= bytes;
        Ok(())
    }

    pub fn grant_send_credit(&mut self, stream: StreamId, bytes: u32) -> Result<()> {
        let limit = self.limits.named_stream_queue_bytes;
        let state = self.stream_mut(stream)?;
        let next = state
            .send_credit
            .checked_add(bytes)
            .ok_or_else(|| SessionError::new(SessionErrorCode::ArithmeticOverflow))?;
        if next > limit {
            return Err(SessionError::new(SessionErrorCode::QueueBackpressure));
        }
        state.send_credit = next;
        Ok(())
    }

    pub(crate) fn refund_send_credit(&mut self, stream: StreamId, bytes: u32) -> Result<()> {
        self.grant_send_credit(stream, bytes)
    }

    pub fn receive_data(&mut self, stream: StreamId, bytes: Vec<u8>) -> Result<StreamEvent> {
        let len = checked_message_len(bytes.len(), self.limits.logical_named_stream_bytes)?;
        self.reserve_receive_fragment(stream, len)?;
        Ok(self.complete_receive(stream, bytes))
    }

    pub(crate) fn reserve_receive_fragment(&mut self, stream: StreamId, bytes: u32) -> Result<()> {
        let aggregate = self
            .aggregate_receive_reserved
            .checked_add(bytes)
            .ok_or_else(|| SessionError::new(SessionErrorCode::ArithmeticOverflow))?;
        if aggregate > self.limits.aggregate_named_stream_queue_bytes {
            return Err(SessionError::new(SessionErrorCode::QueueBackpressure));
        }
        let state = self.stream_mut(stream)?;
        if !matches!(
            state.phase,
            StreamPhase::Open | StreamPhase::HalfClosedLocal
        ) || state.receive_credit < bytes
        {
            return Err(SessionError::new(SessionErrorCode::QueueBackpressure));
        }
        state.receive_credit -= bytes;
        state.receive_reserved = state
            .receive_reserved
            .checked_add(bytes)
            .ok_or_else(|| SessionError::new(SessionErrorCode::ArithmeticOverflow))?;
        self.aggregate_receive_reserved = aggregate;
        Ok(())
    }

    pub(crate) fn complete_receive(&self, stream: StreamId, bytes: Vec<u8>) -> StreamEvent {
        StreamEvent::Data { stream, bytes }
    }

    pub fn release_receive_credit(&mut self, stream: StreamId, bytes: u32) -> Result<u32> {
        let limit = self.limits.named_stream_queue_bytes;
        let state = self.stream_mut(stream)?;
        let next = state
            .receive_credit
            .checked_add(bytes)
            .ok_or_else(|| SessionError::new(SessionErrorCode::ArithmeticOverflow))?;
        if next > limit {
            return Err(SessionError::new(SessionErrorCode::QueueBackpressure));
        }
        if state.receive_reserved < bytes {
            return Err(SessionError::new(SessionErrorCode::InternalInvariant));
        }
        state.receive_credit = next;
        state.receive_reserved -= bytes;
        self.aggregate_receive_reserved = self
            .aggregate_receive_reserved
            .checked_sub(bytes)
            .ok_or_else(|| SessionError::new(SessionErrorCode::InternalInvariant))?;
        Ok(bytes)
    }

    pub fn close_local(&mut self, stream: StreamId) -> Result<StreamPhase> {
        let state = self.stream_mut(stream)?;
        state.phase = match state.phase {
            StreamPhase::Open => StreamPhase::HalfClosedLocal,
            StreamPhase::HalfClosedRemote => StreamPhase::Closed,
            StreamPhase::HalfClosedLocal | StreamPhase::Closed | StreamPhase::Reset => {
                return Err(SessionError::new(SessionErrorCode::UnknownControl));
            }
        };
        Ok(state.phase)
    }

    pub fn receive_close(&mut self, stream: StreamId) -> Result<StreamEvent> {
        let state = self.stream_mut(stream)?;
        state.phase = match state.phase {
            StreamPhase::Open => StreamPhase::HalfClosedRemote,
            StreamPhase::HalfClosedLocal => StreamPhase::Closed,
            StreamPhase::HalfClosedRemote | StreamPhase::Closed | StreamPhase::Reset => {
                return Err(SessionError::new(SessionErrorCode::UnknownControl));
            }
        };
        Ok(StreamEvent::RemoteClosed { stream })
    }

    pub fn reset(&mut self, stream: StreamId) -> Result<StreamEvent> {
        self.stream_mut(stream)?.phase = StreamPhase::Reset;
        Ok(StreamEvent::Reset { stream })
    }

    pub fn remove_terminal(&mut self, stream: StreamId) -> bool {
        if self
            .streams
            .get(&stream)
            .is_some_and(|state| matches!(state.phase, StreamPhase::Closed | StreamPhase::Reset))
        {
            if let Some(state) = self.streams.remove(&stream) {
                self.aggregate_receive_reserved = self
                    .aggregate_receive_reserved
                    .saturating_sub(state.receive_reserved);
            }
            true
        } else {
            false
        }
    }

    pub fn active(&self) -> usize {
        self.streams.len()
    }

    fn stream_mut(&mut self, stream: StreamId) -> Result<&mut StreamState> {
        self.streams
            .get_mut(&stream)
            .ok_or_else(|| SessionError::new(SessionErrorCode::InvalidChannel))
    }
}

fn checked_message_len(bytes: usize, logical_limit: u32) -> Result<u32> {
    let bytes = u32::try_from(bytes)
        .map_err(|_| SessionError::new(SessionErrorCode::ArithmeticOverflow))?;
    if bytes == 0 || bytes > logical_limit {
        return Err(SessionError::new(SessionErrorCode::ReassemblyLimitExceeded));
    }
    Ok(bytes)
}

impl fmt::Debug for NamedStreamMux {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NamedStreamMux")
            .field("active", &self.streams.len())
            .field("stream_ids", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragments_and_streams_share_one_retained_receive_budget() {
        let limits = LimitProfile::local_default();
        let mut mux = NamedStreamMux::new(limits).unwrap();
        let per_stream = limits.named_stream_queue_bytes;
        let full_streams = limits.aggregate_named_stream_queue_bytes / per_stream;
        for index in 0..=full_streams {
            let stream = StreamId::new(u16::try_from(0x100 + index).unwrap()).unwrap();
            mux.open(stream, per_stream, per_stream).unwrap();
            let result = mux.reserve_receive_fragment(stream, per_stream);
            if index < full_streams {
                result.unwrap();
            } else {
                assert_eq!(
                    result.unwrap_err().code(),
                    SessionErrorCode::QueueBackpressure
                );
            }
        }
        let first = StreamId::new(0x100).unwrap();
        mux.release_receive_credit(first, per_stream).unwrap();
        let last = StreamId::new(u16::try_from(0x100 + full_streams).unwrap()).unwrap();
        mux.reserve_receive_fragment(last, per_stream).unwrap();
    }
}
