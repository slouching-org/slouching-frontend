//! Bounded fragmentation for SFrame-protected screen frames over WebRTC SCTP.
//!
//! `webrtc` 0.21 delivers data-channel events up to 16 KiB. A complete SFrame
//! access unit may exceed that, so split it into independently bounded
//! messages and authenticate the reassembled frame with SFrame before decode.

const MAGIC: &[u8; 4] = b"SLVF";
const HEADER_LEN: usize = 12;
const CHUNK_BYTES: usize = 12 * 1024;
const MAX_PROTECTED_FRAME_BYTES: usize = 64 * 1024 + 64;
const MAX_FRAGMENTS: usize = MAX_PROTECTED_FRAME_BYTES.div_ceil(CHUNK_BYTES);
const STOP_SHARING_MARKER: &[u8; 4] = b"SLS0";

pub fn stop_sharing_message() -> &'static [u8] {
    STOP_SHARING_MARKER
}

pub fn is_stop_sharing_message(message: &[u8]) -> bool {
    message == STOP_SHARING_MARKER
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoFragmentHeader {
    pub frame_id: u32,
    pub index: u16,
    pub count: u16,
}

pub fn fragment_frame(frame_id: u32, protected: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if protected.is_empty() || protected.len() > MAX_PROTECTED_FRAME_BYTES {
        return Err("protected video frame is empty or exceeds its 64 KiB bound".to_owned());
    }
    let count = protected.len().div_ceil(CHUNK_BYTES);
    let count_u16 = u16::try_from(count).map_err(|_| "video frame has too many fragments")?;
    let mut chunks = Vec::with_capacity(count);
    for (index, payload) in protected.chunks(CHUNK_BYTES).enumerate() {
        let mut chunk = Vec::with_capacity(HEADER_LEN + payload.len());
        chunk.extend_from_slice(MAGIC);
        chunk.extend_from_slice(&frame_id.to_be_bytes());
        chunk.extend_from_slice(&(index as u16).to_be_bytes());
        chunk.extend_from_slice(&count_u16.to_be_bytes());
        chunk.extend_from_slice(payload);
        chunks.push(chunk);
    }
    Ok(chunks)
}

pub fn parse_fragment(chunk: &[u8]) -> Result<(VideoFragmentHeader, &[u8]), String> {
    if chunk.len() <= HEADER_LEN || chunk.len() > HEADER_LEN + CHUNK_BYTES {
        return Err("video fragment has an invalid byte length".to_owned());
    }
    if &chunk[..4] != MAGIC {
        return Err("video fragment has an unknown wire marker".to_owned());
    }
    let frame_id = u32::from_be_bytes(chunk[4..8].try_into().expect("fixed header"));
    let index = u16::from_be_bytes(chunk[8..10].try_into().expect("fixed header"));
    let count = u16::from_be_bytes(chunk[10..12].try_into().expect("fixed header"));
    if count == 0 || count as usize > MAX_FRAGMENTS || index >= count {
        return Err("video fragment index or count is outside the supported range".to_owned());
    }
    Ok((
        VideoFragmentHeader {
            frame_id,
            index,
            count,
        },
        &chunk[HEADER_LEN..],
    ))
}

#[derive(Default)]
pub struct VideoFrameReassembler {
    frame_id: Option<u32>,
    chunks: Vec<Option<Vec<u8>>>,
    received_bytes: usize,
}

impl VideoFrameReassembler {
    /// Returns a protected encoded access unit once every fragment is present.
    /// A newer frame discards an incomplete older frame instead of buffering
    /// stale screen content indefinitely.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let (header, payload) = parse_fragment(chunk)?;
        if self.frame_id != Some(header.frame_id) {
            self.frame_id = Some(header.frame_id);
            self.chunks = vec![None; header.count as usize];
            self.received_bytes = 0;
        } else if self.chunks.len() != header.count as usize {
            self.reset();
            return Err("video fragment count changed within a frame".to_owned());
        }
        let slot = &mut self.chunks[header.index as usize];
        if slot.is_some() {
            return Ok(None);
        }
        self.received_bytes = self.received_bytes.saturating_add(payload.len());
        if self.received_bytes > MAX_PROTECTED_FRAME_BYTES {
            self.reset();
            return Err("reassembled video frame exceeds its byte limit".to_owned());
        }
        *slot = Some(payload.to_vec());
        if self.chunks.iter().any(Option::is_none) {
            return Ok(None);
        }
        let mut frame = Vec::with_capacity(self.received_bytes);
        for chunk in &mut self.chunks {
            frame.extend_from_slice(chunk.take().as_deref().expect("all fragments present"));
        }
        self.reset();
        Ok(Some(frame))
    }

    pub fn clear(&mut self) {
        self.reset();
    }

    fn reset(&mut self) {
        self.frame_id = None;
        self.chunks.clear();
        self.received_bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_video_frame_round_trips_in_bounded_messages_out_of_order() {
        let frame = (0..(CHUNK_BYTES * 2 + 37))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let fragments = fragment_frame(42, &frame).unwrap();
        assert!(fragments.iter().all(|fragment| fragment.len() <= 16 * 1024));
        let mut reassembler = VideoFrameReassembler::default();
        let mut complete = None;
        for fragment in fragments.iter().rev() {
            if let Some(frame) = reassembler.push(fragment).unwrap() {
                complete = Some(frame);
            }
        }
        assert_eq!(complete.as_deref(), Some(frame.as_slice()));
    }

    #[test]
    fn incomplete_frame_is_discarded_when_a_newer_frame_arrives() {
        let first = fragment_frame(10, &vec![1; CHUNK_BYTES + 1]).unwrap();
        let second = fragment_frame(11, b"new screen frame").unwrap();
        let mut reassembler = VideoFrameReassembler::default();
        assert!(reassembler.push(&first[0]).unwrap().is_none());
        assert_eq!(
            reassembler.push(&second[0]).unwrap().as_deref(),
            Some(b"new screen frame".as_slice())
        );
    }

    #[test]
    fn fragment_parser_rejects_bad_markers_lengths_and_counts() {
        assert!(parse_fragment(b"short").is_err());
        let mut chunk = fragment_frame(1, b"frame").unwrap().remove(0);
        chunk[0] = b'X';
        assert!(parse_fragment(&chunk).is_err());
        let mut chunk = fragment_frame(1, b"frame").unwrap().remove(0);
        chunk[10..12].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(parse_fragment(&chunk).is_err());
    }
}
