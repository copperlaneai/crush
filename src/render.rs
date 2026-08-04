//! Disposable, interruption-safe speculative overlay rendering.
//!
//! The renderer never owns the terminal screen. Its output is limited to
//! same-line, non-wrapping text over cells the shadow model proved empty.
//! Synthetic frames contain only independent one-byte operations (printable
//! ASCII, backspace, and space), so lifecycle invalidation can discard an
//! unwritten suffix without replaying stale relative ANSI or stranding the
//! emulator inside a partial escape sequence.

use std::io::{self, Write};

use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Default)]
pub(crate) struct OverlayRenderer {
    displayed: Zeroizing<Vec<u8>>,
}

impl OverlayRenderer {
    pub(crate) fn has_displayed_overlay(&self) -> bool {
        !self.displayed.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn displayed(&self) -> usize {
        self.displayed.len()
    }

    pub(crate) fn replace(&mut self, output: &mut impl Write, desired: &[u8]) -> io::Result<()> {
        if desired.iter().any(|byte| !(0x20..=0x7e).contains(byte)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "speculative overlay contains a non-printable byte",
            ));
        }
        if self.displayed.as_slice() == desired {
            return Ok(());
        }

        let mut frame = Zeroizing::new(Vec::with_capacity(
            self.displayed.len() + desired.len() + 48,
        ));
        if !self.displayed.is_empty() {
            append_clear(&mut frame, self.displayed.len());
        }
        if !desired.is_empty() {
            frame.extend_from_slice(desired);
        }
        output.write_all(&frame)?;
        output.flush()?;
        self.displayed.zeroize();
        self.displayed.extend_from_slice(desired);
        Ok(())
    }

    pub(crate) fn clear(&mut self, output: &mut impl Write) -> io::Result<()> {
        self.replace(output, &[])
    }

    /// Forget an overlay after a terminal reflow makes its old coordinates
    /// unknowable. Emitting no erase is safer than destroying remote cells;
    /// the application's resize redraw remains authoritative.
    pub(crate) fn abandon(&mut self) {
        self.displayed.zeroize();
    }
}

fn append_clear(frame: &mut Vec<u8>, width: usize) {
    cursor_left(frame, width);
    frame.resize(frame.len() + width, b' ');
    cursor_left(frame, width);
}

fn cursor_left(frame: &mut Vec<u8>, width: usize) {
    frame.resize(frame.len() + width, b'\x08');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FlushCounter {
        bytes: Vec<u8>,
        flushes: usize,
    }

    impl Write for FlushCounter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn remote_bytes_remain_exact_and_ordered() {
        let mut renderer = OverlayRenderer::default();
        let mut output = Vec::new();
        renderer.replace(&mut output, b"abc").unwrap();
        output.clear();
        renderer.clear(&mut output).unwrap();
        output.extend_from_slice(b"\x1b[Hremote\0bytes");
        assert!(output.ends_with(b"\x1b[Hremote\0bytes"));
        assert_eq!(renderer.displayed(), 0);
    }

    #[test]
    fn clear_does_not_scroll_or_save_cursor() {
        let mut renderer = OverlayRenderer::default();
        let mut output = Vec::new();
        renderer.replace(&mut output, b"x").unwrap();
        output.clear();
        renderer.clear(&mut output).unwrap();
        assert_eq!(output, b"\x08 \x08");
        assert!(!output.contains(&b'\n'));
        assert!(!output.windows(2).any(|bytes| bytes == b"\x1b7"));
    }

    #[test]
    fn speculative_frames_are_safe_to_interrupt_between_any_bytes() {
        let mut renderer = OverlayRenderer::default();
        let mut output = Vec::new();

        renderer.replace(&mut output, b"predict").unwrap();
        renderer.replace(&mut output, b"next").unwrap();
        renderer.clear(&mut output).unwrap();

        assert!(!output.contains(&b'\x1b'));
        assert!(output.iter().all(|byte| matches!(byte, 0x08 | 0x20..=0x7e)));
        assert_eq!(
            renderer
                .replace(&mut output, b"unsafe\x1b")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn every_changed_frame_is_flushed_immediately() {
        let mut renderer = OverlayRenderer::default();
        let mut output = FlushCounter::default();

        renderer.replace(&mut output, b"x").unwrap();
        renderer.clear(&mut output).unwrap();

        assert_eq!(output.flushes, 2);
    }
}
