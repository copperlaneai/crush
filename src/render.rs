//! Disposable, interruption-safe speculative overlay rendering.

use std::ffi::OsStr;
use std::io::{self, Write};

use zeroize::{Zeroize, Zeroizing};

const HIDE_CURSOR: &[u8] = b"\x1b[?25l";
const SHOW_CURSOR: &[u8] = b"\x1b[?25h";
const CSI_SYNC_START: &[u8] = b"\x1b[?2026h";
const CSI_SYNC_END: &[u8] = b"\x1b[?2026l";
const KITTY_SYNC_START: &[u8] = b"\x1bP=1s\x1b\\";
const KITTY_SYNC_END: &[u8] = b"\x1bP=2s\x1b\\";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum ReconciliationSync {
    #[default]
    Disabled,
    Csi,
    Kitty,
}

impl ReconciliationSync {
    pub(crate) fn for_term(term: Option<&OsStr>) -> Self {
        match term.map(OsStr::as_encoded_bytes) {
            Some(b"xterm-kitty" | b"kitty") => Self::Kitty,
            Some(_) => Self::Csi,
            None => Self::Disabled,
        }
    }

    fn start(self, frame: &mut Vec<u8>) {
        match self {
            Self::Disabled => {}
            Self::Csi => frame.extend_from_slice(CSI_SYNC_START),
            Self::Kitty => frame.extend_from_slice(KITTY_SYNC_START),
        }
    }

    fn end(self, frame: &mut Vec<u8>) {
        match self {
            Self::Disabled => {}
            Self::Csi => frame.extend_from_slice(CSI_SYNC_END),
            Self::Kitty => frame.extend_from_slice(KITTY_SYNC_END),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CursorLocation {
    pub(crate) line: i32,
    pub(crate) column: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CursorComposition {
    pub(crate) target: CursorLocation,
    pub(crate) previous_software: Option<CursorLocation>,
    pub(crate) columns: usize,
    pub(crate) underlay: Option<u8>,
    pub(crate) native_visible: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OverlayGeometry {
    pub(crate) anchor: CursorLocation,
    pub(crate) columns: usize,
}

impl OverlayGeometry {
    fn cursor_after(self, cells: usize) -> io::Result<CursorLocation> {
        if self.anchor.line < 0 || self.columns == 0 || self.anchor.column >= self.columns {
            return Err(io::Error::other("invalid wrapped overlay geometry"));
        }
        let linear_column = self
            .anchor
            .column
            .checked_add(cells)
            .ok_or_else(|| io::Error::other("wrapped overlay column overflow"))?;
        let added_lines = i32::try_from(linear_column / self.columns)
            .map_err(|_| io::Error::other("wrapped overlay row overflow"))?;
        Ok(CursorLocation {
            line: self
                .anchor
                .line
                .checked_add(added_lines)
                .ok_or_else(|| io::Error::other("wrapped overlay row overflow"))?,
            column: linear_column % self.columns,
        })
    }

    fn after_cells(self, cells: usize) -> io::Result<Self> {
        Ok(Self {
            anchor: self.cursor_after(cells)?,
            columns: self.columns,
        })
    }
}

#[derive(Debug, Default)]
pub(crate) struct OverlayRenderer {
    displayed: Zeroizing<Vec<u8>>,
    underlay: Zeroizing<Vec<u8>>,
    software_cursor_underlay: Option<u8>,
    geometry: Option<OverlayGeometry>,
    dim_predictions: bool,
    reconciliation_sync: ReconciliationSync,
}

impl OverlayRenderer {
    #[cfg(test)]
    pub(crate) fn new(dim_predictions: bool) -> Self {
        Self {
            displayed: Zeroizing::new(Vec::new()),
            underlay: Zeroizing::new(Vec::new()),
            software_cursor_underlay: None,
            geometry: None,
            dim_predictions,
            reconciliation_sync: ReconciliationSync::Disabled,
        }
    }

    pub(crate) fn with_reconciliation_sync(
        dim_predictions: bool,
        reconciliation_sync: ReconciliationSync,
    ) -> Self {
        Self {
            displayed: Zeroizing::new(Vec::new()),
            underlay: Zeroizing::new(Vec::new()),
            software_cursor_underlay: None,
            geometry: None,
            dim_predictions,
            reconciliation_sync,
        }
    }

    pub(crate) fn has_displayed_overlay(&self) -> bool {
        !self.displayed.is_empty() || self.software_cursor_underlay.is_some()
    }

    #[cfg(test)]
    pub(crate) fn displayed(&self) -> usize {
        self.displayed.len()
    }

    pub(crate) fn replace(&mut self, output: &mut impl Write, desired: &[u8]) -> io::Result<()> {
        let underlay = Zeroizing::new(vec![b' '; desired.len()]);
        self.replace_over(output, desired, &underlay)
    }

    pub(crate) fn replace_over(
        &mut self,
        output: &mut impl Write,
        desired: &[u8],
        underlay: &[u8],
    ) -> io::Result<()> {
        self.replace_composed(output, desired, underlay, None, None)
    }

    pub(crate) fn replace_over_with_cursor(
        &mut self,
        output: &mut impl Write,
        desired: &[u8],
        underlay: &[u8],
        cursor_underlay: u8,
        geometry: Option<OverlayGeometry>,
    ) -> io::Result<()> {
        self.replace_composed(output, desired, underlay, Some(cursor_underlay), geometry)
    }

    fn replace_composed(
        &mut self,
        output: &mut impl Write,
        desired: &[u8],
        underlay: &[u8],
        software_cursor_underlay: Option<u8>,
        geometry: Option<OverlayGeometry>,
    ) -> io::Result<()> {
        if desired.iter().any(|byte| !(0x20..=0x7e).contains(byte)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "speculative overlay contains a non-printable byte",
            ));
        }
        if underlay.len() != desired.len()
            || underlay.iter().any(|byte| !(0x20..=0x7e).contains(byte))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "speculative overlay underlay must contain one printable ASCII byte per cell",
            ));
        }
        if software_cursor_underlay.is_some_and(|byte| !(0x20..=0x7e).contains(&byte)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "software cursor underlay must be one printable ASCII byte",
            ));
        }
        if software_cursor_underlay.is_some() && desired.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "software cursor requires a non-empty speculative overlay",
            ));
        }
        if self.displayed.as_slice() == desired
            && self.underlay.as_slice() == underlay
            && self.software_cursor_underlay == software_cursor_underlay
            && self.geometry == geometry
        {
            return Ok(());
        }

        let retained = common_prefix_len(&self.displayed, desired)
            .min(common_prefix_len(&self.underlay, underlay));
        let removed = self.displayed.len().saturating_sub(retained);
        let appended = &desired[retained..];
        let pure_append = retained == self.displayed.len() && !appended.is_empty();
        if self.geometry.is_some() || geometry.is_some() {
            return self.replace_absolute(
                output,
                desired,
                underlay,
                software_cursor_underlay,
                geometry,
            );
        }
        let mut frame = Zeroizing::new(Vec::with_capacity(removed * 4 + appended.len() + 64));
        if self.software_cursor_underlay.is_none() && software_cursor_underlay.is_some() {
            frame.extend_from_slice(HIDE_CURSOR);
        }
        if let Some(previous_cursor_underlay) = self.software_cursor_underlay {
            if !pure_append {
                append_prediction(
                    &mut frame,
                    std::slice::from_ref(&previous_cursor_underlay),
                    self.dim_predictions,
                );
                cursor_left(&mut frame, 1);
            }
        }
        if removed != 0 {
            append_restore(&mut frame, &self.underlay[retained..], self.dim_predictions);
        }
        append_prediction(&mut frame, appended, self.dim_predictions);
        if let Some(cursor_underlay) = software_cursor_underlay {
            append_software_cursor(
                &mut frame,
                cursor_underlay,
                self.dim_predictions && cursor_underlay != b' ',
            );
        } else if self.software_cursor_underlay.is_some() {
            frame.extend_from_slice(SHOW_CURSOR);
        }
        output.write_all(&frame)?;
        output.flush()?;
        self.displayed.zeroize();
        self.displayed.extend_from_slice(desired);
        self.underlay.zeroize();
        self.underlay.extend_from_slice(underlay);
        self.software_cursor_underlay = software_cursor_underlay;
        self.geometry = geometry;
        Ok(())
    }

    fn replace_absolute(
        &mut self,
        output: &mut impl Write,
        desired: &[u8],
        underlay: &[u8],
        software_cursor_underlay: Option<u8>,
        geometry: Option<OverlayGeometry>,
    ) -> io::Result<()> {
        if (!desired.is_empty() || software_cursor_underlay.is_some()) && geometry.is_none() {
            return Err(io::Error::other(
                "absolute prediction requires terminal geometry",
            ));
        }

        let same_geometry = self.geometry == geometry;
        let retained = if same_geometry {
            common_prefix_len(&self.displayed, desired)
                .min(common_prefix_len(&self.underlay, underlay))
        } else {
            0
        };
        let pure_append = same_geometry
            && retained == self.displayed.len()
            && desired.len() > self.displayed.len();
        let mut frame = Zeroizing::new(Vec::with_capacity(
            self.displayed.len() + desired.len() + 128,
        ));
        self.reconciliation_sync.start(&mut frame);
        if self.software_cursor_underlay.is_some() || software_cursor_underlay.is_some() {
            frame.extend_from_slice(HIDE_CURSOR);
        }
        if let Some(previous_geometry) = self.geometry {
            if retained < self.underlay.len() {
                append_wrapped_prediction(
                    &mut frame,
                    previous_geometry.after_cells(retained)?,
                    &self.underlay[retained..],
                    self.dim_predictions,
                )?;
            }
            if let Some(previous_cursor_underlay) =
                self.software_cursor_underlay.filter(|_| !pure_append)
            {
                append_cursor_position(
                    &mut frame,
                    previous_geometry.cursor_after(self.displayed.len())?,
                )?;
                append_prediction(
                    &mut frame,
                    std::slice::from_ref(&previous_cursor_underlay),
                    self.dim_predictions && previous_cursor_underlay != b' ',
                );
            }
        }
        if let Some(next_geometry) = geometry {
            if retained < desired.len() {
                append_wrapped_prediction(
                    &mut frame,
                    next_geometry.after_cells(retained)?,
                    &desired[retained..],
                    self.dim_predictions,
                )?;
            }
            if let Some(cursor_underlay) = software_cursor_underlay {
                append_wrapped_software_cursor(
                    &mut frame,
                    next_geometry,
                    desired.len(),
                    cursor_underlay,
                    self.dim_predictions && cursor_underlay != b' ',
                )?;
            }
        } else if self.software_cursor_underlay.is_some() {
            if let Some(previous_geometry) = self.geometry {
                append_cursor_position(&mut frame, previous_geometry.anchor)?;
            }
            frame.extend_from_slice(SHOW_CURSOR);
        }
        self.reconciliation_sync.end(&mut frame);

        output.write_all(&frame)?;
        output.flush()?;
        self.displayed.zeroize();
        self.displayed.extend_from_slice(desired);
        self.underlay.zeroize();
        self.underlay.extend_from_slice(underlay);
        self.software_cursor_underlay = software_cursor_underlay;
        self.geometry = geometry;
        Ok(())
    }

    pub(crate) fn clear(&mut self, output: &mut impl Write) -> io::Result<()> {
        self.replace(output, &[])
    }

    pub(crate) fn append_remote_transition(&mut self, frame: &mut Vec<u8>, remote: &[u8]) {
        if self.geometry.is_some() {
            self.append_remote_wrapped(frame, remote);
            return;
        }
        if self.remote_shares_entire_prefix(remote) {
            let had_software_cursor = self.software_cursor_underlay.is_some();
            let smooth_cursor = remote.len() <= self.displayed.len()
                || (had_software_cursor && remote.iter().all(|byte| (0x20..=0x7e).contains(byte)));
            let confirmed = remote.len().min(self.displayed.len());
            if smooth_cursor {
                self.reconciliation_sync.start(frame);
                frame.extend_from_slice(HIDE_CURSOR);
            }
            if let Some(cursor_underlay) = self.software_cursor_underlay {
                append_prediction(
                    frame,
                    std::slice::from_ref(&cursor_underlay),
                    self.dim_predictions && cursor_underlay != b' ',
                );
                cursor_left(frame, 1);
            }
            cursor_left(frame, self.displayed.len());
            frame.extend_from_slice(remote);
            let remaining = &self.displayed[confirmed..];
            let has_remaining = !remaining.is_empty();
            append_prediction(frame, remaining, true);
            if has_remaining {
                if let Some(cursor_underlay) = self.software_cursor_underlay {
                    append_software_cursor(
                        frame,
                        cursor_underlay,
                        self.dim_predictions && cursor_underlay != b' ',
                    );
                } else if smooth_cursor {
                    frame.extend_from_slice(SHOW_CURSOR);
                }
            } else if smooth_cursor || had_software_cursor {
                frame.extend_from_slice(SHOW_CURSOR);
            }
            if smooth_cursor {
                self.reconciliation_sync.end(frame);
            }
            let remaining_len = self.displayed.len() - confirmed;
            self.displayed.copy_within(confirmed.., 0);
            self.displayed[remaining_len..].zeroize();
            self.displayed.truncate(remaining_len);
            self.underlay.copy_within(confirmed.., 0);
            self.underlay[remaining_len..].zeroize();
            self.underlay.truncate(remaining_len);
            if !has_remaining {
                self.software_cursor_underlay = None;
            }
        } else {
            if synchronized_update_frame_end(remote).is_some() {
                let update_end = synchronized_update_frame_end(remote)
                    .expect("checked synchronized update boundary");
                frame.extend_from_slice(&remote[..update_end]);
                if self.software_cursor_underlay.is_some() {
                    frame.extend_from_slice(SHOW_CURSOR);
                }
                frame.extend_from_slice(&remote[update_end..]);
            } else {
                let settle_software_cursor = self.software_cursor_underlay.is_some()
                    && remote.iter().all(|byte| (0x20..=0x7e).contains(byte));
                if settle_software_cursor {
                    self.reconciliation_sync.start(frame);
                    frame.extend_from_slice(HIDE_CURSOR);
                }
                if let Some(cursor_underlay) = self.software_cursor_underlay {
                    append_prediction(
                        frame,
                        std::slice::from_ref(&cursor_underlay),
                        self.dim_predictions && cursor_underlay != b' ',
                    );
                    cursor_left(frame, 1);
                }
                append_restore(frame, &self.underlay, self.dim_predictions);
                if self.software_cursor_underlay.is_some() {
                    frame.extend_from_slice(SHOW_CURSOR);
                }
                frame.extend_from_slice(remote);
                if settle_software_cursor {
                    self.reconciliation_sync.end(frame);
                }
            }
            self.displayed.zeroize();
            self.underlay.zeroize();
            self.software_cursor_underlay = None;
        }
    }

    fn append_remote_wrapped(&mut self, frame: &mut Vec<u8>, remote: &[u8]) {
        let geometry = self.geometry.expect("wrapped overlay retains geometry");
        if self.remote_shares_entire_prefix(remote) {
            let confirmed = remote.len().min(self.displayed.len());
            let remaining = &self.displayed[confirmed..];
            self.reconciliation_sync.start(frame);
            frame.extend_from_slice(HIDE_CURSOR);
            append_cursor_position(frame, geometry.anchor).expect("stored wrapped anchor is valid");
            frame.extend_from_slice(remote);

            if remaining.is_empty() {
                if remote.len() <= self.displayed.len() {
                    if let Some(cursor_underlay) = self.software_cursor_underlay {
                        let software_cursor = geometry
                            .cursor_after(self.displayed.len())
                            .expect("wrapped software cursor remains on screen");
                        append_cursor_position(frame, software_cursor)
                            .expect("stored wrapped cursor is valid");
                        append_prediction(
                            frame,
                            std::slice::from_ref(&cursor_underlay),
                            self.dim_predictions && cursor_underlay != b' ',
                        );
                        append_cursor_position(frame, software_cursor)
                            .expect("stored wrapped cursor is valid");
                    }
                }
                frame.extend_from_slice(SHOW_CURSOR);
            } else {
                let next_geometry = OverlayGeometry {
                    anchor: geometry
                        .cursor_after(confirmed)
                        .expect("confirmed wrapped prefix remains on screen"),
                    columns: geometry.columns,
                };
                append_wrapped_prediction(frame, next_geometry, remaining, true)
                    .expect("stored wrapped suffix remains on screen");
                if let Some(cursor_underlay) = self.software_cursor_underlay {
                    append_wrapped_software_cursor(
                        frame,
                        next_geometry,
                        remaining.len(),
                        cursor_underlay,
                        self.dim_predictions && cursor_underlay != b' ',
                    )
                    .expect("stored wrapped cursor remains on screen");
                }
                self.geometry = Some(next_geometry);
            }
            self.reconciliation_sync.end(frame);

            let remaining_len = self.displayed.len() - confirmed;
            self.displayed.copy_within(confirmed.., 0);
            self.displayed[remaining_len..].zeroize();
            self.displayed.truncate(remaining_len);
            self.underlay.copy_within(confirmed.., 0);
            self.underlay[remaining_len..].zeroize();
            self.underlay.truncate(remaining_len);
            if remaining_len == 0 {
                self.software_cursor_underlay = None;
                self.geometry = None;
            }
            return;
        }

        if synchronized_update_frame_end(remote).is_some() {
            let update_end = synchronized_update_frame_end(remote)
                .expect("checked synchronized update boundary");
            frame.extend_from_slice(&remote[..update_end]);
            frame.extend_from_slice(SHOW_CURSOR);
            frame.extend_from_slice(&remote[update_end..]);
        } else {
            self.reconciliation_sync.start(frame);
            frame.extend_from_slice(HIDE_CURSOR);
            append_wrapped_prediction(frame, geometry, &self.underlay, self.dim_predictions)
                .expect("stored wrapped underlay remains on screen");
            if let Some(cursor_underlay) = self.software_cursor_underlay {
                append_cursor_position(
                    frame,
                    geometry
                        .cursor_after(self.displayed.len())
                        .expect("wrapped software cursor remains on screen"),
                )
                .expect("stored wrapped cursor is valid");
                append_prediction(
                    frame,
                    std::slice::from_ref(&cursor_underlay),
                    self.dim_predictions && cursor_underlay != b' ',
                );
            }
            append_cursor_position(frame, geometry.anchor).expect("stored wrapped anchor is valid");
            frame.extend_from_slice(remote);
            frame.extend_from_slice(SHOW_CURSOR);
            self.reconciliation_sync.end(frame);
        }
        self.displayed.zeroize();
        self.underlay.zeroize();
        self.software_cursor_underlay = None;
        self.geometry = None;
    }

    pub(crate) fn append_remote_composed(
        &mut self,
        frame: &mut Vec<u8>,
        remote: &[u8],
        desired: &[u8],
        underlay: &[u8],
        cursor: CursorComposition,
    ) -> io::Result<()> {
        let update_end = synchronized_update_frame_end(remote);
        validate_overlay(desired, underlay)?;
        if cursor
            .underlay
            .is_some_and(|byte| !(0x20..=0x7e).contains(&byte))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "software cursor underlay must be one printable ASCII byte",
            ));
        }

        if let Some(update_end) = update_end {
            frame.extend_from_slice(&remote[..update_end]);
        } else {
            self.reconciliation_sync.start(frame);
            frame.extend_from_slice(remote);
        }
        if !desired.is_empty() {
            frame.extend_from_slice(HIDE_CURSOR);
            let geometry = OverlayGeometry {
                anchor: cursor.target,
                columns: cursor.columns,
            };
            append_wrapped_prediction(frame, geometry, desired, self.dim_predictions)?;
            if let Some(cursor_underlay) = cursor.underlay {
                append_wrapped_software_cursor(
                    frame,
                    geometry,
                    desired.len(),
                    cursor_underlay,
                    self.dim_predictions && cursor_underlay != b' ',
                )?;
            }
        } else if cursor.previous_software == Some(cursor.target) {
            if let Some(cursor_underlay) = cursor.underlay.or(self.software_cursor_underlay) {
                append_cursor_position(frame, cursor.target)?;
                append_prediction(
                    frame,
                    std::slice::from_ref(&cursor_underlay),
                    self.dim_predictions && cursor_underlay != b' ',
                );
                append_cursor_position(frame, cursor.target)?;
            }
            if cursor.native_visible {
                frame.extend_from_slice(SHOW_CURSOR);
            }
        } else if let (Some(previous), Some(previous_underlay)) =
            (cursor.previous_software, self.software_cursor_underlay)
        {
            append_cursor_position(frame, previous)?;
            append_prediction(
                frame,
                std::slice::from_ref(&previous_underlay),
                self.dim_predictions && previous_underlay != b' ',
            );
            append_cursor_position(frame, cursor.target)?;
            if cursor.native_visible {
                frame.extend_from_slice(SHOW_CURSOR);
            }
        } else if self.software_cursor_underlay.is_some() && cursor.native_visible {
            frame.extend_from_slice(SHOW_CURSOR);
        }
        if let Some(update_end) = update_end {
            frame.extend_from_slice(&remote[update_end..]);
        } else {
            self.reconciliation_sync.end(frame);
        }

        self.displayed.zeroize();
        self.displayed.extend_from_slice(desired);
        self.underlay.zeroize();
        self.underlay.extend_from_slice(underlay);
        self.software_cursor_underlay = if desired.is_empty() {
            None
        } else {
            cursor.underlay
        };
        self.geometry = (!desired.is_empty()).then_some(OverlayGeometry {
            anchor: cursor.target,
            columns: cursor.columns,
        });
        Ok(())
    }

    /// Forget an overlay after a terminal reflow makes its old coordinates
    /// unknowable. Emitting no erase is safer than destroying remote cells;
    /// the application's resize redraw remains authoritative.
    pub(crate) fn abandon(&mut self) -> bool {
        let native_cursor_was_hidden = self.software_cursor_underlay.is_some();
        self.displayed.zeroize();
        self.underlay.zeroize();
        self.software_cursor_underlay = None;
        self.geometry = None;
        native_cursor_was_hidden
    }

    fn remote_shares_entire_prefix(&self, remote: &[u8]) -> bool {
        self.dim_predictions
            && !remote.is_empty()
            && !self.displayed.is_empty()
            && remote[..remote.len().min(self.displayed.len())]
                == self.displayed[..remote.len().min(self.displayed.len())]
    }
}

fn common_prefix_len(left: &[u8], right: &[u8]) -> usize {
    left.iter()
        .zip(right)
        .take_while(|(left, right)| left == right)
        .count()
}

pub(crate) fn synchronized_update_frame_end(bytes: &[u8]) -> Option<usize> {
    [
        (CSI_SYNC_START, CSI_SYNC_END),
        (KITTY_SYNC_START, KITTY_SYNC_END),
    ]
    .into_iter()
    .filter_map(|(start_sequence, end_sequence)| {
        let start = bytes
            .windows(start_sequence.len())
            .position(|window| window == start_sequence)?;
        let content_start = start + start_sequence.len();
        bytes[content_start..]
            .windows(end_sequence.len())
            .rposition(|window| window == end_sequence)
            .map(|end| content_start + end)
    })
    .min()
}

fn validate_overlay(desired: &[u8], underlay: &[u8]) -> io::Result<()> {
    if desired.iter().any(|byte| !(0x20..=0x7e).contains(byte)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "speculative overlay contains a non-printable byte",
        ));
    }
    if underlay.len() != desired.len() || underlay.iter().any(|byte| !(0x20..=0x7e).contains(byte))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "speculative overlay underlay must contain one printable ASCII byte per cell",
        ));
    }
    Ok(())
}

fn append_prediction(frame: &mut Vec<u8>, bytes: &[u8], dim: bool) {
    if bytes.is_empty() {
        return;
    }
    if dim {
        frame.extend_from_slice(b"\x1b[2m");
    }
    frame.extend_from_slice(bytes);
    if dim {
        frame.extend_from_slice(b"\x1b[22m");
    }
}

fn append_software_cursor(frame: &mut Vec<u8>, underlay: u8, dim_underlay: bool) {
    if dim_underlay {
        frame.extend_from_slice(b"\x1b[2;7m");
    } else {
        frame.extend_from_slice(b"\x1b[7m");
    }
    frame.push(underlay);
    if dim_underlay {
        frame.extend_from_slice(b"\x1b[22;27m");
    } else {
        frame.extend_from_slice(b"\x1b[27m");
    }
    cursor_left(frame, 1);
}

fn append_wrapped_prediction(
    frame: &mut Vec<u8>,
    geometry: OverlayGeometry,
    bytes: &[u8],
    dim: bool,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let cursor = geometry.cursor_after(offset)?;
        let row_remaining = geometry.columns.saturating_sub(cursor.column);
        let length = row_remaining.min(bytes.len() - offset);
        if length == 0 {
            return Err(io::Error::other("wrapped overlay made no row progress"));
        }
        append_cursor_position(frame, cursor)?;
        append_prediction(frame, &bytes[offset..offset + length], dim);
        offset += length;
    }
    Ok(())
}

fn append_wrapped_software_cursor(
    frame: &mut Vec<u8>,
    geometry: OverlayGeometry,
    offset: usize,
    underlay: u8,
    dim_underlay: bool,
) -> io::Result<()> {
    let cursor = geometry.cursor_after(offset)?;
    append_cursor_position(frame, cursor)?;
    if dim_underlay {
        frame.extend_from_slice(b"\x1b[2;7m");
    } else {
        frame.extend_from_slice(b"\x1b[7m");
    }
    frame.push(underlay);
    if dim_underlay {
        frame.extend_from_slice(b"\x1b[22;27m");
    } else {
        frame.extend_from_slice(b"\x1b[27m");
    }
    // Absolute positioning cancels delayed wrap after painting the final column.
    append_cursor_position(frame, cursor)
}

fn append_cursor_position(frame: &mut Vec<u8>, cursor: CursorLocation) -> io::Result<()> {
    let row = usize::try_from(cursor.line)
        .map_err(|_| io::Error::other("negative compositor cursor row"))?
        .saturating_add(1);
    let column = cursor.column.saturating_add(1);
    frame.extend_from_slice(format!("\x1b[{row};{column}H").as_bytes());
    Ok(())
}

fn append_clear(frame: &mut Vec<u8>, width: usize) {
    cursor_left(frame, width);
    frame.resize(frame.len() + width, b' ');
    cursor_left(frame, width);
}

fn append_restore(frame: &mut Vec<u8>, underlay: &[u8], dim: bool) {
    if underlay.iter().all(|byte| *byte == b' ') {
        append_clear(frame, underlay.len());
        return;
    }

    cursor_left(frame, underlay.len());
    append_prediction(frame, underlay, dim);
    cursor_left(frame, underlay.len());
}

fn cursor_left(frame: &mut Vec<u8>, width: usize) {
    frame.resize(frame.len() + width, b'\x08');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shadow::TerminalSize;
    use alacritty_terminal::event::VoidListener;
    use alacritty_terminal::grid::Dimensions;
    use alacritty_terminal::index::{Column, Line, Point};
    use alacritty_terminal::term::cell::Flags;
    use alacritty_terminal::term::{Config, Term};
    use alacritty_terminal::vte::ansi::Processor;

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

    fn feed_bytewise(
        parser: &mut Processor,
        terminal: &mut Term<VoidListener>,
        bytes: &[u8],
        expected_floor: Option<usize>,
    ) {
        for byte in bytes {
            parser.advance(terminal, std::slice::from_ref(byte));
            if let (Some(floor), Some(visible)) =
                (expected_floor, visible_software_cursor(terminal, 9))
            {
                assert!(
                    visible >= floor,
                    "a byte boundary exposed software cursor column {visible} behind {floor}: {bytes:?}"
                );
            }
        }
    }

    fn visible_software_cursor(terminal: &Term<VoidListener>, line: i32) -> Option<usize> {
        (0..terminal.grid().columns()).find(|column| {
            terminal.grid()[Point::new(Line(line), Column(*column))]
                .flags
                .contains(Flags::INVERSE)
        })
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

    #[test]
    fn append_advances_without_repainting_the_retained_prefix() {
        let mut renderer = OverlayRenderer::default();
        let mut output = Vec::new();

        renderer.replace(&mut output, b"c").unwrap();
        output.clear();
        renderer.replace(&mut output, b"cr").unwrap();
        renderer.replace(&mut output, b"cru").unwrap();

        assert_eq!(output, b"ru");
        assert!(!output.contains(&b'\x08'));
    }

    #[test]
    fn backspace_erases_only_the_removed_suffix() {
        let mut renderer = OverlayRenderer::default();
        let mut output = Vec::new();

        renderer.replace(&mut output, b"crush").unwrap();
        output.clear();
        renderer.replace(&mut output, b"crus").unwrap();

        assert_eq!(output, b"\x08 \x08");
    }

    #[test]
    fn changed_suffix_keeps_its_unchanged_prefix_in_place() {
        let mut renderer = OverlayRenderer::default();
        let mut output = Vec::new();

        renderer.replace(&mut output, b"crisp").unwrap();
        output.clear();
        renderer.replace(&mut output, b"crush").unwrap();

        assert_eq!(output, b"\x08\x08\x08   \x08\x08\x08ush");
    }

    #[test]
    fn fast_overlay_is_visibly_dim_and_restores_intensity() {
        let mut renderer = OverlayRenderer::new(true);
        let mut output = Vec::new();

        renderer.replace(&mut output, b"fast").unwrap();

        assert_eq!(output, b"\x1b[2mfast\x1b[22m");
    }

    #[test]
    fn fast_append_styles_only_the_new_character_without_cursor_rewind() {
        let mut renderer = OverlayRenderer::new(true);
        let mut output = Vec::new();

        renderer.replace(&mut output, b"f").unwrap();
        output.clear();
        renderer.replace(&mut output, b"fa").unwrap();

        assert_eq!(output, b"\x1b[2ma\x1b[22m");
        assert!(!output.contains(&b'\x08'));
    }

    #[test]
    fn fast_software_cursor_moves_as_part_of_the_composed_frame() {
        let mut renderer = OverlayRenderer::new(true);
        let mut output = Vec::new();

        renderer
            .replace_over_with_cursor(&mut output, b"f", b"E", b'x', None)
            .unwrap();
        assert_eq!(
            output,
            b"\x1b[?25l\x1b[2mf\x1b[22m\x1b[2;7mx\x1b[22;27m\x08"
        );
        assert!(
            !output
                .windows(SHOW_CURSOR.len())
                .any(|bytes| bytes == SHOW_CURSOR)
        );

        output.clear();
        renderer
            .replace_over_with_cursor(&mut output, b"fa", b"Ex", b'y', None)
            .unwrap();
        assert_eq!(output, b"\x1b[2ma\x1b[22m\x1b[2;7my\x1b[22;27m\x08");
        assert!(
            !output
                .windows(SHOW_CURSOR.len())
                .any(|bytes| bytes == SHOW_CURSOR)
        );
    }

    #[test]
    fn absolute_fast_append_is_an_atomic_forward_only_cell_diff() {
        let mut renderer = OverlayRenderer::with_reconciliation_sync(true, ReconciliationSync::Csi);
        let geometry = OverlayGeometry {
            anchor: CursorLocation { line: 0, column: 2 },
            columns: 80,
        };
        let mut output = Vec::new();

        renderer
            .replace_over_with_cursor(&mut output, b"f", b"E", b'x', Some(geometry))
            .unwrap();
        output.clear();
        renderer
            .replace_over_with_cursor(&mut output, b"fa", b"Ex", b'y', Some(geometry))
            .unwrap();

        assert_eq!(
            output,
            b"\x1b[?2026h\x1b[?25l\x1b[1;4H\x1b[2ma\x1b[22m\x1b[1;5H\x1b[2;7my\x1b[22;27m\x1b[1;5H\x1b[?2026l"
        );
        assert!(!output.contains(&b'\x08'));
        assert!(!output.contains(&b'f'));
    }

    #[test]
    fn bytewise_terminal_presentation_never_exposes_a_backward_cursor() {
        let size = TerminalSize::new(80, 24);
        let config = Config {
            scrolling_history: 0,
            ..Config::default()
        };
        let mut terminal = Term::new(config, &size, VoidListener);
        let mut parser = Processor::new();
        parser.advance(
            &mut terminal,
            b"\x1b[2J\x1b[10;3H\x1b[2mExplain this codebase\x1b[22m\x1b[10;3H",
        );

        let geometry = OverlayGeometry {
            anchor: CursorLocation { line: 9, column: 2 },
            columns: 80,
        };
        let placeholder = b"Explain this codebase";
        let input = b"crush";
        let mut renderer = OverlayRenderer::with_reconciliation_sync(true, ReconciliationSync::Csi);
        let mut output = Vec::new();
        let mut visible_floor = None;

        for length in 1..=input.len() {
            output.clear();
            renderer
                .replace_over_with_cursor(
                    &mut output,
                    &input[..length],
                    &placeholder[..length],
                    placeholder[length],
                    Some(geometry),
                )
                .unwrap();
            assert!(!output.contains(&b'\x08'));
            feed_bytewise(&mut parser, &mut terminal, &output, visible_floor);
            let expected = geometry.anchor.column + length;
            assert_eq!(visible_software_cursor(&terminal, 9), Some(expected));
            visible_floor = Some(expected);
        }

        output.clear();
        renderer
            .append_remote_composed(
                &mut output,
                b"\x1b[?2026h\x1b[5;1HThinking\x1b[10;3H\x1b[?2026l",
                input,
                &placeholder[..input.len()],
                CursorComposition {
                    target: geometry.anchor,
                    previous_software: Some(CursorLocation { line: 9, column: 7 }),
                    columns: 80,
                    underlay: Some(placeholder[input.len()]),
                    native_visible: true,
                },
            )
            .unwrap();
        feed_bytewise(&mut parser, &mut terminal, &output, visible_floor);
        assert_eq!(visible_software_cursor(&terminal, 9), visible_floor);

        output.clear();
        renderer
            .append_remote_composed(
                &mut output,
                b"\x1b[?2026h\x1b[10;3Hcrush\x1b[10;8H\x1b[?2026l",
                b"",
                b"",
                CursorComposition {
                    target: CursorLocation { line: 9, column: 7 },
                    previous_software: Some(CursorLocation { line: 9, column: 7 }),
                    columns: 80,
                    underlay: Some(placeholder[input.len()]),
                    native_visible: true,
                },
            )
            .unwrap();
        feed_bytewise(&mut parser, &mut terminal, &output, visible_floor);
        assert_eq!(visible_software_cursor(&terminal, 9), None);
        assert_eq!(terminal.grid().cursor.point, Point::new(Line(9), Column(7)));
    }

    #[test]
    fn wrapped_software_cursor_crosses_rows_without_a_visible_rewind() {
        let mut renderer = OverlayRenderer::with_reconciliation_sync(true, ReconciliationSync::Csi);
        let geometry = OverlayGeometry {
            anchor: CursorLocation { line: 0, column: 6 },
            columns: 8,
        };
        let mut output = Vec::new();
        renderer
            .replace_over_with_cursor(&mut output, b"ab", b"  ", b' ', Some(geometry))
            .unwrap();
        assert_eq!(
            output,
            b"\x1b[?2026h\x1b[?25l\x1b[1;7H\x1b[2mab\x1b[22m\x1b[2;1H\x1b[7m \x1b[27m\x1b[2;1H\x1b[?2026l"
        );
        assert!(
            !output.contains(&b'\x08'),
            "row-boundary cursor placement must never depend on backspace"
        );

        output.clear();
        renderer
            .replace_over_with_cursor(&mut output, b"a", b" ", b' ', Some(geometry))
            .unwrap();
        assert!(output.starts_with(b"\x1b[?2026h\x1b[?25l"));
        assert!(output.windows(6).any(|bytes| bytes == b"\x1b[2;1H"));
        assert!(output.ends_with(b"\x1b[?2026l"));
        assert!(renderer.has_displayed_overlay());

        output.clear();
        renderer.append_remote_transition(&mut output, b"a");
        assert!(output.starts_with(b"\x1b[?2026h\x1b[?25l\x1b[1;7Ha"));
        assert!(output.ends_with(b" \x1b[1;8H\x1b[?25h\x1b[?2026l"));
        assert!(!output.contains(&b'\x08'));
        assert!(!renderer.has_displayed_overlay());
    }

    #[test]
    fn synchronized_tui_composition_preserves_the_software_cursor() {
        let mut renderer = OverlayRenderer::new(true);
        let mut output = Vec::new();
        renderer
            .replace_over_with_cursor(&mut output, b"x", b"E", b'y', None)
            .unwrap();

        output.clear();
        renderer
            .append_remote_composed(
                &mut output,
                b"\x1b[?2026h\x1b[5;1HThinking\x1b[10;3H\x1b[?2026l",
                b"x",
                b"E",
                CursorComposition {
                    target: CursorLocation { line: 9, column: 2 },
                    previous_software: Some(CursorLocation { line: 9, column: 3 }),
                    columns: 80,
                    underlay: Some(b'y'),
                    native_visible: true,
                },
            )
            .unwrap();

        assert!(
            output.ends_with(
                b"\x1b[10;3H\x1b[?25l\x1b[10;3H\x1b[2mx\x1b[22m\x1b[10;4H\x1b[2;7my\x1b[22;27m\x1b[10;4H\x1b[?2026l"
            )
        );
        assert!(
            !output
                .windows(SHOW_CURSOR.len())
                .any(|bytes| bytes == SHOW_CURSOR)
        );
    }

    #[test]
    fn synchronized_acknowledgement_hands_back_the_native_cursor_atomically() {
        let mut renderer = OverlayRenderer::new(true);
        let mut output = Vec::new();
        renderer
            .replace_over_with_cursor(&mut output, b"x", b"E", b' ', None)
            .unwrap();

        output.clear();
        renderer
            .append_remote_composed(
                &mut output,
                b"\x1b[?2026h\x1b[10;3Hx\x1b[?2026l",
                b"",
                b"",
                CursorComposition {
                    target: CursorLocation { line: 9, column: 3 },
                    previous_software: Some(CursorLocation { line: 9, column: 3 }),
                    columns: 80,
                    underlay: Some(b' '),
                    native_visible: true,
                },
            )
            .unwrap();

        assert!(output.ends_with(b"\x1b[10;4H \x1b[10;4H\x1b[?25h\x1b[?2026l"));
        assert!(!renderer.has_displayed_overlay());
    }

    #[test]
    fn unsynchronized_tmux_repaint_is_wrapped_around_the_composed_cursor() {
        let mut renderer = OverlayRenderer::with_reconciliation_sync(true, ReconciliationSync::Csi);
        let mut output = Vec::new();
        renderer
            .replace_over_with_cursor(&mut output, b"x", b"E", b'y', None)
            .unwrap();

        output.clear();
        renderer
            .append_remote_composed(
                &mut output,
                b"\x1b[5;1HThinking\x1b[10;3H",
                b"x",
                b"E",
                CursorComposition {
                    target: CursorLocation { line: 9, column: 2 },
                    previous_software: Some(CursorLocation { line: 9, column: 3 }),
                    columns: 80,
                    underlay: Some(b'y'),
                    native_visible: true,
                },
            )
            .unwrap();

        assert!(output.starts_with(b"\x1b[?2026h\x1b[5;1HThinking\x1b[10;3H"));
        assert!(
            output.ends_with(
                b"\x1b[10;3H\x1b[?25l\x1b[10;3H\x1b[2mx\x1b[22m\x1b[10;4H\x1b[2;7my\x1b[22;27m\x1b[10;4H\x1b[?2026l"
            )
        );
    }

    #[test]
    fn clearing_a_software_cursor_restores_native_cursor_visibility() {
        let mut renderer = OverlayRenderer::new(true);
        let mut output = Vec::new();
        renderer
            .replace_over_with_cursor(&mut output, b"x", b"E", b'x', None)
            .unwrap();

        output.clear();
        renderer.clear(&mut output).unwrap();

        assert!(output.ends_with(SHOW_CURSOR));
        assert!(!renderer.has_displayed_overlay());
        assert!(!renderer.abandon());
    }

    #[test]
    fn coding_agent_placeholder_is_restored_when_prediction_is_removed() {
        let mut renderer = OverlayRenderer::new(true);
        let mut output = Vec::new();

        renderer.replace_over(&mut output, b"abc", b"Imp").unwrap();
        assert_eq!(output, b"\x1b[2mabc\x1b[22m");

        output.clear();
        renderer.replace_over(&mut output, b"ab", b"Im").unwrap();
        assert_eq!(output, b"\x08\x1b[2mp\x1b[22m\x08");

        output.clear();
        renderer.clear(&mut output).unwrap();
        assert_eq!(output, b"\x08\x08\x1b[2mIm\x1b[22m\x08\x08");
    }

    #[test]
    fn coding_agent_redraw_replaces_prediction_without_cleanup() {
        let mut renderer = OverlayRenderer::new(true);
        let mut output = Vec::new();

        renderer.replace_over(&mut output, b"x", b"E").unwrap();
        output.clear();
        renderer.append_remote_transition(
            &mut output,
            b"\x1b]0;agent\x07\x1b[?2026h\x1b[10;3Hx\x1b[?2026l",
        );

        assert_eq!(output, b"\x1b]0;agent\x07\x1b[?2026h\x1b[10;3Hx\x1b[?2026l");
        assert!(!output.contains(&b'\x08'));
    }

    #[test]
    fn tmux_kitty_redraw_replaces_prediction_without_cleanup() {
        let mut renderer = OverlayRenderer::new(true);
        let mut output = Vec::new();

        renderer.replace(&mut output, b"x").unwrap();
        output.clear();
        renderer.append_remote_transition(&mut output, b"\x1bP=1s\x1b\\\x1b[10;3Hx\x1bP=2s\x1b\\");

        assert_eq!(output, b"\x1bP=1s\x1b\\\x1b[10;3Hx\x1bP=2s\x1b\\");
        assert!(!output.contains(&b'\x08'));
    }

    #[test]
    fn matching_remote_prefix_overwrites_without_blank_cursor_round_trip() {
        let mut renderer = OverlayRenderer::new(true);
        let mut output = Vec::new();

        renderer.replace(&mut output, b"crush").unwrap();
        output.clear();
        renderer.append_remote_transition(&mut output, b"cr");

        assert_eq!(
            output,
            b"\x1b[?25l\x08\x08\x08\x08\x08cr\x1b[2mush\x1b[22m\x1b[?25h"
        );
        assert_eq!(renderer.displayed(), 3);
        assert!(!output.contains(&b' '));
    }

    #[test]
    fn single_character_echo_hides_the_cursor_until_it_is_settled() {
        let mut renderer = OverlayRenderer::new(true);
        let mut output = Vec::new();

        renderer.replace(&mut output, b"x").unwrap();
        output.clear();
        renderer.append_remote_transition(&mut output, b"x");

        assert_eq!(output, b"\x1b[?25l\x08x\x1b[?25h");
        assert_eq!(renderer.displayed(), 0);
    }

    #[test]
    fn kitty_matching_echo_paints_as_one_synchronized_update() {
        let mut renderer =
            OverlayRenderer::with_reconciliation_sync(true, ReconciliationSync::Kitty);
        let mut output = Vec::new();

        renderer.replace(&mut output, b"x").unwrap();
        output.clear();
        renderer.append_remote_transition(&mut output, b"x");

        assert_eq!(
            output,
            b"\x1bP=1s\x1b\\\x1b[?25l\x08x\x1b[?25h\x1bP=2s\x1b\\"
        );
    }

    #[test]
    fn tmux_matching_echo_uses_standard_synchronized_update_mode() {
        let mut renderer = OverlayRenderer::with_reconciliation_sync(true, ReconciliationSync::Csi);
        let mut output = Vec::new();

        renderer.replace(&mut output, b"x").unwrap();
        output.clear();
        renderer.append_remote_transition(&mut output, b"x");

        assert_eq!(output, b"\x1b[?2026h\x1b[?25l\x08x\x1b[?25h\x1b[?2026l");
    }

    #[test]
    fn matching_complete_echo_flows_directly_into_remote_controls() {
        let mut renderer = OverlayRenderer::new(true);
        let mut output = Vec::new();

        renderer.replace(&mut output, b"go").unwrap();
        output.clear();
        renderer.append_remote_transition(&mut output, b"go\r\nresult");

        assert_eq!(output, b"\x08\x08go\r\nresult");
        assert_eq!(renderer.displayed(), 0);
    }

    #[test]
    fn mismatched_remote_output_erases_before_forwarding() {
        let mut renderer = OverlayRenderer::new(true);
        let mut output = Vec::new();

        renderer.replace(&mut output, b"crush").unwrap();
        output.clear();
        renderer.append_remote_transition(&mut output, b"crisp");

        assert_eq!(
            output,
            b"\x08\x08\x08\x08\x08     \x08\x08\x08\x08\x08crisp"
        );
        assert_eq!(renderer.displayed(), 0);
    }

    #[test]
    fn printable_mismatch_settles_the_software_cursor_atomically() {
        let mut renderer = OverlayRenderer::with_reconciliation_sync(true, ReconciliationSync::Csi);
        let mut output = Vec::new();
        renderer
            .replace_over_with_cursor(&mut output, b"crush", b"     ", b' ', None)
            .unwrap();

        output.clear();
        renderer.append_remote_transition(&mut output, b"crisp");

        assert!(output.starts_with(b"\x1b[?2026h\x1b[?25l"));
        assert!(output.ends_with(b"\x1b[?25hcrisp\x1b[?2026l"));
        assert!(!renderer.has_displayed_overlay());
    }
}
