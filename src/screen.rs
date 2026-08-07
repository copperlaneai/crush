use std::io;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use alacritty_terminal::event::{Event, EventListener, WindowSize};
use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::index::{Column, Line, Point};
use alacritty_terminal::term::cell::{Cell, Flags};
use alacritty_terminal::term::{ClipboardType, Config, Osc52, Term, TermMode};
use alacritty_terminal::vte::ansi::Processor;
use alacritty_terminal::vte::ansi::{Color, NamedColor, Rgb};
use base64::Engine as _;
use zeroize::Zeroize;

const FRAME_MAGIC: &[u8; 4] = b"CRF3";
const FIXED_HEADER_LEN: usize = 50;
const CELL_BYTES: usize = 14;
const MAX_CELLS: usize = 100_000;
const MAX_CLIPBOARD_BYTES: usize = 64 * 1024;
const MAX_FRAME_BYTES: usize =
    FIXED_HEADER_LEN + MAX_CELLS * CELL_BYTES + u16::MAX as usize + MAX_CLIPBOARD_BYTES;
const COLOR_INDEXED: u32 = 1 << 30;
const COLOR_RGB: u32 = 1 << 31;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScreenSize {
    pub(crate) columns: usize,
    pub(crate) lines: usize,
}

impl ScreenSize {
    pub(crate) fn checked(columns: u16, lines: u16) -> io::Result<Self> {
        let size = Self {
            columns: usize::from(columns.max(1)),
            lines: usize::from(lines.max(1)),
        };
        if size.columns.saturating_mul(size.lines) > MAX_CELLS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "terminal dimensions exceed Crush's framebuffer limit",
            ));
        }
        Ok(size)
    }
}

impl Dimensions for ScreenSize {
    fn total_lines(&self) -> usize {
        self.lines
    }

    fn screen_lines(&self) -> usize {
        self.lines
    }

    fn columns(&self) -> usize {
        self.columns
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct WireCell {
    pub(crate) codepoint: u32,
    pub(crate) foreground: u32,
    pub(crate) background: u32,
    pub(crate) flags: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClipboardTarget {
    Clipboard,
    Selection,
}

impl ClipboardTarget {
    fn from_wire(value: u8) -> io::Result<Self> {
        match value {
            1 => Ok(Self::Clipboard),
            2 => Ok(Self::Selection),
            _ => Err(invalid_frame("clipboard target is invalid")),
        }
    }

    fn wire(self) -> u8 {
        match self {
            Self::Clipboard => 1,
            Self::Selection => 2,
        }
    }

    fn osc52(self) -> u8 {
        match self {
            Self::Clipboard => b'c',
            Self::Selection => b'p',
        }
    }
}

impl From<ClipboardType> for ClipboardTarget {
    fn from(value: ClipboardType) -> Self {
        match value {
            ClipboardType::Clipboard => Self::Clipboard,
            ClipboardType::Selection => Self::Selection,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClipboardEvent {
    pub(crate) id: u64,
    pub(crate) target: ClipboardTarget,
    pub(crate) text: String,
}

impl WireCell {
    fn from_cell(cell: &Cell) -> Self {
        Self {
            codepoint: u32::from(cell.c),
            foreground: encode_color(cell.fg),
            background: encode_color(cell.bg),
            flags: cell.flags.bits(),
        }
    }

    fn character(self) -> char {
        char::from_u32(self.codepoint)
            .filter(|character| !character.is_control())
            .unwrap_or(' ')
    }

    fn has(self, flags: Flags) -> bool {
        self.flags & flags.bits() != 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WireFrame {
    pub(crate) columns: u16,
    pub(crate) lines: u16,
    pub(crate) cursor_line: u16,
    pub(crate) cursor_column: u16,
    pub(crate) modes: u32,
    pub(crate) input_ack: u64,
    // Intentionally trails input_ack until its resulting screen is observable.
    pub(crate) echo_ack: u64,
    pub(crate) title: String,
    pub(crate) bell: bool,
    pub(crate) prediction_allowed: bool,
    pub(crate) prediction_stable: bool,
    pub(crate) clipboard: Option<ClipboardEvent>,
    pub(crate) cells: Vec<WireCell>,
}

impl WireFrame {
    pub(crate) fn cell(&self, line: usize, column: usize) -> Option<WireCell> {
        if line >= usize::from(self.lines) || column >= usize::from(self.columns) {
            return None;
        }
        self.cells
            .get(line.saturating_mul(usize::from(self.columns)) + column)
            .copied()
    }

    pub(crate) fn character(&self, line: usize, column: usize) -> Option<char> {
        self.cell(line, column).map(WireCell::character)
    }

    pub(crate) fn cursor_visible(&self) -> bool {
        self.modes & TermMode::SHOW_CURSOR.bits() != 0
    }

    pub(crate) fn encode_compressed(&self) -> io::Result<Vec<u8>> {
        let title = self.title.as_bytes();
        let title_len = u16::try_from(title.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "terminal title is too long")
        })?;
        let (clipboard_id, clipboard_target, clipboard) = match &self.clipboard {
            Some(event) if event.id != 0 && event.text.len() <= MAX_CLIPBOARD_BYTES => {
                (event.id, event.target.wire(), event.text.as_bytes())
            }
            Some(event) if event.id == 0 => {
                return Err(invalid_frame("clipboard event identifier is invalid"));
            }
            Some(_) => return Err(invalid_frame("clipboard payload is too large")),
            None => (0, 0, &[][..]),
        };
        let clipboard_len = u32::try_from(clipboard.len())
            .map_err(|_| invalid_frame("clipboard payload is too large"))?;
        let expected_cells = usize::from(self.columns).saturating_mul(usize::from(self.lines));
        if self.cells.len() != expected_cells || expected_cells > MAX_CELLS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "framebuffer cell count does not match its dimensions",
            ));
        }

        let mut raw = Vec::with_capacity(
            FIXED_HEADER_LEN + title.len() + clipboard.len() + self.cells.len() * CELL_BYTES,
        );
        raw.extend_from_slice(FRAME_MAGIC);
        raw.extend_from_slice(&self.columns.to_be_bytes());
        raw.extend_from_slice(&self.lines.to_be_bytes());
        raw.extend_from_slice(&self.cursor_line.to_be_bytes());
        raw.extend_from_slice(&self.cursor_column.to_be_bytes());
        raw.extend_from_slice(&self.modes.to_be_bytes());
        raw.extend_from_slice(&self.input_ack.to_be_bytes());
        raw.extend_from_slice(&self.echo_ack.to_be_bytes());
        raw.extend_from_slice(&title_len.to_be_bytes());
        raw.push(u8::from(self.bell));
        raw.push(u8::from(self.prediction_allowed));
        raw.extend_from_slice(&clipboard_id.to_be_bytes());
        raw.extend_from_slice(&clipboard_len.to_be_bytes());
        raw.push(clipboard_target);
        raw.push(u8::from(self.prediction_stable));
        raw.extend_from_slice(title);
        raw.extend_from_slice(clipboard);
        for cell in &self.cells {
            raw.extend_from_slice(&cell.codepoint.to_be_bytes());
            raw.extend_from_slice(&cell.foreground.to_be_bytes());
            raw.extend_from_slice(&cell.background.to_be_bytes());
            raw.extend_from_slice(&cell.flags.to_be_bytes());
        }
        Ok(lz4_flex::compress_prepend_size(&raw))
    }

    pub(crate) fn decode_compressed(compressed: &[u8]) -> io::Result<Self> {
        if compressed.len() < 4 {
            return Err(invalid_frame("compressed frame is truncated"));
        }
        let decoded_len = u32::from_le_bytes(
            compressed[..4]
                .try_into()
                .expect("validated compressed size prefix"),
        ) as usize;
        if decoded_len > MAX_FRAME_BYTES {
            return Err(invalid_frame("advertised framebuffer is too large"));
        }
        let raw = lz4_flex::decompress_size_prepended(compressed)
            .map_err(|_| invalid_frame("framebuffer compression is invalid"))?;
        Self::decode(&raw)
    }

    fn decode(raw: &[u8]) -> io::Result<Self> {
        if raw.len() < FIXED_HEADER_LEN || &raw[..4] != FRAME_MAGIC {
            return Err(invalid_frame("framebuffer header is invalid"));
        }
        let columns = read_u16(raw, 4)?;
        let lines = read_u16(raw, 6)?;
        let cursor_line = read_u16(raw, 8)?;
        let cursor_column = read_u16(raw, 10)?;
        let modes = read_u32(raw, 12)?;
        let input_ack = read_u64(raw, 16)?;
        let echo_ack = read_u64(raw, 24)?;
        let title_len = usize::from(read_u16(raw, 32)?);
        let bell = raw[34] != 0;
        let prediction_allowed = raw[35] != 0;
        let clipboard_id = read_u64(raw, 36)?;
        let clipboard_len = usize::try_from(read_u32(raw, 44)?)
            .map_err(|_| invalid_frame("clipboard payload is too large"))?;
        let clipboard_target = raw[48];
        let prediction_stable = raw[49] != 0;
        if clipboard_len > MAX_CLIPBOARD_BYTES {
            return Err(invalid_frame("clipboard payload is too large"));
        }
        let clipboard_metadata_valid = if clipboard_id == 0 {
            clipboard_len == 0 && clipboard_target == 0
        } else {
            matches!(clipboard_target, 1 | 2)
        };
        if !clipboard_metadata_valid {
            return Err(invalid_frame("clipboard metadata is invalid"));
        }
        let cell_count = usize::from(columns).saturating_mul(usize::from(lines));
        if columns == 0 || lines == 0 || cell_count > MAX_CELLS {
            return Err(invalid_frame("framebuffer dimensions are invalid"));
        }
        let title_end = FIXED_HEADER_LEN.saturating_add(title_len);
        let cells_start = title_end.saturating_add(clipboard_len);
        let expected_len = cells_start.saturating_add(cell_count.saturating_mul(CELL_BYTES));
        if raw.len() != expected_len {
            return Err(invalid_frame("framebuffer payload length is invalid"));
        }
        if usize::from(cursor_line) >= usize::from(lines)
            || usize::from(cursor_column) >= usize::from(columns)
        {
            return Err(invalid_frame("framebuffer cursor is outside the screen"));
        }
        let title = String::from_utf8(raw[FIXED_HEADER_LEN..title_end].to_vec())
            .map_err(|_| invalid_frame("terminal title is not UTF-8"))?;
        let clipboard = if clipboard_id == 0 {
            None
        } else {
            Some(ClipboardEvent {
                id: clipboard_id,
                target: ClipboardTarget::from_wire(clipboard_target)?,
                text: String::from_utf8(raw[title_end..cells_start].to_vec())
                    .map_err(|_| invalid_frame("clipboard payload is not UTF-8"))?,
            })
        };
        let mut cells = Vec::with_capacity(cell_count);
        for bytes in raw[cells_start..].chunks_exact(CELL_BYTES) {
            let cell = WireCell {
                codepoint: u32::from_be_bytes(bytes[0..4].try_into().expect("cell width")),
                foreground: u32::from_be_bytes(bytes[4..8].try_into().expect("cell width")),
                background: u32::from_be_bytes(bytes[8..12].try_into().expect("cell width")),
                flags: u16::from_be_bytes(bytes[12..14].try_into().expect("cell width")),
            };
            if char::from_u32(cell.codepoint).is_none() {
                return Err(invalid_frame("framebuffer contains an invalid codepoint"));
            }
            cells.push(cell);
        }
        Ok(Self {
            columns,
            lines,
            cursor_line,
            cursor_column,
            modes,
            input_ack,
            echo_ack,
            title,
            bell,
            prediction_allowed,
            prediction_stable,
            clipboard,
            cells,
        })
    }
}

#[derive(Default)]
struct CapturedEvents {
    pty_writes: Vec<u8>,
    title: String,
    bell: bool,
    clipboard_sequence: u64,
    clipboard: Option<ClipboardEvent>,
}

#[derive(Clone)]
struct ScreenEventProxy {
    events: Arc<Mutex<CapturedEvents>>,
    size: Arc<Mutex<ScreenSize>>,
}

impl EventListener for ScreenEventProxy {
    fn send_event(&self, event: Event) {
        let mut events = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match event {
            Event::PtyWrite(text) => events.pty_writes.extend_from_slice(text.as_bytes()),
            Event::Title(title) => events.title = title,
            Event::ResetTitle => events.title.clear(),
            Event::Bell => events.bell = true,
            Event::ClipboardStore(target, text) if text.len() <= MAX_CLIPBOARD_BYTES => {
                if let Some(id) = events.clipboard_sequence.checked_add(1) {
                    events.clipboard_sequence = id;
                    if let Some(mut previous) = events.clipboard.replace(ClipboardEvent {
                        id,
                        target: target.into(),
                        text,
                    }) {
                        previous.text.zeroize();
                    }
                }
            }
            Event::ClipboardLoad(_, formatter) => {
                events
                    .pty_writes
                    .extend_from_slice(formatter("").as_bytes());
            }
            Event::ColorRequest(index, formatter) => {
                let color = if index == NamedColor::Background as usize {
                    Rgb { r: 0, g: 0, b: 0 }
                } else {
                    Rgb {
                        r: 0xdd,
                        g: 0xdd,
                        b: 0xdd,
                    }
                };
                events
                    .pty_writes
                    .extend_from_slice(formatter(color).as_bytes());
            }
            Event::TextAreaSizeRequest(formatter) => {
                let size = *self
                    .size
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let response = formatter(WindowSize {
                    num_lines: u16::try_from(size.lines).unwrap_or(u16::MAX),
                    num_cols: u16::try_from(size.columns).unwrap_or(u16::MAX),
                    cell_width: 0,
                    cell_height: 0,
                });
                events.pty_writes.extend_from_slice(response.as_bytes());
            }
            _ => {}
        }
    }
}

pub(crate) struct RemoteScreen {
    term: Term<ScreenEventProxy>,
    parser: Processor,
    events: Arc<Mutex<CapturedEvents>>,
    size: Arc<Mutex<ScreenSize>>,
}

impl RemoteScreen {
    pub(crate) fn new(size: ScreenSize) -> Self {
        let events = Arc::new(Mutex::new(CapturedEvents::default()));
        let shared_size = Arc::new(Mutex::new(size));
        let proxy = ScreenEventProxy {
            events: Arc::clone(&events),
            size: Arc::clone(&shared_size),
        };
        let config = Config {
            scrolling_history: 0,
            osc52: Osc52::OnlyCopy,
            ..Config::default()
        };
        Self {
            term: Term::new(config, &size, proxy),
            parser: Processor::new(),
            events,
            size: shared_size,
        }
    }

    pub(crate) fn advance(&mut self, bytes: &[u8]) {
        self.parser.advance(&mut self.term, bytes);
    }

    pub(crate) fn synchronized_update_pending(&self) -> bool {
        self.parser.sync_bytes_count() != 0
    }

    pub(crate) fn finish_expired_synchronized_update(&mut self, now: Instant) -> bool {
        let expired = self
            .parser
            .sync_timeout()
            .sync_timeout()
            .is_some_and(|deadline| deadline <= now);
        if expired {
            self.parser.stop_sync(&mut self.term);
        }
        expired
    }

    pub(crate) fn finish_synchronized_update(&mut self) {
        if self.synchronized_update_pending() {
            self.parser.stop_sync(&mut self.term);
        }
    }

    pub(crate) fn resize(&mut self, size: ScreenSize) {
        self.term.resize(size);
        *self
            .size
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = size;
    }

    pub(crate) fn take_pty_writes(&mut self) -> Vec<u8> {
        std::mem::take(
            &mut self
                .events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pty_writes,
        )
    }

    pub(crate) fn acknowledge_clipboard(&self, id: u64) {
        let mut events = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if events
            .clipboard
            .as_ref()
            .is_some_and(|clipboard| clipboard.id == id)
        {
            if let Some(mut clipboard) = events.clipboard.take() {
                clipboard.text.zeroize();
            }
        }
    }

    pub(crate) fn snapshot(&self, input_ack: u64, echo_ack: u64) -> WireFrame {
        let grid = self.term.grid();
        let columns = grid.columns();
        let lines = grid.screen_lines();
        let mut cells = Vec::with_capacity(columns.saturating_mul(lines));
        for line in 0..lines {
            for column in 0..columns {
                cells.push(WireCell::from_cell(
                    &grid[Point::new(
                        Line(i32::try_from(line).expect("framebuffer line fits i32")),
                        Column(column),
                    )],
                ));
            }
        }
        let cursor = grid.cursor.point;
        let mut events = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        WireFrame {
            columns: u16::try_from(columns).unwrap_or(u16::MAX),
            lines: u16::try_from(lines).unwrap_or(u16::MAX),
            cursor_line: u16::try_from(cursor.line.0.max(0)).unwrap_or(0),
            cursor_column: u16::try_from(cursor.column.0).unwrap_or(0),
            modes: self.term.mode().bits(),
            input_ack,
            echo_ack,
            title: events.title.clone(),
            bell: std::mem::take(&mut events.bell),
            prediction_allowed: self.prediction_allowed(),
            prediction_stable: true,
            clipboard: events.clipboard.clone(),
            cells,
        }
    }

    fn prediction_allowed(&self) -> bool {
        // TUIs disable kernel echo too, so only recognizable secret prompts block prediction.
        let grid = self.term.grid();
        let cursor = grid.cursor.point;
        if cursor.line.0 < 0 {
            return false;
        }
        let mut row = String::with_capacity(cursor.column.0);
        for column in 0..cursor.column.0 {
            let character = grid[Point::new(cursor.line, Column(column))]
                .c
                .to_ascii_lowercase();
            row.push(if character.is_ascii() { character } else { ' ' });
        }
        !["password", "passphrase", "secret", "token", "login:"]
            .iter()
            .any(|needle| row.contains(needle))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OverlayCell {
    pub(crate) line: usize,
    pub(crate) column: usize,
    pub(crate) byte: u8,
}

#[derive(Default)]
pub(crate) struct ScreenRenderer {
    previous: Option<WireFrame>,
    scratch: Option<WireFrame>,
    applied_modes: u32,
    title: String,
    last_clipboard_id: u64,
}

impl ScreenRenderer {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn render(
        &mut self,
        frame: &WireFrame,
        overlay: &[OverlayCell],
        predicted_cursor: Option<(usize, usize)>,
    ) -> io::Result<Vec<u8>> {
        let mut composed = self.scratch.take().unwrap_or_else(|| frame.clone());
        composed.clone_from(frame);
        compose_frame(&mut composed, overlay, predicted_cursor);
        let dimensions_changed = self.previous.as_ref().is_none_or(|previous| {
            previous.columns != composed.columns || previous.lines != composed.lines
        });
        let alternate_changed = self.applied_modes & TermMode::ALT_SCREEN.bits()
            != composed.modes & TermMode::ALT_SCREEN.bits();
        let full = dimensions_changed || alternate_changed;
        let unchanged = !full
            && self.previous.as_ref().is_some_and(|previous| {
                previous.cells == composed.cells
                    && previous.cursor_line == composed.cursor_line
                    && previous.cursor_column == composed.cursor_column
                    && previous.modes == composed.modes
            })
            && composed.title == self.title
            && !composed.bell;
        let clipboard = frame
            .clipboard
            .as_ref()
            .filter(|event| event.id > self.last_clipboard_id);
        if unchanged {
            self.scratch = self.previous.replace(composed);
            let mut output = Vec::new();
            if let Some(event) = clipboard {
                append_clipboard(&mut output, event);
                self.last_clipboard_id = event.id;
            }
            return Ok(output);
        }

        let mut output = Vec::with_capacity(composed.cells.len().saturating_add(512));
        if let Some(event) = clipboard {
            append_clipboard(&mut output, event);
            self.last_clipboard_id = event.id;
        }
        output.extend_from_slice(b"\x1b[?2026h\x1b[?25l");
        append_mode_changes(&mut output, self.applied_modes, composed.modes);
        if full {
            output.extend_from_slice(b"\x1b[0m\x1b[H\x1b[2J");
        }
        if composed.title != self.title {
            output.extend_from_slice(b"\x1b]0;");
            output.extend(
                composed
                    .title
                    .bytes()
                    .filter(|byte| !byte.is_ascii_control()),
            );
            output.push(0x07);
            self.title.clone_from(&composed.title);
        }
        if composed.bell {
            output.push(0x07);
        }

        let columns = usize::from(composed.columns);
        let lines = usize::from(composed.lines);

        for line in 0..lines {
            let row_start = line * columns;
            let mut column = 0;
            while column < columns {
                if !full && !self.cell_changed(&composed, row_start + column) {
                    column += 1;
                    continue;
                }
                let mut start = column;
                if composed.cells[row_start + start].has(Flags::WIDE_CHAR_SPACER) && start != 0 {
                    start -= 1;
                }
                let mut end = column + 1;
                while end < columns && (full || self.cell_changed(&composed, row_start + end)) {
                    end += 1;
                }
                if end < columns && composed.cells[row_start + end - 1].has(Flags::WIDE_CHAR) {
                    end += 1;
                }
                append_cursor(&mut output, line, start)?;
                let mut style = None;
                let mut rendered_wide = false;
                for cell in &composed.cells[row_start + start..row_start + end] {
                    if cell.has(Flags::WIDE_CHAR_SPACER) && rendered_wide {
                        rendered_wide = false;
                        continue;
                    }
                    append_style(&mut output, &mut style, *cell);
                    let character = cell.character();
                    let mut bytes = [0_u8; 4];
                    output.extend_from_slice(character.encode_utf8(&mut bytes).as_bytes());
                    rendered_wide = cell.has(Flags::WIDE_CHAR);
                }
                column = end;
            }
        }

        output.extend_from_slice(b"\x1b[0m");
        append_cursor(
            &mut output,
            usize::from(composed.cursor_line),
            usize::from(composed.cursor_column),
        )?;
        if composed.cursor_visible() || predicted_cursor.is_some() {
            output.extend_from_slice(b"\x1b[?25h");
        }
        output.extend_from_slice(b"\x1b[?2026l");

        self.scratch = self.previous.replace(composed);
        self.applied_modes = frame.modes;
        Ok(output)
    }

    pub(crate) fn invalidate(&mut self) {
        if let Some(previous) = self.previous.take() {
            self.scratch = Some(previous);
        }
    }

    pub(crate) fn restore_bytes() -> &'static [u8] {
        b"\x1b[0m\x1b[?25h\x1b[?1l\x1b[?66l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?1004l\x1b[?1049l\x1b[=0u"
    }

    fn cell_changed(&self, frame: &WireFrame, index: usize) -> bool {
        self.previous
            .as_ref()
            .and_then(|previous| previous.cells.get(index))
            != frame.cells.get(index)
    }
}

fn append_clipboard(output: &mut Vec<u8>, event: &ClipboardEvent) {
    output.extend_from_slice(b"\x1b]52;");
    output.push(event.target.osc52());
    output.push(b';');
    output.extend_from_slice(
        base64::engine::general_purpose::STANDARD
            .encode(event.text.as_bytes())
            .as_bytes(),
    );
    output.push(0x07);
}

fn compose_frame(
    composed: &mut WireFrame,
    overlay: &[OverlayCell],
    predicted_cursor: Option<(usize, usize)>,
) {
    let columns = usize::from(composed.columns);
    let lines = usize::from(composed.lines);
    for predicted in overlay {
        if predicted.line >= lines || predicted.column >= columns {
            continue;
        }
        let cell = &mut composed.cells[predicted.line * columns + predicted.column];
        cell.codepoint = u32::from(predicted.byte);
        let mut flags = Flags::from_bits_retain(cell.flags);
        flags.remove(Flags::WIDE_CHAR | Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER);
        flags.insert(Flags::DIM);
        cell.flags = flags.bits();
    }
    if let Some(cursor) =
        predicted_cursor.filter(|(line, column)| *line < lines && *column < columns)
    {
        composed.cursor_line = u16::try_from(cursor.0).unwrap_or(composed.cursor_line);
        composed.cursor_column = u16::try_from(cursor.1).unwrap_or(composed.cursor_column);
    }
}

fn append_mode_changes(output: &mut Vec<u8>, previous: u32, current: u32) {
    let mappings = [
        (TermMode::APP_CURSOR.bits(), 1),
        (TermMode::APP_KEYPAD.bits(), 66),
        (TermMode::MOUSE_REPORT_CLICK.bits(), 1000),
        (TermMode::MOUSE_DRAG.bits(), 1002),
        (TermMode::MOUSE_MOTION.bits(), 1003),
        (TermMode::FOCUS_IN_OUT.bits(), 1004),
        (TermMode::SGR_MOUSE.bits(), 1006),
        (TermMode::BRACKETED_PASTE.bits(), 2004),
        (TermMode::ALT_SCREEN.bits(), 1049),
    ];
    for (flag, mode) in mappings {
        if previous & flag != current & flag {
            output.extend_from_slice(b"\x1b[?");
            append_decimal(output, mode);
            output.push(if current & flag != 0 { b'h' } else { b'l' });
        }
    }
    let previous_kitty = (previous >> 18) & 0x1f;
    let current_kitty = (current >> 18) & 0x1f;
    if previous_kitty != current_kitty {
        output.extend_from_slice(b"\x1b[=");
        append_decimal(output, current_kitty);
        output.push(b'u');
    }
}

fn append_cursor(output: &mut Vec<u8>, line: usize, column: usize) -> io::Result<()> {
    let line = u16::try_from(line + 1)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "cursor line is too large"))?;
    let column = u16::try_from(column + 1)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "cursor column is too large"))?;
    output.extend_from_slice(b"\x1b[");
    append_decimal(output, u32::from(line));
    output.push(b';');
    append_decimal(output, u32::from(column));
    output.push(b'H');
    Ok(())
}

fn append_decimal(output: &mut Vec<u8>, value: u32) {
    let mut digits = [0_u8; 10];
    let mut cursor = digits.len();
    let mut remaining = value;
    loop {
        cursor -= 1;
        digits[cursor] = b'0' + u8::try_from(remaining % 10).expect("single decimal digit");
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    output.extend_from_slice(&digits[cursor..]);
}

fn append_style(output: &mut Vec<u8>, active: &mut Option<WireCell>, cell: WireCell) {
    if active.is_some_and(|current| {
        current.foreground == cell.foreground
            && current.background == cell.background
            && current.flags == cell.flags
    }) {
        return;
    }
    output.extend_from_slice(b"\x1b[0");
    let flags = Flags::from_bits_retain(cell.flags);
    for (flag, code) in [
        (Flags::BOLD, 1),
        (Flags::DIM, 2),
        (Flags::ITALIC, 3),
        (Flags::UNDERLINE, 4),
        (Flags::INVERSE, 7),
        (Flags::HIDDEN, 8),
        (Flags::STRIKEOUT, 9),
        (Flags::DOUBLE_UNDERLINE, 21),
        (Flags::UNDERCURL, 4),
        (Flags::DOTTED_UNDERLINE, 4),
        (Flags::DASHED_UNDERLINE, 4),
    ] {
        if flags.contains(flag) {
            output.push(b';');
            append_decimal(output, code);
        }
    }
    append_color(output, cell.foreground, true);
    append_color(output, cell.background, false);
    output.push(b'm');
    *active = Some(cell);
}

fn append_color(output: &mut Vec<u8>, color: u32, foreground: bool) {
    output.push(b';');
    if color & COLOR_RGB != 0 {
        append_decimal(output, if foreground { 38 } else { 48 });
        output.extend_from_slice(b";2;");
        append_decimal(output, (color >> 16) & 0xff);
        output.push(b';');
        append_decimal(output, (color >> 8) & 0xff);
        output.push(b';');
        append_decimal(output, color & 0xff);
    } else if color & COLOR_INDEXED != 0 {
        append_decimal(output, if foreground { 38 } else { 48 });
        output.extend_from_slice(b";5;");
        append_decimal(output, color & 0xff);
    } else {
        let named = color & 0x3fff_ffff;
        let code = match named {
            0..=7 => (if foreground { 30 } else { 40 }) + named,
            8..=15 => (if foreground { 90 } else { 100 }) + named - 8,
            value if value == NamedColor::Foreground as u32 && foreground => 39,
            value if value == NamedColor::Background as u32 && !foreground => 49,
            _ => {
                if foreground {
                    39
                } else {
                    49
                }
            }
        };
        append_decimal(output, code);
    }
}

fn encode_color(color: Color) -> u32 {
    match color {
        Color::Named(named) => named as u32,
        Color::Indexed(index) => COLOR_INDEXED | u32::from(index),
        Color::Spec(rgb) => {
            COLOR_RGB | (u32::from(rgb.r) << 16) | (u32::from(rgb.g) << 8) | u32::from(rgb.b)
        }
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> io::Result<u16> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or_else(|| invalid_frame("framebuffer integer is truncated"))
}

fn read_u32(bytes: &[u8], offset: usize) -> io::Result<u32> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| invalid_frame("framebuffer integer is truncated"))
}

fn read_u64(bytes: &[u8], offset: usize) -> io::Result<u64> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or_else(|| invalid_frame("framebuffer integer is truncated"))
}

fn invalid_frame(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain_frame(text: &str, cursor_column: u16) -> WireFrame {
        let columns = 20;
        let mut cells = vec![WireCell::from_cell(&Cell::default()); columns];
        for (index, character) in text.chars().enumerate() {
            cells[index].codepoint = u32::from(character);
        }
        WireFrame {
            columns: u16::try_from(columns).unwrap(),
            lines: 1,
            cursor_line: 0,
            cursor_column,
            modes: (TermMode::SHOW_CURSOR | TermMode::LINE_WRAP).bits(),
            input_ack: 0,
            echo_ack: 0,
            title: String::new(),
            bell: false,
            prediction_allowed: true,
            prediction_stable: true,
            clipboard: None,
            cells,
        }
    }

    #[test]
    fn frame_round_trips_through_bounded_compression() {
        let mut frame = plain_frame("hello", 5);
        frame.clipboard = Some(ClipboardEvent {
            id: 7,
            target: ClipboardTarget::Clipboard,
            text: "copied text".to_owned(),
        });
        frame.prediction_stable = false;
        let encoded = frame.encode_compressed().unwrap();
        assert_eq!(WireFrame::decode_compressed(&encoded).unwrap(), frame);
    }

    #[test]
    fn remote_osc52_write_is_captured_until_its_frame_is_acknowledged() {
        let size = ScreenSize::checked(20, 3).unwrap();
        let mut screen = RemoteScreen::new(size);
        screen.advance(b"\x1b]52;;Zmlyc3Q=\x07");
        let first = screen.snapshot(0, 0).clipboard.unwrap();
        assert_eq!(first.text, "first");
        assert_eq!(first.target, ClipboardTarget::Clipboard);

        screen.advance(b"\x1b]52;p;c2Vjb25k\x07");
        let second = screen.snapshot(0, 0).clipboard.unwrap();
        assert!(second.id > first.id);
        assert_eq!(second.text, "second");
        assert_eq!(second.target, ClipboardTarget::Selection);

        screen.acknowledge_clipboard(first.id);
        assert_eq!(screen.snapshot(0, 0).clipboard.unwrap().id, second.id);
        screen.acknowledge_clipboard(second.id);
        assert!(screen.snapshot(0, 0).clipboard.is_none());
    }

    #[test]
    fn oversized_clipboard_write_is_discarded() {
        let size = ScreenSize::checked(20, 3).unwrap();
        let screen = RemoteScreen::new(size);
        let proxy = ScreenEventProxy {
            events: Arc::clone(&screen.events),
            size: Arc::clone(&screen.size),
        };
        proxy.send_event(Event::ClipboardStore(
            ClipboardType::Clipboard,
            "x".repeat(MAX_CLIPBOARD_BYTES + 1),
        ));
        assert!(screen.snapshot(0, 0).clipboard.is_none());
    }

    #[test]
    fn remote_clipboard_reads_are_disabled() {
        let size = ScreenSize::checked(20, 3).unwrap();
        let mut screen = RemoteScreen::new(size);
        screen.advance(b"\x1b]52;c;?\x07");
        assert!(screen.take_pty_writes().is_empty());
        assert!(screen.snapshot(0, 0).clipboard.is_none());
    }

    #[test]
    fn clipboard_output_is_validated_and_emitted_only_once() {
        let mut frame = plain_frame("prompt", 6);
        frame.clipboard = Some(ClipboardEvent {
            id: 1,
            target: ClipboardTarget::Clipboard,
            text: "copied text".to_owned(),
        });
        let mut renderer = ScreenRenderer::default();
        let first = renderer.render(&frame, &[], None).unwrap();
        assert!(
            first
                .windows(24)
                .any(|bytes| bytes == b"\x1b]52;c;Y29waWVkIHRleHQ=\x07")
        );
        assert!(renderer.render(&frame, &[], None).unwrap().is_empty());

        frame.clipboard = Some(ClipboardEvent {
            id: 2,
            target: ClipboardTarget::Selection,
            text: String::new(),
        });
        assert_eq!(
            renderer.render(&frame, &[], None).unwrap(),
            b"\x1b]52;p;\x07"
        );
    }

    #[test]
    fn malformed_clipboard_metadata_and_payload_are_rejected() {
        let mut frame = plain_frame("hello", 5);
        frame.clipboard = Some(ClipboardEvent {
            id: 1,
            target: ClipboardTarget::Clipboard,
            text: "x".to_owned(),
        });
        let encoded = frame.encode_compressed().unwrap();
        let raw = lz4_flex::decompress_size_prepended(&encoded).unwrap();

        let mut invalid_target = raw.clone();
        invalid_target[48] = 3;
        assert!(WireFrame::decode(&invalid_target).is_err());

        let mut invalid_utf8 = raw;
        invalid_utf8[FIXED_HEADER_LEN] = 0xff;
        assert!(WireFrame::decode(&invalid_utf8).is_err());

        frame.clipboard.as_mut().unwrap().text = "x".repeat(MAX_CLIPBOARD_BYTES + 1);
        assert!(frame.encode_compressed().is_err());
    }

    #[test]
    fn speculative_text_overwrites_one_cell_without_inserting_the_row() {
        let frame = plain_frame("prompt     RP", 6);
        let mut renderer = ScreenRenderer::default();
        let _ = renderer.render(&frame, &[], None).unwrap();
        let paint = renderer
            .render(
                &frame,
                &[OverlayCell {
                    line: 0,
                    column: 6,
                    byte: b'x',
                }],
                Some((0, 7)),
            )
            .unwrap();
        assert!(!paint.windows(3).any(|bytes| bytes == b"\x1b[@"));
        assert!(!paint.windows(4).any(|bytes| bytes == b"\x1b[1@"));
        assert!(paint.windows(6).any(|bytes| bytes == b"\x1b[1;7H"));
        assert_eq!(frame.character(0, 11), Some('R'));
    }

    #[test]
    fn replacing_an_overlay_forces_authoritative_underlay_repaint() {
        let frame = plain_frame("prompt text", 6);
        let mut renderer = ScreenRenderer::default();
        let _ = renderer
            .render(
                &frame,
                &[OverlayCell {
                    line: 0,
                    column: 6,
                    byte: b'x',
                }],
                Some((0, 7)),
            )
            .unwrap();
        let cleanup = renderer.render(&frame, &[], None).unwrap();
        assert!(cleanup.windows(6).any(|bytes| bytes == b"\x1b[1;7H"));
        assert!(cleanup.contains(&b' '));
    }

    #[test]
    fn predicted_cursor_stays_visible_while_remote_cursor_is_hidden() {
        let mut frame = plain_frame("prompt", 6);
        frame.modes &= !TermMode::SHOW_CURSOR.bits();
        let mut renderer = ScreenRenderer::default();
        let paint = renderer
            .render(
                &frame,
                &[OverlayCell {
                    line: 0,
                    column: 6,
                    byte: b'x',
                }],
                Some((0, 7)),
            )
            .unwrap();
        assert!(paint.windows(6).any(|bytes| bytes == b"\x1b[?25h"));
    }

    #[test]
    fn matching_remote_echo_does_not_repaint_a_pending_prediction() {
        let base = plain_frame("prompt", 6);
        let overlay = [OverlayCell {
            line: 0,
            column: 6,
            byte: b'x',
        }];
        let mut renderer = ScreenRenderer::default();
        let _ = renderer.render(&base, &[], None).unwrap();
        let _ = renderer.render(&base, &overlay, Some((0, 7))).unwrap();

        let mut echoed = plain_frame("promptx", 7);
        echoed.input_ack = 1;
        echoed.echo_ack = 0;
        let paint = renderer.render(&echoed, &overlay, Some((0, 7))).unwrap();
        assert!(paint.is_empty());
    }

    #[test]
    fn unrelated_full_screen_change_does_not_touch_prediction_row() {
        let mut base = plain_frame("prompt", 6);
        base.lines = 2;
        base.cells
            .extend(vec![WireCell::from_cell(&Cell::default()); 20]);
        base.cells[20].codepoint = u32::from('A');
        let overlay = [OverlayCell {
            line: 0,
            column: 6,
            byte: b'x',
        }];
        let mut renderer = ScreenRenderer::default();
        let _ = renderer.render(&base, &overlay, Some((0, 7))).unwrap();

        let mut status_update = base.clone();
        status_update.cells[20].codepoint = u32::from('B');
        let paint = renderer
            .render(&status_update, &overlay, Some((0, 7)))
            .unwrap();
        assert!(paint.windows(6).any(|bytes| bytes == b"\x1b[2;1H"));
        assert!(!paint.windows(6).any(|bytes| bytes == b"\x1b[1;7H"));
        assert!(!paint.contains(&b'x'));
    }

    #[test]
    fn raw_full_screen_prompts_allow_prediction_except_for_secrets() {
        let size = ScreenSize::checked(80, 24).unwrap();
        let mut ordinary = RemoteScreen::new(size);
        ordinary.advance(b"\x1b[?1049hCRUSH_TMUX>");
        assert!(ordinary.snapshot(0, 0).prediction_allowed);

        let mut secret = RemoteScreen::new(size);
        secret.advance(b"\x1b[?1049hPassword: ");
        assert!(!secret.snapshot(0, 0).prediction_allowed);
    }

    #[test]
    fn raw_line_editors_are_prediction_eligible_without_alt_screen() {
        let size = ScreenSize::checked(80, 24).unwrap();
        let mut zle = RemoteScreen::new(size);
        zle.advance(b"athan@host ~ > ");
        assert!(zle.snapshot(0, 0).prediction_allowed);
    }

    #[test]
    fn synchronized_tui_update_is_not_visible_before_its_end_marker() {
        let size = ScreenSize::checked(20, 3).unwrap();
        let mut screen = RemoteScreen::new(size);
        screen.advance(b"old");
        let old = screen.snapshot(0, 0);

        screen.advance(b"\x1b[?2026h\x1b[2J\x1b[Hnew\x1b[3;10H");
        assert!(screen.synchronized_update_pending());
        let pending = screen.snapshot(0, 0);
        assert_eq!(pending.cells, old.cells);
        assert_eq!(pending.cursor_line, old.cursor_line);
        assert_eq!(pending.cursor_column, old.cursor_column);

        screen.advance(b"\x1b[?2026l");
        assert!(!screen.synchronized_update_pending());
        let complete = screen.snapshot(0, 0);
        assert_eq!(complete.character(0, 0), Some('n'));
        assert_eq!((complete.cursor_line, complete.cursor_column), (2, 9));
    }
}
