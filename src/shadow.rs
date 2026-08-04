//! Authoritative sidecar terminal model.
//!
//! Remote bytes are always written to the physical terminal independently of
//! this module. A parser failure can therefore only disable prediction.

use alacritty_terminal::event::VoidListener;
use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::index::{Column, Line, Point};
use alacritty_terminal::term::cell::Cell;
use alacritty_terminal::term::{Config, Term, TermMode};
use alacritty_terminal::vte::ansi::Processor;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TerminalSize {
    pub(crate) columns: usize,
    pub(crate) lines: usize,
}

impl TerminalSize {
    pub(crate) fn new(columns: u16, lines: u16) -> Self {
        Self {
            columns: usize::from(columns.max(1)),
            lines: usize::from(lines.max(1)),
        }
    }
}

impl Dimensions for TerminalSize {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CursorSnapshot {
    pub(crate) line: i32,
    pub(crate) column: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OutputObservation {
    pub(crate) before: CursorSnapshot,
    pub(crate) after: CursorSnapshot,
    pub(crate) safe_before: bool,
    pub(crate) safe_after: bool,
    pub(crate) had_control: bool,
}

pub(crate) struct ShadowTerminal {
    term: Term<VoidListener>,
    parser: Processor,
    // `vte::Parser` has an internal partial UTF-8 buffer, but its recovery can
    // dispatch a valid mixed-width stream differently when reads split a
    // codepoint. Feeding it only complete codepoint boundaries avoids making
    // terminal state depend on kernel read boundaries.
    parser_utf8_carry: [u8; 4],
    parser_utf8_carry_len: usize,
    // The VTE backend buffers synchronized-update payloads without updating
    // `Term`. If one contains a control whose delayed-wrap semantics vary
    // between emulators, no cursor comparison is sound when it is released.
    sync_delayed_wrap_uncertain: bool,
    scanner: SafetyScanner,
}

impl ShadowTerminal {
    /// Construct a shadow with no assumptions about inherited emulator state.
    ///
    /// Use this after skipped output, suspend/resume, or any other point where
    /// the physical terminal may have changed without observation.
    pub(crate) fn new(size: TerminalSize) -> Self {
        Self::with_scanner(size, SafetyScanner::new(size.lines))
    }

    /// Construct the initial session shadow at a normal shell/app boundary.
    pub(crate) fn at_application_entry(size: TerminalSize) -> Self {
        Self::with_scanner(size, SafetyScanner::at_application_entry(size.lines))
    }

    fn with_scanner(size: TerminalSize, scanner: SafetyScanner) -> Self {
        let config = Config {
            scrolling_history: 0,
            ..Config::default()
        };
        Self {
            term: Term::new(config, &size, VoidListener),
            parser: Processor::new(),
            parser_utf8_carry: [0; 4],
            parser_utf8_carry_len: 0,
            sync_delayed_wrap_uncertain: false,
            scanner,
        }
    }

    /// Resize the observed emulator without inventing a new application-entry
    /// boundary. Mode/rendition/charset knowledge survives, while coordinates,
    /// cells, scrolling margins, and saved positions become unknown until the
    /// remote application redraws them.
    pub(crate) fn resize(&mut self, size: TerminalSize) {
        let columns_changed = self.term.grid().columns() != size.columns;
        self.term.resize(size);
        self.scanner
            .invalidate_for_resize(size.lines, columns_changed);
    }

    pub(crate) fn cursor(&self) -> CursorSnapshot {
        let point = self.term.grid().cursor.point;
        CursorSnapshot {
            line: point.line.0,
            column: point.column.0,
        }
    }

    pub(crate) fn advance(&mut self, bytes: &[u8]) -> OutputObservation {
        let before = self.cursor();
        let safe_before = self.is_safe();
        let mut had_control = false;
        // Feed controls one byte at a time so a semantic mismatch is noticed
        // before following text in the same kernel read. Raw forwarding is
        // independent of this bounded observer.
        for byte in bytes {
            let synchronized = self.parser.sync_bytes_count() != 0;
            let wrap_pending = self.term.grid().cursor.input_needs_wrap;
            let scan = self.scanner.advance(std::slice::from_ref(byte));
            had_control |= scan.had_control;

            if scan.parser_converged {
                // Bytes observed under VT52/Tek/unknown grammar may have left
                // the ANSI backend parser in any framing state. The grid stays
                // untrusted, but a fresh processor can now recognize the RIS
                // required to converge both physical and shadow state.
                self.parser = Processor::new();
                self.parser_utf8_carry.fill(0);
                self.parser_utf8_carry_len = 0;
                self.sync_delayed_wrap_uncertain = false;
                continue;
            }

            // A later mode reset cannot retroactively validate text, erasure,
            // scrolling, or cursor motion performed while the corresponding
            // physical mode could differ from the backend. Keep that loss of
            // trust sticky until output redraws/reanchors after mode recovery.
            if !self.scanner.modes.geometry_semantics_known() {
                if scan.screen_may_change {
                    self.scanner.invalidate_geometry();
                } else if scan.cursor_may_change {
                    self.scanner.cursor_known = false;
                }
            }
            if !self.scanner.hyperlink_known && scan.screen_may_change {
                // Closing an inherited hyperlink later cannot prove that cells
                // written before the close carry the same metadata as the
                // backend grid.
                self.scanner.screen_known = false;
            }
            if !self.scanner.rendition_coherent && scan.screen_may_change {
                // Printing, scrolling, and line insertion can all create cells
                // using the active rendition. A later SGR reset cannot prove
                // attributes created while backend and emulator could differ.
                self.scanner.screen_known = false;
            }
            if !self.scanner.rendition_known
                && (scan.may_create_erased_rows || (scan.printed && (wrap_pending || synchronized)))
            {
                // Xterm-family terminals and the backend initialize scrolled-in
                // rows differently under a nondefault rendition. Ordinary
                // colored text is coherent, but scrolling under that rendition
                // cannot leave a grid suitable for destructive cleanup.
                self.scanner.screen_known = false;
            }

            if scan.delayed_wrap_semantics_may_differ {
                if synchronized {
                    self.sync_delayed_wrap_uncertain = true;
                } else if wrap_pending {
                    self.scanner.invalidate_geometry();
                }
            }

            // Never rewrite or skip backend operations to mimic a particular
            // emulator. TERM cannot distinguish xterm from every VTE-family
            // implementation that advertises xterm compatibility.
            self.advance_parser(std::slice::from_ref(byte));

            if self.sync_delayed_wrap_uncertain && self.parser.sync_bytes_count() == 0 {
                self.scanner.invalidate_geometry();
                self.sync_delayed_wrap_uncertain = false;
            }
        }
        let after = self.cursor();
        OutputObservation {
            before,
            after,
            safe_before,
            safe_after: self.is_safe(),
            had_control,
        }
    }

    pub(crate) fn is_safe(&self) -> bool {
        self.scanner.model_is_trusted()
            && self.scanner.is_ground()
            && self.parser_utf8_carry_len == 0
            && self.parser.sync_bytes_count() == 0
    }

    fn advance_parser(&mut self, bytes: &[u8]) {
        if self.parser_utf8_carry_len == 0 {
            let carry_len = trailing_incomplete_utf8_len(bytes);
            let parsed_len = bytes.len() - carry_len;
            self.parser.advance(&mut self.term, &bytes[..parsed_len]);
            self.set_parser_utf8_carry(&bytes[parsed_len..]);
            return;
        }

        // UTF-8 codepoints are at most four bytes, so this allocation only
        // occurs after a read actually ends inside one. `Zeroizing` prevents
        // the short-lived copy from lingering in allocator memory.
        let mut combined =
            Zeroizing::new(Vec::with_capacity(self.parser_utf8_carry_len + bytes.len()));
        combined.extend_from_slice(&self.parser_utf8_carry[..self.parser_utf8_carry_len]);
        combined.extend_from_slice(bytes);

        let carry_len = trailing_incomplete_utf8_len(&combined);
        let parsed_len = combined.len() - carry_len;
        self.parser.advance(&mut self.term, &combined[..parsed_len]);
        self.set_parser_utf8_carry(&combined[parsed_len..]);
    }

    fn set_parser_utf8_carry(&mut self, bytes: &[u8]) {
        debug_assert!(bytes.len() < self.parser_utf8_carry.len());
        self.parser_utf8_carry.fill(0);
        self.parser_utf8_carry[..bytes.len()].copy_from_slice(bytes);
        self.parser_utf8_carry_len = bytes.len();
    }

    /// Whether an additive, same-line overlay can be losslessly removed.
    pub(crate) fn can_overlay(&self, width: usize) -> bool {
        if width == 0 || !self.is_safe() {
            return false;
        }

        let grid = self.term.grid();
        let cursor = &grid.cursor;
        let mode = *self.term.mode();
        if cursor.input_needs_wrap
            || mode.contains(TermMode::INSERT)
            || !mode.contains(TermMode::SHOW_CURSOR)
            || cursor.template != Cell::default()
        {
            return false;
        }

        let line = cursor.point.line;
        let start = cursor.point.column.0;
        if line.0 < 0 || start.saturating_add(width) >= grid.columns() {
            return false;
        }

        (start..start + width)
            .all(|column| grid[Point::new(line, Column(column))] == Cell::default())
    }

    /// Count a confirmed linear prefix written at `anchor`.
    pub(crate) fn confirmed_prefix(&self, anchor: CursorSnapshot, pending: &[u8]) -> usize {
        if pending.is_empty() || anchor.line < 0 {
            return 0;
        }
        let grid = self.term.grid();
        if usize::try_from(anchor.line)
            .ok()
            .is_none_or(|line| line >= grid.screen_lines())
        {
            return 0;
        }

        let line = Line(anchor.line);
        pending
            .iter()
            .enumerate()
            .take_while(|(offset, byte)| {
                let column = anchor.column + *offset;
                column < grid.columns()
                    && (byte.is_ascii_graphic() || **byte == b' ')
                    && grid[Point::new(line, Column(column))].c == char::from(**byte)
            })
            .count()
    }
}

/// Return the length of a trailing, structurally valid partial UTF-8 scalar.
///
/// Invalid leading bytes and standalone continuations are deliberately not
/// buffered. They must reach `vte` for its normal replacement/control
/// handling, while the safety scanner independently taints that model epoch.
fn trailing_incomplete_utf8_len(bytes: &[u8]) -> usize {
    let Some(mut start) = bytes.len().checked_sub(1) else {
        return 0;
    };

    while start > 0 && (0x80..=0xbf).contains(&bytes[start]) && bytes.len() - start < 4 {
        start -= 1;
    }

    let suffix = &bytes[start..];
    let (expected_len, next_min, next_max) = match suffix[0] {
        0xc2..=0xdf => (2, 0x80, 0xbf),
        0xe0 => (3, 0xa0, 0xbf),
        0xe1..=0xec | 0xee..=0xef => (3, 0x80, 0xbf),
        0xed => (3, 0x80, 0x9f),
        0xf0 => (4, 0x90, 0xbf),
        0xf1..=0xf3 => (4, 0x80, 0xbf),
        0xf4 => (4, 0x80, 0x8f),
        _ => return 0,
    };

    if suffix.len() >= expected_len {
        return 0;
    }
    if suffix
        .get(1)
        .is_some_and(|byte| !(next_min..=next_max).contains(byte))
    {
        return 0;
    }
    if !suffix
        .get(2..)
        .unwrap_or_default()
        .iter()
        .all(|byte| (0x80..=0xbf).contains(byte))
    {
        return 0;
    }

    suffix.len()
}

#[derive(Clone, Copy, Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
struct ScanResult {
    had_control: bool,
    delayed_wrap_semantics_may_differ: bool,
    cursor_may_change: bool,
    screen_may_change: bool,
    may_create_erased_rows: bool,
    printed: bool,
    parser_converged: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ScanState {
    #[default]
    Ground,
    Escape,
    EscapeIntermediate,
    Csi,
    Osc,
    OscEscape,
    String,
    StringEscape,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ParserMode {
    #[default]
    Unknown,
    Ansi,
}

#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
struct SafetyScanner {
    state: ScanState,
    terminal_lines: usize,
    escape_intermediates: Vec<u8>,
    csi: Vec<u8>,
    string_bytes: usize,
    screen_known: bool,
    cursor_known: bool,
    rendition_known: bool,
    rendition_coherent: bool,
    parser_mode: ParserMode,
    parser_exit_match: usize,
    modes: ModeTrust,
    hyperlink_known: bool,
    hyperlink_active: bool,
    model_tainted: bool,
    saved_cursor_known: bool,
    saved_cursor_rendition_known: bool,
    saved_cursor_rendition_coherent: bool,
    charsets: CharsetTrust,
    saved_cursor_charsets: CharsetTrust,
    saved_primary: Option<ScreenTrust>,
    alternate_state_known: bool,
    in_alternate_screen: bool,
    utf8_continuations: u8,
    utf8_next_min: u8,
    utf8_next_max: u8,
    utf8_may_encode_c1: bool,
    osc_command: Vec<u8>,
    osc_command_complete: bool,
    osc8_uri_separator_seen: bool,
    osc8_uri_nonempty: bool,
}

#[derive(Clone, Copy, Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
struct ScreenTrust {
    screen_known: bool,
    cursor_known: bool,
    rendition_known: bool,
    rendition_coherent: bool,
    saved_cursor_known: bool,
    saved_cursor_rendition_known: bool,
    saved_cursor_rendition_coherent: bool,
    charsets: CharsetTrust,
    saved_cursor_charsets: CharsetTrust,
}

#[derive(Clone, Copy, Debug, Default)]
struct CharsetDesignations {
    g0_ascii: bool,
    g1_ascii: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ActiveCharset {
    #[default]
    Unknown,
    G0,
    G1,
}

#[derive(Clone, Copy, Debug, Default)]
struct CharsetTrust {
    designations: CharsetDesignations,
    active: ActiveCharset,
}

impl CharsetTrust {
    /// Conventional application-entry state assumed by terminal programs.
    ///
    /// POSIX termios cannot report VT character-set state. Tmux itself relies
    /// on the invoking shell having restored GL to ASCII, so Crush uses the
    /// same narrowly scoped precondition without emitting a persistent reset.
    fn application_entry() -> Self {
        Self {
            designations: CharsetDesignations {
                g0_ascii: true,
                g1_ascii: true,
            },
            active: ActiveCharset::G0,
        }
    }

    fn active_is_ascii(self) -> bool {
        match self.active {
            ActiveCharset::Unknown => false,
            ActiveCharset::G0 => self.designations.g0_ascii,
            ActiveCharset::G1 => self.designations.g1_ascii,
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[allow(clippy::struct_excessive_bools)]
struct ModeTrust {
    insert_known: bool,
    newline_known: bool,
    origin_known: bool,
    origin_active: bool,
    wrap_known: bool,
    cursor_visibility_known: bool,
    vertical_margins_known: bool,
    vertical_margins_full: bool,
    horizontal_margins_known: bool,
    tabs_known: bool,
    tabs_backend_default: bool,
    protection_known: bool,
    synchronized_update_known: bool,
    synchronized_update_active: bool,
}

impl Default for ModeTrust {
    fn default() -> Self {
        Self {
            insert_known: false,
            newline_known: false,
            origin_known: false,
            origin_active: false,
            wrap_known: false,
            cursor_visibility_known: false,
            vertical_margins_known: false,
            vertical_margins_full: false,
            horizontal_margins_known: false,
            tabs_known: false,
            // The sidecar starts with default tab stops even though the
            // inherited physical tab stops are unknown.
            tabs_backend_default: true,
            protection_known: false,
            synchronized_update_known: false,
            synchronized_update_active: false,
        }
    }
}

impl ModeTrust {
    /// Backend-default VT modes expected at a normal shell/app boundary.
    ///
    /// These are the same inherited defaults tmux relies upon but does not
    /// explicitly establish. Screen contents, cursor position, and rendition
    /// remain unknown until authoritative remote output proves them.
    fn application_entry() -> Self {
        Self {
            insert_known: true,
            newline_known: true,
            origin_known: true,
            origin_active: false,
            wrap_known: true,
            cursor_visibility_known: true,
            vertical_margins_known: true,
            vertical_margins_full: true,
            horizontal_margins_known: true,
            tabs_known: false,
            tabs_backend_default: true,
            protection_known: true,
            synchronized_update_known: true,
            synchronized_update_active: false,
        }
    }

    fn reset() -> Self {
        Self {
            insert_known: true,
            newline_known: true,
            origin_known: true,
            origin_active: false,
            wrap_known: true,
            cursor_visibility_known: true,
            vertical_margins_known: true,
            vertical_margins_full: true,
            horizontal_margins_known: true,
            tabs_known: true,
            tabs_backend_default: true,
            protection_known: true,
            synchronized_update_known: true,
            synchronized_update_active: false,
        }
    }

    fn all_overlay_relevant_known(self) -> bool {
        self.insert_known
            && self.newline_known
            && self.wrap_known
            && self.cursor_visibility_known
            && self.vertical_margins_known
            && (self.origin_known || self.vertical_margins_full)
            && self.horizontal_margins_known
            && self.protection_known
            && self.synchronized_update_known
            && !self.synchronized_update_active
    }

    /// Modes which can change where ordinary display and cursor operations
    /// land in the backend grid. Presentation-only state and synchronized
    /// update buffering gate overlays separately, but must not make geometry
    /// written inside a synchronized update retroactively unknowable.
    fn geometry_semantics_known(self) -> bool {
        self.insert_known
            && self.newline_known
            && self.wrap_known
            && self.vertical_margins_known
            && (self.origin_known || self.vertical_margins_full)
            && self.horizontal_margins_known
    }
}

impl SafetyScanner {
    fn new(terminal_lines: usize) -> Self {
        Self {
            terminal_lines,
            // Output may have been skipped while an arbitrary terminal grammar
            // or vendor mode was active. Tek and VT52 exits prove ANSI parsing
            // again; only a following RIS clears the rest of the unknown state.
            model_tainted: true,
            ..Self::default()
        }
    }

    fn at_application_entry(terminal_lines: usize) -> Self {
        Self {
            terminal_lines,
            modes: ModeTrust::application_entry(),
            parser_mode: ParserMode::Ansi,
            hyperlink_known: true,
            charsets: CharsetTrust::application_entry(),
            ..Self::default()
        }
    }

    fn invalidate_for_resize(&mut self, terminal_lines: usize, columns_changed: bool) {
        self.terminal_lines = terminal_lines;
        self.screen_known = false;
        self.cursor_known = false;
        self.saved_cursor_known = false;
        self.saved_cursor_rendition_known = false;
        self.saved_cursor_rendition_coherent = false;
        self.saved_cursor_charsets = CharsetTrust::default();
        self.saved_primary = None;
        self.modes.vertical_margins_known = false;
        self.modes.vertical_margins_full = false;
        if columns_changed {
            // Terminals disagree on whether newly exposed columns acquire
            // default tab stops. Treat the next tab motion as unmodelled.
            self.modes.tabs_known = false;
        }
    }

    fn invalidate_geometry(&mut self) {
        self.screen_known = false;
        self.cursor_known = false;
    }

    fn is_ground(&self) -> bool {
        self.state == ScanState::Ground && self.utf8_continuations == 0
    }

    fn model_is_trusted(&self) -> bool {
        self.screen_known
            && self.cursor_known
            && self.rendition_known
            && self.parser_mode == ParserMode::Ansi
            && self.modes.all_overlay_relevant_known()
            && self.hyperlink_known
            && !self.hyperlink_active
            && self.charsets.active_is_ascii()
            && !self.model_tainted
    }

    #[allow(clippy::too_many_lines)]
    fn advance(&mut self, bytes: &[u8]) -> ScanResult {
        let mut result = ScanResult::default();
        for &byte in bytes {
            if self.parser_mode != ParserMode::Ansi {
                result.had_control = true;
                result.parser_converged |= self.advance_parser_convergence(byte);
                continue;
            }
            if matches!(
                self.state,
                ScanState::Ground
                    | ScanState::Escape
                    | ScanState::EscapeIntermediate
                    | ScanState::Csi
            ) {
                match byte {
                    0x08 | 0x09 | 0x0d => result.cursor_may_change = true,
                    0x0a..=0x0c => {
                        result.cursor_may_change = true;
                        result.screen_may_change = true;
                        result.may_create_erased_rows = true;
                    }
                    _ => {}
                }
            }
            if matches!(byte, 0x09..=0x0c) {
                // These C0 controls execute even inside an escape sequence.
                // Their delayed-wrap behavior differs across terminal families.
                result.delayed_wrap_semantics_may_differ = true;
            }
            if matches!(byte, 0x18 | 0x1a) {
                // Xterm can render CAN/SUB as an error glyph while the backend
                // treats them as no-ops, including when they cancel a control
                // sequence. Geometry is recoverably unknown afterwards.
                self.screen_known = false;
                self.cursor_known = false;
            }
            if self.state == ScanState::Ground && self.consume_utf8_continuation(byte, &mut result)
            {
                continue;
            }

            match self.state {
                ScanState::Ground => match byte {
                    0x1b => {
                        self.escape_intermediates.clear();
                        self.state = ScanState::Escape;
                        result.had_control = true;
                    }
                    0x0e => {
                        self.charsets.active = ActiveCharset::G1;
                        result.had_control = true;
                    }
                    0x0f => {
                        self.charsets.active = ActiveCharset::G0;
                        result.had_control = true;
                    }
                    0x09 => {
                        if !self.modes.tabs_known {
                            self.screen_known = false;
                            self.cursor_known = false;
                        }
                        result.had_control = true;
                    }
                    0x0a..=0x0c => {
                        result.had_control = true;
                    }
                    0x00..=0x1f | 0x7f => result.had_control = true,
                    0x20..=0x7e => {
                        result.cursor_may_change = true;
                        result.screen_may_change = true;
                        result.printed = true;
                    }
                    0x90 | 0x98 | 0x9e | 0x9f => {
                        result.had_control = true;
                        self.model_tainted = true;
                        self.begin_string(ScanState::String);
                    }
                    0x9b => {
                        result.had_control = true;
                        self.model_tainted = true;
                        self.csi.clear();
                        self.state = ScanState::Csi;
                    }
                    0x9d => {
                        result.had_control = true;
                        self.model_tainted = true;
                        self.begin_string(ScanState::Osc);
                    }
                    0x80..=0x9f => {
                        result.had_control = true;
                        self.model_tainted = true;
                    }
                    0xa0..=0xbf | 0xc0..=0xc1 | 0xf5..=0xff => self.model_tainted = true,
                    0xc2..=0xdf => {
                        self.invalidate_non_ascii_output();
                        self.begin_utf8(1, 0x80, 0xbf, byte == 0xc2);
                    }
                    0xe0 => {
                        self.invalidate_non_ascii_output();
                        self.begin_utf8(2, 0xa0, 0xbf, false);
                    }
                    0xe1..=0xec | 0xee..=0xef => {
                        self.invalidate_non_ascii_output();
                        self.begin_utf8(2, 0x80, 0xbf, false);
                    }
                    0xed => {
                        self.invalidate_non_ascii_output();
                        self.begin_utf8(2, 0x80, 0x9f, false);
                    }
                    0xf0 => {
                        self.invalidate_non_ascii_output();
                        self.begin_utf8(3, 0x90, 0xbf, false);
                    }
                    0xf1..=0xf3 => {
                        self.invalidate_non_ascii_output();
                        self.begin_utf8(3, 0x80, 0xbf, false);
                    }
                    0xf4 => {
                        self.invalidate_non_ascii_output();
                        self.begin_utf8(3, 0x80, 0x8f, false);
                    }
                },
                ScanState::Escape => {
                    result.had_control = true;
                    match byte {
                        b'[' => {
                            self.csi.clear();
                            self.state = ScanState::Csi;
                        }
                        b']' => self.begin_string(ScanState::Osc),
                        b'P' | b'_' | b'^' | b'X' => {
                            // DCS, APC, PM, and SOS can carry terminal-specific
                            // protocols (including graphics and tmux
                            // passthrough) which the shadow cannot model.
                            self.model_tainted = true;
                            self.begin_string(ScanState::String);
                        }
                        b'c' => {
                            self.reset_trust();
                            self.state = ScanState::Ground;
                        }
                        0x20..=0x2f => {
                            self.escape_intermediates.push(byte);
                            self.state = ScanState::EscapeIntermediate;
                        }
                        0x18 | 0x1a => {
                            self.escape_intermediates.clear();
                            self.state = ScanState::Ground;
                        }
                        0x30..=0x7e => {
                            if matches!(byte, b'D' | b'E' | b'M') {
                                result.cursor_may_change = true;
                                result.screen_may_change = true;
                                result.may_create_erased_rows = true;
                            }
                            if matches!(byte, b'D' | b'M') {
                                result.delayed_wrap_semantics_may_differ = true;
                            }
                            if byte == b'8' {
                                result.cursor_may_change = true;
                            }
                            self.finish_escape(byte);
                        }
                        0x1b => self.escape_intermediates.clear(),
                        0x09 => self.invalidate_unknown_tab_motion(),
                        0x0e => self.charsets.active = ActiveCharset::G1,
                        0x0f => self.charsets.active = ActiveCharset::G0,
                        0x00..=0x17 | 0x19 | 0x1c..=0x1f | 0x7f => {}
                        _ => {
                            self.model_tainted = true;
                            self.escape_intermediates.clear();
                            self.state = ScanState::Ground;
                        }
                    }
                }
                ScanState::EscapeIntermediate => {
                    result.had_control = true;
                    match byte {
                        0x30..=0x7e => {
                            if self.escape_intermediates.is_empty() && matches!(byte, b'D' | b'M') {
                                result.delayed_wrap_semantics_may_differ = true;
                            }
                            self.finish_escape(byte);
                        }
                        0x18 | 0x1a => {
                            self.escape_intermediates.clear();
                            self.state = ScanState::Ground;
                        }
                        0x1b => {
                            self.escape_intermediates.clear();
                            self.state = ScanState::Escape;
                        }
                        0x20..=0x2f if self.escape_intermediates.len() < 2 => {
                            self.escape_intermediates.push(byte);
                        }
                        0x09 => self.invalidate_unknown_tab_motion(),
                        0x0e => self.charsets.active = ActiveCharset::G1,
                        0x0f => self.charsets.active = ActiveCharset::G0,
                        0x00..=0x17 | 0x19 | 0x1c..=0x1f | 0x7f => {}
                        _ => {
                            self.model_tainted = true;
                            self.escape_intermediates.clear();
                            self.state = ScanState::Ground;
                        }
                    }
                }
                ScanState::Csi => {
                    result.had_control = true;
                    if byte == 0x1b {
                        self.csi.clear();
                        self.state = ScanState::Escape;
                    } else if matches!(byte, 0x18 | 0x1a) {
                        self.csi.clear();
                        self.state = ScanState::Ground;
                    } else if byte == 0x09 {
                        self.invalidate_unknown_tab_motion();
                    } else if byte == 0x0e {
                        self.charsets.active = ActiveCharset::G1;
                    } else if byte == 0x0f {
                        self.charsets.active = ActiveCharset::G0;
                    } else if matches!(byte, 0x00..=0x1f | 0x7f) {
                        // Executed/ignored in place by the VTE state machine;
                        // these bytes are not part of the CSI parameter text.
                    } else if (0x40..=0x7e).contains(&byte) {
                        if byte == b'l' && private_mode_list_contains(&self.csi, 2) {
                            // DECANM is optional: the physical terminal may
                            // enter VT52 or remain ANSI. Do not guess which.
                            self.parser_mode = ParserMode::Unknown;
                            self.parser_exit_match = 0;
                        } else if byte == b'h' && private_mode_list_contains(&self.csi, 38) {
                            // Tektronix emulation is also optional, so the
                            // physical parser may switch or ignore the request.
                            self.parser_mode = ParserMode::Unknown;
                            self.parser_exit_match = 0;
                        }
                        if supported_csi(&self.csi, byte) {
                            if matches!(
                                byte,
                                b'@' | b'J' | b'K' | b'L' | b'M' | b'P' | b'S' | b'T' | b'X'
                            ) {
                                result.cursor_may_change = true;
                                result.screen_may_change = true;
                                if matches!(byte, b'S' | b'T') {
                                    result.may_create_erased_rows = true;
                                }
                            } else if matches!(
                                byte,
                                b'A' | b'B'
                                    | b'C'
                                    | b'D'
                                    | b'E'
                                    | b'F'
                                    | b'G'
                                    | b'H'
                                    | b'I'
                                    | b'Z'
                                    | b'`'
                                    | b'a'
                                    | b'd'
                                    | b'e'
                                    | b'f'
                                    | b'r'
                                    | b'u'
                            ) {
                                result.cursor_may_change = true;
                            }
                            if matches!(byte, b'H' | b'f') {
                                self.cursor_known = true;
                            }
                            if byte == b'J' {
                                // DEC erase operations cancel delayed wrap,
                                // while the backend can retain it. ED2 still
                                // proves every cell blank only if the active
                                // erase rendition was already synchronized.
                                // A later SGR reset cannot retroactively prove
                                // the attributes of cells erased before it.
                                self.screen_known = self.csi == b"2"
                                    && self.rendition_known
                                    && self.modes.protection_known;
                                self.cursor_known = false;
                            } else if byte == b'K'
                                || matches!(byte, b'@' | b'L' | b'M' | b'P' | b'X')
                            {
                                // The backend differs from xterm/DEC for
                                // delayed-wrap cancellation, and oversized DCH
                                // can clear cells left of the cursor. Treat the
                                // resulting grid as recoverably unknown until a
                                // complete redraw instead of trusting it.
                                self.screen_known = false;
                                self.cursor_known = false;
                            } else if matches!(byte, b'A' | b'B' | b'e' | b'E' | b'F')
                                && !self.modes.vertical_margins_full
                            {
                                // DEC relative vertical movement is bounded by
                                // active scrolling margins; the backend crosses
                                // them. A later complete redraw can recover.
                                self.screen_known = false;
                                self.cursor_known = false;
                            } else if matches!(byte, b'G' | b'`') && self.modes.origin_active {
                                // The backend applies the origin offset twice
                                // for horizontal absolute motion under DECOM.
                                self.screen_known = false;
                                self.cursor_known = false;
                            } else if byte == b'm' && is_plain_csi_parameter_list(&self.csi) {
                                let trust = advance_sgr_trust(
                                    &self.csi,
                                    self.rendition_known,
                                    self.rendition_coherent,
                                );
                                self.rendition_known = trust.is_default;
                                self.rendition_coherent = trust.is_coherent;
                            } else if matches!(byte, b'h' | b'l') {
                                self.apply_mode_change(byte == b'h');
                            } else if byte == b'r' {
                                let top = simple_parameter_or(&self.csi, 0, 1);
                                let screen_bottom =
                                    u16::try_from(self.terminal_lines).unwrap_or(u16::MAX);
                                let bottom = simple_parameter_or(&self.csi, 1, screen_bottom);
                                let valid = top.zip(bottom).is_some_and(|(top, bottom)| {
                                    top >= 1 && top < bottom && bottom <= screen_bottom
                                });
                                if valid {
                                    self.cursor_known = true;
                                    self.modes.vertical_margins_known = true;
                                    self.modes.vertical_margins_full =
                                        top == Some(1) && bottom == Some(screen_bottom);
                                } else {
                                    self.cursor_known = false;
                                    self.modes.vertical_margins_known = false;
                                    self.modes.vertical_margins_full = false;
                                    self.model_tainted = true;
                                }
                            } else if byte == b'W' {
                                if self.modes.tabs_backend_default {
                                    self.modes.tabs_known = true;
                                } else {
                                    self.model_tainted = true;
                                }
                            } else if byte == b'g' {
                                self.modes.tabs_backend_default = false;
                            } else if matches!(byte, b'I' | b'Z') && !self.modes.tabs_known {
                                // CHT/CBT use terminal tab stops just like HT.
                                // With inherited stops, Alacritty's default
                                // stops can move to a different cell; any text
                                // that follows would then corrupt screen trust.
                                self.screen_known = false;
                                self.cursor_known = false;
                            } else if byte == b'q' && self.csi == b"0\"" {
                                self.modes.protection_known = true;
                            } else if byte == b's' {
                                self.save_cursor_trust();
                            } else if byte == b'u' && is_plain_csi_parameter_list(&self.csi) {
                                self.restore_cursor_trust();
                            }
                        } else {
                            // Unknown CSI controls can alter physical state the
                            // Alacritty sidecar does not model (DECSCA/DECSTR,
                            // margins, protected cells, and vendor protocols).
                            self.model_tainted = true;
                        }
                        self.csi.clear();
                        self.state = ScanState::Ground;
                    } else if self.csi.len() < 64 {
                        self.csi.push(byte);
                    } else {
                        self.model_tainted = true;
                    }
                }
                ScanState::Osc => {
                    result.had_control = true;
                    self.string_bytes += 1;
                    if byte == 0x07 {
                        self.finish_string(true);
                    } else if byte == 0x1b {
                        // Xterm dispatches OSC only after the complete ST
                        // terminator. The backend dispatches at bare ESC, so
                        // defer trust until the following byte proves `ESC \\`.
                        self.state = ScanState::OscEscape;
                    } else if byte == 0x9c {
                        // VTE 0.15 appends raw C1 ST to OSC instead of ending
                        // it. Keep the scanner non-ground and permanently
                        // distrust this epoch rather than desynchronizing.
                        self.model_tainted = true;
                    } else if matches!(byte, 0x18 | 0x1a) {
                        // Backend and xterm cancellation/dispatch behavior
                        // differs here, including possible SUB error glyphs.
                        self.model_tainted = true;
                        self.state = ScanState::Ground;
                    } else if !self.osc_command_complete {
                        if byte == b';' {
                            self.osc_command_complete = true;
                        } else if byte.is_ascii_digit() && self.osc_command.len() < 8 {
                            self.osc_command.push(byte);
                        } else {
                            self.model_tainted = true;
                            self.osc_command_complete = true;
                        }
                    } else if self.osc_command == b"8"
                        && byte == b';'
                        && !self.osc8_uri_separator_seen
                    {
                        self.osc8_uri_separator_seen = true;
                    } else if self.osc_command == b"8" && self.osc8_uri_separator_seen {
                        self.osc8_uri_nonempty = true;
                    }
                }
                ScanState::OscEscape => {
                    result.had_control = true;
                    if byte == b'\\' {
                        self.finish_string(true);
                    } else {
                        // Xterm aborts the OSC while the backend may already
                        // have dispatched it. Preserve no trust across the
                        // ambiguous malformed terminator.
                        self.model_tainted = true;
                        self.state = ScanState::Ground;
                    }
                }
                ScanState::String => {
                    result.had_control = true;
                    self.string_bytes += 1;
                    if byte == 0x1b {
                        self.state = ScanState::StringEscape;
                    } else if matches!(byte, 0x18 | 0x1a | 0x9c) {
                        self.finish_string(false);
                    }
                }
                ScanState::StringEscape => {
                    result.had_control = true;
                    if matches!(byte, b'\\' | 0x18 | 0x1a | 0x9c) {
                        self.finish_string(false);
                    } else if byte != 0x1b {
                        self.state = ScanState::String;
                    }
                }
            }

            if self.string_bytes > 64 * 1024 {
                self.model_tainted = true;
            }
        }
        result
    }

    fn advance_parser_convergence(&mut self, byte: u8) -> bool {
        // These exit sequences are deliberately matched while treating every
        // other byte as opaque. Parsing foreign terminal grammars as ANSI is
        // exactly the ambiguity this state is meant to contain.
        if self.parser_mode == ParserMode::Ansi {
            return false;
        }
        let target = b"\x1b\x03\x1b<";

        if byte == target[self.parser_exit_match] {
            self.parser_exit_match += 1;
        } else {
            self.parser_exit_match = usize::from(byte == target[0]);
        }

        if self.parser_exit_match != target.len() {
            return false;
        }

        self.parser_mode = ParserMode::Ansi;
        self.parser_exit_match = 0;
        self.state = ScanState::Ground;
        self.escape_intermediates.clear();
        self.csi.clear();
        self.string_bytes = 0;
        self.utf8_continuations = 0;
        self.utf8_next_min = 0;
        self.utf8_next_max = 0;
        self.utf8_may_encode_c1 = false;
        self.osc_command.clear();
        self.osc_command_complete = false;
        self.osc8_uri_separator_seen = false;
        self.osc8_uri_nonempty = false;
        true
    }

    fn reset_trust(&mut self) {
        if self.parser_mode != ParserMode::Ansi {
            self.invalidate_geometry();
            self.model_tainted = true;
            return;
        }
        self.screen_known = true;
        self.cursor_known = true;
        self.rendition_known = true;
        self.rendition_coherent = true;
        self.parser_mode = ParserMode::Ansi;
        self.parser_exit_match = 0;
        self.modes = ModeTrust::reset();
        self.hyperlink_known = true;
        self.hyperlink_active = false;
        self.model_tainted = false;
        self.saved_cursor_known = true;
        self.saved_cursor_rendition_known = true;
        self.saved_cursor_rendition_coherent = true;
        self.charsets = CharsetTrust {
            designations: CharsetDesignations {
                g0_ascii: true,
                g1_ascii: true,
            },
            active: ActiveCharset::G0,
        };
        self.saved_cursor_charsets = self.charsets;
        self.saved_primary = None;
        self.alternate_state_known = true;
        self.in_alternate_screen = false;
        self.escape_intermediates.clear();
    }

    fn invalidate_unknown_tab_motion(&mut self) {
        if !self.modes.tabs_known {
            self.screen_known = false;
            self.cursor_known = false;
        }
    }

    fn invalidate_non_ascii_output(&mut self) {
        // Unicode width, grapheme clustering, emoji presentation, and
        // ambiguous-width policy vary across physical terminal emulators.
        // Alacritty's cursor/grid result therefore cannot prove which cells
        // are blank after arbitrary non-ASCII output.
        self.screen_known = false;
        self.cursor_known = false;
    }

    fn finish_escape(&mut self, byte: u8) {
        let known = matches!(
            (self.escape_intermediates.as_slice(), byte),
            (
                [],
                b'<' | b'D' | b'E' | b'H' | b'M' | b'Z' | b'=' | b'>' | b'\\'
            ) | ([b'(' | b')' | b'*' | b'+'], b'B' | b'0')
                | ([b'#'], b'8')
        );

        match (self.escape_intermediates.as_slice(), byte) {
            ([], b'<') => {}
            ([], b'7') => self.save_cursor_trust(),
            ([], b'8') => self.restore_cursor_trust(),
            ([], b'H') => self.modes.tabs_backend_default = false,
            ([b'#'], b'8') => {
                // DECALN homes the physical cursor, resets margins, and resets
                // line attributes. The backend only fills cells with `E`.
                self.screen_known = false;
                self.cursor_known = false;
                self.modes.vertical_margins_known = false;
                self.modes.vertical_margins_full = false;
            }
            ([b'('], b'B' | b'0') => {
                self.charsets.designations.g0_ascii = byte == b'B';
            }
            ([b')'], b'B' | b'0') => {
                self.charsets.designations.g1_ascii = byte == b'B';
            }
            _ if !known => self.model_tainted = true,
            _ => {}
        }

        self.escape_intermediates.clear();
        self.state = ScanState::Ground;
    }

    fn save_cursor_trust(&mut self) {
        self.saved_cursor_known = self.cursor_known;
        self.saved_cursor_rendition_known = self.rendition_known;
        self.saved_cursor_rendition_coherent = self.rendition_coherent;
        self.saved_cursor_charsets = self.charsets;
    }

    fn restore_cursor_trust(&mut self) {
        self.cursor_known = self.saved_cursor_known;
        self.rendition_known = self.saved_cursor_rendition_known;
        self.rendition_coherent = self.saved_cursor_rendition_coherent;
        // DEC cursor restore includes the invoked character set, while the
        // Alacritty backend restores only cursor-held designations. If GL was
        // changed after the save, their models cannot be reconciled safely.
        if self.charsets.active != self.saved_cursor_charsets.active {
            self.model_tainted = true;
        }
        self.charsets = self.saved_cursor_charsets;
        // DEC restore also restores origin and autowrap modes, while
        // `alacritty_terminal` restores only its grid cursor. Their mode state
        // can therefore diverge even though position/rendition agree. Require
        // an explicit mode synchronization (or full-height margins for origin)
        // before overlays resume.
        self.modes.origin_known = false;
        self.modes.wrap_known = false;
        // OSC 8 save/restore behavior is not portable across DEC/SCO terminal
        // families, so an explicit close is required after any restore.
        self.hyperlink_known = false;
        self.hyperlink_active = false;
    }

    fn apply_mode_change(&mut self, set: bool) {
        if self.csi == b"?69" && !set {
            // DECLRMM is not modeled by Alacritty, but resetting it converges
            // the physical terminal with the backend's no-margin default.
            self.modes.horizontal_margins_known = true;
            return;
        }
        if !supported_mode_list(&self.csi) {
            self.model_tainted = true;
            return;
        }

        let (private, parameters) = self
            .csi
            .strip_prefix(b"?")
            .map_or((false, self.csi.as_slice()), |parameters| {
                (true, parameters)
            });
        for parameter in parameters.split(|byte| *byte == b';') {
            let Some(mode) = std::str::from_utf8(parameter)
                .ok()
                .and_then(|parameter| parameter.parse::<u16>().ok())
            else {
                continue;
            };
            match (private, mode) {
                (false, 4) => self.modes.insert_known = true,
                (false, 20) if set => {
                    // alacritty_terminal records LNM but does not apply its
                    // CR-on-LF receive semantics. A later reset plus complete
                    // redraw can recover the shadow, so invalidate geometry.
                    self.screen_known = false;
                    self.cursor_known = false;
                    self.modes.newline_known = false;
                }
                (false, 20) => self.modes.newline_known = true,
                (true, 6) => {
                    self.modes.origin_known = true;
                    self.modes.origin_active = set;
                    if !set {
                        // DECRST DECOM homes the physical cursor, while the
                        // backend only clears its mode bit.
                        self.cursor_known = false;
                    }
                }
                (true, 7) => self.modes.wrap_known = true,
                (true, 25) => self.modes.cursor_visibility_known = true,
                (true, 2026) => {
                    self.modes.synchronized_update_known = true;
                    self.modes.synchronized_update_active = set;
                }
                _ => {}
            }
        }

        if private_mode_list_contains(&self.csi, 1049) {
            self.apply_alternate_screen_change(set);
        }
    }

    fn apply_alternate_screen_change(&mut self, set: bool) {
        if set {
            if self.alternate_state_known && self.in_alternate_screen {
                return;
            }

            self.saved_primary = self.alternate_state_known.then_some(ScreenTrust {
                screen_known: self.screen_known,
                cursor_known: self.cursor_known,
                rendition_known: self.rendition_known,
                rendition_coherent: self.rendition_coherent,
                // Alacritty's 1049 implementation overwrites the primary
                // saved cursor with the cursor current at entry.
                saved_cursor_known: self.cursor_known,
                saved_cursor_rendition_known: self.rendition_known,
                saved_cursor_rendition_coherent: self.rendition_coherent,
                charsets: self.charsets,
                saved_cursor_charsets: self.charsets,
            });
            self.alternate_state_known = true;
            self.in_alternate_screen = true;
            // If Crush inherited an already-active alternate screen, DECSET
            // 1049 is a physical no-op while Alacritty swaps to a fresh grid.
            // Require the application's following ED2/full redraw.
            self.screen_known = false;
            self.saved_cursor_known = false;
            self.saved_cursor_rendition_known = false;
            self.saved_cursor_rendition_coherent = false;
            self.saved_cursor_charsets = CharsetTrust::default();
            return;
        }

        if self.alternate_state_known && !self.in_alternate_screen {
            return;
        } else if let Some(primary) = self.saved_primary.take() {
            self.screen_known = primary.screen_known;
            self.cursor_known = primary.cursor_known;
            self.rendition_known = primary.rendition_known;
            self.rendition_coherent = primary.rendition_coherent;
            self.saved_cursor_known = primary.saved_cursor_known;
            self.saved_cursor_rendition_known = primary.saved_cursor_rendition_known;
            self.saved_cursor_rendition_coherent = primary.saved_cursor_rendition_coherent;
            if self.charsets.active != primary.charsets.active {
                self.model_tainted = true;
            }
            self.charsets = primary.charsets;
            self.saved_cursor_charsets = primary.saved_cursor_charsets;
            // DEC 1049 restore semantics cover state (for example origin/wrap
            // and character protection) which Alacritty does not save with
            // its alternate grid. Require a new explicit synchronization
            // before predicting on the restored primary screen.
            self.modes = ModeTrust::default();
            self.hyperlink_known = false;
            self.hyperlink_active = false;
        } else {
            // A restore without a corresponding transition can expose terminal
            // state inherited before Crush started observing the stream.
            self.screen_known = false;
            self.cursor_known = false;
            self.rendition_known = false;
            self.rendition_coherent = false;
            self.saved_cursor_known = false;
            self.saved_cursor_rendition_known = false;
            self.saved_cursor_rendition_coherent = false;
            self.charsets = CharsetTrust::default();
            self.saved_cursor_charsets = CharsetTrust::default();
            self.modes = ModeTrust::default();
            self.hyperlink_known = false;
            self.hyperlink_active = false;
        }
        self.alternate_state_known = true;
        self.in_alternate_screen = false;
    }

    /// Consume a continuation byte, returning whether this byte was consumed.
    ///
    /// The first continuation has tighter bounds for codepoints which could be
    /// overlong, surrogate codepoints, or above U+10FFFF. Invalid input taints
    /// the current model epoch and is then reprocessed as a standalone byte.
    fn consume_utf8_continuation(&mut self, byte: u8, result: &mut ScanResult) -> bool {
        if self.utf8_continuations == 0 {
            return false;
        }

        if !(self.utf8_next_min..=self.utf8_next_max).contains(&byte) {
            self.model_tainted = true;
            self.utf8_continuations = 0;
            self.utf8_may_encode_c1 = false;
            return false;
        }

        // UTF-8 encoded C1 codepoints are executed by vte rather than printed.
        // Treat them like opaque controls since this scanner intentionally does
        // not model their terminal-specific semantics.
        if self.utf8_may_encode_c1 && byte <= 0x9f {
            result.had_control = true;
            self.model_tainted = true;
        }

        self.utf8_continuations -= 1;
        self.utf8_next_min = 0x80;
        self.utf8_next_max = 0xbf;
        self.utf8_may_encode_c1 = false;
        true
    }

    fn begin_utf8(&mut self, continuations: u8, next_min: u8, next_max: u8, may_encode_c1: bool) {
        self.utf8_continuations = continuations;
        self.utf8_next_min = next_min;
        self.utf8_next_max = next_max;
        self.utf8_may_encode_c1 = may_encode_c1;
    }

    fn begin_string(&mut self, state: ScanState) {
        self.state = state;
        self.string_bytes = 0;
        self.osc_command.clear();
        self.osc_command_complete = false;
        self.osc8_uri_separator_seen = false;
        self.osc8_uri_nonempty = false;
    }

    fn finish_string(&mut self, validate_osc: bool) {
        if validate_osc && !known_nondisplay_osc(&self.osc_command) {
            self.model_tainted = true;
        }
        if validate_osc && self.osc_command == b"8" && self.osc8_uri_separator_seen {
            // Any well-framed OSC 8 operation establishes the hyperlink state
            // in both the physical terminal and Alacritty's cursor template.
            self.hyperlink_known = true;
            self.hyperlink_active = self.osc8_uri_nonempty;
        }
        self.state = ScanState::Ground;
        self.string_bytes = 0;
        self.osc_command.clear();
        self.osc_command_complete = false;
        self.osc8_uri_separator_seen = false;
        self.osc8_uri_nonempty = false;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RenditionTrust {
    is_default: bool,
    is_coherent: bool,
}

/// Advance rendition trust through the portable SGR subset modeled identically
/// by the physical terminal families Crush supports and `alacritty_terminal`.
/// Unknown attributes lose coherence until a later in-sequence full reset.
fn advance_sgr_trust(parameters: &[u8], is_default: bool, is_coherent: bool) -> RenditionTrust {
    if parameters.contains(&b':') {
        return RenditionTrust {
            is_default: false,
            is_coherent: false,
        };
    }

    let mut parsed = Vec::new();
    if parameters.is_empty() {
        parsed.push(0);
    } else {
        for parameter in parameters.split(|byte| *byte == b';') {
            let value = if parameter.is_empty() {
                0
            } else if let Ok(text) = std::str::from_utf8(parameter) {
                if let Ok(value) = text.parse::<u16>() {
                    value
                } else {
                    return RenditionTrust {
                        is_default: false,
                        is_coherent: false,
                    };
                }
            } else {
                return RenditionTrust {
                    is_default: false,
                    is_coherent: false,
                };
            };
            parsed.push(value);
        }
    }

    let mut trust = RenditionTrust {
        is_default,
        is_coherent,
    };
    let mut index = 0;
    while index < parsed.len() {
        let parameter = parsed[index];
        match parameter {
            0 => {
                trust.is_default = true;
                trust.is_coherent = true;
            }
            1 | 2 | 3 | 4 | 7 | 8 | 9 | 30..=37 | 40..=47 | 90..=97 | 100..=107 => {
                trust.is_default = false;
            }
            22 | 23 | 24 | 27 | 28 | 29 | 39 | 49 => {
                // We intentionally do not infer the default rendition from a
                // partial reset because other attributes may still be active.
            }
            38 | 48 => {
                let Some(kind) = parsed.get(index + 1).copied() else {
                    return RenditionTrust {
                        is_default: false,
                        is_coherent: false,
                    };
                };
                let component_count = match kind {
                    5 if parsed.get(index + 2).is_some_and(|value| *value <= 255) => 3,
                    2 if parsed
                        .get(index + 2..index + 5)
                        .is_some_and(|rgb| rgb.iter().all(|value| *value <= 255)) =>
                    {
                        5
                    }
                    _ => {
                        return RenditionTrust {
                            is_default: false,
                            is_coherent: false,
                        };
                    }
                };
                trust.is_default = false;
                index += component_count;
                continue;
            }
            _ => {
                trust.is_default = false;
                trust.is_coherent = false;
            }
        }
        index += 1;
    }
    trust
}

fn is_plain_csi_parameter_list(parameters: &[u8]) -> bool {
    parameters
        .iter()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b';' | b':'))
}

#[derive(Clone, Copy, Debug)]
struct CsiParts<'a> {
    leader: Option<u8>,
    parameters: &'a [u8],
    intermediates: &'a [u8],
}

fn split_csi(raw: &[u8]) -> Option<CsiParts<'_>> {
    let (leader, raw) = match raw.split_first() {
        Some((leader @ (b'?' | b'>' | b'=' | b'<'), raw)) => (Some(*leader), raw),
        _ => (None, raw),
    };
    let intermediate_start = raw
        .iter()
        .position(|byte| (0x20..=0x2f).contains(byte))
        .unwrap_or(raw.len());
    let (parameters, intermediates) = raw.split_at(intermediate_start);

    if !is_plain_csi_parameter_list(parameters)
        || intermediates.len() > 2
        || !intermediates
            .iter()
            .all(|byte| (0x20..=0x2f).contains(byte))
    {
        return None;
    }

    Some(CsiParts {
        leader,
        parameters,
        intermediates,
    })
}

#[allow(clippy::too_many_lines)]
fn supported_csi(raw: &[u8], final_byte: u8) -> bool {
    let Some(parts) = split_csi(raw) else {
        return false;
    };
    let plain = parts.leader.is_none() && parts.intermediates.is_empty();

    match final_byte {
        b'@' | b'A' | b'B' | b'e' | b'C' | b'a' | b'D' | b'd' | b'E' | b'F' | b'G' | b'`'
        | b'I' | b'L' | b'M' | b'P' | b'S' | b'T' | b'X' | b'Z' => {
            plain && simple_parameter_count(parts.parameters).is_some_and(|count| count <= 1)
        }
        b'H' | b'f' | b'r' => {
            plain && simple_parameter_count(parts.parameters).is_some_and(|count| count <= 2)
        }
        b'c' => {
            parts.intermediates.is_empty()
                && matches!(parts.leader, None | Some(b'>'))
                && simple_parameter_count(parts.parameters).is_some_and(|count| count <= 1)
                && simple_parameter_or(parts.parameters, 0, 0) == Some(0)
        }
        b'W' => {
            parts.leader == Some(b'?')
                && parts.intermediates.is_empty()
                && simple_parameter_or(parts.parameters, 0, 0) == Some(5)
                && simple_parameter_count(parts.parameters) == Some(1)
        }
        b'g' => {
            plain
                && simple_parameter_count(parts.parameters).is_some_and(|count| count <= 1)
                && simple_parameter_or(parts.parameters, 0, 0)
                    .is_some_and(|mode| matches!(mode, 0 | 3))
        }
        b'h' | b'l' => {
            parts.intermediates.is_empty()
                && (supported_mode_list(raw) || (final_byte == b'l' && raw == b"?69"))
        }
        b'J' => {
            plain
                && simple_parameter_count(parts.parameters).is_some_and(|count| count <= 1)
                && simple_parameter_or(parts.parameters, 0, 0)
                    .is_some_and(|mode| matches!(mode, 0..=3))
        }
        b'K' => {
            plain
                && simple_parameter_count(parts.parameters).is_some_and(|count| count <= 1)
                && simple_parameter_or(parts.parameters, 0, 0)
                    .is_some_and(|mode| matches!(mode, 0..=2))
        }
        b'm' => supported_sgr_or_key_mode(parts),
        b'n' => {
            (plain && simple_parameter_count(parts.parameters).is_some_and(|count| count <= 1))
                || (parts.leader == Some(b'?')
                    && parts.intermediates.is_empty()
                    && simple_parameter_count(parts.parameters) == Some(1)
                    && simple_parameter_or(parts.parameters, 0, 0) == Some(996))
        }
        b'p' => {
            parts.intermediates == b"$"
                && matches!(parts.leader, None | Some(b'?'))
                && simple_parameter_count(parts.parameters).is_some_and(|count| count <= 1)
        }
        b'q' => {
            (parts.leader.is_none()
                && parts.intermediates == b" "
                && simple_parameter_count(parts.parameters).is_some_and(|count| count <= 1)
                && simple_parameter_or(parts.parameters, 0, 0)
                    .is_some_and(|style| style <= 6))
                // XT version query used during tmux capability negotiation.
                || (parts.leader == Some(b'>')
                    && parts.intermediates.is_empty()
                    && simple_parameter_count(parts.parameters).is_some_and(|count| count <= 1)
                    && simple_parameter_or(parts.parameters, 0, 0) == Some(0))
                // DECSCA reset converges protected-cell state with the
                // Alacritty backend, which has no protected-cell support.
                || (parts.leader.is_none()
                    && parts.intermediates == b"\""
                    && simple_parameter_count(parts.parameters) == Some(1)
                    && simple_parameter_or(parts.parameters, 0, 0) == Some(0))
        }
        // CSI s intentionally falls through: it varies between position-only
        // SCO semantics and DEC-style cursor-state semantics, while a
        // parameterized form can also be DECSLRM.
        b't' => plain && supported_window_operation(parts.parameters),
        b'u' => supported_keyboard_mode(parts),
        _ => false,
    }
}

fn supported_sgr_or_key_mode(parts: CsiParts<'_>) -> bool {
    match (parts.leader, parts.intermediates) {
        (None, []) => is_plain_csi_parameter_list(parts.parameters),
        (Some(b'>'), []) => {
            simple_parameter_count(parts.parameters).is_some_and(|count| count <= 2)
                && simple_parameter_or(parts.parameters, 0, 1) == Some(4)
                && simple_parameter_or(parts.parameters, 1, 0).is_some_and(|mode| mode <= 2)
        }
        (Some(b'?'), []) => {
            simple_parameter_count(parts.parameters) == Some(1)
                && simple_parameter_or(parts.parameters, 0, 0) == Some(4)
        }
        _ => false,
    }
}

fn supported_window_operation(parameters: &[u8]) -> bool {
    let Some(count) = simple_parameter_count(parameters) else {
        return false;
    };
    match simple_parameter_or(parameters, 0, 1) {
        Some(14 | 18) => count == 1,
        Some(22 | 23) => (1..=3).contains(&count),
        _ => false,
    }
}

fn supported_keyboard_mode(parts: CsiParts<'_>) -> bool {
    if !parts.intermediates.is_empty() {
        return false;
    }

    match parts.leader {
        Some(b'?') => simple_parameter_count(parts.parameters).is_some_and(|count| count <= 1),
        Some(b'=') => simple_parameter_count(parts.parameters).is_some_and(|count| count <= 2),
        Some(b'>' | b'<') => {
            simple_parameter_count(parts.parameters).is_some_and(|count| count <= 1)
        }
        _ => false,
    }
}

fn simple_parameter_count(parameters: &[u8]) -> Option<usize> {
    if parameters.is_empty() {
        return Some(0);
    }
    if parameters.contains(&b':') {
        return None;
    }

    let mut count = 0;
    for parameter in parameters.split(|byte| *byte == b';') {
        if !parameter.is_empty() && std::str::from_utf8(parameter).ok()?.parse::<u16>().is_err() {
            return None;
        }
        count += 1;
    }
    Some(count)
}

fn simple_parameter_or(parameters: &[u8], index: usize, default: u16) -> Option<u16> {
    let count = simple_parameter_count(parameters)?;
    if index >= count {
        return Some(default);
    }

    let parameter = parameters.split(|byte| *byte == b';').nth(index)?;
    if parameter.is_empty() {
        Some(default)
    } else {
        std::str::from_utf8(parameter).ok()?.parse().ok()
    }
}

fn supported_mode_list(parameters: &[u8]) -> bool {
    if let Some(private) = parameters.strip_prefix(b"?") {
        return numeric_parameters_all(private, supported_private_mode);
    }

    numeric_parameters_all(parameters, |mode| matches!(mode, 4 | 20))
}

fn supported_private_mode(mode: u16) -> bool {
    matches!(
        mode,
        1 | 6
            | 7
            | 12
            | 25
            | 1000
            | 1002
            | 1003
            | 1004
            | 1005
            | 1006
            | 1007
            | 1042
            | 1049
            | 2004
            | 2026
            // Tmux 3.6 enables this terminal theme-reporting mode. It changes
            // only whether the terminal reports theme updates and has no
            // display state for the shadow to model.
            | 2031
    )
}

fn private_mode_list_contains(parameters: &[u8], needle: u16) -> bool {
    parameters
        .strip_prefix(b"?")
        .is_some_and(|parameters| numeric_parameters_any(parameters, |mode| mode == needle))
}

fn numeric_parameters_all(parameters: &[u8], predicate: impl Fn(u16) -> bool) -> bool {
    !parameters.is_empty()
        && parameters.split(|byte| *byte == b';').all(|parameter| {
            !parameter.is_empty()
                && std::str::from_utf8(parameter)
                    .ok()
                    .and_then(|parameter| parameter.parse::<u16>().ok())
                    .is_some_and(&predicate)
        })
}

fn numeric_parameters_any(parameters: &[u8], predicate: impl Fn(u16) -> bool) -> bool {
    parameters.split(|byte| *byte == b';').any(|parameter| {
        std::str::from_utf8(parameter)
            .ok()
            .and_then(|parameter| parameter.parse::<u16>().ok())
            .is_some_and(&predicate)
    })
}

fn known_nondisplay_osc(command: &[u8]) -> bool {
    let Ok(command) = std::str::from_utf8(command) else {
        return false;
    };
    let Ok(command) = command.parse::<u16>() else {
        return false;
    };
    matches!(
        command,
        0..=2 | 4 | 7..=19 | 22 | 52 | 104 | 110..=119 | 133 | 777
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn strings_and_csi_are_chunk_boundary_safe() {
        let data = b"\x1b\x03\x1b<\x1bc\x1b]8;;https://example.test\x1b\\x\x1b]8;;\x1b\\";
        for split in 0..=data.len() {
            let mut shadow = ShadowTerminal::new(TerminalSize::new(80, 24));
            shadow.advance(&data[..split]);
            shadow.advance(&data[split..]);
            assert!(shadow.is_safe(), "split {split}");
        }
    }

    #[test]
    fn synchronized_updates_do_not_expose_intermediate_state() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(80, 24));
        shadow.advance(b"\x1b\x03\x1b<\x1bc");
        shadow.advance(b"\x1b[?2026hpartial");
        assert!(!shadow.is_safe());
        shadow.advance(b" update\x1b[?2026l");
        assert!(shadow.is_safe());
    }

    #[test]
    fn synchronized_delayed_wrap_mismatch_fails_closed_after_release() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(10, 3));
        shadow.advance(b"\x1b\x03\x1b<\x1bc\x1b[?2026h1234567890\t\x1b[?2026l");
        assert!(
            !shadow.is_safe(),
            "stale pre-buffer cursor state cannot validate delayed wrap"
        );
        shadow.advance(b"\x1b[0m\x1b[2J\x1b[H");
        assert!(shadow.is_safe(), "a later complete redraw can recover");
    }

    #[test]
    fn one_column_terminal_never_accepts_an_overlay() {
        let mut shadow = ShadowTerminal::at_application_entry(TerminalSize::new(1, 2));
        shadow.advance(b"\x1b[m\x1b[2J\x1b[H");
        assert!(shadow.is_safe());
        assert!(!shadow.can_overlay(1));
    }

    #[test]
    fn mid_session_reset_and_resize_do_not_invent_entry_state() {
        let size = TerminalSize::new(80, 24);
        let mut unknown = ShadowTerminal::new(size);
        unknown.advance(b"\x1b[m\x1b[2J\x1b[H\x1b[1;24r");
        assert!(!unknown.is_safe());

        let mut resized = ShadowTerminal::at_application_entry(size);
        resized.advance(b"\x1b[m\x1b[2J\x1b[H");
        assert!(resized.is_safe());
        resized.resize(TerminalSize::new(100, 30));
        assert!(!resized.is_safe());
        resized.advance(b"\x1b[1;30r\x1b[2J\x1b[H");
        assert!(
            resized.is_safe(),
            "observed non-geometric state survives resize"
        );
    }

    #[test]
    fn column_resize_invalidates_observed_tab_stops() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(10, 3));
        shadow.advance(b"\x1b\x03\x1b<\x1bc\x1b[3g");
        shadow.resize(TerminalSize::new(20, 3));
        shadow.advance(b"\x1b[1;3r\x1b[0m\x1b[2J\x1b[H");
        assert!(shadow.is_safe(), "tab knowledge is lazy until tab motion");

        shadow.advance(b"\t");
        assert!(
            !shadow.is_safe(),
            "new columns acquire terminal-dependent tab stops"
        );
    }

    #[test]
    fn overlay_requires_known_blank_cells_and_room_to_avoid_wrap() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(10, 2));
        shadow.advance(b"\x1b\x03\x1b<\x1bcprompt");
        assert!(shadow.can_overlay(3));
        assert!(!shadow.can_overlay(5));
    }

    #[test]
    fn preexisting_physical_screen_is_unknown_until_cleared_and_anchored() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(10, 2));
        shadow.advance(b"\r\nprompt");
        assert!(!shadow.can_overlay(1));
        shadow.advance(b"\x1b[2J");
        assert!(!shadow.can_overlay(1));
        shadow.advance(b"\x1b[Hprompt");
        assert!(!shadow.can_overlay(1), "inherited rendition is unknown");
        shadow.advance(b"\x1b\x03\x1b<\x1bcprompt");
        assert!(shadow.can_overlay(1));
    }

    #[test]
    fn inherited_rendition_requires_an_explicit_full_reset() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(20, 2));
        shadow.advance(b"\x1b\x03\x1b<");

        // The sidecar starts with a default cursor template, but the physical
        // terminal could have bold, reverse video, or a nondefault background
        // inherited from its previous application.
        shadow.advance(b"\x1b[2J\x1b[Hprompt");
        assert!(!shadow.scanner.rendition_known);
        assert!(!shadow.is_safe());
        assert!(!shadow.can_overlay(1));

        shadow.advance(b"\x1b[0m");
        assert!(shadow.scanner.rendition_known);
        assert!(!shadow.is_safe(), "inherited terminal modes remain unknown");

        let mut app_entry = ShadowTerminal::at_application_entry(TerminalSize::new(20, 2));
        app_entry.advance(b"\x1b[2J\x1b[0m\x1b[H");
        assert!(
            !app_entry.is_safe(),
            "a rendition reset cannot prove attributes erased earlier"
        );
        app_entry.advance(b"\x1b[2J\x1b[Hprompt");
        assert!(
            app_entry.can_overlay(1),
            "a rendition-first full erase proves blank-cell attributes"
        );

        shadow.advance(b"\x1b\x03\x1b<\x1bc");
        assert!(shadow.can_overlay(1));
    }

    #[test]
    fn reset_cannot_reclassify_cells_written_under_unknown_rendition() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(20, 2));
        shadow.advance(b"\x1b\x03\x1b<\x1bc\x1b[51m \x1b[0m\x1b[H");
        assert!(shadow.scanner.rendition_known);
        assert!(
            !shadow.is_safe(),
            "unsupported framing made the physical cell attributes unknowable"
        );

        shadow.advance(b"\x1b[2J\x1b[H");
        assert!(shadow.is_safe(), "a later default-rendition erase recovers");
    }

    #[test]
    fn portable_colored_prompts_preserve_screen_coherence() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(20, 2));
        shadow.advance(b"\x1b\x03\x1b<\x1bc\x1b[31;1mprompt\x1b[0m\x1b[2;1H");

        assert!(shadow.scanner.rendition_known);
        assert!(shadow.scanner.rendition_coherent);
        assert!(shadow.is_safe());
        assert!(shadow.can_overlay(1));

        let mut truecolor = ShadowTerminal::new(TerminalSize::new(20, 2));
        truecolor.advance(b"\x1b\x03\x1b<\x1bc\x1b[38;2;12;34;56mtext\x1b[0m\x1b[2;1H");
        assert!(truecolor.can_overlay(1));
    }

    #[test]
    fn scrolling_under_nondefault_rendition_revokes_screen_trust() {
        for scroll in [
            b"\x1b[1S".as_slice(),
            b"\x1b[1T",
            b"\n",
            b"\x1bD",
            b"\x1bE",
            b"\x1bM",
        ] {
            let mut shadow = ShadowTerminal::new(TerminalSize::new(10, 2));
            shadow.advance(b"\x1b\x03\x1b<\x1bc\x1b[31m");
            shadow.advance(scroll);
            shadow.advance(b"\x1b[0m\x1b[2;1H");
            assert!(!shadow.is_safe(), "scroll sequence {scroll:?}");

            shadow.advance(b"\x1b[2J\x1b[H");
            assert!(shadow.is_safe(), "a default-rendition erase recovers");
        }

        let mut wrapped = ShadowTerminal::new(TerminalSize::new(10, 2));
        wrapped.advance(b"\x1b\x03\x1b<\x1bc\x1b[31m12345678901234567890X\x1b[0m\x1b[2;1H");
        assert!(
            !wrapped.is_safe(),
            "a pending-wrap print can scroll in rendition-dependent cells"
        );

        let mut synchronized = ShadowTerminal::new(TerminalSize::new(10, 2));
        synchronized.advance(
            b"\x1b\x03\x1b<\x1bc\x1b[?2026h\x1b[31m123456789012345678901\
              \x1b[0m\x1b[2;1H\x1b[?2026l",
        );
        assert!(
            !synchronized.is_safe(),
            "buffered output hides the backend's intermediate wrap state"
        );
    }

    #[test]
    fn writes_while_hyperlink_state_is_unknown_stay_unknown_after_close() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(20, 2));
        shadow.advance(b"\x1b\x03\x1b<\x1bc\x1b7\x1b8\x1b[?6l\x1b[?7h\x1b[H");
        assert!(!shadow.scanner.hyperlink_known);
        assert!(shadow.scanner.screen_known);

        shadow.advance(b" \x1b]8;;\x1b\\\x1b[H");
        assert!(shadow.scanner.hyperlink_known);
        assert!(!shadow.is_safe());

        shadow.advance(b"\x1b[2J\x1b[H");
        assert!(shadow.is_safe(), "a known-state erase recovers safely");
    }

    #[test]
    fn alternate_screen_restores_primary_screen_knowledge() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(20, 2));
        shadow.advance(b"\x1b\x03\x1b<\x1bcprimary");
        assert!(shadow.can_overlay(1));
        shadow.advance(b"\x1b[?1049h\x1b[2J\x1b[Halternate");
        assert!(shadow.can_overlay(1));
        shadow.advance(b"\x1b(0\x1b[1m");
        assert!(!shadow.is_safe());
        shadow.advance(b"\x1b[?1049l");
        assert!(shadow.scanner.rendition_known);
        assert!(shadow.scanner.charsets.designations.g0_ascii);
        assert!(!shadow.is_safe(), "1049 mode restore is not fully modeled");

        let mut unknown_primary_rendition = ShadowTerminal::new(TerminalSize::new(20, 2));
        unknown_primary_rendition
            .advance(b"\x1b\x03\x1b<\x1bc\x1b[1m\x1b[?1049h\x1b[2J\x1b[H\x1b[m");
        assert!(
            unknown_primary_rendition.scanner.rendition_known,
            "alternate rendition was explicitly reset"
        );
        unknown_primary_rendition.advance(b"\x1b[?1049l");
        assert!(
            !unknown_primary_rendition.scanner.rendition_known,
            "alternate reset must not leak into primary rendition trust"
        );
    }

    #[test]
    fn alternate_screen_inherits_cursor_position_trust() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(20, 2));
        shadow.advance(b"\x1b\x03\x1b<\x1bc");
        shadow.scanner.cursor_known = false;
        shadow.advance(b"\x1b[?1049h\x1b[2J");
        assert!(
            !shadow.is_safe(),
            "1049 copies rather than initializes the primary cursor"
        );
        shadow.advance(b"\x1b[H");
        assert!(shadow.is_safe());
    }

    #[test]
    fn confirms_ascii_at_a_recorded_anchor() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(20, 2));
        shadow.advance(b"\x1b\x03\x1b<\x1bc$ ");
        let anchor = shadow.cursor();
        shadow.advance(b"abc");
        assert_eq!(shadow.confirmed_prefix(anchor, b"abcd"), 3);
    }

    #[test]
    fn overlay_refuses_to_clobber_active_rendition() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(20, 2));
        shadow.advance(b"\x1b\x03\x1b<\x1bc\x1b[1m");
        assert!(!shadow.can_overlay(1));
        shadow.advance(b"\x1b[0m");
        assert!(shadow.can_overlay(1));
    }

    #[test]
    fn escape_intermediates_are_chunk_boundary_safe() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(20, 2));
        shadow.advance(b"\x1b\x03\x1b<\x1bc\x1b(");
        assert!(!shadow.is_safe());
        shadow.advance(b"B");
        assert!(shadow.is_safe());
    }

    #[test]
    fn unsupported_escape_intermediates_taint_the_model() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(20, 2));
        shadow.advance(b"\x1b\x03\x1b<\x1bc\x1b(B");
        assert!(
            shadow.is_safe(),
            "tmux's ASCII charset selection is modeled"
        );

        shadow.advance(b"\x1b%G");
        assert!(
            !shadow.is_safe(),
            "unsupported encoding selection must fail closed"
        );
    }

    #[test]
    fn restore_before_save_does_not_trust_the_inherited_cursor() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(20, 2));
        shadow.advance(b"\x1b8");
        assert!(!shadow.is_safe());

        shadow.advance(b"\x1b\x03\x1b<\x1bc\x1b7\x1b(0\x1b[1m\x1b8\x1b]8;;\x1b\\");
        assert!(shadow.scanner.rendition_known);
        assert!(shadow.scanner.charsets.designations.g0_ascii);
        assert!(
            !shadow.is_safe(),
            "DEC restore mode semantics differ from the backend"
        );
        shadow.advance(b"\x1b[?7h\x1b[1;2r");
        assert!(shadow.is_safe(), "explicit mode state can re-arm safety");
    }

    #[test]
    fn unsupported_modes_and_left_right_margins_taint_the_epoch() {
        for sequence in [
            b"\x1b[?69h".as_slice(),
            b"\x1b[?9999h",
            b"\x1b[9999l",
            b"\x1b[3;10s",
        ] {
            let mut shadow = ShadowTerminal::new(TerminalSize::new(20, 2));
            shadow.advance(b"\x1b\x03\x1b<\x1bc");
            assert!(shadow.is_safe());
            shadow.advance(sequence);
            assert!(!shadow.is_safe(), "sequence {sequence:?}");
        }

        let mut reset = ShadowTerminal::new(TerminalSize::new(20, 2));
        reset.advance(b"\x1b\x03\x1b<\x1bc\x1b[?69l");
        assert!(reset.is_safe(), "DECLRMM reset converges with the backend");
    }

    #[test]
    fn backend_semantic_mismatches_fail_passive_until_redraw() {
        for sequence in [
            b"\x1b[@".as_slice(),
            b"\x1b[P",
            b"\x1b[X",
            b"\x1b[K",
            b"\x1b[L",
            b"\x1b[M",
            b"\x1b#8",
        ] {
            let mut shadow = ShadowTerminal::new(TerminalSize::new(20, 4));
            shadow.advance(b"\x1b\x03\x1b<\x1bccontent");
            assert!(shadow.is_safe());
            shadow.advance(sequence);
            assert!(!shadow.is_safe(), "sequence {sequence:?}");
        }

        let mut lnm = ShadowTerminal::new(TerminalSize::new(20, 4));
        lnm.advance(b"\x1b\x03\x1b<\x1bc\x1b[20htext\nmore");
        assert!(!lnm.is_safe(), "LNM set is not modeled by the backend");
        lnm.advance(b"\x1b[20l\x1b[2J\x1b[H");
        assert!(lnm.is_safe(), "reset plus complete redraw recovers safely");

        let mut decom = ShadowTerminal::new(TerminalSize::new(20, 4));
        decom.advance(b"\x1b\x03\x1b<\x1bc\x1b[?6h\x1b[?6l");
        assert!(
            !decom.is_safe(),
            "DECOM reset homes only the physical cursor"
        );
        decom.advance(b"\x1b[H");
        assert!(decom.is_safe());
    }

    #[test]
    fn delayed_wrap_terminal_family_differences_fail_closed() {
        let mut linefeed = ShadowTerminal::new(TerminalSize::new(10, 3));
        linefeed.advance(b"\x1b\x03\x1b<\x1bc1234567890\nA");
        assert!(!linefeed.is_safe());

        let mut tab = ShadowTerminal::new(TerminalSize::new(10, 3));
        tab.advance(b"\x1b\x03\x1b<\x1bc1234567890\tA");
        assert!(!tab.is_safe());

        let mut erase = ShadowTerminal::new(TerminalSize::new(10, 3));
        erase.advance(b"\x1b\x03\x1b<\x1bc1234567890\x1b[2J\x1b[H");
        assert!(erase.is_safe());
        assert_eq!(erase.cursor(), CursorSnapshot { line: 0, column: 0 });
    }

    #[test]
    fn writes_under_unknown_wrap_mode_cannot_rearm_retroactively() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(10, 3));
        shadow.advance(
            b"\x1b\x03\x1b<\x1bc\x1b7\x1b[?7l\x1b8\
              12345678901\x1b]8;;\x1b\\\x1b[?7h\x1b[2;1H",
        );
        assert!(shadow.scanner.modes.wrap_known);
        assert!(
            !shadow.is_safe(),
            "mode convergence cannot validate cells written during divergence"
        );
        assert!(!shadow.can_overlay(1));

        shadow.advance(b"\x1b[0m\x1b[2J\x1b[H");
        assert!(shadow.is_safe(), "a later complete redraw recovers");
    }

    #[test]
    fn motion_under_unknown_newline_mode_stays_invalid_after_reset() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(10, 3));
        shadow.advance(b"\x1b\x03\x1b<\x1bc\x1b[20h\x1b[0m\x1b[2J\x1b[H\n\x1b[20l");
        assert!(shadow.scanner.modes.newline_known);
        assert!(
            !shadow.is_safe(),
            "LNM reset cannot retroactively reconcile the prior linefeed"
        );

        shadow.advance(b"\x1b[2J\x1b[H");
        assert!(shadow.is_safe());
    }

    #[test]
    fn invalid_margins_relative_motion_and_cancel_controls_revoke_trust() {
        let mut margins = ShadowTerminal::new(TerminalSize::new(20, 4));
        margins.advance(b"\x1b\x03\x1b<\x1bc\x1b[4;2r");
        assert!(!margins.is_safe(), "top must precede bottom");

        let mut relative = ShadowTerminal::new(TerminalSize::new(20, 6));
        relative.advance(b"\x1b\x03\x1b<\x1bc\x1b[2;5r\x1b[4;1H\x1b[99B");
        assert!(
            !relative.is_safe(),
            "relative movement must respect margins"
        );

        for byte in [0x18, 0x1a] {
            let mut cancelled = ShadowTerminal::new(TerminalSize::new(20, 4));
            cancelled.advance(b"\x1b\x03\x1b<\x1bc");
            cancelled.advance(&[byte]);
            assert!(!cancelled.is_safe(), "control {byte:#x}");
        }
    }

    #[test]
    fn known_vte_modes_and_tmux_theme_reporting_remain_safe() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(80, 24));
        shadow.advance(b"\x1b\x03\x1b<\x1bc");
        shadow.advance(b"\x1b[?1;6;7;12;25;1000;1002;1003;1004;1005;1006;1007;1042;2004;2031h");
        shadow.advance(b"\x1b[?2004;2031l\x1b[4h\x1b[4l\x1b[20l");
        assert!(shadow.is_safe());
    }

    #[test]
    fn tmux_startup_fails_closed_until_a_rendition_first_redraw() {
        let mut shadow = ShadowTerminal::at_application_entry(TerminalSize::new(80, 24));
        shadow.advance(b"\x1b[?1049h");
        assert!(
            !shadow.is_safe(),
            "1049 can be a no-op when the physical terminal was already alternate"
        );
        shadow.advance(
            b"\x1b[22;0;0t\x1b[?1h\x1b=\x1b[H\x1b[2J\
              \x1b[?12l\x1b[?25h\x1b[?1000;1002;1003;1005;1006l\
              \x1b[?2004h\x1b[?2031h\x1b[?996n\x1b(B\x1b[m\x1b[1;24r",
        );
        assert!(
            !shadow.is_safe(),
            "tmux clears before resetting an inherited rendition"
        );
        shadow.advance(b"\x1b[m\x1b[2J\x1b[H\x1b[1;24r");
        assert!(shadow.is_safe());
        assert!(shadow.can_overlay(1));
    }

    #[test]
    fn application_entry_baseline_requires_authoritative_geometry_and_rendition() {
        let mut shadow = ShadowTerminal::at_application_entry(TerminalSize::new(80, 24));
        assert!(!shadow.scanner.rendition_known);
        assert!(shadow.scanner.charsets.active_is_ascii());
        assert!(shadow.scanner.hyperlink_known);
        assert!(!shadow.scanner.hyperlink_active);
        assert!(shadow.scanner.modes.insert_known);
        assert!(shadow.scanner.modes.newline_known);
        assert!(shadow.scanner.modes.wrap_known);
        assert!(shadow.scanner.modes.cursor_visibility_known);
        assert!(shadow.scanner.modes.horizontal_margins_known);
        assert!(shadow.scanner.modes.protection_known);
        assert!(shadow.scanner.modes.synchronized_update_known);
        assert!(!shadow.is_safe(), "screen geometry is still inherited");

        shadow.advance(b"\x1b[m\x1b[2J\x1b[H");
        assert!(
            shadow.is_safe(),
            "authoritative erase, cursor, and rendition complete the baseline"
        );
    }

    #[test]
    fn foreign_or_unobserved_parser_state_requires_exit_before_ris() {
        let size = TerminalSize::new(80, 24);
        let mut skipped = ShadowTerminal::new(size);
        skipped.advance(b"\x1bc");
        assert!(
            !skipped.is_safe(),
            "RIS can be ignored in an inherited foreign parser mode"
        );
        skipped.advance(b"\x1b\x03\x1b<\x1bc");
        assert!(
            skipped.is_safe(),
            "Tek and VT52 exits followed by RIS converge an unknown parser"
        );

        let mut vt52 = ShadowTerminal::at_application_entry(size);
        vt52.advance(b"\x1b[0m\x1b[2J\x1b[H");
        assert!(vt52.is_safe());
        vt52.advance(b"\x1b[?25;2l\x1bc");
        assert!(
            !vt52.is_safe(),
            "a mixed DECANM reset makes bare ANSI RIS a false recovery"
        );
        vt52.advance(b"\x1b<\x1bc");
        assert!(
            !vt52.is_safe(),
            "optional VT52 support prevents trusting one exit alone"
        );
        vt52.advance(b"\x1b\x03\x1b<\x1bc");
        assert!(vt52.is_safe());

        let mut tek = ShadowTerminal::at_application_entry(size);
        tek.advance(b"\x1b[0m\x1b[2J\x1b[H");
        assert!(tek.is_safe());
        tek.advance(b"\x1b[?25;38h\x1b<\x1bc");
        assert!(
            !tek.is_safe(),
            "VT52 exit and ANSI RIS are data in Tektronix mode"
        );
        tek.advance(b"\x1b\x03\x1bc");
        assert!(
            !tek.is_safe(),
            "optional Tektronix support prevents trusting one exit alone"
        );
        tek.advance(b"\x1b\x03\x1b<\x1bc");
        assert!(tek.is_safe());

        let mut optional_modes = ShadowTerminal::at_application_entry(size);
        optional_modes.advance(b"\x1b[0m\x1b[2J\x1b[H");
        assert!(optional_modes.is_safe());
        optional_modes.advance(b"\x1b[?38h\x1b[?2l\x1b\x03\x1bc");
        assert!(
            !optional_modes.is_safe(),
            "one optional switch can be ignored before another takes effect"
        );
        optional_modes.advance(b"\x1b\x03\x1b<\x1bc");
        assert!(optional_modes.is_safe());
    }

    #[test]
    fn unknown_mid_session_state_does_not_reuse_application_entry_assumptions() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(80, 24));
        shadow.advance(b"\x1b\x03\x1b<");
        shadow.advance(b"\x0f\x1b(B\x1b[m\x1b[2J\x1b[H\x1b[1;24r");
        assert!(
            !shadow.scanner.screen_known,
            "a redraw under unknown placement modes is not authoritative"
        );
        assert!(!shadow.scanner.cursor_known);
        assert!(shadow.scanner.rendition_known);
        assert!(shadow.scanner.charsets.active_is_ascii());
        assert!(!shadow.is_safe(), "skipped terminal modes remain unknown");
    }

    #[test]
    fn inherited_tab_stops_invalidate_tab_based_cursor_motion() {
        for sequence in [b"\t".as_slice(), b"\x1b[I", b"\x1b[Z"] {
            let mut shadow = ShadowTerminal::at_application_entry(TerminalSize::new(80, 24));
            shadow.advance(b"\x1b[m\x1b[2J\x1b[H");
            assert!(shadow.is_safe());

            shadow.advance(sequence);
            assert!(!shadow.is_safe(), "sequence {sequence:?}");
            assert!(!shadow.scanner.screen_known);
            assert!(!shadow.scanner.cursor_known);
        }
    }

    #[test]
    fn c0_controls_inside_escape_sequences_update_safety_state() {
        for sequence in [b"\x1b\tD".as_slice(), b"\x1b(\tB", b"\x1b[\t\x18"] {
            let mut shadow = ShadowTerminal::at_application_entry(TerminalSize::new(80, 24));
            shadow.advance(b"\x1b[m\x1b[2J\x1b[H");
            assert!(shadow.is_safe());

            shadow.advance(sequence);
            assert!(!shadow.is_safe(), "sequence {sequence:?}");
            assert!(!shadow.scanner.cursor_known);
        }

        for sequence in [b"\x1b\x0eD".as_slice(), b"\x1b(\x0eB", b"\x1b[\x0e\x18"] {
            let mut shadow = ShadowTerminal::new(TerminalSize::new(80, 24));
            shadow.advance(b"\x1b\x03\x1b<\x1bc\x1b)0");
            assert!(shadow.is_safe());

            shadow.advance(sequence);
            assert_eq!(shadow.scanner.charsets.active, ActiveCharset::G1);
            assert!(!shadow.is_safe(), "sequence {sequence:?}");
        }
    }

    #[test]
    fn osc_escape_starts_a_new_escape_for_every_split_boundary() {
        let data = b"\x1b\x03\x1b<\x1bc\x1b]2;title\x1bXopaque\x07still opaque\x1b\\";
        for split in 0..=data.len() {
            let mut shadow = ShadowTerminal::new(TerminalSize::new(20, 2));
            shadow.advance(&data[..split]);
            shadow.advance(&data[split..]);
            assert!(!shadow.is_safe(), "split {split}");
        }
    }

    #[test]
    fn c1_st_does_not_prematurely_end_osc() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(20, 2));
        shadow.advance(b"\x1b\x03\x1b<\x1bc\x1b]2;title\x9c");
        assert!(!shadow.is_safe());
        shadow.advance(b"payload\x07");
        assert!(!shadow.is_safe(), "C1 OSC mismatch taints the epoch");
    }

    #[test]
    fn opaque_control_strings_permanently_taint_the_epoch() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(20, 2));
        shadow.advance(b"\x1b\x03\x1b<\x1bc\x1bPtmux;payload\x1b\\");
        assert!(!shadow.is_safe());
        shadow.advance(b"\x1b\x03\x1b<\x1bc");
        assert!(shadow.is_safe());
    }

    #[test]
    fn eight_bit_controls_and_utf8_are_distinguished_across_chunks() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(20, 2));
        shadow.advance(b"\x1b\x03\x1b<\x1bc\xc3");
        assert!(!shadow.is_safe(), "incomplete UTF-8 must block prediction");
        shadow.advance(b"\x9b");
        assert!(
            !shadow.is_safe(),
            "valid non-ASCII still has terminal-dependent cell width"
        );

        shadow.advance(b"\x9b2J\x9bH");
        assert!(!shadow.is_safe());
        shadow.advance(b"\x1b\x03\x1b<\x1bc");
        assert!(shadow.is_safe());
        shadow.advance(b"\x90opaque\x9c");
        assert!(!shadow.is_safe());
    }

    #[test]
    fn valid_utf8_is_identical_at_every_split_boundary() {
        let data = "\x1b\x03\x1b<\x1bcASCII élan — 世界 🙂 done".as_bytes();
        let size = TerminalSize::new(80, 24);
        let mut whole = ShadowTerminal::new(size);
        whole.advance(data);
        assert!(!whole.is_safe(), "Unicode width is not portable");

        for split in 0..=data.len() {
            let mut chunked = ShadowTerminal::new(size);
            chunked.advance(&data[..split]);
            chunked.advance(&data[split..]);

            assert_eq!(whole.cursor(), chunked.cursor(), "split {split}");
            assert_eq!(whole.is_safe(), chunked.is_safe(), "split {split}");
            assert_eq!(
                whole.can_overlay(1),
                chunked.can_overlay(1),
                "split {split}"
            );
        }
    }

    #[test]
    fn utf8_carry_accepts_only_structurally_valid_prefixes() {
        assert_eq!(trailing_incomplete_utf8_len(b"ascii\xc2"), 1);
        assert_eq!(trailing_incomplete_utf8_len(b"ascii\xe2\x82"), 2);
        assert_eq!(trailing_incomplete_utf8_len(b"ascii\xf0\x9f\x99"), 3);

        assert_eq!(trailing_incomplete_utf8_len("é🙂".as_bytes()), 0);
        assert_eq!(trailing_incomplete_utf8_len(b"\xc0"), 0);
        assert_eq!(trailing_incomplete_utf8_len(b"\xe0\x80"), 0);
        assert_eq!(trailing_incomplete_utf8_len(b"\xed\xa0"), 0);
        assert_eq!(trailing_incomplete_utf8_len(b"\xf4\x90"), 0);
        assert_eq!(trailing_incomplete_utf8_len(b"\x80"), 0);
    }

    #[test]
    fn malformed_utf8_taints_for_every_split_boundary() {
        let malformed: &[&[u8]] = &[
            b"\xc0\x80",         // Overlong two-byte encoding.
            b"\xe0\x80\x80",     // Overlong three-byte encoding.
            b"\xed\xa0\x80",     // UTF-16 surrogate.
            b"\xf4\x90\x80\x80", // Above U+10FFFF.
            b"\xf5\x80\x80\x80", // Invalid leading byte.
            b"\x80",             // Standalone continuation byte.
            b"\xc2\x9b",         // Encoded C1 control executed by vte.
        ];

        for suffix in malformed {
            let mut data = b"\x1b\x03\x1b<\x1bc".to_vec();
            data.extend_from_slice(suffix);
            for split in 0..=data.len() {
                let mut shadow = ShadowTerminal::new(TerminalSize::new(80, 24));
                shadow.advance(&data[..split]);
                shadow.advance(&data[split..]);
                assert!(!shadow.is_safe(), "suffix {suffix:?}, split {split}");
            }
        }
    }

    #[test]
    fn unknown_osc_protocols_taint_but_known_metadata_does_not() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(40, 2));
        shadow.advance(b"\x1b\x03\x1b<\x1bc\x1b]8;;https://example.test\x1b\\");
        assert!(!shadow.can_overlay(1), "active hyperlink is unsafe");
        shadow.advance(b"\x1b]8;;\x1b\\");
        assert!(shadow.is_safe());

        shadow.advance(b"\x1b]8;;https://example.test\x1a");
        assert!(
            !shadow.is_safe(),
            "OSC cancellation differs across physical terminal and backend"
        );
        shadow.advance(b"\x1b]8;;\x1b\\");
        assert!(
            !shadow.is_safe(),
            "a malformed OSC epoch needs a full reset"
        );
        shadow.advance(b"\x1b\x03\x1b<\x1bc");
        assert!(shadow.is_safe());
        shadow.advance(b"\x1b]1337;File=name=x:payload\x07");
        assert!(!shadow.is_safe());
    }

    #[test]
    fn malformed_osc_st_cannot_falsely_close_a_hyperlink() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(40, 2));
        shadow.advance(b"\x1b\x03\x1b<\x1bc\x1b]8;;https://example.test\x07");
        assert!(!shadow.is_safe());
        shadow.advance(b"\x1b]8;;\x1b[H");
        assert!(!shadow.is_safe());
    }

    #[test]
    fn font_changing_osc_is_not_treated_as_metadata() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(40, 2));
        shadow.advance(b"\x1b\x03\x1b<\x1bc\x1b]50;Monospace-14\x07");
        assert!(!shadow.is_safe());

        let mut cancelled = ShadowTerminal::new(TerminalSize::new(40, 2));
        cancelled.advance(b"\x1b\x03\x1b<\x1bc\x1b]50;Monospace-14\x18");
        assert!(
            !cancelled.is_safe(),
            "vte dispatches OSC payload when CAN exits the string"
        );
    }

    #[test]
    fn active_line_drawing_charset_blocks_ascii_overlays() {
        let mut shadow = ShadowTerminal::new(TerminalSize::new(20, 2));
        shadow.advance(b"\x1b\x03\x1b<\x1bc");
        assert!(shadow.can_overlay(1));

        shadow.advance(b"\x1b(0");
        assert!(
            !shadow.can_overlay(1),
            "ASCII q would render as line drawing"
        );
        shadow.advance(b"\x1b(B");
        assert!(shadow.can_overlay(1));

        shadow.advance(b"\x1b)0\x0e");
        assert!(!shadow.can_overlay(1), "SO selects the non-ASCII G1 set");
        shadow.advance(b"\x0f");
        assert!(shadow.can_overlay(1), "SI returns to the ASCII G0 set");
    }

    #[test]
    fn unmodeled_csi_controls_taint_the_epoch() {
        for sequence in [
            b"\x1b[1\"q".as_slice(), // DECSCA protected-cell attribute.
            b"\x1b[!p",              // DECSTR soft reset.
            b"\x1b[2;3 k",           // SCP path/update mode is not modeled.
            b"\x1b[3b",              // REP depends on inherited preceding text.
            b"\x1b[1z",              // Unknown display-affecting final.
            b"\x1b[s",               // Ambiguous SCO/DEC save semantics.
            b"\x1b[u",               // Ambiguous SCO/DEC restore semantics.
            b"\x1b[?3h",             // DECCOLM changes terminal geometry.
        ] {
            let mut shadow = ShadowTerminal::new(TerminalSize::new(20, 2));
            shadow.advance(b"\x1b\x03\x1b<\x1bc");
            shadow.advance(sequence);
            assert!(!shadow.is_safe(), "sequence {sequence:?}");
        }
    }

    proptest! {
        #[test]
        fn arbitrary_output_is_chunk_boundary_invariant(
            bytes in prop::collection::vec(any::<u8>(), 0..1_024),
            chunk_size in 1_usize..64,
        ) {
            let size = TerminalSize::new(80, 24);
            let mut whole = ShadowTerminal::new(size);
            whole.advance(&bytes);

            let mut chunked = ShadowTerminal::new(size);
            for chunk in bytes.chunks(chunk_size) {
                chunked.advance(chunk);
            }

            prop_assert_eq!(whole.is_safe(), chunked.is_safe());
            // `vte` deliberately recovers malformed UTF-8 differently based
            // on call boundaries. A tainted model is never used for prediction,
            // so cursor equality is only a safety property for trusted streams.
            if whole.is_safe() {
                prop_assert_eq!(whole.cursor(), chunked.cursor());
                prop_assert_eq!(whole.can_overlay(1), chunked.can_overlay(1));
            }
        }

        #[test]
        fn valid_utf8_output_is_chunk_boundary_invariant(
            characters in prop::collection::vec(
                prop_oneof![
                    prop::char::range(' ', '~'),
                    prop::char::range('\u{a0}', '\u{d7ff}'),
                    prop::char::range('\u{e000}', '\u{10ffff}'),
                ],
                0..256,
            ),
            chunk_size in 1_usize..16,
        ) {
            let text: String = characters.into_iter().collect();
            let expected_safe = text.is_ascii();
            let mut bytes = b"\x1b\x03\x1b<\x1bc".to_vec();
            bytes.extend_from_slice(text.as_bytes());
            let size = TerminalSize::new(80, 24);

            let mut whole = ShadowTerminal::new(size);
            whole.advance(&bytes);

            let mut chunked = ShadowTerminal::new(size);
            for chunk in bytes.chunks(chunk_size) {
                chunked.advance(chunk);
            }

            prop_assert_eq!(whole.is_safe(), expected_safe);
            prop_assert_eq!(chunked.is_safe(), expected_safe);
            prop_assert_eq!(whole.cursor(), chunked.cursor());
            prop_assert_eq!(whole.can_overlay(1), chunked.can_overlay(1));
        }
    }
}
