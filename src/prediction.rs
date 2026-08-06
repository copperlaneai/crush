//! Conservative, transport-independent local echo prediction.
//!
//! This module is a side tap. Callers must forward the original input bytes
//! unchanged and use the returned effects only to manage a disposable overlay.
//! The predictor never renders, rewrites input, or interprets authoritative
//! terminal output on its own.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub const MIN_STALE_DEADLINE: Duration = Duration::from_millis(750);

pub const MAX_STALE_DEADLINE: Duration = Duration::from_secs(3);

pub const DEFAULT_MAX_PENDING: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalTrust {
    Unknown,
    Safe,
    Tainted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoConfidence {
    Cold,
    Probe,
    Trusted,
    Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputBarrier {
    Control(u8),
    Escape,
    EscapeSequence,
    PasteStart,
    PasteData,
    PasteEnd,
    NonAscii(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputClass {
    SafePrintable(u8),
    Backspace(u8),
    Barrier(InputBarrier),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetReason {
    InputBarrier,
    TerminalUntrusted,
    UnsafeBackspace,
    EchoMismatch,
    PendingLimit,
    Stale,
    AuthoritativeChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetEffect {
    pub rollback_chars: usize,
    pub reason: ResetReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEffect {
    ForwardOnly,
    Probe { byte: u8 },
    DrawAppend { byte: u8 },
    DrawBackspace { erased: u8 },
    Submit,
    Suspend(ResetEffect),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputDecision {
    pub class: InputClass,
    pub effect: InputEffect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedEcho {
    Printable { byte: u8, visible: bool },
    Backspace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoConfirmation {
    Printable(u8),
    Backspace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmedEcho {
    Probe,
    Printable { byte: u8, was_visible: bool },
    Backspace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationResult {
    NothingPending,
    Matched {
        echo: ConfirmedEcho,
        sample_rtt: Duration,
        measured_rtt: Duration,
    },
    Mismatch(ResetEffect),
}

#[derive(Debug)]
enum PendingOperation {
    Append {
        byte: u8,
        sent_at: Instant,
        visible: bool,
        probe: bool,
    },
    Backspace {
        sent_at: Instant,
    },
}

impl PendingOperation {
    fn sent_at(&self) -> Instant {
        match self {
            Self::Append { sent_at, .. } | Self::Backspace { sent_at } => *sent_at,
        }
    }

    fn zero_byte(&mut self) {
        if let Self::Append { byte, .. } = self {
            // Best-effort erasure for bounded, unexposed queue storage.
            *byte = 0;
            std::hint::black_box(byte);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputParseState {
    Ground,
    Escape,
    EscapeIntermediate,
    Csi {
        exact_paste_start: bool,
        matched: u8,
    },
    Ss3,
    ControlString {
        osc: bool,
        saw_escape: bool,
    },
    Paste {
        end_matched: u8,
    },
}

impl InputParseState {
    fn is_ground(self) -> bool {
        matches!(self, Self::Ground)
    }
}

#[derive(Debug)]
pub struct PredictionEngine {
    terminal_trust: TerminalTrust,
    echo_confidence: EchoConfidence,
    immediate_echo: bool,
    submitted: bool,
    input_state: InputParseState,
    pending: VecDeque<PendingOperation>,
    max_pending: usize,
    measured_rtt: Option<Duration>,
}

impl Default for PredictionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PredictionEngine {
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_pending(DEFAULT_MAX_PENDING)
    }

    /// Skips the echo probe and can display input at a silent password prompt.
    #[must_use]
    pub fn new_immediate() -> Self {
        Self::with_mode(DEFAULT_MAX_PENDING, true)
    }

    #[must_use]
    pub fn with_max_pending(max_pending: usize) -> Self {
        Self::with_mode(max_pending, false)
    }

    fn with_mode(max_pending: usize, immediate_echo: bool) -> Self {
        Self {
            terminal_trust: TerminalTrust::Unknown,
            echo_confidence: if immediate_echo {
                EchoConfidence::Trusted
            } else {
                EchoConfidence::Cold
            },
            immediate_echo,
            submitted: false,
            input_state: InputParseState::Ground,
            pending: VecDeque::new(),
            max_pending: max_pending.max(1),
            measured_rtt: None,
        }
    }

    #[must_use]
    pub fn terminal_trust(&self) -> TerminalTrust {
        self.terminal_trust
    }

    #[must_use]
    pub fn echo_confidence(&self) -> EchoConfidence {
        self.echo_confidence
    }

    #[must_use]
    pub fn pending_operations(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub fn visible_predictions(&self) -> usize {
        self.pending
            .iter()
            .filter(|operation| matches!(operation, PendingOperation::Append { visible: true, .. }))
            .count()
    }

    #[must_use]
    pub fn measured_rtt(&self) -> Option<Duration> {
        self.measured_rtt
    }

    #[must_use]
    pub fn stale_deadline(&self) -> Duration {
        self.measured_rtt.map_or_else(
            || {
                if self.immediate_echo {
                    MAX_STALE_DEADLINE
                } else {
                    MIN_STALE_DEADLINE
                }
            },
            |rtt| {
                rtt.saturating_mul(3)
                    .clamp(MIN_STALE_DEADLINE, MAX_STALE_DEADLINE)
            },
        )
    }

    pub fn set_terminal_trust(&mut self, trust: TerminalTrust) -> Option<ResetEffect> {
        if self.terminal_trust == trust {
            return None;
        }

        self.terminal_trust = trust;
        if trust == TerminalTrust::Safe {
            None
        } else {
            Some(self.suspend(ResetReason::TerminalUntrusted))
        }
    }

    pub fn rearm_at_safe_anchor(&mut self) -> bool {
        if self.terminal_trust != TerminalTrust::Safe
            || !self.input_state.is_ground()
            || !self.pending.is_empty()
        {
            return false;
        }

        if self.echo_confidence == EchoConfidence::Quarantined {
            self.echo_confidence = if self.immediate_echo {
                EchoConfidence::Trusted
            } else {
                EchoConfidence::Cold
            };
        }
        true
    }

    pub fn observe_input(&mut self, byte: u8, now: Instant) -> InputDecision {
        let class = self.classify_input(byte);
        if self.submitted {
            return InputDecision {
                class,
                effect: InputEffect::ForwardOnly,
            };
        }
        let effect = match class {
            InputClass::SafePrintable(printable) => self.observe_printable(printable, now),
            InputClass::Backspace(_) => self.observe_backspace(now),
            InputClass::Barrier(InputBarrier::Control(0x0a | 0x0d))
                if self.immediate_echo
                    && self.terminal_trust == TerminalTrust::Safe
                    && self.echo_confidence == EchoConfidence::Trusted
                    && self.visible_predictions() != 0 =>
            {
                self.submitted = true;
                InputEffect::Submit
            }
            InputClass::Barrier(_) => {
                if self.echo_confidence == EchoConfidence::Quarantined && self.pending.is_empty() {
                    InputEffect::ForwardOnly
                } else {
                    InputEffect::Suspend(self.suspend(ResetReason::InputBarrier))
                }
            }
        };

        InputDecision { class, effect }
    }

    #[must_use]
    pub fn expected_echo(&self) -> Option<ExpectedEcho> {
        self.pending.front().map(|operation| match operation {
            PendingOperation::Append { byte, visible, .. } => ExpectedEcho::Printable {
                byte: *byte,
                visible: *visible,
            },
            PendingOperation::Backspace { .. } => ExpectedEcho::Backspace,
        })
    }

    pub fn confirm_echo(
        &mut self,
        confirmation: EchoConfirmation,
        now: Instant,
    ) -> ConfirmationResult {
        let Some(expected) = self.expected_echo() else {
            return ConfirmationResult::NothingPending;
        };

        let matches = matches!(
            (expected, confirmation),
            (
                ExpectedEcho::Printable { byte: expected, .. },
                EchoConfirmation::Printable(actual)
            ) if expected == actual
        ) || matches!(
            (expected, confirmation),
            (ExpectedEcho::Backspace, EchoConfirmation::Backspace)
        );

        if !matches {
            return ConfirmationResult::Mismatch(self.suspend(ResetReason::EchoMismatch));
        }

        let mut operation = self
            .pending
            .pop_front()
            .expect("expected echo requires a pending operation");
        let sample_rtt = now
            .checked_duration_since(operation.sent_at())
            .unwrap_or_default();
        let measured_rtt = self.record_rtt(sample_rtt);

        let echo = match &mut operation {
            PendingOperation::Append {
                byte,
                visible,
                probe,
                ..
            } => {
                let confirmed_byte = *byte;
                let was_visible = *visible;
                let was_probe = *probe;
                operation.zero_byte();

                if was_probe && self.echo_confidence == EchoConfidence::Probe {
                    self.echo_confidence = EchoConfidence::Trusted;
                    ConfirmedEcho::Probe
                } else {
                    ConfirmedEcho::Printable {
                        byte: confirmed_byte,
                        was_visible,
                    }
                }
            }
            PendingOperation::Backspace { .. } => ConfirmedEcho::Backspace,
        };

        ConfirmationResult::Matched {
            echo,
            sample_rtt,
            measured_rtt,
        }
    }

    pub fn authoritative_change(&mut self) -> ResetEffect {
        self.suspend(ResetReason::AuthoritativeChange)
    }

    pub fn expire_stale(&mut self, now: Instant) -> Option<ResetEffect> {
        // Expiring immediate predictions would manufacture a backward cursor jump.
        if self.immediate_echo {
            return None;
        }
        let sent_at = self.pending.front().map(PendingOperation::sent_at)?;
        let elapsed = now.checked_duration_since(sent_at).unwrap_or_default();

        if elapsed >= self.stale_deadline() {
            Some(self.suspend(ResetReason::Stale))
        } else {
            None
        }
    }

    fn observe_printable(&mut self, byte: u8, now: Instant) -> InputEffect {
        if self.terminal_trust != TerminalTrust::Safe {
            if self.echo_confidence == EchoConfidence::Quarantined && self.pending.is_empty() {
                return InputEffect::ForwardOnly;
            }
            return InputEffect::Suspend(self.suspend(ResetReason::TerminalUntrusted));
        }

        match self.echo_confidence {
            EchoConfidence::Cold => {
                if !self.push_append(byte, now, false, true) {
                    return InputEffect::Suspend(self.suspend(ResetReason::PendingLimit));
                }
                self.echo_confidence = EchoConfidence::Probe;
                InputEffect::Probe { byte }
            }
            EchoConfidence::Probe => {
                if self.push_append(byte, now, false, false) {
                    InputEffect::ForwardOnly
                } else {
                    InputEffect::Suspend(self.suspend(ResetReason::PendingLimit))
                }
            }
            EchoConfidence::Trusted => {
                // Characters typed while the initial undrawn probe was in
                // flight are also undrawn. Do not place a later prediction at
                // their column; wait until that invisible prefix is confirmed.
                let can_draw = self.pending.iter().all(|operation| {
                    !matches!(operation, PendingOperation::Append { visible: false, .. })
                });
                if self.push_append(byte, now, can_draw, false) {
                    if can_draw {
                        InputEffect::DrawAppend { byte }
                    } else {
                        InputEffect::ForwardOnly
                    }
                } else {
                    InputEffect::Suspend(self.suspend(ResetReason::PendingLimit))
                }
            }
            EchoConfidence::Quarantined => InputEffect::ForwardOnly,
        }
    }

    fn observe_backspace(&mut self, now: Instant) -> InputEffect {
        if self.terminal_trust != TerminalTrust::Safe
            || self.echo_confidence != EchoConfidence::Trusted
        {
            if self.echo_confidence == EchoConfidence::Quarantined && self.pending.is_empty() {
                return InputEffect::ForwardOnly;
            }
            return InputEffect::Suspend(self.suspend(ResetReason::UnsafeBackspace));
        }

        if self.pending.len() >= self.max_pending {
            return InputEffect::Suspend(self.suspend(ResetReason::PendingLimit));
        }

        let erased = self.pending.iter_mut().rev().find_map(|operation| {
            if let PendingOperation::Append {
                byte,
                visible: true,
                ..
            } = operation
            {
                let erased = *byte;
                if let PendingOperation::Append { visible, .. } = operation {
                    *visible = false;
                }
                Some(erased)
            } else {
                None
            }
        });

        let Some(erased) = erased else {
            return InputEffect::Suspend(self.suspend(ResetReason::UnsafeBackspace));
        };

        self.pending
            .push_back(PendingOperation::Backspace { sent_at: now });
        InputEffect::DrawBackspace { erased }
    }

    fn push_append(&mut self, byte: u8, now: Instant, visible: bool, probe: bool) -> bool {
        if self.pending.len() >= self.max_pending {
            return false;
        }

        self.pending.push_back(PendingOperation::Append {
            byte,
            sent_at: now,
            visible,
            probe,
        });
        true
    }

    fn record_rtt(&mut self, sample: Duration) -> Duration {
        let measured = self.measured_rtt.map_or(sample, |previous| {
            let previous_nanos = previous.as_nanos();
            let sample_nanos = sample.as_nanos();
            let smoothed = previous_nanos
                .saturating_mul(7)
                .saturating_add(sample_nanos)
                / 8;
            Duration::from_nanos(
                u64::try_from(smoothed.min(u128::from(u64::MAX))).unwrap_or(u64::MAX),
            )
        });
        self.measured_rtt = Some(measured);
        measured
    }

    fn suspend(&mut self, reason: ResetReason) -> ResetEffect {
        let rollback_chars = self.visible_predictions();
        self.clear_pending();
        self.submitted = false;
        self.echo_confidence = EchoConfidence::Quarantined;
        ResetEffect {
            rollback_chars,
            reason,
        }
    }

    fn clear_pending(&mut self) {
        self.zero_pending_bytes();
        self.pending.clear();
    }

    fn zero_pending_bytes(&mut self) {
        for operation in &mut self.pending {
            operation.zero_byte();
        }
    }

    #[allow(clippy::too_many_lines)]
    fn classify_input(&mut self, byte: u8) -> InputClass {
        const PASTE_START_BODY: &[u8; 3] = b"200";
        const PASTE_END: &[u8; 6] = b"\x1b[201~";

        match self.input_state {
            InputParseState::Ground => match byte {
                0x1b => {
                    self.input_state = InputParseState::Escape;
                    InputClass::Barrier(InputBarrier::Escape)
                }
                0x08 | 0x7f => InputClass::Backspace(byte),
                0x20..=0x7e => InputClass::SafePrintable(byte),
                0x00..=0x1f => InputClass::Barrier(InputBarrier::Control(byte)),
                0x8f => {
                    self.input_state = InputParseState::Ss3;
                    InputClass::Barrier(InputBarrier::EscapeSequence)
                }
                0x90 | 0x98 | 0x9d | 0x9e | 0x9f => {
                    self.input_state = InputParseState::ControlString {
                        osc: byte == 0x9d,
                        saw_escape: false,
                    };
                    InputClass::Barrier(InputBarrier::EscapeSequence)
                }
                0x9b => {
                    self.input_state = InputParseState::Csi {
                        exact_paste_start: true,
                        matched: 0,
                    };
                    InputClass::Barrier(InputBarrier::EscapeSequence)
                }
                0x80..=0x9f => InputClass::Barrier(InputBarrier::EscapeSequence),
                _ => InputClass::Barrier(InputBarrier::NonAscii(byte)),
            },
            InputParseState::Escape => {
                self.input_state = match byte {
                    b'[' => InputParseState::Csi {
                        exact_paste_start: true,
                        matched: 0,
                    },
                    b'O' => InputParseState::Ss3,
                    b']' => InputParseState::ControlString {
                        osc: true,
                        saw_escape: false,
                    },
                    b'P' | b'X' | b'^' | b'_' => InputParseState::ControlString {
                        osc: false,
                        saw_escape: false,
                    },
                    0x20..=0x2f => InputParseState::EscapeIntermediate,
                    0x1b | 0x00..=0x17 | 0x19 | 0x1c..=0x1f | 0x7f => InputParseState::Escape,
                    // CAN/SUB and a completed escape final return to ground.
                    _ => InputParseState::Ground,
                };
                InputClass::Barrier(InputBarrier::EscapeSequence)
            }
            InputParseState::EscapeIntermediate => {
                self.input_state = match byte {
                    0x20..=0x2f | 0x00..=0x17 | 0x19 | 0x1c..=0x1f | 0x7f => {
                        InputParseState::EscapeIntermediate
                    }
                    0x1b => InputParseState::Escape,
                    _ => InputParseState::Ground,
                };
                InputClass::Barrier(InputBarrier::EscapeSequence)
            }
            InputParseState::Csi {
                mut exact_paste_start,
                mut matched,
            } => {
                if byte == 0x1b {
                    self.input_state = InputParseState::Escape;
                    return InputClass::Barrier(InputBarrier::EscapeSequence);
                }

                if (0x40..=0x7e).contains(&byte) {
                    let paste_start = exact_paste_start
                        && usize::from(matched) == PASTE_START_BODY.len()
                        && byte == b'~';
                    self.input_state = if paste_start {
                        InputParseState::Paste { end_matched: 0 }
                    } else {
                        InputParseState::Ground
                    };
                    return InputClass::Barrier(if paste_start {
                        InputBarrier::PasteStart
                    } else {
                        InputBarrier::EscapeSequence
                    });
                }

                let index = usize::from(matched);
                if index >= PASTE_START_BODY.len() || PASTE_START_BODY[index] != byte {
                    exact_paste_start = false;
                }
                matched = matched.saturating_add(1);
                self.input_state = InputParseState::Csi {
                    exact_paste_start,
                    matched,
                };
                InputClass::Barrier(InputBarrier::EscapeSequence)
            }
            InputParseState::Ss3 => {
                self.input_state = match byte {
                    0x1b => InputParseState::Escape,
                    0x00..=0x17 | 0x19 | 0x1c..=0x1f | 0x7f => InputParseState::Ss3,
                    // CAN/SUB and a completed SS3 final return to ground.
                    _ => InputParseState::Ground,
                };
                InputClass::Barrier(InputBarrier::EscapeSequence)
            }
            InputParseState::ControlString {
                osc,
                mut saw_escape,
            } => {
                // vte 0.15 treats raw C1 ST inside OSC as payload rather than
                // a terminator. Keep OSC input quarantined instead of letting
                // later payload bytes become printable predictions. Other
                // control strings do accept C1 ST.
                let terminated_by_st = (saw_escape && byte == b'\\') || (!osc && byte == 0x9c);
                let terminated_by_bel = osc && byte == 0x07;
                let cancelled = matches!(byte, 0x18 | 0x1a);

                if terminated_by_st || terminated_by_bel || cancelled {
                    self.input_state = InputParseState::Ground;
                } else {
                    saw_escape = byte == 0x1b;
                    self.input_state = InputParseState::ControlString { osc, saw_escape };
                }
                InputClass::Barrier(InputBarrier::EscapeSequence)
            }
            InputParseState::Paste { mut end_matched } => {
                let index = usize::from(end_matched);
                if PASTE_END[index] == byte {
                    end_matched += 1;
                    if usize::from(end_matched) == PASTE_END.len() {
                        self.input_state = InputParseState::Ground;
                        InputClass::Barrier(InputBarrier::PasteEnd)
                    } else {
                        self.input_state = InputParseState::Paste { end_matched };
                        InputClass::Barrier(InputBarrier::PasteData)
                    }
                } else {
                    self.input_state = InputParseState::Paste {
                        end_matched: u8::from(byte == PASTE_END[0]),
                    };
                    InputClass::Barrier(InputBarrier::PasteData)
                }
            }
        }
    }
}

impl Drop for PredictionEngine {
    fn drop(&mut self) {
        self.zero_pending_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn safe_engine() -> (PredictionEngine, Instant) {
        let mut engine = PredictionEngine::new();
        assert_eq!(engine.set_terminal_trust(TerminalTrust::Safe), None);
        assert!(engine.rearm_at_safe_anchor());
        (engine, Instant::now())
    }

    fn trust_with_probe(engine: &mut PredictionEngine, start: Instant, byte: u8) {
        assert_eq!(
            engine.observe_input(byte, start),
            InputDecision {
                class: InputClass::SafePrintable(byte),
                effect: InputEffect::Probe { byte },
            }
        );
        assert!(matches!(
            engine.confirm_echo(
                EchoConfirmation::Printable(byte),
                start + Duration::from_millis(100)
            ),
            ConfirmationResult::Matched {
                echo: ConfirmedEcho::Probe,
                ..
            }
        ));
        assert_eq!(engine.echo_confidence(), EchoConfidence::Trusted);
    }

    #[test]
    fn terminal_must_be_safe_and_explicitly_rearmed() {
        let mut engine = PredictionEngine::new();
        let now = Instant::now();

        assert_eq!(
            engine.observe_input(b'a', now).effect,
            InputEffect::Suspend(ResetEffect {
                rollback_chars: 0,
                reason: ResetReason::TerminalUntrusted,
            })
        );
        assert_eq!(engine.echo_confidence(), EchoConfidence::Quarantined);

        assert_eq!(engine.set_terminal_trust(TerminalTrust::Safe), None);
        assert_eq!(engine.echo_confidence(), EchoConfidence::Quarantined);
        assert!(engine.rearm_at_safe_anchor());
        assert_eq!(engine.echo_confidence(), EchoConfidence::Cold);
    }

    #[test]
    fn immediate_mode_draws_the_first_character_and_rearms_without_a_probe() {
        let mut engine = PredictionEngine::new_immediate();
        let now = Instant::now();

        assert_eq!(engine.set_terminal_trust(TerminalTrust::Safe), None);
        assert!(engine.rearm_at_safe_anchor());
        assert_eq!(
            engine.observe_input(b'x', now).effect,
            InputEffect::DrawAppend { byte: b'x' }
        );

        let _ = engine.authoritative_change();
        assert_eq!(engine.echo_confidence(), EchoConfidence::Quarantined);
        assert!(engine.rearm_at_safe_anchor());
        assert_eq!(engine.echo_confidence(), EchoConfidence::Trusted);
        assert_eq!(
            engine
                .observe_input(b'y', now + Duration::from_millis(1))
                .effect,
            InputEffect::DrawAppend { byte: b'y' }
        );
    }

    #[test]
    fn immediate_submit_keeps_predictions_visible_until_remote_output() {
        let mut engine = PredictionEngine::new_immediate();
        let now = Instant::now();
        assert_eq!(engine.set_terminal_trust(TerminalTrust::Safe), None);
        assert!(engine.rearm_at_safe_anchor());

        assert!(matches!(
            engine.observe_input(b'x', now).effect,
            InputEffect::DrawAppend { byte: b'x' }
        ));
        assert_eq!(engine.observe_input(b'\r', now).effect, InputEffect::Submit);
        assert_eq!(engine.visible_predictions(), 1);
        assert_eq!(
            engine.observe_input(b'y', now).effect,
            InputEffect::ForwardOnly
        );

        let reset = engine.authoritative_change();
        assert_eq!(reset.rollback_chars, 1);
        assert_eq!(engine.visible_predictions(), 0);
    }

    #[test]
    fn first_character_is_an_undrawn_probe_then_trusts_matching_echo() {
        let (mut engine, start) = safe_engine();
        let decision = engine.observe_input(b'x', start);

        assert_eq!(decision.effect, InputEffect::Probe { byte: b'x' });
        assert_eq!(engine.visible_predictions(), 0);
        assert_eq!(engine.echo_confidence(), EchoConfidence::Probe);
        assert_eq!(
            engine.expected_echo(),
            Some(ExpectedEcho::Printable {
                byte: b'x',
                visible: false,
            })
        );

        let result = engine.confirm_echo(
            EchoConfirmation::Printable(b'x'),
            start + Duration::from_millis(80),
        );
        assert_eq!(
            result,
            ConfirmationResult::Matched {
                echo: ConfirmedEcho::Probe,
                sample_rtt: Duration::from_millis(80),
                measured_rtt: Duration::from_millis(80),
            }
        );
        assert_eq!(engine.echo_confidence(), EchoConfidence::Trusted);
        assert_eq!(engine.pending_operations(), 0);
    }

    #[test]
    fn safe_anchor_rearm_does_not_downgrade_trusted_echo() {
        let (mut engine, start) = safe_engine();
        trust_with_probe(&mut engine, start, b'x');

        assert!(engine.rearm_at_safe_anchor());
        assert_eq!(engine.echo_confidence(), EchoConfidence::Trusted);
        assert!(matches!(
            engine
                .observe_input(b'y', start + Duration::from_millis(150))
                .effect,
            InputEffect::DrawAppend { byte: b'y' }
        ));
    }

    #[test]
    fn bytes_typed_behind_probe_are_tracked_but_not_drawn() {
        let (mut engine, start) = safe_engine();
        assert_eq!(
            engine.observe_input(b'a', start).effect,
            InputEffect::Probe { byte: b'a' }
        );
        assert_eq!(
            engine
                .observe_input(b'b', start + Duration::from_millis(1))
                .effect,
            InputEffect::ForwardOnly
        );
        assert_eq!(engine.pending_operations(), 2);
        assert_eq!(engine.visible_predictions(), 0);

        engine.confirm_echo(
            EchoConfirmation::Printable(b'a'),
            start + Duration::from_millis(50),
        );
        assert_eq!(engine.echo_confidence(), EchoConfidence::Trusted);
        assert_eq!(
            engine.expected_echo(),
            Some(ExpectedEcho::Printable {
                byte: b'b',
                visible: false,
            })
        );

        assert_eq!(
            engine
                .observe_input(b'c', start + Duration::from_millis(51))
                .effect,
            InputEffect::ForwardOnly
        );
        assert_eq!(engine.visible_predictions(), 0);
    }

    #[test]
    fn trusted_ascii_is_drawn_and_confirmed_in_order() {
        let (mut engine, start) = safe_engine();
        trust_with_probe(&mut engine, start, b'a');
        let typed = start + Duration::from_millis(110);

        assert_eq!(
            engine.observe_input(b'b', typed).effect,
            InputEffect::DrawAppend { byte: b'b' }
        );
        assert_eq!(engine.visible_predictions(), 1);
        assert_eq!(
            engine.confirm_echo(
                EchoConfirmation::Printable(b'b'),
                typed + Duration::from_millis(120)
            ),
            ConfirmationResult::Matched {
                echo: ConfirmedEcho::Printable {
                    byte: b'b',
                    was_visible: true,
                },
                sample_rtt: Duration::from_millis(120),
                measured_rtt: Duration::from_micros(102_500),
            }
        );
        assert_eq!(engine.visible_predictions(), 0);
    }

    #[test]
    fn mismatch_rolls_back_and_quarantines() {
        let (mut engine, start) = safe_engine();
        trust_with_probe(&mut engine, start, b'a');
        engine.observe_input(b'b', start + Duration::from_millis(110));
        engine.observe_input(b'c', start + Duration::from_millis(120));

        assert_eq!(
            engine.confirm_echo(
                EchoConfirmation::Printable(b'z'),
                start + Duration::from_millis(200)
            ),
            ConfirmationResult::Mismatch(ResetEffect {
                rollback_chars: 2,
                reason: ResetReason::EchoMismatch,
            })
        );
        assert_eq!(engine.echo_confidence(), EchoConfidence::Quarantined);
        assert_eq!(engine.pending_operations(), 0);
    }

    #[test]
    fn backspace_only_erases_an_unresolved_predicted_suffix() {
        let (mut engine, start) = safe_engine();
        trust_with_probe(&mut engine, start, b'a');
        let typed = start + Duration::from_millis(110);
        engine.observe_input(b'b', typed);

        assert_eq!(
            engine.observe_input(0x7f, typed + Duration::from_millis(1)),
            InputDecision {
                class: InputClass::Backspace(0x7f),
                effect: InputEffect::DrawBackspace { erased: b'b' },
            }
        );
        assert_eq!(engine.visible_predictions(), 0);
        assert_eq!(
            engine.expected_echo(),
            Some(ExpectedEcho::Printable {
                byte: b'b',
                visible: false,
            })
        );

        engine.confirm_echo(
            EchoConfirmation::Printable(b'b'),
            typed + Duration::from_millis(100),
        );
        assert_eq!(engine.expected_echo(), Some(ExpectedEcho::Backspace));
        assert!(matches!(
            engine.confirm_echo(
                EchoConfirmation::Backspace,
                typed + Duration::from_millis(110)
            ),
            ConfirmationResult::Matched {
                echo: ConfirmedEcho::Backspace,
                ..
            }
        ));

        assert_eq!(
            engine
                .observe_input(0x08, typed + Duration::from_millis(120))
                .effect,
            InputEffect::Suspend(ResetEffect {
                rollback_chars: 0,
                reason: ResetReason::UnsafeBackspace,
            })
        );
    }

    #[test]
    fn controls_and_non_ascii_are_barriers() {
        let (mut engine, start) = safe_engine();
        assert_eq!(
            engine.observe_input(b'\n', start).class,
            InputClass::Barrier(InputBarrier::Control(b'\n'))
        );
        assert_eq!(engine.echo_confidence(), EchoConfidence::Quarantined);
        assert!(engine.rearm_at_safe_anchor());
        assert_eq!(
            engine.observe_input(0xc3, start).class,
            InputClass::Barrier(InputBarrier::NonAscii(0xc3))
        );
    }

    #[test]
    fn escape_sequence_fragments_never_become_printable_input() {
        let (mut engine, start) = safe_engine();
        let sequence = b"\x1b[1;5A";
        let classes: Vec<_> = sequence
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                engine
                    .observe_input(*byte, start + Duration::from_millis(index as u64))
                    .class
            })
            .collect();

        assert_eq!(classes[0], InputClass::Barrier(InputBarrier::Escape));
        assert!(
            classes[1..]
                .iter()
                .all(|class| *class == InputClass::Barrier(InputBarrier::EscapeSequence))
        );
        assert_eq!(engine.pending_operations(), 0);
        assert!(engine.rearm_at_safe_anchor());
    }

    #[test]
    fn escape_intermediates_never_leak_a_final_as_printable_input() {
        let (mut engine, now) = safe_engine();
        for byte in b"\x1b(B" {
            assert!(matches!(
                engine.observe_input(*byte, now).class,
                InputClass::Barrier(InputBarrier::Escape | InputBarrier::EscapeSequence)
            ));
        }
    }

    #[test]
    fn c0_controls_do_not_terminate_escape_or_ss3_input() {
        let (mut engine, now) = safe_engine();
        for sequence in [b"\x1b\x0eD".as_slice(), b"\x1bO\x0eP"] {
            for byte in sequence {
                assert!(matches!(
                    engine.observe_input(*byte, now).class,
                    InputClass::Barrier(InputBarrier::Escape | InputBarrier::EscapeSequence)
                ));
            }
            assert_eq!(
                engine.observe_input(b'x', now).class,
                InputClass::SafePrintable(b'x')
            );
        }

        for sequence in [b"\x1b\x18".as_slice(), b"\x1bO\x1a"] {
            for byte in sequence {
                assert!(matches!(
                    engine.observe_input(*byte, now).class,
                    InputClass::Barrier(_)
                ));
            }
            assert_eq!(
                engine.observe_input(b'x', now).class,
                InputClass::SafePrintable(b'x')
            );
        }
    }

    #[test]
    fn eight_bit_c1_sequences_remain_barriers_until_their_terminator() {
        let (mut engine, now) = safe_engine();
        for byte in [0x9b, b'1', b'm'] {
            assert!(matches!(
                engine.observe_input(byte, now).class,
                InputClass::Barrier(_)
            ));
        }
        for byte in [0x9d, b't', b'i', b't', b'l', b'e', 0x9c] {
            assert!(matches!(
                engine.observe_input(byte, now).class,
                InputClass::Barrier(_)
            ));
        }
        assert!(matches!(
            engine.observe_input(b'x', now).class,
            InputClass::Barrier(InputBarrier::EscapeSequence)
        ));
        assert!(matches!(
            engine.observe_input(0x07, now).class,
            InputClass::Barrier(InputBarrier::EscapeSequence)
        ));
        assert_eq!(
            engine.observe_input(b'x', now).class,
            InputClass::SafePrintable(b'x')
        );
    }

    proptest! {
        #[test]
        fn arbitrary_input_never_exceeds_the_pending_bound(bytes in prop::collection::vec(any::<u8>(), 0..2_048)) {
            let (mut engine, now) = safe_engine();
            for byte in bytes {
                let _ = engine.observe_input(byte, now);
                prop_assert!(engine.pending_operations() <= DEFAULT_MAX_PENDING);
            }
        }
    }

    #[test]
    fn bracketed_paste_is_a_cross_chunk_barrier() {
        let (mut engine, start) = safe_engine();
        let bytes = b"\x1b[200~hello\x1b[201~";
        let classes: Vec<_> = bytes
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                engine
                    .observe_input(*byte, start + Duration::from_millis(index as u64))
                    .class
            })
            .collect();

        assert!(
            classes
                .iter()
                .all(|class| matches!(class, InputClass::Barrier(_)))
        );
        assert!(classes.contains(&InputClass::Barrier(InputBarrier::PasteStart)));
        assert_eq!(
            classes.last(),
            Some(&InputClass::Barrier(InputBarrier::PasteEnd))
        );
        assert_eq!(engine.pending_operations(), 0);
        assert!(engine.rearm_at_safe_anchor());
    }

    #[test]
    fn partial_paste_end_marker_keeps_payload_quarantined() {
        let (mut engine, start) = safe_engine();
        for byte in b"\x1b[200~payload\x1b[20xstill paste" {
            let decision = engine.observe_input(*byte, start);
            assert!(matches!(decision.class, InputClass::Barrier(_)));
        }
        assert!(!engine.rearm_at_safe_anchor());

        for byte in b"\x1b[201~" {
            let decision = engine.observe_input(*byte, start);
            assert!(matches!(decision.class, InputClass::Barrier(_)));
        }
        assert!(engine.rearm_at_safe_anchor());
    }

    #[test]
    fn stale_deadline_uses_three_rtts_with_bounds() {
        let (mut engine, start) = safe_engine();
        assert_eq!(engine.stale_deadline(), Duration::from_millis(750));

        engine.measured_rtt = Some(Duration::from_millis(400));
        assert_eq!(engine.stale_deadline(), Duration::from_millis(1_200));

        engine.measured_rtt = Some(Duration::from_secs(2));
        assert_eq!(engine.stale_deadline(), Duration::from_secs(3));

        engine.measured_rtt = Some(Duration::from_millis(10));
        assert_eq!(engine.stale_deadline(), Duration::from_millis(750));

        engine.observe_input(b'a', start);
        assert_eq!(
            engine.expire_stale(start + Duration::from_millis(749)),
            None
        );
        assert_eq!(
            engine.expire_stale(start + Duration::from_millis(750)),
            Some(ResetEffect {
                rollback_chars: 0,
                reason: ResetReason::Stale,
            })
        );
        assert_eq!(engine.echo_confidence(), EchoConfidence::Quarantined);
    }

    #[test]
    fn immediate_mode_never_expires_a_locally_composed_cursor() {
        let mut engine = PredictionEngine::new_immediate();
        let start = Instant::now();
        engine.set_terminal_trust(TerminalTrust::Safe);
        assert!(engine.rearm_at_safe_anchor());
        assert_eq!(engine.stale_deadline(), Duration::from_secs(3));

        engine.observe_input(b'a', start);
        assert_eq!(engine.expire_stale(start + Duration::from_secs(30)), None);
        assert_eq!(engine.visible_predictions(), 1);
        assert_eq!(
            engine.observe_input(b'\r', start).effect,
            InputEffect::Submit
        );
        assert_eq!(engine.expire_stale(start + Duration::from_secs(300)), None);
        assert_eq!(engine.visible_predictions(), 1);
    }

    #[test]
    fn pending_limit_fails_closed() {
        let mut engine = PredictionEngine::with_max_pending(1);
        let start = Instant::now();
        engine.set_terminal_trust(TerminalTrust::Safe);
        assert!(engine.rearm_at_safe_anchor());
        engine.observe_input(b'a', start);

        assert_eq!(
            engine
                .observe_input(b'b', start + Duration::from_millis(1))
                .effect,
            InputEffect::Suspend(ResetEffect {
                rollback_chars: 0,
                reason: ResetReason::PendingLimit,
            })
        );
        assert_eq!(engine.echo_confidence(), EchoConfidence::Quarantined);
        assert_eq!(engine.pending_operations(), 0);
    }

    #[test]
    fn pending_bytes_are_zeroed_before_the_queue_is_cleared() {
        let (mut engine, start) = safe_engine();
        engine.observe_input(b's', start);
        engine.observe_input(b'e', start);
        engine.observe_input(b'c', start);

        engine.zero_pending_bytes();
        for operation in &engine.pending {
            if let PendingOperation::Append { byte, .. } = operation {
                assert_eq!(*byte, 0);
            }
        }
        engine.clear_pending();
        assert!(engine.pending.is_empty());
    }

    #[test]
    fn authoritative_change_rolls_back_visible_suffix() {
        let (mut engine, start) = safe_engine();
        trust_with_probe(&mut engine, start, b'a');
        engine.observe_input(b'b', start + Duration::from_millis(101));

        assert_eq!(
            engine.authoritative_change(),
            ResetEffect {
                rollback_chars: 1,
                reason: ResetReason::AuthoritativeChange,
            }
        );
        assert_eq!(engine.echo_confidence(), EchoConfidence::Quarantined);
    }
}
