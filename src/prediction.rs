//! Conservative, transport-independent local echo prediction.
//!
//! This module is a side tap. Callers must forward the original input bytes
//! unchanged and use the returned effects only to manage a disposable overlay.
//! The predictor never renders, rewrites input, or interprets authoritative
//! terminal output on its own.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// The minimum time an unconfirmed prediction may remain pending.
pub const MIN_STALE_DEADLINE: Duration = Duration::from_millis(750);

/// The maximum time an unconfirmed prediction may remain pending.
pub const MAX_STALE_DEADLINE: Duration = Duration::from_secs(3);

/// The default bound on retained, unconfirmed input operations.
pub const DEFAULT_MAX_PENDING: usize = 256;

/// Whether the authoritative terminal model is safe to use as an overlay anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalTrust {
    /// There is not yet enough terminal state to place an overlay safely.
    Unknown,
    /// Cursor, modes, and underlying cells are known and safe.
    Safe,
    /// Parsing or state reconciliation has become unreliable.
    Tainted,
}

/// Confidence that the remote application is performing simple linear echo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoConfidence {
    /// The next safe character will be forwarded as an undrawn probe.
    Cold,
    /// An undrawn probe is awaiting an authoritative echo.
    Probe,
    /// Linear echo was confirmed and safe characters may be overlaid.
    Trusted,
    /// Prediction is disabled until the caller establishes a new safe anchor.
    Quarantined,
}

/// Why an input byte is unsafe for local echo prediction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputBarrier {
    /// A C0 control byte other than Escape or Backspace.
    Control(u8),
    /// The opening Escape byte of a terminal sequence.
    Escape,
    /// A byte belonging to an Escape sequence.
    EscapeSequence,
    /// The final byte of a bracketed-paste opening marker.
    PasteStart,
    /// A byte inside bracketed paste, including partial closing markers.
    PasteData,
    /// The final byte of a bracketed-paste closing marker.
    PasteEnd,
    /// A non-ASCII byte. V1 deliberately does not predict Unicode input.
    NonAscii(u8),
}

/// Exact conservative classification of one input byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputClass {
    /// A single-column printable ASCII byte (`0x20..=0x7e`).
    SafePrintable(u8),
    /// Either ASCII Backspace (`0x08`) or Delete (`0x7f`).
    Backspace(u8),
    /// Input that forms a prediction barrier.
    Barrier(InputBarrier),
}

/// Why the current prediction epoch was suspended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetReason {
    /// Input crossed a control, escape, paste, or non-ASCII boundary.
    InputBarrier,
    /// The terminal model is not currently trustworthy.
    TerminalUntrusted,
    /// Backspace targeted confirmed rather than unresolved predicted text.
    UnsafeBackspace,
    /// An authoritative echo contradicted the expected input operation.
    EchoMismatch,
    /// The bounded pending-operation queue filled.
    PendingLimit,
    /// The oldest pending operation exceeded its adaptive deadline.
    Stale,
    /// Authoritative output invalidated the current overlay anchor.
    AuthoritativeChange,
}

/// Work the renderer must perform when an epoch is suspended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetEffect {
    /// Number of currently visible speculative characters to remove.
    pub rollback_chars: usize,
    /// Cause of the reset.
    pub reason: ResetReason,
}

/// Optional local action associated with a classified input byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEffect {
    /// Forward the original byte, but do not alter the local overlay.
    ForwardOnly,
    /// Forward this byte as the undrawn confidence probe.
    Probe { byte: u8 },
    /// Append one disposable speculative character to the overlay.
    DrawAppend { byte: u8 },
    /// Remove the last unresolved speculative character from the overlay.
    DrawBackspace { erased: u8 },
    /// Remove the indicated overlay suffix and suspend prediction.
    Suspend(ResetEffect),
}

/// Classification and overlay effect for one byte observed by the side tap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputDecision {
    /// The byte's conservative semantic class.
    pub class: InputClass,
    /// The optional overlay action. The original byte must still be forwarded.
    pub effect: InputEffect,
}

/// The next remote operation the shadow terminal may authoritatively confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedEcho {
    /// A printable echo, with whether it is currently present in the overlay.
    Printable { byte: u8, visible: bool },
    /// An application-specific erasure corresponding to a forwarded backspace.
    Backspace,
}

/// A confirmation supplied after the shadow terminal recognizes authoritative output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoConfirmation {
    /// The remote application echoed this exact printable byte at the expected anchor.
    Printable(u8),
    /// The remote application authoritatively applied the expected backspace.
    Backspace,
}

/// What kind of pending operation was confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmedEcho {
    /// The first, deliberately undrawn confidence probe.
    Probe,
    /// A later printable operation.
    Printable { byte: u8, was_visible: bool },
    /// A predicted backspace operation.
    Backspace,
}

/// Result of reconciling authoritative output with pending input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationResult {
    /// There was no pending input to confirm.
    NothingPending,
    /// The next pending operation matched.
    Matched {
        /// The operation that matched.
        echo: ConfirmedEcho,
        /// RTT sample for this operation.
        sample_rtt: Duration,
        /// Smoothed RTT after incorporating the sample.
        measured_rtt: Duration,
    },
    /// The confirmation contradicted the expected operation.
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
            // Best-effort erasure without adding a dependency to this core module.
            // The queue is also bounded and never exposed through diagnostics.
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

/// Dependency-free prediction state machine for a single interactive session.
#[derive(Debug)]
pub struct PredictionEngine {
    terminal_trust: TerminalTrust,
    echo_confidence: EchoConfidence,
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
    /// Construct a cold predictor with an unknown terminal model.
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_pending(DEFAULT_MAX_PENDING)
    }

    /// Construct a predictor with a custom pending-operation bound.
    ///
    /// A zero bound is promoted to one so an undrawn probe remains possible.
    #[must_use]
    pub fn with_max_pending(max_pending: usize) -> Self {
        Self {
            terminal_trust: TerminalTrust::Unknown,
            echo_confidence: EchoConfidence::Cold,
            input_state: InputParseState::Ground,
            pending: VecDeque::new(),
            max_pending: max_pending.max(1),
            measured_rtt: None,
        }
    }

    /// Current terminal-model trust.
    #[must_use]
    pub fn terminal_trust(&self) -> TerminalTrust {
        self.terminal_trust
    }

    /// Current learned echo confidence.
    #[must_use]
    pub fn echo_confidence(&self) -> EchoConfidence {
        self.echo_confidence
    }

    /// Number of input operations awaiting authoritative confirmation.
    #[must_use]
    pub fn pending_operations(&self) -> usize {
        self.pending.len()
    }

    /// Number of speculative characters currently visible in the overlay.
    #[must_use]
    pub fn visible_predictions(&self) -> usize {
        self.pending
            .iter()
            .filter(|operation| matches!(operation, PendingOperation::Append { visible: true, .. }))
            .count()
    }

    /// Smoothed echo RTT, if at least one operation has been confirmed.
    #[must_use]
    pub fn measured_rtt(&self) -> Option<Duration> {
        self.measured_rtt
    }

    /// Adaptive expiry interval: `max(750 ms, 3 * RTT)`, capped at 3 seconds.
    #[must_use]
    pub fn stale_deadline(&self) -> Duration {
        self.measured_rtt.map_or(MIN_STALE_DEADLINE, |rtt| {
            rtt.saturating_mul(3)
                .clamp(MIN_STALE_DEADLINE, MAX_STALE_DEADLINE)
        })
    }

    /// Update terminal-model trust.
    ///
    /// Becoming safe does not implicitly re-arm prediction. The shadow terminal
    /// must separately call [`Self::rearm_at_safe_anchor`] after verifying the
    /// cursor and underlying cells.
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

    /// Re-arm prediction after the shadow terminal verifies a safe anchor.
    ///
    /// Re-arming is refused in the middle of an escape sequence or bracketed
    /// paste, or while old operations still await confirmation. An already
    /// trusted echo epoch remains trusted; ordinary authoritative echoes must
    /// not turn every following key back into an undrawn probe.
    pub fn rearm_at_safe_anchor(&mut self) -> bool {
        if self.terminal_trust != TerminalTrust::Safe
            || !self.input_state.is_ground()
            || !self.pending.is_empty()
        {
            return false;
        }

        if self.echo_confidence == EchoConfidence::Quarantined {
            self.echo_confidence = EchoConfidence::Cold;
        }
        true
    }

    /// Observe one raw input byte without consuming or transforming it.
    ///
    /// The caller must forward `byte` regardless of the returned effect.
    pub fn observe_input(&mut self, byte: u8, now: Instant) -> InputDecision {
        let class = self.classify_input(byte);
        let effect = match class {
            InputClass::SafePrintable(printable) => self.observe_printable(printable, now),
            InputClass::Backspace(_) => self.observe_backspace(now),
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

    /// Return the next operation the shadow terminal may confirm.
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

    /// Reconcile one operation recognized in authoritative terminal output.
    ///
    /// Call this only after the shadow model establishes that the output occurred
    /// at the expected anchor. Ordinary unrelated remote bytes are not mismatches.
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

    /// Suspend prediction because authoritative output invalidated the anchor.
    pub fn authoritative_change(&mut self) -> ResetEffect {
        self.suspend(ResetReason::AuthoritativeChange)
    }

    /// Expire pending prediction state when its oldest operation becomes stale.
    pub fn expire_stale(&mut self, now: Instant) -> Option<ResetEffect> {
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

        // A later key cannot be drawn over the still-undrawn `b` column.
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
