//! Conservative classification of an OpenSSH command line.
//!
//! This module observes arguments but never normalizes or rewrites them. An
//! option shape that is not in the maintained OpenSSH short-option table is
//! deliberately handed straight to the user's `ssh` binary.

use std::ffi::OsString;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InvocationDisposition {
    Interactive,
    Passthrough,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClassificationReason {
    LoginShell,
    ExplicitTtyCommand,
    NoLocalTty,
    MissingDestination,
    RemoteCommandWithoutTty,
    NonInteractiveOption(u8),
    UnknownOption(u8),
    NonAsciiOption,
    MissingOptionArgument(u8),
}

impl fmt::Display for ClassificationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LoginShell => f.write_str("interactive login shell"),
            Self::ExplicitTtyCommand => f.write_str("remote command with explicit TTY"),
            Self::NoLocalTty => f.write_str("local input/output is not a terminal"),
            Self::MissingDestination => f.write_str("missing SSH destination"),
            Self::RemoteCommandWithoutTty => {
                f.write_str("remote command does not explicitly allocate a TTY")
            }
            Self::NonInteractiveOption(option) => {
                write!(
                    f,
                    "SSH option -{} requires passthrough",
                    char::from(*option)
                )
            }
            Self::UnknownOption(option) => {
                write!(f, "unknown SSH option -{}", char::from(*option))
            }
            Self::NonAsciiOption => f.write_str("non-ASCII SSH option"),
            Self::MissingOptionArgument(option) => write!(
                f,
                "SSH option -{} is missing its argument",
                char::from(*option)
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InvocationClassification {
    pub(crate) disposition: InvocationDisposition,
    pub(crate) reason: ClassificationReason,
}

impl InvocationClassification {
    pub(crate) fn is_interactive(self) -> bool {
        self.disposition == InvocationDisposition::Interactive
    }

    fn interactive(reason: ClassificationReason) -> Self {
        Self {
            disposition: InvocationDisposition::Interactive,
            reason,
        }
    }

    fn passthrough(reason: ClassificationReason) -> Self {
        Self {
            disposition: InvocationDisposition::Passthrough,
            reason,
        }
    }
}

/// Classify the arguments that will be passed to OpenSSH (excluding argv[0]).
///
/// A login shell is interactive when the caller has a usable local terminal.
/// A remote command is interactive only when `-t`/`-tt` explicitly requests a
/// PTY. Options representing queries, forwarding-only sessions, background
/// jobs, subsystems, or multiplex control are always passed through directly.
pub(crate) fn classify_ssh_invocation(
    args: &[OsString],
    local_tty: bool,
) -> InvocationClassification {
    let mut index = 0;
    let mut destination = None;
    let mut force_tty = false;
    let mut noninteractive = None;
    let mut options_finished = false;

    while index < args.len() {
        let bytes = args[index].as_encoded_bytes();

        if options_finished || bytes == b"-" || !bytes.starts_with(b"-") {
            destination = Some(index);
            break;
        }

        if bytes == b"--" {
            options_finished = true;
            index += 1;
            continue;
        }

        // A leading '-' followed by one or more short options. OpenSSH uses
        // getopt-style attached values (`-p22`, `-oKey=value`) and groups
        // no-argument flags (`-vvtt`).
        let mut offset = 1;
        while offset < bytes.len() {
            let option = bytes[offset];
            if !option.is_ascii() {
                return InvocationClassification::passthrough(ClassificationReason::NonAsciiOption);
            }

            match option_arity(option) {
                Some(OptionArity::None) => {
                    if option == b't' {
                        force_tty = true;
                    }
                    if is_noninteractive_flag(option) && noninteractive.is_none() {
                        noninteractive = Some(option);
                    }
                    offset += 1;
                }
                Some(OptionArity::Required) => {
                    if is_noninteractive_flag(option) && noninteractive.is_none() {
                        noninteractive = Some(option);
                    }

                    // The remainder of this token is the value. Otherwise the
                    // following OsString is consumed whole and left untouched.
                    if offset + 1 == bytes.len() {
                        index += 1;
                        if index == args.len() {
                            return InvocationClassification::passthrough(
                                ClassificationReason::MissingOptionArgument(option),
                            );
                        }
                    }
                    break;
                }
                None => {
                    return InvocationClassification::passthrough(
                        ClassificationReason::UnknownOption(option),
                    );
                }
            }
        }

        index += 1;
    }

    if let Some(option) = noninteractive {
        return InvocationClassification::passthrough(ClassificationReason::NonInteractiveOption(
            option,
        ));
    }

    let Some(destination) = destination else {
        return InvocationClassification::passthrough(ClassificationReason::MissingDestination);
    };

    if !local_tty {
        return InvocationClassification::passthrough(ClassificationReason::NoLocalTty);
    }

    let has_remote_command = destination + 1 < args.len();
    match (has_remote_command, force_tty) {
        (false, _) => InvocationClassification::interactive(ClassificationReason::LoginShell),
        (true, true) => {
            InvocationClassification::interactive(ClassificationReason::ExplicitTtyCommand)
        }
        (true, false) => {
            InvocationClassification::passthrough(ClassificationReason::RemoteCommandWithoutTty)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OptionArity {
    None,
    Required,
}

fn option_arity(option: u8) -> Option<OptionArity> {
    match option {
        // OpenSSH 10.x no-argument options.
        b'4' | b'6' | b'A' | b'a' | b'C' | b'f' | b'G' | b'g' | b'K' | b'k' | b'M' | b'N'
        | b'n' | b'q' | b's' | b'T' | b't' | b'V' | b'v' | b'X' | b'x' | b'Y' | b'y' => {
            Some(OptionArity::None)
        }

        // OpenSSH 10.x options consuming either the rest of this token or the
        // next argv element. Keep this table conservative as OpenSSH evolves.
        b'B' | b'b' | b'c' | b'D' | b'E' | b'e' | b'F' | b'I' | b'i' | b'J' | b'L' | b'l'
        | b'm' | b'O' | b'o' | b'P' | b'p' | b'Q' | b'R' | b'S' | b'W' | b'w' => {
            Some(OptionArity::Required)
        }
        _ => None,
    }
}

fn is_noninteractive_flag(option: u8) -> bool {
    matches!(
        option,
        // Background/config/version/query, master/control operations,
        // forwarding-only/no-stdin, subsystem, no PTY, and stdio forwarding.
        b'f' | b'G' | b'M' | b'N' | b'n' | b'O' | b'Q' | b's' | b'T' | b'V' | b'W'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn classify(values: &[&str]) -> InvocationClassification {
        classify_ssh_invocation(&args(values), true)
    }

    #[test]
    fn recognizes_login_shells_without_rewriting_arguments() {
        for values in [
            vec!["host"],
            vec!["user@host"],
            vec!["-v", "-p", "2222", "user@host"],
            vec!["-vvv", "-p2222", "-oBatchMode=no", "host"],
            vec!["-J", "jump", "-i", "key", "host"],
            vec!["--", "-unusual-host"],
        ] {
            let original = args(&values);
            let snapshot = original.clone();
            let classification = classify_ssh_invocation(&original, true);
            assert_eq!(
                classification,
                InvocationClassification::interactive(ClassificationReason::LoginShell),
                "{values:?}"
            );
            assert_eq!(original, snapshot);
            assert!(classification.is_interactive());
        }
    }

    #[test]
    fn requires_explicit_tty_for_remote_commands() {
        assert_eq!(
            classify(&["host", "tmux", "attach"]),
            InvocationClassification::passthrough(ClassificationReason::RemoteCommandWithoutTty)
        );

        for values in [
            &["-t", "host", "tmux", "attach"][..],
            &["-tt", "host", "tmux", "attach"][..],
            &["-vt", "host", "nvim"][..],
        ] {
            assert_eq!(
                classify(values),
                InvocationClassification::interactive(ClassificationReason::ExplicitTtyCommand)
            );
        }
    }

    #[test]
    fn passes_through_when_no_local_terminal_is_available() {
        assert_eq!(
            classify_ssh_invocation(&args(&["host"]), false),
            InvocationClassification::passthrough(ClassificationReason::NoLocalTty)
        );
        assert_eq!(
            classify_ssh_invocation(&args(&["-tt", "host", "nvim"]), false),
            InvocationClassification::passthrough(ClassificationReason::NoLocalTty)
        );
    }

    #[test]
    fn passes_through_every_noninteractive_option() {
        let cases: &[(&[&str], u8)] = &[
            (&["-f", "host", "true"], b'f'),
            (&["-G", "host"], b'G'),
            (&["-M", "host"], b'M'),
            (&["-N", "host"], b'N'),
            (&["-n", "host"], b'n'),
            (&["-O", "check", "host"], b'O'),
            (&["-Ocheck", "host"], b'O'),
            (&["-Q", "cipher"], b'Q'),
            (&["-Qcipher"], b'Q'),
            (&["-s", "host", "sftp"], b's'),
            (&["-T", "host"], b'T'),
            (&["-V"], b'V'),
            (&["-W", "target:22", "jump"], b'W'),
            (&["-Wtarget:22", "jump"], b'W'),
        ];

        for &(values, option) in cases {
            assert_eq!(
                classify(values),
                InvocationClassification::passthrough(ClassificationReason::NonInteractiveOption(
                    option
                )),
                "{values:?}"
            );
        }
    }

    #[test]
    fn noninteractive_option_wins_over_tty_request() {
        assert_eq!(
            classify(&["-tT", "host", "nvim"]),
            InvocationClassification::passthrough(ClassificationReason::NonInteractiveOption(b'T'))
        );
        assert_eq!(
            classify(&["-tN", "host"]),
            InvocationClassification::passthrough(ClassificationReason::NonInteractiveOption(b'N'))
        );
    }

    #[test]
    fn forwarding_options_can_accompany_an_interactive_shell() {
        for values in [
            &["-D", "1080", "host"][..],
            &["-L8080:localhost:80", "host"][..],
            &["-R", "9000:localhost:9000", "host"][..],
            &["-S", "/tmp/control", "host"][..],
            &["-w", "any:any", "host"][..],
        ] {
            assert_eq!(
                classify(values),
                InvocationClassification::interactive(ClassificationReason::LoginShell),
                "{values:?}"
            );
        }
    }

    #[test]
    fn consumes_option_operands_even_when_they_begin_with_dash() {
        assert_eq!(
            classify(&["-F", "-custom-config", "host"]),
            InvocationClassification::interactive(ClassificationReason::LoginShell)
        );
        assert_eq!(
            classify(&["-o", "-not-an-option-token", "host"]),
            InvocationClassification::interactive(ClassificationReason::LoginShell)
        );
    }

    #[test]
    fn unknown_and_malformed_options_are_conservative() {
        assert_eq!(
            classify(&["-Z", "route", "host"]),
            InvocationClassification::passthrough(ClassificationReason::UnknownOption(b'Z'))
        );
        assert_eq!(
            classify(&["-vp"]),
            InvocationClassification::passthrough(ClassificationReason::MissingOptionArgument(
                b'p'
            ))
        );
        assert_eq!(
            classify(&["-p"]),
            InvocationClassification::passthrough(ClassificationReason::MissingOptionArgument(
                b'p'
            ))
        );
        assert_eq!(
            classify(&[]),
            InvocationClassification::passthrough(ClassificationReason::MissingDestination)
        );
        assert_eq!(
            classify(&["--"]),
            InvocationClassification::passthrough(ClassificationReason::MissingDestination)
        );
    }

    #[test]
    fn arguments_after_destination_are_never_parsed_as_local_options() {
        assert_eq!(
            classify(&["-t", "host", "command", "-T", "-Z"]),
            InvocationClassification::interactive(ClassificationReason::ExplicitTtyCommand)
        );
    }

    #[cfg(unix)]
    #[test]
    fn preserves_and_accepts_a_non_utf8_destination() {
        use std::os::unix::ffi::OsStringExt;

        let destination = OsString::from_vec(b"host-\xff".to_vec());
        let original = vec![destination.clone()];
        let classification = classify_ssh_invocation(&original, true);

        assert_eq!(
            classification,
            InvocationClassification::interactive(ClassificationReason::LoginShell)
        );
        assert_eq!(original[0], destination);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_non_ascii_option_without_lossy_conversion() {
        use std::os::unix::ffi::OsStringExt;

        let option = OsString::from_vec(vec![b'-', 0xff]);
        assert_eq!(
            classify_ssh_invocation(&[option], true),
            InvocationClassification::passthrough(ClassificationReason::NonAsciiOption)
        );
    }

    #[test]
    fn reason_messages_are_stable_and_useful() {
        assert_eq!(
            ClassificationReason::UnknownOption(b'Z').to_string(),
            "unknown SSH option -Z"
        );
        assert_eq!(
            ClassificationReason::MissingOptionArgument(b'p').to_string(),
            "SSH option -p is missing its argument"
        );
    }
}
