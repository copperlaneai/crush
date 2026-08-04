//! Crush configuration sourced exclusively from the process environment.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::PathBuf;
use std::process::Command;

pub(crate) const CRUSH_SSH: &str = "CRUSH_SSH";
pub(crate) const CRUSH_MODE: &str = "CRUSH_MODE";
pub(crate) const CRUSH_PREDICT: &str = "CRUSH_PREDICT";
pub(crate) const CRUSH_TRACE: &str = "CRUSH_TRACE";
pub(crate) const CRUSH_ACTION: &str = "CRUSH_ACTION";

/// Known Crush variables. `strip_crush_env` also strips future `CRUSH_*`
/// variables inherited from the current process.
pub(crate) const CRUSH_ENV_VARS: [&str; 5] = [
    CRUSH_SSH,
    CRUSH_MODE,
    CRUSH_PREDICT,
    CRUSH_TRACE,
    CRUSH_ACTION,
];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Mode {
    #[default]
    Auto,
    Passthrough,
    Force,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Prediction {
    #[default]
    Auto,
    Off,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Action {
    Version,
    Doctor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Config {
    /// Kept as an `OsString` so a non-UTF-8 executable path is not changed.
    pub(crate) ssh_program: OsString,
    pub(crate) mode: Mode,
    pub(crate) prediction: Prediction,
    /// Kept as a `PathBuf` so a non-UTF-8 trace path is not changed.
    pub(crate) trace: Option<PathBuf>,
    pub(crate) action: Option<Action>,
}

impl Config {
    pub(crate) fn from_env() -> Result<Self, ConfigError> {
        Self::from_source(read_env)
    }

    fn from_source(mut get: impl FnMut(&str) -> Option<OsString>) -> Result<Self, ConfigError> {
        let ssh_program = match get(CRUSH_SSH) {
            Some(value) => nonempty(CRUSH_SSH, value, "a non-empty executable name or path")?,
            None => OsString::from("ssh"),
        };

        let mode = match get(CRUSH_MODE) {
            None => Mode::Auto,
            Some(value) if value == OsStr::new("auto") => Mode::Auto,
            Some(value) if value == OsStr::new("passthrough") => Mode::Passthrough,
            Some(value) if value == OsStr::new("force") => Mode::Force,
            Some(value) => {
                return Err(ConfigError::invalid(
                    CRUSH_MODE,
                    value,
                    "one of: auto, passthrough, force",
                ));
            }
        };

        let prediction = match get(CRUSH_PREDICT) {
            None => Prediction::Auto,
            Some(value) if value == OsStr::new("auto") => Prediction::Auto,
            Some(value) if value == OsStr::new("off") => Prediction::Off,
            Some(value) => {
                return Err(ConfigError::invalid(
                    CRUSH_PREDICT,
                    value,
                    "one of: auto, off",
                ));
            }
        };

        let trace = get(CRUSH_TRACE)
            .map(|value| nonempty(CRUSH_TRACE, value, "a non-empty file path").map(PathBuf::from))
            .transpose()?;

        let action = match get(CRUSH_ACTION) {
            None => None,
            Some(value) if value == OsStr::new("version") => Some(Action::Version),
            Some(value) if value == OsStr::new("doctor") => Some(Action::Doctor),
            Some(value) => {
                return Err(ConfigError::invalid(
                    CRUSH_ACTION,
                    value,
                    "one of: version, doctor",
                ));
            }
        };

        Ok(Self {
            ssh_program,
            mode,
            prediction,
            trace,
            action,
        })
    }
}

fn read_env(name: &str) -> Option<OsString> {
    env::var_os(name)
}

fn nonempty(
    variable: &'static str,
    value: OsString,
    expected: &'static str,
) -> Result<OsString, ConfigError> {
    if value.is_empty() {
        Err(ConfigError::invalid(variable, value, expected))
    } else {
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConfigError {
    pub(crate) variable: &'static str,
    pub(crate) value: OsString,
    pub(crate) expected: &'static str,
}

impl ConfigError {
    fn invalid(variable: &'static str, value: OsString, expected: &'static str) -> Self {
        Self {
            variable,
            value,
            expected,
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid {} value {:?}; expected {}",
            self.variable, self.value, self.expected
        )
    }
}

impl std::error::Error for ConfigError {}

/// Remove Crush's private control variables before starting OpenSSH.
///
/// Known names are always removed, including if the caller added an override
/// directly to `command`. Scanning the inherited environment also ensures
/// future `CRUSH_*` variables do not leak to the child before this binary has
/// learned about them.
pub(crate) fn strip_crush_env(command: &mut Command) {
    strip_crush_env_from(command, env::vars_os().map(|(key, _)| key));
}

fn strip_crush_env_from(command: &mut Command, inherited_keys: impl IntoIterator<Item = OsString>) {
    for key in CRUSH_ENV_VARS {
        command.env_remove(key);
    }

    for key in inherited_keys {
        if is_crush_env_key(&key) {
            command.env_remove(key);
        }
    }
}

fn is_crush_env_key(key: &OsStr) -> bool {
    // `as_encoded_bytes` preserves ASCII boundaries on supported platforms,
    // while avoiding a lossy Unicode conversion for unusual environment keys.
    key.as_encoded_bytes().starts_with(b"CRUSH_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(values: &[(&str, OsString)]) -> Result<Config, ConfigError> {
        let values: HashMap<&str, OsString> = values.iter().cloned().collect();
        Config::from_source(|name| values.get(name).cloned())
    }

    #[test]
    fn defaults_are_safe_and_minimal() {
        assert_eq!(
            config(&[]).unwrap(),
            Config {
                ssh_program: OsString::from("ssh"),
                mode: Mode::Auto,
                prediction: Prediction::Auto,
                trace: None,
                action: None,
            }
        );
    }

    #[test]
    fn parses_every_supported_value() {
        let parsed = config(&[
            (CRUSH_SSH, OsString::from("/opt/openssh/bin/ssh")),
            (CRUSH_MODE, OsString::from("force")),
            (CRUSH_PREDICT, OsString::from("off")),
            (CRUSH_TRACE, OsString::from("/tmp/crush.trace")),
            (CRUSH_ACTION, OsString::from("doctor")),
        ])
        .unwrap();

        assert_eq!(parsed.ssh_program, OsStr::new("/opt/openssh/bin/ssh"));
        assert_eq!(parsed.mode, Mode::Force);
        assert_eq!(parsed.prediction, Prediction::Off);
        assert_eq!(parsed.trace, Some(PathBuf::from("/tmp/crush.trace")));
        assert_eq!(parsed.action, Some(Action::Doctor));

        assert_eq!(
            config(&[(CRUSH_MODE, OsString::from("passthrough"))])
                .unwrap()
                .mode,
            Mode::Passthrough
        );
        assert_eq!(
            config(&[(CRUSH_ACTION, OsString::from("version"))])
                .unwrap()
                .action,
            Some(Action::Version)
        );
    }

    #[test]
    fn values_are_case_sensitive() {
        let error = config(&[(CRUSH_MODE, OsString::from("AUTO"))]).unwrap_err();
        assert_eq!(error.variable, CRUSH_MODE);
        assert_eq!(error.value, OsStr::new("AUTO"));
    }

    #[test]
    fn rejects_empty_paths_and_invalid_enums() {
        for (name, value) in [
            (CRUSH_SSH, ""),
            (CRUSH_MODE, "fast"),
            (CRUSH_PREDICT, "on"),
            (CRUSH_TRACE, ""),
            (CRUSH_ACTION, "help"),
        ] {
            let error = config(&[(name, OsString::from(value))]).unwrap_err();
            assert_eq!(error.variable, name);
            assert!(error.to_string().contains(name));
        }
    }

    #[cfg(unix)]
    #[test]
    fn preserves_non_utf8_program_and_trace_paths() {
        use std::os::unix::ffi::OsStringExt;

        let program = OsString::from_vec(b"/tmp/ssh-\xff".to_vec());
        let trace = OsString::from_vec(b"/tmp/trace-\xfe".to_vec());
        let parsed = config(&[(CRUSH_SSH, program.clone()), (CRUSH_TRACE, trace.clone())]).unwrap();

        assert_eq!(parsed.ssh_program, program);
        assert_eq!(parsed.trace, Some(PathBuf::from(trace)));
    }

    #[test]
    fn strips_known_and_future_crush_variables_only() {
        let mut command = Command::new("ssh");
        command
            .env(CRUSH_MODE, "force")
            .env("CRUSH_FUTURE", "private")
            .env("NOT_CRUSH_MODE", "keep")
            .env("Crush_MODE", "keep");

        strip_crush_env_from(
            &mut command,
            [OsString::from("CRUSH_FUTURE"), OsString::from("PATH")],
        );

        let removed = |name: &str| {
            command
                .get_envs()
                .any(|(key, value)| key == OsStr::new(name) && value.is_none())
        };
        let retained = |name: &str| {
            command
                .get_envs()
                .any(|(key, value)| key == OsStr::new(name) && value.is_some())
        };

        assert!(removed(CRUSH_MODE));
        assert!(removed("CRUSH_FUTURE"));
        assert!(retained("NOT_CRUSH_MODE"));
        assert!(retained("Crush_MODE"));
    }

    #[cfg(unix)]
    #[test]
    fn recognizes_non_utf8_future_crush_variable_names() {
        use std::os::unix::ffi::OsStringExt;

        let key = OsString::from_vec(b"CRUSH_\xff".to_vec());
        assert!(is_crush_env_key(&key));
    }
}
